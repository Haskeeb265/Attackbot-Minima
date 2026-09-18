"""Canonicalize and classify URLs — this stage's identity contract.

A URL is not a hostname, and that difference is the whole reason this module
exists.  Historical harvests return the *same* resource spelled many ways::

    HTTP://Example.com:80/a/b/../c?id=1&utm_source=x#frag
    https://example.com/a/c?id=1

Downstream code — a graph node, an endpoint list, a report row — needs one
answer for "is this the same asset as that one", and it must be the same answer
in every stage.  So every URL that enters this pipeline is reduced to exactly one
canonical string, and that string is the identity.

The rules, each chosen for a failure that actually happens in archived data:

* **Only ``http`` / ``https``.**  ``mailto:``, ``javascript:``, ``ftp:`` and
  schemeless tokens are not web assets; they are dropped, not guessed at.
* **Host lowercased, IDNA-encoded, trailing dot stripped** — via the sibling
  names stage's :func:`canonicalize_host`, so a host here and a subdomain there
  can never disagree about what a name is.
* **Default ports removed** (``:80`` for http, ``:443`` for https) so
  ``https://host:443/x`` and ``https://host/x`` are one asset.
* **Path normalized** — duplicate slashes collapsed and ``.``/``..`` resolved,
  because archived crawls record both ``/a//b`` and ``/a/b``.
* **Tracking parameters stripped and the rest sorted.**  ``utm_*``, ``fbclid``,
  ``gclid`` and friends are campaign decoration that multiply one endpoint into
  dozens of fake distinct ones.  Sorting makes the canonical form deterministic
  rather than "whatever order the crawler saw".
* **Fragment dropped** — it never reaches a server, so it cannot distinguish two
  requests.
* **Length capped** and **in-scope filter** — a URL whose host is not the apex or
  a subdomain of it is out of scope, exactly as the names stage treats a foreign
  hostname.

On top of identity, the module *classifies*: every URL gets a ``kind`` (page,
api, js, json, xml, css, sourcemap, image, doc, archive, media, other) and an
``interesting`` flag for the paths that are worth a human's first five minutes —
``.git/config``, ``.env``, ``backup.sql``, ``/swagger``, ``/actuator`` and the
rest.  Classification is what lets the extract stage say "12 javascript bundles,
3 source maps, 41 parameter names" instead of "9 812 URLs".

Everything here is pure: no network, no Docker, no clock.  That is what makes the
identity contract unit-testable, which is the only way to trust it.
"""

from __future__ import annotations

import ipaddress
import posixpath
import re
from collections.abc import Iterable
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from service.recon_pipeline.platform.common.normalize import canonicalize_host, is_subdomain_of

#: Anything longer than this is almost certainly a data blob, not a page.
MAX_URL_LENGTH = 4096

#: The only schemes that can name a web asset.
ALLOWED_SCHEMES = ("http", "https")

_DEFAULT_PORTS = {"http": 80, "https": 443}

#: Campaign/telemetry parameters.  These are the ones that routinely turn one
#: archived endpoint into hundreds of seemingly distinct URLs; the list is
#: deliberately explicit rather than a ``utm_`` prefix rule, because a genuine
#: application parameter may legitimately begin with ``utm``.
TRACKING_PARAMS = frozenset(
    {
        "utm_source",
        "utm_medium",
        "utm_campaign",
        "utm_term",
        "utm_content",
        "utm_id",
        "utm_name",
        "utm_reader",
        "utm_referrer",
        "gclid",
        "gclsrc",
        "dclid",
        "fbclid",
        "msclkid",
        "twclid",
        "igshid",
        "yclid",
        "mc_cid",
        "mc_eid",
        "_ga",
        "_gl",
        "_hsenc",
        "_hsmi",
        "hsctatracking",
        "vero_id",
        "ref",
        "ref_src",
        "ref_url",
        "referrer",
        "source",
    }
)

# --------------------------------------------------------------------------- #
# Classification tables
# --------------------------------------------------------------------------- #

KIND_PAGE = "page"
KIND_API = "api"
KIND_JSON = "json"
KIND_XML = "xml"
KIND_JS = "js"
KIND_CSS = "css"
KIND_SOURCEMAP = "sourcemap"
KIND_IMAGE = "image"
KIND_DOC = "doc"
KIND_ARCHIVE = "archive"
KIND_MEDIA = "media"
KIND_OTHER = "other"

#: Extension -> kind.  An extension is only a hint, which is why it is a table
#: and not a chain of ``if``s: the kinds below are mutually exclusive by
#: construction, so classification cannot become order-dependent.
EXTENSION_KINDS: dict[str, str] = {
    # scripts
    "js": KIND_JS,
    "mjs": KIND_JS,
    "cjs": KIND_JS,
    "jsx": KIND_JS,
    "ts": KIND_JS,
    "tsx": KIND_JS,
    "map": KIND_SOURCEMAP,
    # structured data
    "json": KIND_JSON,
    "jsonl": KIND_JSON,
    "ndjson": KIND_JSON,
    "geojson": KIND_JSON,
    # markup
    "xml": KIND_XML,
    "rss": KIND_XML,
    "atom": KIND_XML,
    "wsdl": KIND_XML,
    # style
    "css": KIND_CSS,
    "scss": KIND_CSS,
    "sass": KIND_CSS,
    "less": KIND_CSS,
    # images
    "png": KIND_IMAGE,
    "jpg": KIND_IMAGE,
    "jpeg": KIND_IMAGE,
    "gif": KIND_IMAGE,
    "svg": KIND_IMAGE,
    "webp": KIND_IMAGE,
    "ico": KIND_IMAGE,
    "bmp": KIND_IMAGE,
    "avif": KIND_IMAGE,
    "tif": KIND_IMAGE,
    "tiff": KIND_IMAGE,
    # documents
    "pdf": KIND_DOC,
    "doc": KIND_DOC,
    "docx": KIND_DOC,
    "xls": KIND_DOC,
    "xlsx": KIND_DOC,
    "ppt": KIND_DOC,
    "pptx": KIND_DOC,
    "txt": KIND_DOC,
    "md": KIND_DOC,
    "csv": KIND_DOC,
    "rtf": KIND_DOC,
    "odt": KIND_DOC,
    # archives / packages (also ``interesting`` — see below)
    "zip": KIND_ARCHIVE,
    "tar": KIND_ARCHIVE,
    "gz": KIND_ARCHIVE,
    "tgz": KIND_ARCHIVE,
    "bz2": KIND_ARCHIVE,
    "xz": KIND_ARCHIVE,
    "7z": KIND_ARCHIVE,
    "rar": KIND_ARCHIVE,
    "jar": KIND_ARCHIVE,
    "war": KIND_ARCHIVE,
    "ear": KIND_ARCHIVE,
    "apk": KIND_ARCHIVE,
    "ipa": KIND_ARCHIVE,
    "whl": KIND_ARCHIVE,
    # media
    "mp4": KIND_MEDIA,
    "webm": KIND_MEDIA,
    "mov": KIND_MEDIA,
    "avi": KIND_MEDIA,
    "mkv": KIND_MEDIA,
    "mp3": KIND_MEDIA,
    "wav": KIND_MEDIA,
    "ogg": KIND_MEDIA,
    "flac": KIND_MEDIA,
    "m3u8": KIND_MEDIA,
    "mpd": KIND_MEDIA,
}

#: A plausible query-parameter name.  Historical harvests are full of debris that
#: is not a parameter at all — a shell command pasted into a URL, a sentence from a
#: documentation page, a regex fragment.  Requiring an identifier shape is what
#: keeps the ``parameters`` artifact a list of *names an application reads* rather
#: than a transcript of everything the internet ever typed.
PLAUSIBLE_PARAM_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.\-\[\]]*$")

#: Longest token still treated as a name.  Beyond this a "name" is prose that
#: happens to be identifier-shaped, which archived query strings are full of.
MAX_PARAMETER_LENGTH = 64

#: Documentation/template placeholders.  ``${P}.tar.bz2`` and ``{{ var }}`` are
#: real strings in archived URLs and are never real endpoints; a live run against
#: ``example.com`` produced an entire page of them, which is what motivated this.
_JUNK_MARKER_RE = re.compile(r"[$][{]|[{][{]|[$][(]")

#: Path shapes that are an API surface regardless of extension.
_API_HINT_RE = re.compile(
    r"/(?:api|rest|graphql|gql|rpc|soap|odata|jsonrpc|v\d+)(?:/|$)", re.IGNORECASE
)

#: Extensions that are, by themselves, a finding worth surfacing: source
#: archives, database dumps, editor backups, config and key material.
INTERESTING_EXTENSIONS = frozenset(
    {
        "bak",
        "backup",
        "old",
        "orig",
        "save",
        "swp",
        "swo",
        "sql",
        "dump",
        "db",
        "sqlite",
        "sqlite3",
        "env",
        "yml",
        "yaml",
        "toml",
        "ini",
        "conf",
        "config",
        "cfg",
        "log",
        "pem",
        "key",
        "crt",
        "cer",
        "p12",
        "pfx",
        "jks",
        "keystore",
        "ds_store",
        "sh",
        "bat",
        "ps1",
        "htpasswd",
        "passwd",
        "npmrc",
        "dockerenv",
        # Downloadable archives are a classic finding: a source tarball or a
        # site backup left in the web root is exactly what an operator should
        # read first, so every archive extension is a triage hint too.
        "zip",
        "tar",
        "gz",
        "tgz",
        "bz2",
        "xz",
        "7z",
        "rar",
        "jar",
        "war",
        "ear",
        "apk",
        "ipa",
        "whl",
    }
)

#: Path segments whose presence is a finding on any extension.
INTERESTING_SEGMENTS = frozenset(
    {
        ".git",
        ".svn",
        ".hg",
        ".bzr",
        ".env",
        ".aws",
        ".ssh",
        ".well-known",
        "admin",
        "administrator",
        "backup",
        "backups",
        "swagger",
        "swagger-ui",
        "openapi",
        "api-docs",
        "graphql",
        "actuator",
        "debug",
        "phpinfo.php",
        "server-status",
        "server-info",
        "console",
        "jenkins",
        "grafana",
        "kibana",
        "elasticsearch",
        "_cat",
        "_cluster",
        "wp-admin",
        "wp-config",
        "phpmyadmin",
        "manager",
        "jmx-console",
        "web-console",
    }
)

#: Whole-path suffixes that are interesting even when the extension is mundane.
INTERESTING_PATH_SUFFIXES = (
    ".git/config",
    ".git/head",
    ".env",
    ".env.local",
    ".env.production",
    "/docker-compose.yml",
    "/.dockerenv",
    "/id_rsa",
    "/.htpasswd",
    "/web.config",
    "/crossdomain.xml",
    "/.ds_store",
)


# --------------------------------------------------------------------------- #
# Parsed URL
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ParsedUrl:
    """One canonical URL and everything the pipeline knows about it."""

    #: The canonical string — this is the asset identity.
    url: str
    scheme: str
    host: str
    port: int | None
    path: str
    query: str
    #: Query parameters as ``(name, value)`` pairs, tracking ones removed and
    #: sorted.  Kept on the object because the extract stage needs the names.
    params: tuple[tuple[str, str], ...]
    extension: str
    kind: str
    interesting: bool
    #: True when the URL parses but is not a real address a request could be sent
    #: to — a template placeholder, a shell fragment, a control character.  Junk
    #: is a *property*, not a parse failure, so it is recorded rather than raised;
    #: the batch helpers exclude it and the report counts it.
    junk: bool = False

    @property
    def endpoint(self) -> str:
        """The URL without its query — the endpoint identity.

        ``https://api.example.com/v1/user?id=7`` and ``.../v1/user?id=9`` are
        the *same* endpoint with different parameters, which is the unit a
        content-discovery or fuzzing pass cares about.
        """
        return build_url(self.scheme, self.host, self.port, self.path, "")

    @property
    def parameter_names(self) -> tuple[str, ...]:
        """Sorted, deduplicated parameter names on this URL."""
        return tuple(sorted({name for name, _ in self.params}))

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "url": self.url,
            "host": self.host,
            "path": self.path,
            "kind": self.kind,
        }
        if self.query:
            payload["query"] = self.query
        if self.extension:
            payload["extension"] = self.extension
        if self.port is not None:
            payload["port"] = self.port
        if self.interesting:
            payload["interesting"] = True
        return payload


# --------------------------------------------------------------------------- #
# Path / query helpers
# --------------------------------------------------------------------------- #


def _normalize_path(raw: str) -> str:
    """Collapse duplicate slashes and resolve ``.``/``..``, preserving the root.

    Archived crawls record ``/a//b``, ``/a/./b`` and ``/a/../a/b`` as distinct
    strings for one resource; without this they would be three assets.
    """
    path = raw or "/"
    if not path.startswith("/"):
        path = "/" + path

    # POSIX treats a leading ``//`` as implementation-defined, so collapse before
    # normpath rather than relying on its behaviour.
    path = re.sub(r"/{2,}", "/", path)

    trailing_slash = path.endswith("/") and path != "/"
    normalized = posixpath.normpath(path)
    if normalized == ".":
        normalized = "/"
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    if trailing_slash and not normalized.endswith("/"):
        normalized += "/"
    return normalized


def extension_of(path: str) -> str:
    """Lowercase extension of the last path segment, without the dot.

    ``""`` when the segment has none.  A leading dot does not count: ``/.git``
    is a directory name, not a ``git`` file, and classifying it as one would
    mislabel the most common finding in archived URLs.
    """
    segment = path.rstrip("/").rsplit("/", 1)[-1]
    if "." not in segment.lstrip("."):
        return ""
    return segment.rsplit(".", 1)[-1].lower()


def parse_parameters(query: str, *, strip_tracking: bool = True) -> tuple[tuple[str, str], ...]:
    """Parse a query string into sorted ``(name, value)`` pairs.

    Tracking parameters are removed and the rest sorted, so the same logical
    request always produces the same pair list (and therefore the same canonical
    URL) regardless of the order the crawler emitted it in.
    """
    if not query:
        return ()
    pairs = parse_qsl(query, keep_blank_values=True)
    if strip_tracking:
        pairs = [(name, value) for name, value in pairs if name.lower() not in TRACKING_PARAMS]
    return tuple(sorted(pairs, key=lambda pair: (pair[0], pair[1])))


def build_url(scheme: str, host: str, port: int | None, path: str, query: str) -> str:
    """Assemble a canonical URL string, omitting a default port."""
    netloc = host
    if port is not None and port != _DEFAULT_PORTS.get(scheme):
        netloc = f"{host}:{port}"
    return urlunsplit((scheme, netloc, path or "/", query, ""))


# --------------------------------------------------------------------------- #
# Canonicalization
# --------------------------------------------------------------------------- #


def _canonical_host(raw: str | None) -> str | None:
    """Canonicalize a URL host, accepting bare IP literals as well as names.

    Names go through the sibling stage's :func:`canonicalize_host` so the two
    pipelines agree on what a hostname is; IP literals are allowed through
    (archived URLs do reference them) even though they will later fail the
    apex-scope filter for a domain target — which is the correct outcome, not a
    parsing failure.
    """
    if not raw:
        return None
    host = canonicalize_host(raw)
    if host is not None:
        return host
    try:
        return str(ipaddress.ip_address(raw.strip().strip("[]")))
    except ValueError:
        return None


def parse_url(
    value: object,
    *,
    apex: str | None = None,
    max_length: int = MAX_URL_LENGTH,
) -> ParsedUrl | None:
    """Reduce a raw token to a :class:`ParsedUrl`, or ``None`` if it is not one.

    Returns ``None`` — rather than raising — for every malformed, schemeless,
    non-HTTP(S), out-of-scope or oversized token, because archived harvests are
    full of them and one bad line must never stop the pipeline.  When *apex* is
    given, a URL whose host is neither the apex nor a subdomain of it is refused,
    which is how foreign-domain leakage is kept out of the output.
    """
    if value is None:
        return None
    token = str(value).strip().strip("\"'`")
    if not token or "://" not in token:
        return None

    split = urlsplit(token)
    scheme = split.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        return None

    host = _canonical_host(split.hostname)
    if host is None:
        return None

    try:
        raw_port = split.port
    except ValueError:
        # e.g. ``https://host:notaport/`` or a port above 65535.
        return None
    port = None if raw_port in (None, _DEFAULT_PORTS[scheme]) else raw_port

    if apex is not None:
        apex = apex.lower().rstrip(".")
        if host != apex and not is_subdomain_of(host, apex):
            return None

    path = _normalize_path(split.path)
    pairs = parse_parameters(split.query)
    query = urlencode(pairs) if pairs else ""

    url = build_url(scheme, host, port, path, query)
    if len(url) > max_length:
        return None

    return ParsedUrl(
        junk=_is_junk(path, query, pairs, url),
        url=url,
        scheme=scheme,
        host=host,
        port=port,
        path=path,
        query=query,
        params=pairs,
        extension=extension_of(path),
        kind=classify(path, query),
        interesting=is_interesting(path),
    )


def canonicalize_url(
    value: object,
    *,
    apex: str | None = None,
    max_length: int = MAX_URL_LENGTH,
) -> str | None:
    """The canonical string for *value*, or ``None`` when it is not a URL.

    Note that this is the *identity* function, so a URL that parses but is junk
    (see :func:`is_junk`) still gets a canonical string — junk is excluded at the
    batch level (:func:`urls_for_apex`, :func:`parse_urls`), not hidden here.
    """
    parsed = parse_url(value, apex=apex, max_length=max_length)
    return parsed.url if parsed else None


def _is_junk(
    path: str,
    query: str,
    pairs: tuple[tuple[str, str], ...],
    url: str,
) -> bool:
    """True when a parsed URL is debris rather than an address.

    Four witnesses, each observed in a real harvest:

    * a template placeholder (``${P}``, ``{{x}}``, ``$(cmd)``) in the path or query;
    * a raw control character or NUL escape (shell/terminal debris copied into a
      URL, which also makes the string unsafe to log verbatim);
    * a literal space, which means the token was never a URL to begin with;
    * a query string that contains another absolute URL, which is the signature of
      a pasted browser address bar or a broken redirect, not an application query.
    """
    if _JUNK_MARKER_RE.search(path) or _JUNK_MARKER_RE.search(query):
        return True
    if "%00" in url.lower() or any(ord(char) < 0x20 for char in url):
        return True
    if " " in path or " " in query:
        return True
    # A parameter whose *value* is itself an absolute URL is the signature of a
    # pasted address bar or a broken open redirect.  Checked on the parsed values
    # rather than the encoded query, because ``urlencode`` renders the ``://``
    # as ``%3A%2F%2F`` and would hide it from a string test.
    return any("://" in value for _, value in pairs)


def is_plausible_parameter(name: str) -> bool:
    """True when *name* looks like a query parameter rather than harvest debris.

    Two rejections beyond the identifier shape are empirical, both added after a
    live 49 000-URL harvest of a real target:

    * **a top-level dot.**  ``?hackddos.com`` and ``?index.html`` occurred as query
      *keys* — spam injection and broken links — and neither is a name an
      application reads.  A dot is only meaningful inside brackets, where it is a
      nested member (``filter[user.name]``).
    * **an over-long token.**  Prose that happens to be identifier-shaped.
    """
    if not name or len(name) > MAX_PARAMETER_LENGTH:
        return False
    if PLAUSIBLE_PARAM_RE.match(name) is None:
        return False
    return "." not in name.split("[", 1)[0]


# --------------------------------------------------------------------------- #
# Classification
# --------------------------------------------------------------------------- #


def classify(path: str, query: str = "") -> str:
    """The kind of resource a path names.

    Extension first (it is the most reliable signal available from a URL alone),
    then an API-shaped path, then ``page``.  Query strings are consulted only for
    the one case where they carry the signal: a ``graphql`` query parameter means
    the endpoint is an API whatever the path looks like.
    """
    extension = extension_of(path)
    kind = EXTENSION_KINDS.get(extension)
    if kind is not None:
        return kind
    if _API_HINT_RE.search(path):
        return KIND_API
    if query and re.search(r"(?:^|&)query=", query):
        return KIND_API
    return KIND_PAGE


def is_interesting(path: str) -> bool:
    """True when a path is the kind an operator should look at first.

    Three independent witnesses, any one of which is enough: a sensitive
    extension (``.sql``, ``.env``, ``.zip``), a sensitive path segment
    (``/.git``, ``/swagger``, ``/actuator``), or a sensitive whole-path suffix
    (``/.git/config``).  This is a triage hint, not a verdict — it never gates a
    request, it only decides ordering in the report.
    """
    lowered = path.lower()
    if extension_of(lowered) in INTERESTING_EXTENSIONS:
        return True
    if any(suffix in lowered for suffix in INTERESTING_PATH_SUFFIXES):
        return True
    return any(segment in INTERESTING_SEGMENTS for segment in lowered.split("/"))


# --------------------------------------------------------------------------- #
# Batch operations
# --------------------------------------------------------------------------- #


def _iter_tokens(values: object) -> Iterable[object]:
    """Normalise the accepted input shapes into one iterable.

    Callers legitimately hold a list, a generator, a single string, or nothing at
    all; this is the one place that decides how each is iterated, so the three
    batch functions below cannot disagree (and so a bare string is treated as one
    token rather than as a sequence of characters).
    """
    if values is None:
        return ()
    if isinstance(values, (str, bytes)):
        return (values,)
    if isinstance(values, Iterable):
        return values
    return (values,)


def urls_for_apex(values: object, apex: str) -> list[str]:
    """Canonical, in-scope, deduplicated, sorted URLs from an iterable of tokens.

    The single entry point every source's raw output passes through, so
    normalization and scope policy cannot drift between sources.
    """
    seen: set[str] = set()
    for value in _iter_tokens(values):
        parsed = parse_url(value, apex=apex)
        if parsed is not None and not parsed.junk:
            seen.add(parsed.url)
    return sorted(seen)


def parse_urls(values: object, apex: str) -> list[ParsedUrl]:
    """Parsed, deduplicated URLs for *values* — the extract stage's input.

    Deduplication happens on the canonical string, which is the asset identity;
    the returned list is sorted by that identity so output is reproducible.
    """
    parsed: dict[str, ParsedUrl] = {}
    for value in _iter_tokens(values):
        item = parse_url(value, apex=apex)
        if item is not None and not item.junk:
            parsed.setdefault(item.url, item)
    return [parsed[key] for key in sorted(parsed)]


def group_by_kind(items: Iterable[ParsedUrl]) -> dict[str, list[str]]:
    """Group parsed URLs by their ``kind``, each list sorted."""
    grouped: dict[str, list[str]] = {}
    for item in items:
        grouped.setdefault(item.kind, []).append(item.url)
    return {kind: sorted(urls) for kind, urls in sorted(grouped.items())}


def parameter_index(items: Iterable[ParsedUrl]) -> dict[str, list[str]]:
    """``{parameter_name: [url, ...]}`` across parsed URLs.

    The reverse index is the useful shape: a parameter name that appears on many
    endpoints is a shared convention (an auth token, an id scheme), while one
    that appears once is often a debug leftover — both worth seeing.
    """
    index: dict[str, set[str]] = {}
    for item in items:
        for name in item.parameter_names:
            index.setdefault(name, set()).add(item.url)
    return {name: sorted(urls) for name, urls in sorted(index.items())}
