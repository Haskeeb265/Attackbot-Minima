"""S24 — the light-active JS bundle crawl + endpoint extraction.

The passive harvest already knows where the JavaScript *is* (``javascript.txt``
is the archive-union of bundle URLs).  What was missing is looking inside the
bundles: the API routes, hardcoded paths and query parameters a client-side app
ships to every browser.  This module fetches those bundles and extracts that
surface.

The spec's invariants, kept exactly:

* **No new execution path (D5v2).**  Active work travels through the same
  dispatcher/session plumbing the validate stage uses — one token bucket, one
  quarantine, one budget.  The fetcher here is *injected*, so tests run the
  whole pipeline with zero network and production inherits the stealth
  transport by construction.
* **Scope gate before any request.**  A bundle whose host has no in-scope
  verdict is never fetched — the check happens before the queue, not after a
  response.  This source discovers new *paths* on already-cleared hosts; it
  never discovers new hosts.
* **Static extraction only.**  Regexes are the v1 cut: ``fetch(...)`` and
  ``axios.*(...)`` calls, string-literal paths, and query-parameter names.
  Source maps are fetched too when referenced (same gate, same budget) because
  the pre-minification source usually carries more explicit endpoint strings.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urljoin, urlparse

from service.recon_pipeline.platform.common.io import read_jsonl, read_text, write_jsonl, write_lines

from . import settings

#: Cap on bundles fetched per run — the budget that bounds this stage's
#: requests no matter how many bundles the harvest found.
MAX_BUNDLES = settings.MAX_CRAWL_BUNDLES if hasattr(settings, "MAX_CRAWL_BUNDLES") else 120

#: Bundles are text; anything over this is a binary or a broken response.
MAX_BUNDLE_BYTES = 3_000_000

# --------------------------------------------------------------------------- #
# extraction — pure, the part every test can exercise without a network
# --------------------------------------------------------------------------- #

#: ``fetch("...")`` / ``fetch(`...`)`` with a literal first argument.
_FETCH_RE = re.compile(r"""fetch\(\s*["'`]([^"'`]+)["'`]""")

#: ``axios.get/post/put/delete/patch/request("...")`` — the method call form.
_AXIOS_RE = re.compile(
    r"""axios\s*\.\s*(?:get|post|put|delete|patch|request)\s*\(\s*["'`]([^"'`]+)["'`]"""
)

#: ``axios({ url: "..." })`` — the config-object form.
_AXIOS_CONFIG_RE = re.compile(r"""axios\s*\(\s*\{[^}]*?url\s*:\s*["'`]([^"'`]+)["'`]""")

#: String literals that look like API paths: start with ``/``, contain a letter,
#: are not obviously a file asset or a regex fragment.
_PATH_RE = re.compile(r"""["'`](/[a-zA-Z0-9_\-./\[\]{}:@%+=,;&~]+)["'`]""")

#: Asset extensions that disqualify a string literal from being an API path.
_NOT_PATH_SUFFIX = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".webm", ".mp3",
)

#: Query-parameter names inside any extracted string: ``?a=1&b=2`` / ``{a}``.
_PARAM_NAMES_RE = re.compile(r"""[?&]([a-zA-Z_][a-zA-Z0-9_]*)=""")

#: ``/users/{id}`` / ``/users/:id``-style template segments — a parameter the
#: app reads.  Plain path segments are not parameters, so the prefix is strict:
#: an opening brace or a colon, never a bare ``/``.
_TEMPLATE_PARAM_RE = re.compile(r"""(?::|{)([a-zA-Z_][a-zA-Z0-9_]*)}?""")

#: Source-map reference at the end of a bundle.
_SOURCEMAP_RE = re.compile(r"""//[#@]\s*sourceMappingURL\s*=\s*(\S+)""")


def extract_paths(bundle: str) -> list[str]:
    """API paths a bundle exposes: fetch/axios calls, then plausible literals.

    Deduplicated, archive-literal-free, and capped at nothing — the caller owns
    the budget on fetches, and a big bundle producing many paths is exactly the
    surface this stage exists to reveal.
    """
    found: list[str] = []
    seen: set[str] = set()

    def add(path: str) -> None:
        path = path.strip()
        if not path or path in seen:
            return
        seen.add(path)
        found.append(path)

    for pattern in (_FETCH_RE, _AXIOS_RE, _AXIOS_CONFIG_RE):
        for match in pattern.finditer(bundle):
            add(match.group(1))
    for match in _PATH_RE.finditer(bundle):
        candidate = match.group(1)
        lowered = candidate.lower()
        if lowered.endswith(_NOT_PATH_SUFFIX):
            continue
        # A lone "/" or a fragment-like blob is noise; require a letter and
        # at least one segment boundary.
        if not re.search(r"[a-zA-Z]", candidate) or candidate.count("/") < 1:
            continue
        add(candidate)
    return found


def extract_parameters(paths: list[str], bundle: str) -> list[str]:
    """Parameter names the bundle reads: from paths and from template strings."""
    names: list[str] = []
    seen: set[str] = set()

    def add(name: str) -> None:
        if name and name not in seen:
            seen.add(name)
            names.append(name)

    for path in paths:
        for name in _PARAM_NAMES_RE.findall(path):
            add(name)
        # A path that kept its template segments (``/users/{id}/orders``) is
        # telling us the parameter directly.
        for name in _TEMPLATE_PARAM_RE.findall(path):
            add(name)
    for match in re.finditer(r"""["'`]([^"'`]*(?:\{|:)[a-zA-Z_][a-zA-Z0-9_]*[^"'`]*)["'`]""", bundle):
        for name in _TEMPLATE_PARAM_RE.findall(match.group(1)):
            add(name)
        # Template strings also carry query params: "/items?page=2".
        for name in _PARAM_NAMES_RE.findall(match.group(1)):
            add(name)
    return sorted(names)


def resolve_reference(base_url: str, reference: str) -> str | None:
    """One extraction result → an absolute URL, or ``None`` when it cannot be.

    Relative paths resolve against the bundle's own URL; scheme-relative and
    absolute references resolve as themselves; ``http(s)`` only — the crawl
    requests web surface, nothing else.
    """
    reference = reference.strip()
    if not reference or reference.startswith("#"):
        return None
    absolute = urljoin(base_url, reference)
    scheme = urlparse(absolute).scheme.lower()
    if scheme not in ("http", "https"):
        return None
    return absolute


def source_map_url(bundle: str, bundle_url: str) -> str | None:
    """The bundle's source-map reference, resolved absolute."""
    match = _SOURCEMAP_RE.search(bundle)
    if match is None:
        return None
    return resolve_reference(bundle_url, match.group(1))


@dataclass
class CrawlFinding:
    """One endpoint a bundle revealed, with where it came from."""

    url: str
    host: str
    path: str
    bundle: str
    parameters: list[str] = field(default_factory=list)
    via_source_map: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "url": self.url,
            "host": self.host,
            "path": self.path,
            "bundle": self.bundle,
            **({"parameters": self.parameters} if self.parameters else {}),
            **({"via_source_map": True} if self.via_source_map else {}),
        }


def _host_of(url: str) -> str:
    return urlparse(url).netloc.lower()


def _path_of(url: str) -> str:
    parsed = urlparse(url)
    return parsed.path or "/"


def _params_for(path: str, bundle_params: list[str]) -> list[str]:
    """Parameters this *path* itself carries, else none — never the bundle-wide set."""
    own = [name for name in bundle_params if name in path]
    return own


def crawl(
    bundle_urls: list[str],
    *,
    fetcher,
    scope=None,
    max_bundles: int = MAX_BUNDLES,
    timeout: float | None = None,
) -> tuple[list[CrawlFinding], dict[str, int]]:
    """Fetch in-scope bundles and extract their endpoint surface.

    ``fetcher(url) -> (status, text)`` is injected — production passes the
    stealth session's GET, tests pass a table.  A host without an in-scope
    verdict is skipped *before* its bundle is requested; the count of those
    refusals is reported, because a silent skip would look like a harvest gap.
    """
    findings: list[CrawlFinding] = []
    # ``js_`` prefix on every key: the summary merges stage counts flat, and
    # ``endpoints``/``parameters`` are already the *extract* stage's numbers.
    counts = {
        "js_bundles": 0,
        "js_fetched": 0,
        "js_failed": 0,
        "js_scope_refused": 0,
        "js_endpoints": 0,
        "js_parameters": 0,
        "js_source_maps": 0,
        "js_truncated": 0,
    }
    seen_urls: set[str] = set()

    for bundle_url in bundle_urls:
        if counts["js_fetched"] >= max_bundles:
            counts["js_truncated"] += 1
            continue
        if bundle_url in seen_urls:
            continue
        seen_urls.add(bundle_url)
        counts["js_bundles"] += 1

        host = _host_of(bundle_url)
        if scope is not None:
            verdict = scope.check_host(host)
            if getattr(verdict, "state", "") != "in_scope":
                counts["js_scope_refused"] += 1
                continue

        status, text = fetcher(bundle_url)
        if status is None or status >= 400 or not text:
            counts["js_failed"] += 1
            continue
        counts["js_fetched"] += 1
        text = text[:MAX_BUNDLE_BYTES]

        paths = extract_paths(text)
        bundle_params = extract_parameters(paths, text)
        for path in paths:
            absolute = resolve_reference(bundle_url, path)
            if absolute is None:
                continue
            findings.append(
                CrawlFinding(
                    url=absolute,
                    host=_host_of(absolute),
                    path=_path_of(absolute),
                    bundle=bundle_url,
                    parameters=_params_for(path, bundle_params),
                )
            )
            counts["js_endpoints"] += 1

        # Source maps: same gate, same budget, one extra fetch per bundle.  The
        # value is ``sourcesContent`` — the pre-minification code, which carries
        # more explicit endpoint strings than the minified bundle.  (The
        # ``sources`` entries are file paths of the original tree, not URLs;
        # resolving them produced only noise, so v1 ignores them.)
        map_url = source_map_url(text, bundle_url)
        if map_url and counts["js_fetched"] < max_bundles and map_url not in seen_urls:
            seen_urls.add(map_url)
            map_scope = scope.check_host(_host_of(map_url)).state if scope is not None else "in_scope"
            if map_scope == "in_scope":
                status, map_text = fetcher(map_url)
                if status is not None and status < 400 and map_text:
                    counts["js_fetched"] += 1
                    counts["js_source_maps"] += 1
                    map_findings = 0
                    try:
                        parsed_map = json.loads(map_text[:MAX_BUNDLE_BYTES])
                    except (json.JSONDecodeError, ValueError):
                        parsed_map = {}
                    for source in parsed_map.get("sourcesContent", []) or []:
                        if not isinstance(source, str) or not source:
                            continue
                        for path in extract_paths(source):
                            absolute = resolve_reference(bundle_url, path)
                            if absolute is None:
                                continue
                            findings.append(
                                CrawlFinding(
                                    url=absolute,
                                    host=_host_of(absolute),
                                    path=_path_of(absolute),
                                    bundle=bundle_url,
                                    via_source_map=True,
                                )
                            )
                            map_findings += 1
                    counts["js_endpoints"] += map_findings
        counts["js_parameters"] = len({p for f in findings for p in f.parameters})

    return findings, counts
