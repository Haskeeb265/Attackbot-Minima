"""Browser identities: one coherent story per host, not one random header set.

Why this module exists
----------------------
The cheapest way to look automated is to be *incoherent*: claim a Chrome
``User-Agent`` while negotiating with a Go TLS stack, send a Firefox version
string with Chrome Client Hints, advertise ``zstd`` to a browser that never
supported it, or rotate all of the above between requests to the same host.

That last one is not hypothetical.  Measured against ``tls.peet.ws`` with the
toolchain this project actually runs (see the stealth README for the captures):

* default ``httpx`` random user agents resolve to things like
  ``Mozilla/5.0 (X11; Linux i686; rv:1.9.7.20) Gecko/ Firefox/3.6.13`` (a 2010
  user agent) or ``Mozilla/5.0 (Kubuntu; Linux i686) ... Chrome/134.0.0.0`` (a
  spelling no browser has ever sent);
* ``httpx -tlsi chrome`` *does* produce the real Chrome ClientHello
  (``t13d1516h2_8daaf6152771_...``, the same cipher hash Cloudflare publishes
  for current Chrome) — but paired with whichever user agent the randomiser
  picked, which is exactly the mismatch modern bot scores look for.

So each identity here is a single, internally consistent bundle:

* a user agent and, for Chromium-family profiles, matching Client Hints
  (``sec-ch-ua``, ``sec-ch-ua-mobile``, ``sec-ch-ua-platform``);
* the header *order* that family actually sends (Chrome puts ``sec-ch-ua``
  before ``user-agent``; Firefox sends no Client Hints at all);
* an accept-encoding token set the family supports;
* a TLS ClientHello target for ``httpx -tlsi`` / ``curl_cffi`` impersonation;
* the fetch metadata that makes the request look like a page load rather than a
  bare request from a script.

``verify()`` asserts those internal invariants, so a bad edit fails in tests
instead of at the target.

Why *stable* identities
-----------------------
Cloudflare's JA4 Signals are computed over *aggregates* of the last hour of
traffic: how browser-like a fingerprint is globally (``browser_ratio_1h``), how
cacheable its responses are, how often it speaks HTTP/2 or HTTP/3.  A rare or
novel fingerprint is suspicious by construction, and a fingerprint that changes
between requests from the same client is rarer still.  The winning strategy is
therefore to be *common and boring*: pick one mainstream profile per host and
keep it for the whole engagement.  :meth:`IdentityPool.for_host` does that
deterministically, so a re-run presents the same identity to the same host.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

#: Chrome major version used by the Chromium-family profiles.
#:
#: Must stay in lockstep with the TLS ClientHello we ask for: a user agent far
#: ahead of the impersonated ClientHello is a mismatch all by itself.  Chrome
#: 134 pairs with a 15-cipher/16-extension ClientHello whose cipher hash is
#: ``8daaf6152771``, which is what ``httpx -tlsi chrome`` negotiates.
CHROME_MAJOR = "134"

#: Firefox major/version string, matched to the same reasoning.
FIREFOX_VERSION = "135.0"

#: Safari version string (WebKit sends no Client Hints, so only the UA matters).
SAFARI_VERSION = "18.3"

#: Header names the way browsers actually spell them on the wire.  HTTP/2
#: lowercases them by protocol, but HTTP/1.1 does not: a Chromium browser sends
#: ``Sec-Ch-Ua``/``User-Agent``, so a client that sends all-lowercase names in
#: HTTP/1.1 is a fingerprint mismatch before any value is even read.  Headers are
#: stored lowercase (so lookups stay simple) and cased here, once.
_WIRE_CASE: dict[str, str] = {
    "accept": "Accept",
    "accept-encoding": "Accept-Encoding",
    "accept-language": "Accept-Language",
    "connection": "Connection",
    "priority": "Priority",
    "referer": "Referer",
    "sec-ch-ua": "Sec-Ch-Ua",
    "sec-ch-ua-mobile": "Sec-Ch-Ua-Mobile",
    "sec-ch-ua-platform": "Sec-Ch-Ua-Platform",
    "sec-fetch-dest": "Sec-Fetch-Dest",
    "sec-fetch-mode": "Sec-Fetch-Mode",
    "sec-fetch-site": "Sec-Fetch-Site",
    "sec-fetch-user": "Sec-Fetch-User",
    "upgrade-insecure-requests": "Upgrade-Insecure-Requests",
    "user-agent": "User-Agent",
}


def wire_case(name: str) -> str:
    """The browser spelling of a lowercase header name."""
    return _WIRE_CASE.get(name.lower(), name)


_ACCEPT_NAVIGATE = (
    "text/html,application/xhtml+xml,application/xml;q=0.9,"
    "image/avif,image/webp,image/apng,*/*;q=0.8,"
    "application/signed-exchange;v=b3;q=0.7"
)
_ACCEPT_ANY = "*/*"


@dataclass(frozen=True)
class BrowserIdentity:
    """One coherent browser identity.

    ``headers`` is ordered exactly as the family sends it.  ``Host`` and
    ``Connection`` are deliberately absent: the transport owns them so it can
    keep a connection alive (a browser keeps its connection open; every
    ``httpx`` CLI request sends ``Connection: close``, which is a tell).
    """

    name: str
    family: str
    ua: str
    platform: str
    headers: tuple[tuple[str, str], ...]
    tls_profile: str
    impersonate: str
    accept_encoding: str
    notes: str = ""
    #: Client Hints are Chromium-only; ``None`` means the family never sends them.
    client_hints: dict[str, str] | None = field(default=None)

    @property
    def accept(self) -> str:
        return dict(self.headers).get("accept", _ACCEPT_NAVIGATE)

    @property
    def accept_language(self) -> str:
        return dict(self.headers).get("accept-language", "en-US,en;q=0.9")

    def header_pairs(self, *, url: str = "", referer: str = "") -> list[tuple[str, str]]:
        """Ordered headers for one request, with fetch metadata filled in.

        A direct navigation to ``https://host/`` is ``Sec-Fetch-Site: none`` —
        the request a person makes by typing the address or opening a bookmark,
        and the only story consistent with probing a host's root URL with no
        referer.  Following a link from another host is ``cross-site`` with a
        ``Referer``; pass *referer* to model that.
        """
        pairs = [(name, value) for name, value in self.headers if name != "referer"]
        site = "cross-site" if referer else "none"
        pairs = [(name, site if name == "sec-fetch-site" else value) for name, value in pairs]
        if referer and self.family in {"chrome", "edge"}:
            insert_at = next(
                (index for index, (name, _) in enumerate(pairs) if name == "accept-encoding"),
                len(pairs),
            )
            pairs.insert(insert_at, ("referer", referer))
        elif referer:
            pairs.append(("referer", referer))
        return [(wire_case(name), value) for name, value in pairs]

    def httpx_header_args(self, *, url: str = "", referer: str = "") -> list[str]:
        """``httpx -H`` arguments carrying this identity's headers.

        The CLI alphabetises headers whatever order they are passed in, so this
        makes the *contents* coherent even though it cannot fix the order; the
        Python transport is the one that preserves order (see ``transport.py``).
        """
        args: list[str] = []
        for name, value in self.header_pairs(url=url, referer=referer):
            args += ["-H", f"{name}: {value}"]
        return args

    def verify(self) -> list[str]:
        """Return the list of coherence problems (empty means coherent)."""
        problems: list[str] = []
        names = [name for name, _ in self.headers]

        if len(names) != len(set(names)):
            problems.append("duplicate header names")
        if any(name != name.lower() for name in names):
            problems.append("header names must be lowercase")
        if "host" in names or "connection" in names:
            problems.append("host/connection are owned by the transport")

        if not self.ua.startswith("Mozilla/5.0 ("):
            problems.append("user agent is not a browser user agent")

        if self.family in {"chrome", "edge"}:
            token = {"chrome": f"Chrome/{CHROME_MAJOR}.", "edge": f"Edg/{CHROME_MAJOR}."}[self.family]
            if token not in self.ua:
                problems.append(f"user agent missing {token}")
            if not self.client_hints:
                problems.append("chromium family must send client hints")
            else:
                brands = " ".join(self.client_hints.values())
                if f'v="{CHROME_MAJOR}"' not in brands:
                    problems.append("client hint brands disagree with the user agent version")
                if self.client_hints.get("sec-ch-ua-platform") != f'"{self.platform}"':
                    problems.append("client hint platform disagrees with the identity platform")
                if dict(self.headers).get("sec-ch-ua") != self.client_hints.get("sec-ch-ua"):
                    problems.append("sec-ch-ua header disagrees with the identity's client hints")
        else:
            if self.client_hints:
                problems.append(f"{self.family} must not send client hints")
            if self.family == "firefox" and f"Firefox/{FIREFOX_VERSION}" not in self.ua:
                problems.append(f"user agent missing Firefox/{FIREFOX_VERSION}")
            if self.family == "safari" and "Version/" not in self.ua:
                problems.append("safari user agent missing Version/")

        # The platform token inside the user agent must match the declared one.
        platform_token = {
            "Windows": "Windows NT",
            "macOS": "Macintosh",
            "Linux": "X11",
        }[self.platform]
        if platform_token not in self.ua:
            problems.append(f"user agent platform does not look like {self.platform}")

        if "zstd" in self.accept_encoding and self.family == "safari":
            problems.append("safari does not negotiate zstd")
        if not self.tls_profile:
            problems.append("no TLS profile to impersonate")

        # A navigation-shaped fetch metadata is the only one we send.
        header_map = dict(self.headers)
        for required in ("accept", "accept-encoding", "accept-language", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest"):
            if required not in header_map:
                problems.append(f"missing {required}")
        if header_map.get("sec-fetch-mode") != "navigate":
            problems.append("sec-fetch-mode should be navigate for a root fetch")
        return problems


def _chromium(name: str, family: str, ua: str, platform: str, tls_profile: str, brands: str) -> BrowserIdentity:
    return BrowserIdentity(
        name=name,
        family=family,
        ua=ua,
        platform=platform,
        headers=(
            ("sec-ch-ua", brands),
            ("sec-ch-ua-mobile", "?0"),
            ("sec-ch-ua-platform", f'"{platform}"'),
            ("upgrade-insecure-requests", "1"),
            ("user-agent", ua),
            ("accept", _ACCEPT_NAVIGATE),
            ("sec-fetch-site", "none"),
            ("sec-fetch-mode", "navigate"),
            ("sec-fetch-user", "?1"),
            ("sec-fetch-dest", "document"),
            ("accept-encoding", "gzip, deflate, br, zstd"),
            ("accept-language", "en-US,en;q=0.9"),
            ("priority", "u=0, i"),
        ),
        tls_profile=tls_profile,
        impersonate="chrome" if family == "chrome" else "edge",
        accept_encoding="gzip, deflate, br, zstd",
        client_hints={
            "sec-ch-ua": brands,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": f'"{platform}"',
        },
    )


CHROME_WIN = _chromium(
    "chrome-win",
    "chrome",
    f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    f"Chrome/{CHROME_MAJOR}.0.0.0 Safari/537.36",
    "Windows",
    "chrome",
    f'"Chromium";v="{CHROME_MAJOR}", "Not:A-Brand";v="24", "Google Chrome";v="{CHROME_MAJOR}"',
)

CHROME_MAC = _chromium(
    "chrome-mac",
    "chrome",
    f"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
    f"Chrome/{CHROME_MAJOR}.0.0.0 Safari/537.36",
    "macOS",
    "chrome",
    f'"Chromium";v="{CHROME_MAJOR}", "Not:A-Brand";v="24", "Google Chrome";v="{CHROME_MAJOR}"',
)

CHROME_LINUX = _chromium(
    "chrome-linux",
    "chrome",
    f"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    f"Chrome/{CHROME_MAJOR}.0.0.0 Safari/537.36",
    "Linux",
    "chrome",
    f'"Chromium";v="{CHROME_MAJOR}", "Not:A-Brand";v="24", "Google Chrome";v="{CHROME_MAJOR}"',
)

EDGE_WIN = _chromium(
    "edge-win",
    "edge",
    f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    f"Chrome/{CHROME_MAJOR}.0.0.0 Safari/537.36 Edg/{CHROME_MAJOR}.0.0.0",
    "Windows",
    "chrome",
    f'"Microsoft Edge";v="{CHROME_MAJOR}", "Chromium";v="{CHROME_MAJOR}", "Not:A-Brand";v="24"',
)

FIREFOX_WIN = BrowserIdentity(
    name="firefox-win",
    family="firefox",
    ua=f"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{FIREFOX_VERSION}) Gecko/20100101 Firefox/{FIREFOX_VERSION}",
    platform="Windows",
    headers=(
        ("user-agent", f"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{FIREFOX_VERSION}) Gecko/20100101 Firefox/{FIREFOX_VERSION}"),
        ("accept", _ACCEPT_NAVIGATE),
        ("accept-language", "en-US,en;q=0.5"),
        ("accept-encoding", "gzip, deflate, br, zstd"),
        ("upgrade-insecure-requests", "1"),
        ("sec-fetch-dest", "document"),
        ("sec-fetch-mode", "navigate"),
        ("sec-fetch-site", "none"),
        ("sec-fetch-user", "?1"),
        ("priority", "u=0, i"),
    ),
    tls_profile="firefox",
    impersonate="firefox",
    accept_encoding="gzip, deflate, br, zstd",
    notes="Firefox sends no Client Hints; sending them is a mismatch.",
)

SAFARI_MAC = BrowserIdentity(
    name="safari-mac",
    family="safari",
    ua="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    f"Version/{SAFARI_VERSION} Safari/605.1.15",
    platform="macOS",
    headers=(
        ("accept", _ACCEPT_NAVIGATE),
        ("sec-fetch-site", "none"),
        ("accept-encoding", "gzip, deflate, br"),
        ("accept-language", "en-US,en;q=0.9"),
        ("sec-fetch-mode", "navigate"),
        ("user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
        f"(KHTML, like Gecko) Version/{SAFARI_VERSION} Safari/605.1.15"),
        ("sec-fetch-dest", "document"),
    ),
    tls_profile="safari",
    impersonate="safari",
    accept_encoding="gzip, deflate, br",
    notes="Safari sends no Client Hints and no zstd; its ClientHello is the least common "
    "of the three, so it is the last resort rather than the default.",
)

#: The pool, ordered by how *common* the fingerprint is (research says a rare
#: fingerprint is itself a signal, so Chrome on Windows leads).
PROFILES: tuple[BrowserIdentity, ...] = (
    CHROME_WIN,
    CHROME_MAC,
    CHROME_LINUX,
    EDGE_WIN,
    FIREFOX_WIN,
    SAFARI_MAC,
)

BY_NAME: dict[str, BrowserIdentity] = {profile.name: profile for profile in PROFILES}


def verify_all() -> dict[str, list[str]]:
    """Coherence report for every bundled profile (empty lists mean clean)."""
    return {profile.name: profile.verify() for profile in PROFILES}


class IdentityPool:
    """Hands out one stable identity per host.

    Deterministic in ``(host, salt)`` so that re-running an engagement against
    the same host presents the same identity — the inter-request coherence that
    aggregate fingerprint signals reward.  Rotating identities per request is
    worse than using a plain tool, because "the same client changed browser
    mid-session" is a much rarer pattern than any single tool fingerprint.
    """

    def __init__(self, profiles: tuple[BrowserIdentity, ...] = PROFILES, *, salt: str = "", pinned: str = "") -> None:
        if not profiles:
            raise ValueError("identity pool needs at least one profile")
        for profile in profiles:
            problems = profile.verify()
            if problems:
                raise ValueError(f"identity {profile.name} is incoherent: {'; '.join(problems)}")
        self._profiles = profiles
        self._salt = salt
        self._pinned = pinned
        if pinned and pinned not in {profile.name for profile in profiles}:
            raise ValueError(f"unknown identity {pinned!r}; known: {sorted(p.name for p in profiles)}")

    @property
    def profiles(self) -> tuple[BrowserIdentity, ...]:
        return self._profiles

    def for_host(self, host: str) -> BrowserIdentity:
        """The identity this host is always probed with."""
        if self._pinned:
            for profile in self._profiles:
                if profile.name == self._pinned:
                    return profile
            return BY_NAME[self._pinned]
        key = f"{self._salt}|{host.strip().lower().rstrip('.')}".encode()
        digest = hashlib.blake2b(key, digest_size=8).digest()
        return self._profiles[int.from_bytes(digest, "big") % len(self._profiles)]

    def assignment(self, hosts: list[str]) -> dict[str, str]:
        """Host → identity name, for the run report."""
        return {host: self.for_host(host).name for host in sorted(set(hosts))}
