"""Request transports, and an honest account of what each one can fake.

Measured on this project's own toolchain (captures in the stealth README):

* ``httpx`` (the Go CLI the stages already ship) can produce the real Chrome
  ClientHello via ``-tlsi chrome`` — verified: ``t13d1516h2_8daaf6152771_...``,
  the same cipher hash Cloudflare publishes for current Chrome.  But its normal
  mode **alphabetises headers** (``Accept-Charset, Accept-Encoding,
  Accept-Language, Priority, Sec-Ch-Ua, ...``), and every request it sends
  carries ``Connection: close``.  Its raw mode (``-unsafe``) preserves order but
  drops the impersonation entirely — the fingerprint reverts to Go's default.
  So the CLI can have coherent *contents* **or** real order, not both.
* ``requests`` gives exact control over header contents and order (it writes
  headers in insertion order), and genuine connection reuse — but it cannot
  change the TLS fingerprint at all: it will always look like Python to a JA3/JA4
  check.  That is a real limitation, stated rather than hidden.
* ``curl_cffi`` (optional) is the only backend here that impersonates the
  complete stack — ClientHello *and* HTTP/2 settings/priority frames *and*
  header order — which is precisely what Akamai-style HTTP/2 fingerprints and
  Cloudflare's JA4 Signals measure.  It is an optional dependency: if it is
  importable the session uses it, otherwise it falls back to ``requests`` and
  says so in the report.

Nothing here disables certificate verification, downgrades TLS, or spoofs an IP.
Choosing an identity is not hiding who we are; it is refusing to look like a
misconfigured crawler, which is what makes engagements noisy.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

from .identity import BrowserIdentity, IdentityPool, wire_case

log = logging.getLogger("stealth.transport")

#: Backend identifiers, reported verbatim so a run says which was used.
CURL_CFFI = "curl_cffi"
REQUESTS = "requests"
HTTPX_CLI = "httpx-cli"


@dataclass
class Request:
    """One request to make."""

    url: str
    host: str = ""
    referer: str = ""
    method: str = "GET"
    headers: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.host:
            self.host = self.url.split("//", 1)[-1].split("/", 1)[0].split(":", 1)[0].lower()


@dataclass
class Response:
    """One response, with whatever the backend could observe."""

    url: str
    status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    error: str | None = None
    seconds: float = 0.0
    transport: str = ""

    @property
    def ok(self) -> bool:
        return self.error is None and self.status is not None


@dataclass(frozen=True)
class Capabilities:
    """What a backend can and cannot do, for the run report."""

    name: str
    tls_impersonation: bool
    http2: bool
    header_order: bool
    keepalive: bool
    caveats: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "name": self.name,
            "tls_impersonation": self.tls_impersonation,
            "http2": self.http2,
            "header_order": self.header_order,
            "keepalive": self.keepalive,
        }
        if self.caveats:
            payload["caveats"] = list(self.caveats)
        return payload


class Transport(Protocol):
    """Minimal transport interface (the spec's ``Transport.send``)."""

    @property
    def name(self) -> str: ...

    @property
    def capabilities(self) -> Capabilities: ...

    def send(self, request: Request, *, identity: BrowserIdentity | None = None) -> Response: ...

    def close(self) -> None: ...


class CurlCffiTransport:
    """Full-stack browser impersonation via ``curl_cffi`` when it is installed."""

    name = CURL_CFFI
    capabilities = Capabilities(
        name=CURL_CFFI,
        tls_impersonation=True,
        http2=True,
        header_order=True,
        keepalive=True,
        caveats=(
            "impersonation profile supplies the user agent and header set; changing them "
            "individually would break the ordering the profile exists to reproduce",
        ),
    )

    def __init__(self, *, timeout: float = 10.0, verify: bool = True) -> None:
        from curl_cffi import requests as curl_requests  # imported lazily: optional dependency

        self._module = curl_requests
        self.timeout = timeout
        self.verify = verify
        self._sessions: dict[str, Any] = {}

    def _session(self, identity: BrowserIdentity):
        session = self._sessions.get(identity.impersonate)
        if session is None:
            session = self._module.Session(
                impersonate=identity.impersonate,
                timeout=self.timeout,
                verify=self.verify,
            )
            self._sessions[identity.impersonate] = session
        return session

    def send(self, request: Request, *, identity: BrowserIdentity | None = None) -> Response:
        identity = identity or IdentityPool().for_host(request.host)
        started = time.monotonic()
        headers: dict[str, str] = {}
        if request.referer:
            headers["referer"] = request.referer
        headers.update(request.headers)
        try:
            response = self._session(identity).request(
                request.method,
                request.url,
                headers=headers or None,
                allow_redirects=True,
            )
        except Exception as exc:  # noqa: BLE001 - network stack raises many types
            return Response(
                url=request.url,
                error=f"{type(exc).__name__}: {exc}",
                seconds=time.monotonic() - started,
                transport=self.name,
            )
        body = response.text if len(response.content) <= 64_000 else ""
        return Response(
            url=str(response.url),
            status=int(response.status_code),
            headers={str(k): str(v) for k, v in response.headers.items()},
            body=body,
            seconds=time.monotonic() - started,
            transport=self.name,
        )

    def close(self) -> None:
        for session in self._sessions.values():
            try:
                session.close()
            except Exception:  # noqa: BLE001 - best effort
                pass
        self._sessions.clear()


class RequestsTransport:
    """Ordered headers and connection reuse, with Python's TLS stack.

    The one thing it cannot do is impersonate a browser's ClientHello, and the
    report says so.  It still matters: header contents *and* order, a coherent
    identity, keep-alive and paced requests are most of what "looks human" means
    in practice, and every one of them is an improvement over a stock tool.
    """

    name = REQUESTS
    capabilities = Capabilities(
        name=REQUESTS,
        tls_impersonation=False,
        http2=False,
        header_order=True,
        keepalive=True,
        caveats=(
            "Python TLS stack: JA3/JA4 will not match a browser (install curl_cffi to fix)",
            "HTTP/1.1 only",
        ),
    )

    def __init__(self, *, timeout: float = 10.0, verify: bool = True, pool_size: int = 4) -> None:
        import requests

        self._module = requests
        self.timeout = timeout
        self.verify = verify
        self.pool_size = pool_size
        self._sessions: dict[str, Any] = {}

    def _session(self, identity: BrowserIdentity):
        session = self._sessions.get(identity.name)
        if session is None:
            session = self._module.Session()
            # Replace the library defaults outright: a missing header here would
            # be filled in by requests *after* our headers, which both breaks the
            # order and re-introduces the stock fingerprint we are avoiding.
            session.headers.clear()
            for name, value in [(wire_case("connection"), "keep-alive"), *identity.header_pairs()]:
                session.headers[name] = value
            adapter = self._module.adapters.HTTPAdapter(
                pool_connections=self.pool_size,
                pool_maxsize=self.pool_size,
                max_retries=0,
            )
            session.mount("https://", adapter)
            session.mount("http://", adapter)
            self._sessions[identity.name] = session
        return session

    def _headers(self, request: Request) -> dict[str, str]:
        headers = dict(request.headers)
        if request.referer:
            headers.setdefault("referer", request.referer)
        return headers

    def prepare(self, request: Request, *, identity: BrowserIdentity | None = None):
        """The exact ``PreparedRequest`` this transport would send.

        Exposed so tests can assert on header *order* without a network call:
        the order urllib3 writes onto the wire is the order of this object's
        ``headers`` mapping, so verifying it here verifies the real request.
        """
        identity = identity or IdentityPool().for_host(request.host)
        return self._session(identity).prepare_request(
            self._module.Request(request.method, request.url, headers=self._headers(request) or None)
        )

    def send(self, request: Request, *, identity: BrowserIdentity | None = None) -> Response:
        identity = identity or IdentityPool().for_host(request.host)
        started = time.monotonic()
        try:
            response = self._session(identity).request(
                request.method,
                request.url,
                headers=self._headers(request) or None,
                timeout=self.timeout,
                verify=self.verify,
                allow_redirects=True,
            )
        except Exception as exc:  # noqa: BLE001 - network stack raises many types
            return Response(
                url=request.url,
                error=f"{type(exc).__name__}: {exc}",
                seconds=time.monotonic() - started,
                transport=self.name,
            )
        return Response(
            url=response.url,
            status=response.status_code,
            headers={str(k): str(v) for k, v in response.headers.items()},
            body=response.text if len(response.content) <= 64_000 else "",
            seconds=time.monotonic() - started,
            transport=self.name,
        )

    def close(self) -> None:
        for session in self._sessions.values():
            try:
                session.close()
            except Exception:  # noqa: BLE001 - best effort
                pass
        self._sessions.clear()


@dataclass
class Selection:
    """Which transport was chosen, and why."""

    transport: Transport
    reason: str
    installed: tuple[str, ...] = ()

    @property
    def name(self) -> str:
        return self.transport.name


def curl_cffi_available() -> bool:
    try:
        import curl_cffi  # noqa: F401
    except Exception:  # noqa: BLE001 - absent or unusable
        return False
    return True


def select_transport(*, timeout: float = 10.0, prefer: str = "auto") -> Selection:
    """Pick the strongest available transport.

    ``prefer`` may pin a backend (``curl_cffi``/``requests``) for testing and for
    environments that must not install extras; ``auto`` takes the best available.
    """
    installed: list[str] = []
    if curl_cffi_available():
        installed.append(CURL_CFFI)
    installed.append(REQUESTS)

    if prefer in {CURL_CFFI, REQUESTS}:
        if prefer == CURL_CFFI:
            if not curl_cffi_available():
                raise RuntimeError("curl_cffi requested but not installed")
            return Selection(CurlCffiTransport(timeout=timeout), "pinned by caller", tuple(installed))
        return Selection(RequestsTransport(timeout=timeout), "pinned by caller", tuple(installed))

    if curl_cffi_available():
        return Selection(
            CurlCffiTransport(timeout=timeout),
            "curl_cffi installed: real ClientHello, HTTP/2 frames and header order",
            tuple(installed),
        )
    return Selection(
        RequestsTransport(timeout=timeout),
        "curl_cffi not installed: ordered headers and keep-alive only, TLS fingerprint is Python",
        tuple(installed),
    )
