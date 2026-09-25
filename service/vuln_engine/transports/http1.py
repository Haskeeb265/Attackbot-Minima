"""The http1 effect: one HTTP round trip, and nothing else.

Deliberately dumb, in three specific ways:

* **it decides nothing.** It does not know what an XSS is, what is in scope, or
  whether the request was a good idea. It builds a request, sends it, and hands
  back :class:`RawHttpExchange`. Every question about *whether* to send it was
  answered before this module was called, by ``policy/gate.py``;
* **it never raises on a network failure.** A timeout is a fact — it becomes an
  ``error`` on the exchange and flows into the observation layer. An exception
  here would turn "this host did not answer" into "the run crashed", which is the
  difference between an inconclusive attempt and a lost engagement;
* **it keeps the raw bytes to itself.** The response body leaves as bytes and is
  parsed by ``world/observe.py`` — the module that is *allowed* to read it. Raw
  bodies are never returned as truth.

The client is injectable (`httpx.MockTransport` in tests, canned output) following
the idiom ``pipelines/url_endpoint/validate.py`` already established for the recon
side: no test in this engine touches the network.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from ..kernel.exchange import RawHttpExchange

#: The transport's name in the world log and in capability reports.
NAME = "http1"

#: Cap on how much of a response body we keep.  A response we cannot read is a
#: response we cannot observe, but neither is a gigabyte of it this engine's
#: business: the limit exists so a hostile response cannot exhaust a run.
DEFAULT_MAX_BYTES = 2 * 1024 * 1024

DEFAULT_TIMEOUT = 15.0

DEFAULT_USER_AGENT = "vuln-engine/0.1 (authorized engagement; phase 1)"

#: Target-side etiquette. When a target answers ``429 Too Many Requests`` (or
#: ``503 Service Unavailable`` with no ``Retry-After``), it is not a measurement
#: — it is the target saying *too fast*. The transport honors that with a
#: bounded wait, because hammering a throttling target is how a scanner gets a
#: program's attention for the wrong reason, and because a 429 recorded as a
#: timing sample would poison the differential. Two retries, on GETs only
#: (a repeated POST is not idempotent), and a persistent throttle still returns
#: the exchange as measured — the run continues, honestly degraded.
DEFAULT_BACKOFF_RETRIES = 2

#: Backoff ceiling per wait, in seconds. Honors the server's ``Retry-After``
#: when it is sane; the cap exists so a hostile or broken ``Retry-After``
#: cannot pin a run.
DEFAULT_BACKOFF_CEILING = 8.0

#: Fallback delay growth when the server sends no ``Retry-After``.
_DEFAULT_BACKOFF_BASE = 1.0


@dataclass(frozen=True)
class Http1Capabilities:
    """What this transport can do, reported rather than assumed.

    Same idea as the recon side's stealth transport capability report: a caller
    that needs something this transport cannot do must be able to *ask*, so
    "silently did nothing" never happens.
    """

    name: str = NAME
    #: Present-and-usable.  ``True`` for this transport by construction: an http1
    #: effect that exists can always send a request. The field is here so all three
    #: capability reports have the same shape — a caller should not have to know
    #: which transport it is asking about before it can read the answer.
    available: bool = True
    reason: str = ""
    http2: bool = False
    #: Raw header ordering control: False, deliberately.  Framing-level work is
    #: the owned-HTTP-engine tier, not Phase 1, and claiming it here would be a
    #: false capability report.
    header_order: bool = False
    tls_impersonation: bool = False
    keepalive: bool = True
    max_bytes: int = DEFAULT_MAX_BYTES

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "available": self.available,
            "reason": self.reason,
            "http2": self.http2,
            "header_order": self.header_order,
            "tls_impersonation": self.tls_impersonation,
            "keepalive": self.keepalive,
            "max_bytes": self.max_bytes,
        }


@dataclass
class Http1Effect:
    """The HTTP/1.1 transport.

    ``client`` is injectable so tests can hand it a mock transport; when it is
    ``None`` one is built lazily, so importing this module costs nothing.
    """

    timeout: float = DEFAULT_TIMEOUT
    user_agent: str = DEFAULT_USER_AGENT
    max_bytes: int = DEFAULT_MAX_BYTES
    verify: bool = True
    #: Extra headers every request carries (the engagement's traffic identity).
    default_headers: dict[str, str] = field(default_factory=dict)
    #: Bounded 429/503 retries (target etiquette — see the constant's comment).
    backoff_retries: int = DEFAULT_BACKOFF_RETRIES
    backoff_ceiling: float = DEFAULT_BACKOFF_CEILING
    client: Any = None
    _owned_client: bool = False

    def __post_init__(self) -> None:
        if self.client is None:
            import httpx

            self.client = httpx.Client(
                timeout=httpx.Timeout(self.timeout),
                follow_redirects=False,
                verify=self.verify,
                headers={"User-Agent": self.user_agent, **self.default_headers},
            )
            self._owned_client = True

    @property
    def capabilities(self) -> Http1Capabilities:
        return Http1Capabilities(max_bytes=self.max_bytes)

    # ------------------------------------------------------------------ #
    # the one operation
    # ------------------------------------------------------------------ #

    def perform(
        self,
        url: str,
        *,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        content: bytes | None = None,
        params: dict[str, str] | None = None,
        at: float = 0.0,
    ) -> RawHttpExchange:
        """Send one request and return the exchange, success or failure.

        *at* is accepted for signature parity with the browser and OOB effects so
        the gate can call any of them the same way. It is not used to timestamp
        anything: the world log's ``at`` is passed in by the scheduler.

        The duration is measured here rather than read off the client. httpx only
        fills ``response.elapsed`` once it has read a *stream*, so asking a mock
        transport — or any client that handed back an already-buffered response —
        raises instead of answering. The transport is reporting a measurement, not
        a library's bookkeeping, so it makes the measurement.

        When the target throttles (429, or 503 without guidance), the send is
        retried a bounded number of times after an honor-the-server wait — see
        ``DEFAULT_BACKOFF_RETRIES``. The retry lives in the transport rather
        than behind the gate because it is not an authorization question: the
        gate decided this request should happen; the transport only decides
        *when*, within a small declared budget, so the measurement it hands
        back is of a target answering, not a target refusing.
        """
        started = time.monotonic()
        try:
            response = self.client.request(
                method,
                url,
                headers=headers or None,
                content=content,
                params=params or None,
            )
            for attempt in range(self.backoff_retries):
                throttled = response.status_code == 429 or (
                    response.status_code == 503 and not response.headers.get("retry-after")
                )
                if not throttled or method.upper() != "GET":
                    break
                delay = _retry_delay(
                    response.headers.get("retry-after", ""),
                    attempt,
                    self.backoff_ceiling,
                )
                time.sleep(delay)
                response = self.client.request(
                    method,
                    url,
                    headers=headers or None,
                    content=content,
                    params=params or None,
                )
        except Exception as exc:  # noqa: BLE001 - a failure is a fact, not a crash
            return RawHttpExchange(
                url=url,
                method=method.upper(),
                error=f"{type(exc).__name__}: {exc}",
                elapsed=time.monotonic() - started,
                transport=NAME,
            )
        elapsed = time.monotonic() - started
        body = response.content or b""
        truncated = len(body) > self.max_bytes
        return RawHttpExchange(
            url=url,
            method=method.upper(),
            status=response.status_code,
            headers={key.lower(): value for key, value in response.headers.items()},
            body=body[: self.max_bytes],
            final_url=str(response.url) if str(response.url) != url else "",
            elapsed=elapsed,
            error="response truncated at the byte cap" if truncated else "",
            transport=NAME,
        )

    def close(self) -> None:
        """Close the client, but only the one this effect owns."""
        if self._owned_client and self.client is not None:
            self.client.close()
            self._owned_client = False

    def __enter__(self) -> "Http1Effect":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


def _retry_delay(retry_after: str, attempt: int, ceiling: float) -> float:
    """The wait a throttled response asks for, sane-capped.

    ``Retry-After`` may be seconds or HTTP-date; seconds is what servers send in
    practice, and an unparseable value falls back to the exponential default.
    The ceiling is the hostile-value guard: our own politeness must not become
    someone else's lever against the run.
    """
    try:
        delay = min(float(retry_after.strip()), ceiling)
    except ValueError:
        delay = min(_DEFAULT_BACKOFF_BASE * (2**attempt), ceiling)
    return max(delay, 0.0)


__all__ = [
    "DEFAULT_BACKOFF_CEILING",
    "DEFAULT_BACKOFF_RETRIES",
    "DEFAULT_MAX_BYTES",
    "DEFAULT_TIMEOUT",
    "DEFAULT_USER_AGENT",
    "Http1Capabilities",
    "Http1Effect",
    "NAME",
]
