"""A small JSON HTTP helper that *keeps the status code*.

The sibling passive stage's helper collapses every failure to ``None``, which is
the right contract for crt.sh and the Wayback CDX API: there, "no body" and "no
data" are the same answer.  It is the wrong contract here, because Shodan
InternetDB answers **404** to mean "I have never scanned this address" — a real,
usable fact about the address — and 429/5xx to mean "ask again later".  Treating
those as one thing would make the report unable to distinguish "no open ports"
from "we never found out".

So this helper returns a :class:`FetchResult` carrying the status, the body and
the transport error separately, and the callers decide what each combination
means.  Retries are limited to the statuses that are genuinely transient.

``requests`` is used because it is already the project's HTTP client
(``shared/connectors/base.py``, ``passive/httpget.py``); no new dependency is
introduced.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass

import requests

log = logging.getLogger("psh.passive.httpjson")

#: Identifies the pipeline politely to the free public APIs it depends on.
USER_AGENT = "attackbot-recon-ports/1.0 (+asset-pipeline)"

#: Status codes worth retrying: the services' own transient failure modes.
RETRY_STATUS = frozenset({429, 500, 502, 503, 504})

#: Read cap.  InternetDB responses are tiny; RDAP responses are not huge either,
#: but a cap means a wrong URL can never cost more than this.
MAX_BYTES = 4 * 1024 * 1024

#: Status used when no HTTP exchange happened at all (DNS failure, timeout).
STATUS_UNREACHABLE = 0


@dataclass(frozen=True)
class FetchResult:
    """Outcome of one HTTP GET, with the parts that differ kept apart."""

    status: int
    body: str | None = None
    error: str | None = None

    @property
    def ok(self) -> bool:
        """True when the server answered with a success status and a body."""
        return 200 <= self.status < 300 and self.body is not None

    @property
    def unreachable(self) -> bool:
        return self.status == STATUS_UNREACHABLE

    @property
    def not_modified(self) -> bool:
        return self.status == 304

    @property
    def rate_limited(self) -> bool:
        return self.status == 429

    @property
    def missing(self) -> bool:
        """The server answered, but has nothing for this resource (404/410)."""
        return self.status in (404, 410)


def fetch_json(
    url: str,
    *,
    params: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 20.0,
    retries: int = 2,
    expect_json: bool = True,
) -> FetchResult:
    """GET *url*, returning a :class:`FetchResult`.  Never raises.

    *expect_json* only affects the ``Accept`` header; the body is returned as
    received so a source that answers with HTML on failure still gives the caller
    something to inspect.

    One deliberate exception: a *retryable* status (:data:`RETRY_STATUS`) has its
    body discarded, because that body describes the failed attempt and the attempt
    is about to be made again — surfacing it would invite a caller to parse a
    transient error page as data.  The status is kept in ``error`` instead, and the
    result is ``unreachable`` ("we did not find out"), never ``missing``.
    """
    request_headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json,text/plain,*/*" if expect_json else "text/plain,*/*",
    }
    request_headers.update(headers or {})

    last_error: str | None = None
    for attempt in range(1, max(1, retries) + 1):
        try:
            with requests.get(
                url,
                params=params,
                headers=request_headers,
                timeout=(10, timeout),
                stream=True,
                allow_redirects=True,
            ) as response:
                status = response.status_code
                if status in RETRY_STATUS:
                    last_error = f"HTTP {status}"
                    response.close()
                    raise _Retryable(last_error)

                chunks: list[bytes] = []
                total = 0
                for chunk in response.iter_content(chunk_size=32768):
                    if not chunk:
                        continue
                    chunks.append(chunk)
                    total += len(chunk)
                    if total >= MAX_BYTES:
                        break
                body = b"".join(chunks).decode("utf-8", errors="replace")
                return FetchResult(status=status, body=body)

        except requests.RequestException as exc:
            last_error = f"{type(exc).__name__}: {exc}"
        except _Retryable:
            pass

        if attempt < retries:
            backoff = min(2**attempt, 10)
            time.sleep(backoff)

    log.debug("%s unreachable (%s)", url, last_error)
    return FetchResult(status=STATUS_UNREACHABLE, error=last_error or "unreachable")


class _Retryable(Exception):
    """Internal marker for a transient failure that should be retried."""


__all__ = [
    "FetchResult",
    "MAX_BYTES",
    "RETRY_STATUS",
    "STATUS_UNREACHABLE",
    "USER_AGENT",
    "fetch_json",
]
