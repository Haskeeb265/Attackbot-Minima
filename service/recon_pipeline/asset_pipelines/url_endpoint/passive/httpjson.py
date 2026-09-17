"""A status-preserving HTTP GET for the keyless URL sources.

The names stage's :mod:`...passive.httpget` deliberately collapses every failure
to ``None``, and for crt.sh and the host-only Wayback query that is correct: to
that caller, "no data" and "source is down" mean the same thing.

It is the wrong contract here.  These sources have to tell three states apart:

* **404 with a body** — Common Crawl's index answers ``404`` and the text
  ``No Captures found for: ...`` for a domain it simply never crawled.  That is a
  *usable fact*: the domain has no historical coverage in that index.
* **429 / 5xx / connection error** — "ask again later"; we learned nothing.
* **200** — the body is real.

Collapsing the first into the second would make the report claim the harvest
failed when it succeeded with an empty answer, and collapsing the second into the
first would silently under-report coverage.  So this helper returns a
:class:`HttpResult` that keeps the distinction, retries only what is genuinely
transient, and never raises.

``requests`` is reused because it is already the project's HTTP client; no new
dependency is introduced.  Unlike the sibling helper this one accepts headers,
which is what lets the urlscan source send its optional ``api-key``.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass

import requests

from ..settings import HTTP_CONNECT_TIMEOUT, HTTP_MAX_BYTES, HTTP_RETRIES

log = logging.getLogger("url.passive.httpjson")

#: Identifies the pipeline politely to the free public APIs it depends on.
USER_AGENT = "attackbot-recon-url-endpoint/1.0 (+asset-pipeline)"

#: Statuses worth retrying: the public APIs' own transient failure modes.
RETRY_STATUS = frozenset({429, 500, 502, 503, 504})


@dataclass(frozen=True)
class HttpResult:
    """The outcome of one GET, with "no data" kept apart from "no answer"."""

    #: HTTP status, or ``None`` when the request never completed.
    status: int | None
    text: str = ""
    error: str = ""

    @property
    def ok(self) -> bool:
        """True only for a 2xx response with a body."""
        return self.status is not None and 200 <= self.status < 300

    @property
    def missing(self) -> bool:
        """True for a 404 — the source answered, and the answer is "none"."""
        return self.status == 404

    @property
    def failed(self) -> bool:
        """True when no HTTP status was obtained (transport/failure)."""
        return self.status is None

    def json(self) -> object | None:
        """Parse the body as JSON, returning ``None`` when it will not parse."""
        import json

        try:
            return json.loads(self.text)
        except (ValueError, TypeError):
            return None

    def json_lines(self) -> list[object]:
        """Parse a JSON-lines body, skipping blank and malformed lines.

        Common Crawl's index is newline-delimited JSON, so a single corrupt line
        must cost one row, not the whole response.
        """
        import json

        rows: list[object] = []
        for line in self.text.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            try:
                rows.append(json.loads(stripped))
            except (ValueError, TypeError):
                continue
        return rows


def get(
    url: str,
    *,
    params: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 60.0,
    connect_timeout: float = HTTP_CONNECT_TIMEOUT,
    retries: int = HTTP_RETRIES,
    max_bytes: int = HTTP_MAX_BYTES,
) -> HttpResult:
    """GET *url*, returning a :class:`HttpResult` — never raising.

    The body is streamed and truncated at *max_bytes*, so an unexpectedly huge
    response (a multi-hundred-megabyte CDX export) cannot exhaust memory.  A
    truncated body is still returned: every parser in this stage treats its input
    defensively, and a partial harvest is worth more than none.
    """
    send_headers = {"User-Agent": USER_AGENT, "Accept": "application/json,text/plain,*/*"}
    send_headers.update(headers or {})

    attempts = max(1, retries)
    last_error = "unknown error"

    for attempt in range(1, attempts + 1):
        try:
            with requests.get(
                url,
                params=params,
                headers=send_headers,
                timeout=(connect_timeout, timeout),
                stream=True,
            ) as response:
                if response.status_code in RETRY_STATUS:
                    last_error = f"HTTP {response.status_code}"
                    response.close()
                else:
                    body = _read_capped(response, max_bytes=max_bytes, url=url)
                    return HttpResult(status=response.status_code, text=body)
        except requests.RequestException as exc:
            last_error = f"{type(exc).__name__}: {exc}"

        if attempt < attempts:
            backoff = min(2**attempt, 10)
            log.warning(
                "%s attempt %d/%d failed (%s); retrying in %ss",
                url,
                attempt,
                attempts,
                last_error,
                backoff,
            )
            time.sleep(backoff)

    log.warning("%s unavailable after %d attempt(s) (%s)", url, attempts, last_error)
    return HttpResult(status=None, error=last_error)


def _read_capped(response: requests.Response, *, max_bytes: int, url: str) -> str:
    """Read a streaming response, stopping at *max_bytes*."""
    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_content(chunk_size=65536):
        if not chunk:
            continue
        chunks.append(chunk)
        total += len(chunk)
        if total >= max_bytes:
            log.warning(
                "%s exceeded the %d byte read cap - using truncated body",
                url,
                max_bytes,
            )
            break
    return b"".join(chunks).decode("utf-8", errors="replace")
