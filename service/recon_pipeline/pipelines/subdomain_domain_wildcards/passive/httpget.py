"""
Small resilient HTTP GET helper for the keyless passive sources.

crt.sh and the Wayback CDX API are both free, unauthenticated, and occasionally
slow or flaky.  This wrapper exists so both sources share one policy for the
things that matter: a bounded read, a real timeout, a small retry budget with
backoff, and — most importantly — a failure that degrades to ``None`` instead of
taking the whole enumeration run down with it.

``requests`` is used because it is already the project's HTTP client
(``shared/connectors/base.py``); no new dependency is introduced.
"""

from __future__ import annotations

import logging
import time

import requests

from .settings import HTTP_MAX_BYTES, HTTP_RETRIES

log = logging.getLogger("passive.httpget")

#: Identifies the pipeline politely to the free public APIs it depends on.
USER_AGENT = "attackbot-recon-passive/1.0 (+asset-pipeline)"

#: Status codes worth retrying: the services' own transient failure modes.
_RETRY_STATUS = {429, 500, 502, 503, 504}


def fetch_text(
    url: str,
    *,
    params: dict[str, str] | None = None,
    timeout: float = 180.0,
    retries: int = HTTP_RETRIES,
    max_bytes: int = HTTP_MAX_BYTES,
) -> str | None:
    """GET *url* and return the decoded body, or ``None`` if it cannot be read.

    The body is streamed and truncated at *max_bytes* so an unexpectedly huge
    response cannot exhaust memory.  Callers must treat ``None`` as "source
    unavailable", not as "source returned nothing".
    """
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json,text/plain,*/*"}
    last_error: str | None = None

    for attempt in range(1, max(1, retries) + 1):
        try:
            with requests.get(
                url,
                params=params,
                headers=headers,
                timeout=(10, timeout),
                stream=True,
            ) as response:
                if response.status_code in _RETRY_STATUS:
                    last_error = f"HTTP {response.status_code}"
                    response.close()
                    raise _Retryable(last_error)
                if response.status_code >= 400:
                    log.warning("%s returned HTTP %s", url, response.status_code)
                    return None

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

        except requests.RequestException as exc:
            last_error = f"{type(exc).__name__}: {exc}"
        except _Retryable:
            pass

        if attempt < retries:
            backoff = min(2 ** attempt, 10)
            log.warning(
                "%s attempt %d/%d failed (%s); retrying in %ss",
                url,
                attempt,
                retries,
                last_error,
                backoff,
            )
            time.sleep(backoff)

    log.warning("%s unavailable after %d attempt(s) (%s)", url, retries, last_error)
    return None


class _Retryable(Exception):
    """Internal marker for a transient failure that should be retried."""
