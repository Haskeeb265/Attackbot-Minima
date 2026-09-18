"""Keyless (quota-limited) URL source: the urlscan.io search API.

urlscan.io has already crawled the target — someone submitted a scan, or it was
submitted automatically — and its search index exposes the pages and subresources
from that scan.  That makes it the third independent view of the target's web
surface, alongside the Wayback Machine and Common Crawl, and the only one that
regularly carries *live* single-page-application routes.

What shapes the code:

* **Authentication is optional, and its absence is not an error.**  An unsigned
  request still answers, with a much smaller quota; the ``api-key`` header is sent
  when ``URL_URLSCAN_KEY`` is set and omitted otherwise.  The source therefore
  degrades to "fewer results", never to a failure.
* **The docs are explicit about rate limits, and a 429 is not an answer.**  A
  ``429`` is expected behaviour under load, so it is retried by the HTTP helper;
  if it persists the source raises :class:`SourceUnavailable` rather than
  returning ``[]``.  "urlscan told us it has no scans" and "urlscan would not talk
  to us" are different facts — see :mod:`.errors` — and collapsing them produced a
  false ``ok=True`` in a live run.
* **The payload shape is not guaranteed.**  urlscan's own best-practices page
  warns that properties may be missing, so every field is read defensively and a
  scan with no page URL contributes nothing rather than raising.

Only the first page of results is requested.  Pagination (``search_after``) is a
documented follow-up, deliberately not implemented here: the marginal page rarely
names another distinct *host*, and paging a rate-limited API is how a passive
source becomes a liability.
"""

from __future__ import annotations

import logging

from ..settings import DEFAULT_SOURCE_TIMEOUT, URLSCAN_KEY, URLSCAN_LIMIT
from .errors import SourceUnavailable
from .httpjson import get

log = logging.getLogger("url.passive.urlscan")

NAME = "urlscan"

SEARCH_URL = "https://urlscan.io/api/v1/search/"

#: urlscan's documented ceiling for one search response.
MAX_RESULTS = 10_000


def extract_urls(payload: object) -> list[str]:
    """Every URL in a urlscan search response.

    A result carries the scanned page under ``page.url`` and the originally
    submitted URL under ``task.url``; both are real observations, so both are
    collected and the caller dedupes.
    """
    if not isinstance(payload, dict):
        return []
    results = payload.get("results")
    if not isinstance(results, list):
        return []

    urls: list[str] = []
    for entry in results:
        if not isinstance(entry, dict):
            continue
        for section in ("page", "task"):
            block = entry.get(section)
            if isinstance(block, dict):
                url = block.get("url")
                if isinstance(url, str) and url.startswith(("http://", "https://")):
                    urls.append(url)
    return urls


def fetch(
    apex: str,
    *,
    timeout: float = DEFAULT_SOURCE_TIMEOUT,
    limit: int = URLSCAN_LIMIT,
    api_key: str | None = None,
) -> list[str]:
    """Raw in-scope URLs urlscan.io has seen for *apex*.

    Returns an empty list when the API **answered** that it has no scans for the
    domain.  Raises :class:`SourceUnavailable` when it could not be reached, was
    rate-limited, or refused the query, so the stage reports a failed source
    instead of a successful empty one.
    """
    apex = apex.lower().rstrip(".")
    key = api_key if api_key is not None else URLSCAN_KEY
    headers = {"api-key": key} if key else None

    result = get(
        SEARCH_URL,
        params={"q": f"domain:{apex}", "size": str(min(max(1, limit), MAX_RESULTS))},
        headers=headers,
        timeout=timeout,
    )
    if result.failed:
        raise SourceUnavailable(f"urlscan.io unreachable for {apex}: {result.error}")
    if result.status == 429:
        raise SourceUnavailable(
            f"urlscan.io rate-limited for {apex} - set URL_URLSCAN_KEY for a larger "
            "quota, or re-run later"
        )
    if not result.ok:
        raise SourceUnavailable(f"urlscan.io returned HTTP {result.status} for {apex}")

    urls = extract_urls(result.json())
    log.info("urlscan: %d raw URL(s) for %s", len(urls), apex)
    return urls
