"""Keyless historical-URL source: the Common Crawl index.

Common Crawl is the other half of "historical depth".  Where the Wayback Machine
archives what people linked and saved, Common Crawl crawled the open web
independently and keeps a columnar index of every URL it fetched — including
paths that were never archived, and hosts that existed for one crawl window.

Two things make this source different from a naive GET:

* **The index is versioned.**  ``collinfo.json`` lists every crawl in reverse
  chronological order; querying a hard-coded index id is how a source silently
  goes stale, so the newest id is discovered per run (and can be pinned through
  ``URL_COMMONCRAWL_INDEX`` when reproducibility matters more than freshness).
* **"Not crawled" is a 404 with a prose body.**  The index answers ``404`` and
  ``No Captures found for: ...`` for a domain it has no data on.  That is a fact,
  not a failure, so it is logged and returned as an empty list.

The index accepts wildcard patterns: ``*.apex`` matches hosts under the apex and
``apex/*`` matches paths on the apex itself.  Neither alone is the full surface,
so both are queried and unioned — two cheap requests instead of a coverage gap.
"""

from __future__ import annotations

import logging

from ..settings import COMMONCRAWL_INDEX, COMMONCRAWL_LIMIT, DEFAULT_SOURCE_TIMEOUT
from .errors import SourceUnavailable
from .httpjson import get

log = logging.getLogger("url.passive.commoncrawl")

NAME = "commoncrawl"

COLLINFO_URL = "https://index.commoncrawl.org/collinfo.json"


def latest_index(*, timeout: float = DEFAULT_SOURCE_TIMEOUT) -> str | None:
    """The newest Common Crawl index id, or ``None`` when it cannot be read.

    ``collinfo.json`` is ordered newest-first, so the first entry is the answer;
    the id is validated against the ``CC-MAIN-...`` shape so a schema change
    upstream cannot smuggle an arbitrary string into a URL.
    """
    result = get(COLLINFO_URL, timeout=timeout)
    if not result.ok:
        log.warning("Common Crawl collinfo unavailable (%s)", result.error or result.status)
        return None

    payload = result.json()
    if not isinstance(payload, list):
        return None
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        identifier = str(entry.get("id") or "").strip()
        if identifier.startswith("CC-MAIN-"):
            return identifier
    return None


def _query(
    index: str,
    pattern: str,
    *,
    timeout: float,
    limit: int,
) -> tuple[list[str], bool, bool]:
    """Query one index pattern.  Returns ``(urls, missing, failed)``.

    ``missing`` means the index answered 404 ("never crawled") — a usable fact.
    ``failed`` means no answer was obtained at all.  The two are kept apart
    because collapsing them is how a source claims coverage it does not have.
    """
    result = get(
        f"https://index.commoncrawl.org/{index}-index",
        params={"url": pattern, "output": "json", "fl": "url", "limit": str(limit)},
        timeout=timeout,
    )
    if result.missing:
        log.info("commoncrawl: no captures for %s in %s", pattern, index)
        return [], True, False
    if not result.ok:
        log.warning(
            "commoncrawl: %s failed for %s (%s)", index, pattern, result.error or result.status
        )
        return [], False, True

    urls: list[str] = []
    for row in result.json_lines():
        if isinstance(row, dict):
            url = row.get("url")
            if isinstance(url, str) and url:
                urls.append(url)
        elif isinstance(row, str) and row.startswith(("http://", "https://")):
            urls.append(row)
    return urls, False, False


def fetch(
    apex: str,
    *,
    timeout: float = DEFAULT_SOURCE_TIMEOUT,
    limit: int = COMMONCRAWL_LIMIT,
    index: str | None = None,
) -> list[str]:
    """Raw in-scope URLs the Common Crawl index holds for *apex*.

    Returns an empty list when the index is unreachable or has no coverage —
    never raises.  Both the subdomain pattern and the apex-path pattern are
    queried; either may legitimately be empty.
    """
    apex = apex.lower().rstrip(".")
    index = index or COMMONCRAWL_INDEX or latest_index(timeout=timeout)
    if not index:
        # No index id means we never got to ask a question.  Reporting that as
        # "0 URLs" would be a lie about coverage (it happened on a live run), so
        # it is a failure the stage records and the report shows.
        raise SourceUnavailable(
            f"Common Crawl index id unavailable (collinfo.json unreachable) for {apex}"
        )

    outcomes = [
        _query(index, f"*.{apex}", timeout=timeout, limit=limit),
        _query(index, f"{apex}/*", timeout=timeout, limit=limit),
    ]
    if all(failed for _, _, failed in outcomes):
        raise SourceUnavailable(f"Common Crawl index {index} unreachable for {apex}")

    urls = [url for urls, _, _ in outcomes for url in urls]
    log.info("commoncrawl: %d raw URL(s) for %s from %s", len(urls), apex, index)
    return urls
