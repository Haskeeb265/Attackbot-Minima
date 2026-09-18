"""Keyless historical-URL source: the Wayback Machine CDX API.

The names stage already queries this endpoint for a different reason — it wants
the *hosts* inside archived URLs and discards the rest.  This module wants the
opposite half: the full URL, because ``https://legacy.example.com/admin/export``
names an endpoint that no DNS record or open port will ever reveal.

Three properties of the CDX API shape the code:

* **It is keyless and best-effort.**  Under load it answers with an HTML error
  page or a truncated body rather than a 4xx, so parsing falls back to a regex
  sweep over raw URLs, which is lossless for ``original``.
* **It is ordered by capture time, not by path.**  A large ``limit`` therefore
  buys mostly the apex and ``www``; the cap is generous rather than unbounded, and
  ``collapse=urlkey`` removes the exact duplicates that dominate the stream.
* **Its rows are small JSON arrays.**  Row 0 is the header when ``fl`` is used,
  but that is not guaranteed, so every row shape is handled and a header row is
  recognised by its content rather than by position.
"""

from __future__ import annotations

import json
import logging
import re

from ..settings import DEFAULT_SOURCE_TIMEOUT, WAYBACK_LIMIT
from .errors import SourceUnavailable
from .httpjson import get

log = logging.getLogger("url.passive.wayback")

NAME = "wayback"

CDX_URL = "https://web.archive.org/cdx/search/cdx"

#: Fallback for a body that is not the JSON array we expect: pull URLs straight
#: out of the raw text.  Also used when the body was truncated mid-array.
_URL_RE = re.compile(r"https?://[^\s\"'\\<>]+", re.IGNORECASE)


def extract_urls(body: str) -> list[str]:
    """Every URL referenced by a CDX body — JSON array, JSON-lines, or raw text."""
    if not body:
        return []

    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        payload = None

    urls: list[str] = []
    if isinstance(payload, list):
        for row in payload:
            url = _url_from_row(row)
            if url:
                urls.append(url)
        if urls:
            return urls

    # Either the body did not parse (an HTML error page / a truncated array) or
    # it parsed into nothing usable.  The regex sweep is lossless for the field
    # we care about, and duplicates are harmless (the caller dedupes).
    return _URL_RE.findall(body)


def _looks_like_html(body: str) -> bool:
    """True when the body is a page rather than data.

    The CDX API answers with an HTML error page under load instead of a 4xx, and
    an empty regex sweep over that page would otherwise be recorded as "the
    archive has nothing for this domain" — a claim the archive never made.
    """
    head = body.lstrip()[:200].lower()
    return head.startswith(("<", "<!doctype")) or "<html" in head


def _url_from_row(row: object) -> str:
    """Pull the URL out of one CDX row, whatever shape it arrived in."""
    if isinstance(row, str):
        # output=json with a single ``fl`` field still yields an array per row,
        # but a plain string occurs when output=text is used by mistake.
        return row if row.lower().startswith(("http://", "https://")) else ""
    if isinstance(row, dict):
        for key in ("original", "url", "u"):
            value = row.get(key)
            if isinstance(value, str) and value:
                return value
        return ""
    if isinstance(row, list) and row:
        first = str(row[0])
        # Row 0 is the header row only when it literally names the field.
        if first.lower() == "original":
            return ""
        return first
    return ""


def fetch(
    apex: str,
    *,
    timeout: float = DEFAULT_SOURCE_TIMEOUT,
    limit: int = WAYBACK_LIMIT,
) -> list[str]:
    """Raw in-scope URLs the Wayback Machine has archived for *apex*.

    Returns an empty list when the archive **answered** with no coverage.  Raises
    :class:`SourceUnavailable` when it could not be reached at all, so the stage
    records a failed source rather than a successful empty one.  Scope filtering
    and canonicalization are the pipeline's job; this returns what the archive
    said, so provenance stays honest.
    """
    apex = apex.lower().rstrip(".")
    result = get(
        CDX_URL,
        params={
            "url": apex,
            "matchType": "domain",
            "fl": "original",
            "collapse": "urlkey",
            "output": "json",
            "limit": str(limit),
        },
        timeout=timeout,
    )
    if result.failed:
        raise SourceUnavailable(f"Wayback CDX unavailable for {apex}: {result.error}")
    if not result.ok and not result.missing:
        raise SourceUnavailable(f"Wayback CDX returned HTTP {result.status} for {apex}")

    urls = extract_urls(result.text)
    if not urls and _looks_like_html(result.text):
        raise SourceUnavailable(
            f"Wayback CDX answered {apex} with an HTML page instead of CDX data "
            "(the API does this under load) - re-run or use another source"
        )

    log.info("wayback: %d raw URL(s) for %s", len(urls), apex)
    return urls
