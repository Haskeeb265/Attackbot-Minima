"""
Keyless historical-URL source: the Wayback Machine CDX API.

``recon.md`` calls this out as "historical depth — organizations clean the
present while leaving the past intact".  For subdomain enumeration specifically
the value is that archived URLs name hosts that may no longer hold a certificate
or a live DNS record, so they are surface that CT logs alone will not reveal::

    https://legacy-internal.example.com/admin  ->  legacy-internal.example.com

The CDX endpoint is keyless and returns compact JSON.  Like crt.sh it is a
best-effort public service, so the same defensive posture applies: bounded read,
retries, and a regex fallback when the body is not the JSON we expect.
"""

from __future__ import annotations

import json
import logging
import re
from urllib.parse import urlsplit

from .httpget import fetch_text
from .normalize import canonicalize_host, is_subdomain_of

log = logging.getLogger("passive.wayback")

NAME = "wayback"

CDX_URL = "https://web.archive.org/cdx/search/cdx"
WAYBACK_TIMEOUT = 300.0

#: Ceiling on rows requested — the CDX API will happily try to stream millions.
#:
#: Measured caveat: rows come back ordered by capture time, not by host, so on a
#: large target most of the budget is consumed by the apex and ``www`` (on
#: ``tesla.com``: 49,889 of the first 50,000 rows were ``www``).  The cap is kept
#: modest because a page beyond it rarely buys another distinct host.
DEFAULT_LIMIT = 20_000

#: Fallback for a non-JSON body: pull hosts straight out of raw URLs.
_URL_HOST_RE = re.compile(r"https?://([^/\s\"'\\]+)", re.IGNORECASE)


def extract_hosts(body: str) -> list[str]:
    """Every host referenced by a CDX body (JSON rows or a raw URL dump)."""
    hosts: list[str] = []

    try:
        rows = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        rows = None

    if isinstance(rows, list):
        for index, row in enumerate(rows):
            url = ""
            if isinstance(row, list) and row:
                # Row 0 is the header when the API includes one.
                url = str(row[0])
            elif isinstance(row, str):
                url = row
            if index == 0 and url.lower() == "original":
                continue
            host = urlsplit(url).hostname if "://" in url else url
            if host:
                hosts.append(host)
        if hosts:
            return hosts

    return _URL_HOST_RE.findall(body)


def fetch(
    apex: str,
    *,
    timeout: float = WAYBACK_TIMEOUT,
    limit: int = DEFAULT_LIMIT,
) -> list[str]:
    """Return the in-scope hosts that appear in archived URLs for *apex*.

    Returns an empty list when the API is unavailable or has no coverage —
    never raises.
    """
    apex = apex.lower().rstrip(".")
    body = fetch_text(
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
    if body is None:
        log.warning("Wayback CDX unavailable for %s — skipping source", apex)
        return []

    rows = extract_hosts(body)
    in_scope: set[str] = set()
    out_of_scope: set[str] = set()
    for candidate in rows:
        host = canonicalize_host(candidate)
        if host is None:
            continue
        if is_subdomain_of(host, apex):
            in_scope.add(host)
        else:
            out_of_scope.add(host)

    if out_of_scope:
        sample = sorted(out_of_scope)[:5]
        log.info(
            "wayback: dropped %d out-of-scope host(s) for %s, e.g. %s",
            len(out_of_scope),
            apex,
            ", ".join(sample),
        )
    log.info(
        "wayback: %d in-scope subdomain(s) from %d archived row(s) for %s",
        len(in_scope),
        len(rows),
        apex,
    )
    return sorted(in_scope)
