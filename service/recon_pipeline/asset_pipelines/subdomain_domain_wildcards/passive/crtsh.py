"""
Keyless Certificate Transparency source: crt.sh.

This is the spec's primary passive source (``IMPLEMENTATION_PLAN.md`` S5 —
"Certificate Transparency via crt.sh — producing subdomains + SANs for a seed
domain").  It runs as pure Python against crt.sh's public JSON API, so it needs
no Docker image and no API key, and it is the fastest way to get an independent
view of the target's certificate history.

Two practical details make the difference between "works on a demo domain" and
"works on a real one":

* **The response is untrustworthy on failure.** crt.sh answers with an HTML
  error page rather than a 4xx under load, so the body is parsed defensively and
  falls back to a regex sweep over raw ``name_value`` fields.
* **The response can be enormous** (targets like ``tesla.com`` have hundreds of
  thousands of certificates), so the body is read through a byte cap and any
  truncation falls back to the same regex sweep — which is lossless for the
  field we care about.

Only in-scope subdomains are emitted.  Certificates routinely cover unrelated
SANs; those are counted and logged, not reported as leakage, because they are an
expected property of CT data rather than a symptom of the wrong target.
"""

from __future__ import annotations

import json
import logging
import re

from .httpget import fetch_text
from .normalize import canonicalize_host, is_subdomain_of

log = logging.getLogger("passive.crtsh")

NAME = "crtsh"

CRTSH_URL = "https://crt.sh/"
CRTSH_TIMEOUT = 240.0

#: Pulls every ``"name_value": "..."`` (or ``"common_name"``) field out of a
#: possibly-truncated JSON body.  Works whether or not the JSON parses, which is
#: what makes the truncation fallback lossless for names.
_JSON_FIELD_RE = re.compile(
    r'"(?:name_value|common_name)"\s*:\s*"((?:[^"\\]|\\.)*)"',
    re.IGNORECASE,
)

_JSON_ESCAPE_RE = re.compile(r"\\(.)")


def _unescape(value: str) -> str:
    """Resolve the JSON string escapes crt.sh emits (``\\n`` separates SANs)."""

    def replace(match: re.Match[str]) -> str:
        char = match.group(1)
        return {"n": "\n", "r": "\r", "t": "\t"}.get(char, char)

    return _JSON_ESCAPE_RE.sub(replace, value)


def extract_names(body: str) -> list[str]:
    """Every candidate name in a crt.sh body, JSON or truncated HTML."""
    names: list[str] = []

    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        payload = None

    if isinstance(payload, list):
        for entry in payload:
            if not isinstance(entry, dict):
                continue
            for field in ("name_value", "common_name"):
                value = entry.get(field)
                if value:
                    names.extend(str(value).splitlines())
        if names:
            return names

    # Either the body did not parse or parsed into nothing usable: sweep the raw
    # text.  Duplicates across the two strategies are harmless (the caller
    # dedupes) and a truncated body is still fully mined this way.
    for match in _JSON_FIELD_RE.finditer(body):
        names.extend(_unescape(match.group(1)).splitlines())
    return names


def fetch(apex: str, *, timeout: float = CRTSH_TIMEOUT) -> list[str]:
    """Return the in-scope subdomains crt.sh knows for *apex*.

    Returns an empty list when crt.sh is unreachable, rate-limiting, or simply
    has no coverage for the domain — never raises.
    """
    apex = apex.lower().rstrip(".")
    body = fetch_text(
        CRTSH_URL,
        params={"q": f"%.{apex}", "output": "json"},
        timeout=timeout,
    )
    if body is None:
        log.warning("crt.sh unavailable for %s — skipping source", apex)
        return []

    candidates = extract_names(body)
    in_scope: set[str] = set()
    out_of_scope: set[str] = set()

    for candidate in candidates:
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
            "crt.sh: dropped %d out-of-scope certificate name(s) (unrelated SANs) "
            "for %s, e.g. %s",
            len(out_of_scope),
            apex,
            ", ".join(sample),
        )
    log.info("crt.sh: %d in-scope subdomain(s) for %s", len(in_scope), apex)
    return sorted(in_scope)
