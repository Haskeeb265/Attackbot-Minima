"""The keyless network-ownership sources: RIPEstat and RDAP.

Two mechanisms, because each answers the question the other cannot:

* **RIPEstat Data API** (``stat.ripe.net``) answers the *routing* question.
  ``announced-prefixes`` lists which prefixes an AS currently announces — a
  routing claim, not an ownership claim, and explicitly excluded from
  scan-authorising input by the design's §5.4.  ``prefix-overview`` answers the
  reverse: which AS(es) announce the prefix an address lives in.  Keyless, no
  auth, a documented 8-concurrent-request limit per source IP, and a
  ``sourceapp`` identification parameter that is the difference between a
  polite client and anonymous load.
* **RDAP** (via the IANA-blessed ``rdap.org`` bootstrap redirector) answers the
  *allocation* question: which organisation is responsible for which range, with
  start/end addresses, registry and country.  The sibling ports stage's
  ``ownership.jsonl`` already carries RDAP facts for scanned addresses — this
  pipeline reads that artifact when it exists (corroboration for free) and
  queries RDAP directly for the rest.

Every function is either pure parsing (``parse_*``, unit-testable offline) or a
thin ``fetch_*`` wrapper with an injectable HTTP callable (so a flaky public API
never reaches inside a test).  The status discipline is the one the URL stage
learned the hard way: **"no data" and "no answer" stay apart** — a 404 from an
RIR is a usable fact (nothing allocated there), a refused connection is not.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone

import requests

from . import settings

log = logging.getLogger("asn_cidr.sources")

#: Statuses a lookup can end in.  Kept as strings because they go straight into
#: the report, where the difference between them is the point.
STATUS_OK = "ok"
STATUS_NO_DATA = "no-data"
STATUS_UNAVAILABLE = "unavailable"
STATUS_ERROR = "error"

Fetcher = Callable[..., "FetchResult"]


@dataclass(frozen=True)
class FetchResult:
    """The outcome of one GET, with the three states kept apart."""

    status: int | None
    text: str = ""
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.status is not None and 200 <= self.status < 300

    @property
    def missing(self) -> bool:
        return self.status == 404

    @property
    def failed(self) -> bool:
        return self.status is None


def http_get(
    url: str,
    *,
    params: dict[str, str] | None = None,
    timeout: float | None = None,
    retries: int | None = None,
) -> FetchResult:
    """GET *url*, returning a :class:`FetchResult` — never raising."""
    timeout = settings.HTTP_TIMEOUT if timeout is None else timeout
    retries = settings.HTTP_RETRIES if retries is None else retries
    headers = {
        "User-Agent": "attackbot-recon-asn-cidr/1.0 (+asset-pipeline)",
        "Accept": "application/json",
    }
    last_error = "unknown error"
    for attempt in range(1, max(1, retries) + 1):
        try:
            response = requests.get(
                url, params=params, headers=headers, timeout=(settings.HTTP_CONNECT_TIMEOUT, timeout)
            )
            if response.status_code in {429, 500, 502, 503, 504} and attempt < max(1, retries):
                last_error = f"HTTP {response.status_code}"
            else:
                return FetchResult(status=response.status_code, text=response.text)
        except requests.RequestException as exc:
            last_error = f"{type(exc).__name__}: {exc}"
        if attempt < max(1, retries):
            log.warning("%s attempt %d/%d failed (%s)", url, attempt, retries, last_error)
    return FetchResult(status=None, error=last_error)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --------------------------------------------------------------------------- #
# RIPEstat — the routing view
# --------------------------------------------------------------------------- #


@dataclass
class AnnouncedPrefixes:
    """What one AS announces, with the lookup's status kept honest."""

    asn: str
    status: str
    prefixes: list[str] = field(default_factory=list)
    error: str = ""
    fetched_at: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "asn": self.asn,
            "status": self.status,
            "prefixes": len(self.prefixes),
            "error": self.error,
            "fetched_at": self.fetched_at,
        }


def parse_announced_prefixes(asn: str, payload: object) -> list[str]:
    """Prefix strings from a RIPEstat ``announced-prefixes`` body.

    The payload is ``{"data": {"prefixes": [{"prefix": "1.2.3.0/24", ...}]}}``.
    Rows without a ``prefix`` key contribute nothing — a schema change upstream
    must degrade to "fewer rows", not to a crash.
    """
    if not isinstance(payload, dict):
        return []
    data = payload.get("data")
    if not isinstance(data, dict):
        return []
    rows = data.get("prefixes")
    if not isinstance(rows, list):
        return []
    prefixes: list[str] = []
    for row in rows:
        if isinstance(row, dict):
            prefix = row.get("prefix")
            if isinstance(prefix, str) and prefix:
                prefixes.append(prefix)
    return prefixes


def fetch_announced_prefixes(
    asn: str,
    *,
    fetcher: Fetcher | None = None,
    timeout: float | None = None,
) -> AnnouncedPrefixes:
    """Prefixes *asn* currently announces, per RIPEstat."""
    asn = str(asn).strip().upper().lstrip("AS")
    fetch = fetcher or http_get
    result = fetch(
        f"{settings.RIPESTAT_BASE}/announced-prefixes/data.json",
        params={"resource": f"AS{asn}", "sourceapp": settings.RIPESTAT_SOURCEAPP},
        timeout=timeout,
    )
    if result.failed:
        return AnnouncedPrefixes(
            asn=asn, status=STATUS_UNAVAILABLE, error=result.error, fetched_at=_utc_now()
        )
    if not result.ok:
        return AnnouncedPrefixes(
            asn=asn,
            status=STATUS_ERROR,
            error=f"HTTP {result.status}",
            fetched_at=_utc_now(),
        )
    try:
        payload = json.loads(result.text)
    except (json.JSONDecodeError, ValueError):
        return AnnouncedPrefixes(
            asn=asn, status=STATUS_ERROR, error="body is not JSON", fetched_at=_utc_now()
        )
    return AnnouncedPrefixes(
        asn=asn,
        status=STATUS_OK,
        prefixes=parse_announced_prefixes(asn, payload),
        fetched_at=_utc_now(),
    )


@dataclass
class PrefixOverview:
    """Which AS(es) announce the prefix (or the block) an address lives in."""

    address: str
    status: str
    asns: list[str] = field(default_factory=list)
    as_holders: dict[str, str] = field(default_factory=dict)
    block: str = ""
    error: str = ""
    fetched_at: str = ""


def parse_prefix_overview(payload: object) -> tuple[list[str], dict[str, str], str]:
    """``([asn, ...], {asn: holder, ...}, block)`` from a ``prefix-overview`` body."""
    if not isinstance(payload, dict):
        return [], {}, ""
    data = payload.get("data")
    if not isinstance(data, dict):
        return [], {}, ""
    asns: list[str] = []
    holders: dict[str, str] = {}
    for row in data.get("asns") or []:
        if not isinstance(row, dict):
            continue
        asn = str(row.get("asn") or "").strip()
        if not asn:
            continue
        asns.append(asn)
        holder = str(row.get("holder") or "").strip()
        if holder:
            holders[asn] = holder
    block = str((data.get("block") or {}).get("resource") or "")
    return asns, holders, block


def fetch_prefix_overview(
    address: str,
    *,
    fetcher: Fetcher | None = None,
    timeout: float | None = None,
) -> PrefixOverview:
    """Which AS(es) announce the prefix *address* lives in, per RIPEstat."""
    fetch = fetcher or http_get
    result = fetch(
        f"{settings.RIPESTAT_BASE}/prefix-overview/data.json",
        params={"resource": address, "sourceapp": settings.RIPESTAT_SOURCEAPP},
        timeout=timeout,
    )
    overview = PrefixOverview(address=address, status=STATUS_OK, fetched_at=_utc_now())
    if result.failed:
        overview.status = STATUS_UNAVAILABLE
        overview.error = result.error
        return overview
    if not result.ok:
        overview.status = STATUS_ERROR
        overview.error = f"HTTP {result.status}"
        return overview
    try:
        payload = json.loads(result.text)
    except (json.JSONDecodeError, ValueError):
        overview.status = STATUS_ERROR
        overview.error = "body is not JSON"
        return overview
    overview.asns, overview.as_holders, overview.block = parse_prefix_overview(payload)
    if not overview.asns:
        overview.status = STATUS_NO_DATA
    return overview


# --------------------------------------------------------------------------- #
# RDAP — the allocation view
# --------------------------------------------------------------------------- #


@dataclass
class RdapRange:
    """One allocation range with its registry facts, RDAP-shaped."""

    network: str  # canonical "start-end"-collapsed text (normalize.py)
    status: str
    org: str = ""
    org_handle: str = ""
    country: str = ""
    registry: str = ""
    start_address: str = ""
    end_address: str = ""
    error: str = ""
    fetched_at: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "network": self.network,
            "status": self.status,
            "org": self.org,
            "org_handle": self.org_handle,
            "country": self.country,
            "registry": self.registry,
            "start_address": self.start_address,
            "end_address": self.end_address,
            "error": self.error,
            "fetched_at": self.fetched_at,
        }


def parse_rdap_network(payload: object) -> dict[str, str]:
    """The fields this pipeline uses from an RDAP IP network object.

    ``name`` is the netblock's name (often a customer code), the registrant
    entity's ``fn`` is the organisation, and ``startAddress``/``endAddress`` are
    what :func:`..normalize.canonicalize_network` collapses to CIDR text.  All
    reads are defensive: RDAP responses differ between the five RIRs.
    """
    if not isinstance(payload, dict):
        return {}
    parsed: dict[str, str] = {}
    for key in ("name", "startAddress", "endAddress", "country"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            parsed[key] = value.strip()
    handle = payload.get("handle")
    if isinstance(handle, str) and handle.strip():
        parsed["handle"] = handle.strip()

    for entity in payload.get("entities") or []:
        if not isinstance(entity, dict):
            continue
        if "registrant" not in (entity.get("roles") or []):
            continue
        handle = entity.get("handle")
        if isinstance(handle, str) and handle.strip() and "org_handle" not in parsed:
            parsed["org_handle"] = handle.strip()
        vcard = entity.get("vcardArray")
        if isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list):
            for item in vcard[1]:
                if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                    value = item[3]
                    if isinstance(value, str) and value.strip():
                        parsed["org"] = value.strip()
                        break
                    if isinstance(value, list) and value:
                        parsed["org"] = str(value[0]).strip()
                        break
        if "org" in parsed and "org_handle" in parsed:
            break
    return parsed


def fetch_rdap_network(
    address: str,
    *,
    fetcher: Fetcher | None = None,
    timeout: float | None = None,
) -> RdapRange:
    """The allocation record *address* falls in, via the RDAP bootstrap."""
    fetch = fetcher or http_get
    result = fetch(f"{settings.RDAP_URL}{address}", timeout=timeout)
    if result.failed:
        return RdapRange(network="", status=STATUS_UNAVAILABLE, error=result.error, fetched_at=_utc_now())
    if result.missing:
        # A 404 from an RIR is a usable fact: nothing is allocated there.  That
        # is a different thing from "the RIR did not answer".
        return RdapRange(network="", status=STATUS_NO_DATA, error="HTTP 404", fetched_at=_utc_now())
    if not result.ok:
        return RdapRange(
            network="", status=STATUS_ERROR, error=f"HTTP {result.status}", fetched_at=_utc_now()
        )
    try:
        payload = json.loads(result.text)
    except (json.JSONDecodeError, ValueError):
        return RdapRange(
            network="", status=STATUS_ERROR, error="body is not JSON", fetched_at=_utc_now()
        )

    parsed = parse_rdap_network(payload)
    start = parsed.get("startAddress", "")
    end = parsed.get("endAddress", "")
    from .normalize import canonicalize_network

    network_text = ""
    if start and end:
        canonical = canonicalize_network(f"{start}_{end}")
        network_text = canonical or ""
    return RdapRange(
        network=network_text,
        status=STATUS_OK if network_text else STATUS_NO_DATA,
        org=parsed.get("org", ""),
        org_handle=parsed.get("org_handle", ""),
        country=parsed.get("country", ""),
        registry=parsed.get("handle", ""),
        start_address=start,
        end_address=end,
        fetched_at=_utc_now(),
    )
