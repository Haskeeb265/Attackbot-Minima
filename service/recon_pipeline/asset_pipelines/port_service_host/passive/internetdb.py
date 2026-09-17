"""Shodan InternetDB: keyless per-IP intel, collected before any packet is sent.

The stage's default intel source, and the reason the design can claim to be
"passive first".  One GET per address returns what Shodan knows about it — open
ports, hostnames, tags, CPEs and CVEs — with no API key and no quota, which makes
it usable at the scale of a whole scan set.

Three properties of this source drive the whole module, and each one is a place
where a naive implementation would lie to the report:

1. **The data is refreshed weekly, not live.**  What comes back describes some
   point in the last seven days.  Every record therefore carries
   :attr:`IpIntel.age_days` as an explicit *upper bound* on its age, derived from
   the documented refresh period rather than invented — and
   :meth:`IpIntel.is_stale` lets the caller decide whether that is good enough to
   seed a scan, or good enough to report as current state.
2. **Absence is not closure.**  ``404`` means Shodan has never scanned this
   address (routine for freshly-allocated IPv4 and most of the IPv6 space), and
   an empty port list means "no ports seen recently" — not "no open ports".
   Those are different states and the status field keeps them apart.
3. **The source can be down.**  A timeout is not "no ports"; it is "we did not
   find out", and the report must say so rather than quietly reporting an empty
   host.

Parsing and interpretation are pure functions, so the whole module is testable
against canned payloads with no network access.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime, timezone

from ..normalize import canonicalize_ip, open_ports_from_intel
from .httpjson import FetchResult, fetch_json

log = logging.getLogger("psh.passive.internetdb")

NAME = "internetdb"

BASE_URL = "https://internetdb.shodan.io/"

#: Record states, in the order of "how much this tells us".
STATUS_OK = "indexed"
STATUS_NOT_INDEXED = "not-indexed"
STATUS_UNAVAILABLE = "unavailable"
STATUS_INVALID = "invalid-address"

#: Cached answers are never this module's business — the cache is the caller's
#: file on disk, keyed by ``fetched_at``.  The refresh period is kept here because
#: it is the only age information the source itself gives us.
DEFAULT_REFRESH_DAYS = 7

#: Type of the injectable HTTP callable (tests pass a stub).
Fetcher = Callable[..., FetchResult]


@dataclass(frozen=True)
class IpIntel:
    """What one passive source knows about one address."""

    ip: str
    source: str = NAME
    status: str = STATUS_OK
    ports: tuple[int, ...] = ()
    hostnames: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    cpes: tuple[str, ...] = ()
    vulns: tuple[str, ...] = ()
    #: Upper bound, in days, on how old this record is (see the module docstring).
    age_days: int = 0
    fetched_at: str = ""
    note: str = ""

    @property
    def indexed(self) -> bool:
        return self.status == STATUS_OK

    @property
    def has_ports(self) -> bool:
        return bool(self.ports)

    def is_stale(self, max_age_days: int) -> bool:
        """True when this record is too old to be a claim about *now*.

        Note the deliberate asymmetry: a stale record may still *seed* the scan
        ladder (an old open port is a good reason to look), it just may not be
        reported as current state.
        """
        return self.age_days >= max_age_days

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "ip": self.ip,
            "source": self.source,
            "status": self.status,
            "ports": list(self.ports),
            "hostnames": list(self.hostnames),
            "tags": list(self.tags),
            "cpes": list(self.cpes),
            "vulns": list(self.vulns),
            "intel_age_days": self.age_days,
            "fetched_at": self.fetched_at,
        }
        if self.note:
            payload["note"] = self.note
        return payload


def _as_str_tuple(value: object) -> tuple[str, ...]:
    """Coerce a JSON array into a tuple of non-empty strings."""
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(str(item).strip() for item in value if str(item).strip())


def parse_intel(ip: str, payload: object, *, refresh_days: int = DEFAULT_REFRESH_DAYS) -> IpIntel:
    """Turn an InternetDB JSON body into an :class:`IpIntel`.

    Tolerates the shapes the endpoint actually returns: a full object, an object
    with several empty arrays, and anything unexpected (in which case the record
    is marked ``not-indexed`` with a note rather than half-populated).
    """
    if not isinstance(payload, dict):
        return IpIntel(
            ip=ip,
            status=STATUS_NOT_INDEXED,
            age_days=refresh_days,
            note="unexpected payload shape",
        )
    return IpIntel(
        ip=ip,
        status=STATUS_OK,
        ports=tuple(open_ports_from_intel(payload.get("ports") or ())),
        hostnames=_as_str_tuple(payload.get("hostnames")),
        tags=_as_str_tuple(payload.get("tags")),
        cpes=_as_str_tuple(payload.get("cpes")),
        vulns=_as_str_tuple(payload.get("vulns")),
        age_days=refresh_days,
    )


def fetch_ip(
    ip: str,
    *,
    fetch: Fetcher = fetch_json,
    timeout: float = 20.0,
    retries: int = 2,
    refresh_days: int = DEFAULT_REFRESH_DAYS,
    now: datetime | None = None,
) -> IpIntel:
    """Look one address up.  Returns a record in every case — never raises.

    The four outcomes are all represented, because the report depends on telling
    them apart: indexed, not-indexed (404), unavailable (the source did not
    answer), and invalid (the token was not an address).
    """
    canonical = canonicalize_ip(ip)
    if canonical is None:
        return IpIntel(ip=str(ip), status=STATUS_INVALID, note="not an IP literal")

    result = fetch(f"{BASE_URL}{canonical}", timeout=timeout, retries=retries)
    fetched_at = (now or datetime.now(timezone.utc)).isoformat(timespec="seconds")

    if result.unreachable:
        return IpIntel(
            ip=canonical,
            status=STATUS_UNAVAILABLE,
            age_days=refresh_days,
            fetched_at=fetched_at,
            note=result.error or "source unreachable",
        )
    if result.missing:
        return IpIntel(
            ip=canonical,
            status=STATUS_NOT_INDEXED,
            age_days=refresh_days,
            fetched_at=fetched_at,
            note="Shodan has no scan of this address (404)",
        )
    if result.rate_limited:
        return IpIntel(
            ip=canonical,
            status=STATUS_UNAVAILABLE,
            age_days=refresh_days,
            fetched_at=fetched_at,
            note="rate limited (429)",
        )
    if not result.ok:
        return IpIntel(
            ip=canonical,
            status=STATUS_UNAVAILABLE,
            age_days=refresh_days,
            fetched_at=fetched_at,
            note=f"HTTP {result.status}",
        )

    try:
        payload = json.loads(result.body or "")
    except (json.JSONDecodeError, ValueError):
        return IpIntel(
            ip=canonical,
            status=STATUS_UNAVAILABLE,
            age_days=refresh_days,
            fetched_at=fetched_at,
            note="response was not JSON",
        )

    record = parse_intel(canonical, payload, refresh_days=refresh_days)
    return _with_fetch_metadata(record, fetched_at)


def _with_fetch_metadata(record: IpIntel, fetched_at: str) -> IpIntel:
    """Copy *record* with the fetch timestamp attached (frozen dataclass)."""
    return IpIntel(
        ip=record.ip,
        source=record.source,
        status=record.status,
        ports=record.ports,
        hostnames=record.hostnames,
        tags=record.tags,
        cpes=record.cpes,
        vulns=record.vulns,
        age_days=record.age_days,
        fetched_at=fetched_at,
        note=record.note,
    )


def fetch_many(
    ips: Iterable[str],
    *,
    fetch: Fetcher = fetch_json,
    timeout: float = 20.0,
    retries: int = 2,
    refresh_days: int = DEFAULT_REFRESH_DAYS,
    now: datetime | None = None,
    on_progress: Callable[[int, int], None] | None = None,
) -> list[IpIntel]:
    """Look up many addresses **sequentially**.

    Sequential on purpose.  InternetDB is a free keyless endpoint with no
    published quota; the polite pattern for an unauthenticated API is one
    connection at a time, and the per-address response is small enough that
    concurrency buys wall-clock we do not need.  The design's §5.1 names this
    explicitly, and it is also why failures degrade per address rather than
    taking the batch down.
    """
    records: list[IpIntel] = []
    addresses = list(dict.fromkeys(ips))
    total = len(addresses)
    for index, address in enumerate(addresses, start=1):
        records.append(
            fetch_ip(
                address,
                fetch=fetch,
                timeout=timeout,
                retries=retries,
                refresh_days=refresh_days,
                now=now,
            )
        )
        if on_progress is not None:
            on_progress(index, total)
    return records


def summarise(records: Iterable[IpIntel]) -> dict[str, object]:
    """Counts per status plus the addresses each state covers, for the report."""
    buckets: dict[str, list[str]] = {}
    with_ports = 0
    for record in records:
        buckets.setdefault(record.status, []).append(record.ip)
        if record.has_ports:
            with_ports += 1
    return {
        "records": sum(len(values) for values in buckets.values()),
        "indexed": len(buckets.get(STATUS_OK, [])),
        "not_indexed": len(buckets.get(STATUS_NOT_INDEXED, [])),
        "unavailable": len(buckets.get(STATUS_UNAVAILABLE, [])),
        "invalid": len(buckets.get(STATUS_INVALID, [])),
        "with_ports": with_ports,
    }


__all__ = [
    "BASE_URL",
    "DEFAULT_REFRESH_DAYS",
    "IpIntel",
    "NAME",
    "STATUS_INVALID",
    "STATUS_NOT_INDEXED",
    "STATUS_OK",
    "STATUS_UNAVAILABLE",
    "fetch_ip",
    "fetch_many",
    "parse_intel",
    "summarise",
]
