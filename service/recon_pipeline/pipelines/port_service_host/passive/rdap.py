"""IP ownership: whose address is this, and which AS announces it?

Two keyless mechanisms, because each answers a question the other cannot:

* **RDAP** (over HTTPS at ``rdap.org``, which bootstraps to the responsible
  registry) gives the *allocation* record: the organisation name, the country,
  the parent handle and the address range.  It is the authoritative answer to
  "who owns this block", and it is what turns an address into an ownership edge.
* **Team Cymru's DNS service** (``origin.asn.cymru.com`` and
  ``AS<n>.asn.cymru.com``) gives the *routing* answer: the origin ASN, its prefix
  and the AS's registered name.  It is reached over DNS TXT records, so it needs
  no HTTP client and no `whois` binary — which matters on Windows, where the
  usual ``whois -h whois.cymru.com`` recipe is not available.

Both are advisory.  The design's §5.4 is explicit that ASN-derived prefixes never
enter the scan set: they are reported as "the organisation also owns X — not
scanned (outside declared scope)" and nothing more.  That gate lives in the
pipeline; this module only collects the facts the gate needs.

Parsing is pure (``parse_rdap``, ``parse_cymru_origin``, ``parse_cymru_as``), and
the DNS transport is injectable, so the whole module is testable offline.
"""

from __future__ import annotations

import ipaddress
import json
import logging
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime, timezone

from ..normalize import canonicalize_ip
from .httpjson import FetchResult, fetch_json

log = logging.getLogger("psh.passive.rdap")

NAME = "rdap"

#: ``rdap.org`` is the IANA-blessed bootstrap redirector: one URL, and the
#: response comes from whichever RIR is authoritative for the address.
RDAP_URL = "https://rdap.org/ip/"

#: Team Cymru's DNS zones.  ``origin`` maps an address to its origin ASN;
#: ``asn`` maps an ASN back to its registered name.
Cymru_ORIGIN_ZONE_V4 = "origin.asn.cymru.com"
Cymru_ORIGIN_ZONE_V6 = "origin6.asn.cymru.com"
Cymru_AS_ZONE = "asn.cymru.com"

STATUS_OK = "resolved"
STATUS_NOT_FOUND = "not-found"
STATUS_UNAVAILABLE = "unavailable"
STATUS_INVALID = "invalid-address"

Fetcher = Callable[..., FetchResult]
#: ``query(name) -> list[str]`` of TXT record strings; empty on any failure.
TxtQuery = Callable[[str], list[str]]


@dataclass(frozen=True)
class IpOwnership:
    """Ownership facts about one address, from whichever sources answered."""

    ip: str
    asn: str = ""
    as_name: str = ""
    prefix: str = ""
    registry: str = ""
    country: str = ""
    org: str = ""
    handle: str = ""
    parent_handle: str = ""
    start_address: str = ""
    end_address: str = ""
    sources: tuple[str, ...] = ()
    fetched_at: str = ""
    note: str = ""

    @property
    def resolved(self) -> bool:
        return bool(self.asn or self.org or self.prefix)

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "ip": self.ip,
            "asn": self.asn,
            "as_name": self.as_name,
            "prefix": self.prefix,
            "sources": list(self.sources),
        }
        for key, value in (
            ("org", self.org),
            ("handle", self.handle),
            ("parent_handle", self.parent_handle),
            ("country", self.country),
            ("registry", self.registry),
            ("start_address", self.start_address),
            ("end_address", self.end_address),
            ("fetched_at", self.fetched_at),
            ("note", self.note),
        ):
            if value:
                payload[key] = value
        return payload


# --------------------------------------------------------------------------- #
# Pure parsers
# --------------------------------------------------------------------------- #


def parse_rdap(ip: str, payload: object) -> dict[str, object]:
    """Pull the useful fields out of an RDAP object.

    RDAP responses carry a lot of ceremony (``entities``, ``events``, links) and
    the useful parts are the top-level ``name``/``handle``/``country`` plus the
    address range.  An entity flagged ``registrant`` is preferred for the
    organisation name when the top-level ``name`` is absent, which is common for
    large allocations.
    """
    if not isinstance(payload, dict):
        return {}

    fields: dict[str, object] = {}
    for key in ("name", "handle", "country"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            fields[key] = value.strip()

    parent = payload.get("parentHandle")
    if isinstance(parent, str) and parent.strip():
        fields["parent_handle"] = parent.strip()

    for key in ("startAddress", "endAddress"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            fields["start_address" if key == "startAddress" else "end_address"] = value.strip()

    # ``cidr0_cidrs`` is RDAP's machine-readable range; fall back to it when the
    # start/end pair is absent.
    cidrs = payload.get("cidr0_cidrs")
    if isinstance(cidrs, list):
        for entry in cidrs:
            if not isinstance(entry, dict):
                continue
            prefix_length = entry.get("length")
            base = entry.get("v4prefix") or entry.get("v6prefix")
            if base and prefix_length is not None:
                fields.setdefault("prefix", f"{base}/{prefix_length}")
                break

    if "org" not in fields:
        entities = payload.get("entities")
        if isinstance(entities, list):
            for entity in entities:
                if not isinstance(entity, dict):
                    continue
                roles = entity.get("roles")
                if not isinstance(roles, list) or "registrant" not in roles:
                    continue
                vcard = entity.get("vcardArray")
                name = _vcard_fn(vcard)
                if name:
                    fields["org"] = name
                    break

    return fields


def _vcard_fn(vcard: object) -> str:
    """Extract the ``fn`` (formatted name) out of an RDAP jCard array."""
    if not isinstance(vcard, list) or len(vcard) < 2 or not isinstance(vcard[1], list):
        return ""
    for item in vcard[1]:
        if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
            value = item[3]
            if isinstance(value, str) and value.strip():
                return value.strip()
            if isinstance(value, list) and value:
                return str(value[0]).strip()
    return ""


def parse_cymru_origin(text: str) -> dict[str, str]:
    """Parse a Team Cymru origin TXT record.

    Format: ``13335 | 173.245.48.0/20 | US | arin | 2014-03-28``.  The ASN list
    can be multivalued for multi-origin prefixes (``13335 209242``), in which
    case the first is the primary and all are preserved in ``asn_all``.
    """
    fields = [part.strip() for part in text.strip().strip('"').split("|")]
    if len(fields) < 2:
        return {}
    asns = fields[0].split()
    if not asns:
        return {}
    parsed: dict[str, str] = {"asn": asns[0]}
    if len(asns) > 1:
        parsed["asn_all"] = " ".join(asns)
    if fields[1]:
        parsed["prefix"] = fields[1]
    if len(fields) > 2 and fields[2]:
        parsed["country"] = fields[2]
    if len(fields) > 3 and fields[3]:
        parsed["registry"] = fields[3]
    return parsed


def parse_cymru_as(text: str) -> dict[str, str]:
    """Parse a Team Cymru AS TXT record.

    Format: ``13335 | US | arin | 1997-01-01 | CLOUDFLARENET, US``.  The AS name
    is the last field, and it is what makes an ASN legible in a report.
    """
    fields = [part.strip() for part in text.strip().strip('"').split("|")]
    if len(fields) < 2:
        return {}
    parsed: dict[str, str] = {}
    if fields[1]:
        parsed["country"] = fields[1]
    if len(fields) > 2 and fields[2]:
        parsed["registry"] = fields[2]
    if len(fields) > 4 and fields[4]:
        parsed["as_name"] = fields[4]
    return parsed


def cymru_query_name(ip: str) -> str | None:
    """The reverse-labelled Cymru lookup name for *ip*, or ``None``.

    IPv4 reverses the octets (``1.2.3.4`` -> ``4.3.2.1``); IPv6 reverses the
    *nibbles* under ``origin6``.  Getting this wrong is the classic silent
    failure of this API (a valid-looking name that simply does not exist), which
    is why it is a named, tested function.
    """
    canonical = canonicalize_ip(ip)
    if canonical is None:
        return None
    address = ipaddress.ip_address(canonical)
    if isinstance(address, ipaddress.IPv4Address):
        octets = canonical.split(".")
        return f"{'.'.join(reversed(octets))}.{Cymru_ORIGIN_ZONE_V4}"
    nibbles = address.exploded.replace(":", "")
    return f"{'.'.join(reversed(nibbles))}.{Cymru_ORIGIN_ZONE_V6}"


def as_query_name(asn: str) -> str | None:
    """The Cymru lookup name for one ASN (``13335`` -> ``AS13335.asn.cymru.com``)."""
    digits = "".join(character for character in str(asn) if character.isdigit())
    if not digits:
        return None
    return f"AS{digits}.{Cymru_AS_ZONE}"


# --------------------------------------------------------------------------- #
# Transports
# --------------------------------------------------------------------------- #


def dns_txt(name: str, *, timeout: float = 5.0) -> list[str]:
    """Resolve TXT records for *name* using dnspython, or return ``[]``.

    A tiny wrapper rather than a general DNS client: the only records this module
    needs are TXT strings, and every failure mode (NXDOMAIN, timeout, no
    ``dnspython`` installed) means the same thing to the caller — this lookup
    contributed nothing.
    """
    try:
        import dns.resolver  # imported lazily: the module must import without it
    except ImportError:  # pragma: no cover - dependency is present in practice
        log.warning("dnspython is not installed - IP ownership lookups are skipped")
        return []

    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout
        answers = resolver.resolve(name, "TXT")
    except Exception as exc:  # dns.resolver raises a wide family here
        log.debug("TXT lookup %s failed: %s: %s", name, type(exc).__name__, exc)
        return []

    records: list[str] = []
    for answer in answers:
        try:
            records.append(b"".join(answer.strings).decode("utf-8", errors="replace"))
        except AttributeError:  # older dnspython exposes .to_text()
            records.append(answer.to_text())
    return records


# --------------------------------------------------------------------------- #
# Lookups
# --------------------------------------------------------------------------- #


def fetch_rdap(
    ip: str,
    *,
    fetch: Fetcher = fetch_json,
    timeout: float = 20.0,
    retries: int = 2,
) -> dict[str, object]:
    """RDAP allocation fields for *ip* (``{}`` when nothing usable came back)."""
    result = fetch(f"{RDAP_URL}{ip}", timeout=timeout, retries=retries)
    if result.unreachable or result.missing or not result.ok:
        return {}
    try:
        payload = json.loads(result.body or "")
    except (json.JSONDecodeError, ValueError):
        return {}
    return parse_rdap(ip, payload)


def fetch_ip(
    ip: str,
    *,
    fetch: Fetcher = fetch_json,
    query: TxtQuery = dns_txt,
    timeout: float = 20.0,
    retries: int = 2,
    dns_timeout: float = 5.0,
    now: datetime | None = None,
) -> IpOwnership:
    """Ownership facts for one address, combining RDAP and Team Cymru.

    Neither source is required: whichever answers, answers.  The record keeps the
    list of sources that contributed so a report reader can tell a fully-resolved
    address from one that only RDAP knew about.
    """
    canonical = canonicalize_ip(ip)
    if canonical is None:
        return IpOwnership(ip=str(ip), note="not an IP literal")

    fetched_at = (now or datetime.now(timezone.utc)).isoformat(timespec="seconds")
    facts: dict[str, object] = {}
    sources: list[str] = []
    notes: list[str] = []

    rdap_fields = fetch_rdap(canonical, fetch=fetch, timeout=timeout, retries=retries)
    if rdap_fields:
        facts.update(rdap_fields)
        sources.append("rdap")

    query_name = cymru_query_name(canonical)
    if query_name:
        for record in query(query_name):
            parsed = parse_cymru_origin(record)
            if parsed:
                facts.update({"asn": parsed.get("asn", ""), "prefix": parsed.get("prefix", "")})
                for key in ("country", "registry"):
                    if parsed.get(key) and not facts.get(key):
                        facts[key] = parsed[key]
                sources.append("cymru")
                break

    asn = str(facts.get("asn") or "")
    if asn:
        for record in query(as_query_name(asn) or ""):
            parsed = parse_cymru_as(record)
            if parsed:
                facts.update({key: value for key, value in parsed.items() if value})
                break

    if not sources:
        notes.append("no ownership source answered")

    return IpOwnership(
        ip=canonical,
        asn=asn,
        as_name=str(facts.get("as_name") or ""),
        prefix=str(facts.get("prefix") or ""),
        registry=str(facts.get("registry") or ""),
        country=str(facts.get("country") or ""),
        org=str(facts.get("name") or facts.get("org") or ""),
        handle=str(facts.get("handle") or ""),
        parent_handle=str(facts.get("parent_handle") or ""),
        start_address=str(facts.get("start_address") or ""),
        end_address=str(facts.get("end_address") or ""),
        sources=tuple(dict.fromkeys(sources)),
        fetched_at=fetched_at,
        note="; ".join(notes),
    )


def fetch_many(
    ips: Iterable[str],
    *,
    fetch: Fetcher = fetch_json,
    query: TxtQuery = dns_txt,
    timeout: float = 20.0,
    retries: int = 2,
    dns_timeout: float = 5.0,
    now: datetime | None = None,
) -> list[IpOwnership]:
    """Ownership for many addresses, sequentially (one lookup per public API)."""
    return [
        fetch_ip(
            address,
            fetch=fetch,
            query=query,
            timeout=timeout,
            retries=retries,
            dns_timeout=dns_timeout,
            now=now,
        )
        for address in dict.fromkeys(ips)
    ]


def summarise(records: Iterable[IpOwnership]) -> dict[str, object]:
    """Counts per ASN plus how many addresses resolved at all, for the report."""
    records = list(records)
    by_asn: dict[str, int] = {}
    orgs: dict[str, int] = {}
    for record in records:
        if record.asn:
            by_asn[record.asn] = by_asn.get(record.asn, 0) + 1
        if record.org:
            orgs[record.org] = orgs.get(record.org, 0) + 1
    return {
        "records": len(records),
        "resolved": sum(1 for record in records if record.resolved),
        "asns": dict(sorted(by_asn.items(), key=lambda item: (-item[1], item[0]))),
        "orgs": dict(sorted(orgs.items(), key=lambda item: (-item[1], item[0]))),
    }


__all__ = [
    "IpOwnership",
    "NAME",
    "RDAP_URL",
    "STATUS_OK",
    "as_query_name",
    "cymru_query_name",
    "dns_txt",
    "fetch_ip",
    "fetch_many",
    "fetch_rdap",
    "parse_cymru_as",
    "parse_cymru_origin",
    "parse_rdap",
    "summarise",
]
