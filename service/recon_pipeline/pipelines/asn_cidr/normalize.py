"""Canonicalization, classification and scope arithmetic for network claims.

This module is the pipeline's identity layer, and it is pure: no network, no
clock, no filesystem.  Everything the sources bring back flows through here
before it is counted, because the whole pipeline's hard problem is the same one
the URL stage solved for URLs: **two spellings of one fact must collapse to one
row, or every count lies.**

The rules, each tied to a failure that occurs in real registry/routing data:

* ``10.0.0.0/8`` and ``10.0.0.0/8`` written ``10.0.0.0 255.0.0.0`` — RDAP emits
  ``startAddress``/``endAddress`` pairs, RIPEstat emits CIDR strings; both are
  normalised to one canonical ``ip_network`` text.
* A prefix announced as ``2001:db8::/32`` and its re-announcement as
  ``2001:db8::/33`` are *different claims* (different reach) and are kept
  apart; containment is recorded, not assumed away.
* Non-globally-routable space (RFC 1918, loopback, link-local, ULA) is refused
  with a reason — the sibling ports stage refuses it too, and a scope file that
  mixed it in would silently shrink that stage's usable set.

``annotation`` is where the honesty lives: every network this pipeline emits
carries *how we know* — ``announced`` (routing claim), ``allocated`` (registry
claim) or both — plus provenance, so a downstream stage can apply the design's
§5.4 rule (announced ≠ owned ≠ in-scope) without re-deriving it.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

#: Reasons a network can be refused, in the wording the report uses.
REFUSED_NOT_GLOBAL = "not globally routable (private/reserved)"
REFUSED_INVALID = "not a valid network or range"
REFUSED_TOO_WIDE = "wider than the usable ceiling (aggregate/supernet announcement)"

#: Network classes an emitted CIDR can carry.
CLASS_ANNOUNCED = "announced"
CLASS_ALLOCATED = "allocated"

#: The origin claim kinds a network row can carry (both may apply).
ORIGIN_ANNOUNCEMENT = "announcement"
ORIGIN_ALLOCATION = "allocation"


def canonicalize_network(value: str) -> str | None:
    """Canonical text for a CIDR or ``start-end`` range, or ``None``.

    Accepts what the two source families actually emit:

    * CIDR strings: ``104.16.0.0/12``, ``2001:db8::/32`` (host bits set are
      tolerated with ``strict=False`` — registries emit aligned prefixes, but
      AS announcements occasionally do not);
    * ``start-end`` pairs as RDAP writes them: ``40.74.0.0_40.125.127.255``
      or ``40.74.0.0-40.125.127.255`` — collapsed to the smallest CIDR(s) that
      exactly cover the range, which for RDAP's aligned allocations is one.

    Returns the canonical network text (``str(ip_network)``), which is stable
    across spellings and usable as a merge key.
    """
    raw = (value or "").strip()
    if not raw:
        return None

    if "/" in raw:
        try:
            return str(ipaddress.ip_network(raw, strict=False))
        except ValueError:
            return None

    for separator in ("_", "-", " "):
        if separator in raw:
            left, _, right = raw.partition(separator)
            try:
                start = ipaddress.ip_address(left.strip())
                end = ipaddress.ip_address(right.strip())
            except ValueError:
                continue
            if int(start) > int(end) or start.version != end.version:
                return None
            networks = list(ipaddress.summarize_address_range(start, end))
            if len(networks) == 1:
                return str(networks[0])
            # A range that is not a single aligned prefix is kept as its first
            # covering prefix only if it exactly covers it; otherwise it cannot
            # be one network row without lying about what it covers.
            return None

    # Bare address: a /32 (or /128) is a legitimate, if narrow, claim.
    try:
        return str(ipaddress.ip_network(raw, strict=False))
    except ValueError:
        return None


def is_globally_routable(network: ipaddress._BaseNetwork) -> bool:  # noqa: SLF001
    """True unless the network is private, loopback, link-local or reserved."""
    return not (
        network.is_private
        or network.is_loopback
        or network.is_link_local
        or network.is_multicast
        or network.is_reserved
        or network.is_unspecified
    )


def parse_prefixes(
    values: list[str],
    *,
    min_prefix_len: int,
    max_prefix_len: int = 0,
) -> tuple[list[str], list[tuple[str, str]]]:
    """Canonicalize and filter a list of prefixes; keep refusals with reasons.

    Two floors/walls, both added after a live run, not from theory:

    * ``min_prefix_len`` (v4, ``0`` disables) drops narrow announcements:
      /25-or-longer VIP announcements inside an otherwise wide space are noise
      in an artifact whose job is to name *networks*.
    * ``max_prefix_len`` (v4, ``0`` disables) drops *aggregates*: a /8
      supernet announcement (measured: AS8075 announces 40.0.0.0/8) names
      millions of addresses the organisation does not operate — it is a
      routing-table convenience, not a footprint fact.  A /8 containing one
      target address would otherwise present 16 million "discovered" hosts.
    """
    accepted: list[str] = []
    refused: list[tuple[str, str]] = []
    seen: set[str] = set()

    for value in values:
        canonical = canonicalize_network(value)
        if canonical is None:
            refused.append((value, REFUSED_INVALID))
            continue
        network = ipaddress.ip_network(canonical)
        if not is_globally_routable(network):
            refused.append((canonical, REFUSED_NOT_GLOBAL))
            continue
        if (
            min_prefix_len
            and network.version == 4
            and network.prefixlen > min_prefix_len
        ):
            refused.append(
                (canonical, f"prefix narrower than /{min_prefix_len} (VIP-scale announcement)")
            )
            continue
        if (
            max_prefix_len
            and network.version == 4
            and network.prefixlen < max_prefix_len
        ):
            refused.append(
                (canonical, REFUSED_TOO_WIDE)
            )
            continue
        if canonical not in seen:
            seen.add(canonical)
            accepted.append(canonical)

    return accepted, refused


@dataclass
class NetworkClaim:
    """One network, one origin kind, one provenance trail.

    The same prefix can arrive from two origins (RIPEstat announces it and RDAP
    allocates it); :func:`merge_claims` folds those into one row with both
    origins rather than counting the network twice.
    """

    network: str
    origin: str  # ORIGIN_ANNOUNCEMENT or ORIGIN_ALLOCATION
    asns: set[str] = field(default_factory=set)
    as_names: dict[str, str] = field(default_factory=dict)
    org: str = ""
    org_handle: str = ""
    country: str = ""
    registry: str = ""
    sources: set[str] = field(default_factory=set)
    #: The sibling-stage addresses already known inside this network (filled by
    #: the orchestrator from the ports stage's artifacts, when present).
    known_hosts: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def classes(self) -> list[str]:
        """What the network is evidence of, in the report's vocabulary."""
        classes: list[str] = []
        if ORIGIN_ANNOUNCEMENT in self.origin:
            classes.append(CLASS_ANNOUNCED)
        if ORIGIN_ALLOCATION in self.origin:
            classes.append(CLASS_ALLOCATED)
        return classes

    @property
    def announced(self) -> bool:
        return ORIGIN_ANNOUNCEMENT in self.origin

    @property
    def allocated(self) -> bool:
        return ORIGIN_ALLOCATION in self.origin

    def to_dict(self) -> dict[str, object]:
        network = ipaddress.ip_network(self.network)
        return {
            "network": self.network,
            "version": network.version,
            "prefixlen": network.prefixlen,
            "num_addresses": network.num_addresses,
            "origin": self.origin,
            "classes": self.classes,
            "asns": sorted(self.asns),
            "as_names": dict(sorted(self.as_names.items())),
            "org": self.org,
            "org_handle": self.org_handle,
            "country": self.country,
            "registry": self.registry,
            "sources": sorted(self.sources),
            "known_hosts": len(self.known_hosts),
            "notes": list(self.notes),
        }


def merge_claims(claims: list[NetworkClaim]) -> list[NetworkClaim]:
    """Fold claims about the same network into one row with unioned facts."""
    merged: dict[str, NetworkClaim] = {}
    for claim in claims:
        existing = merged.get(claim.network)
        if existing is None:
            merged[claim.network] = claim
            continue
        existing.origin = f"{existing.origin}+{claim.origin}"
        existing.asns |= claim.asns
        for asn, name in claim.as_names.items():
            existing.as_names.setdefault(asn, name)
        existing.sources |= claim.sources
        existing.org = existing.org or claim.org
        existing.org_handle = existing.org_handle or claim.org_handle
        existing.country = existing.country or claim.country
        existing.registry = existing.registry or claim.registry
        existing.notes.extend(claim.notes)

    return sorted(
        merged.values(),
        key=lambda claim: (
            ipaddress.ip_network(claim.network).version,
            int(ipaddress.ip_network(claim.network).network_address),
            ipaddress.ip_network(claim.network).prefixlen,
        ),
    )


def containment_map(claims: list[NetworkClaim]) -> dict[str, list[str]]:
    """``network -> [networks that contain it]`` — wider allocations first.

    This is what makes the artifact readable when an organisation both holds a
    /14 allocation and announces pieces of it: the /24 row can point at its /14
    parent instead of looking like an unrelated fact.
    """
    networks = [(claim.network, ipaddress.ip_network(claim.network)) for claim in claims]
    containment: dict[str, list[str]] = {}
    for network_text, network in networks:
        parents = [
            other_text
            for other_text, other in networks
            if other_text != network_text
            and other.version == network.version
            and other.prefixlen < network.prefixlen
            and network.subnet_of(other)  # type: ignore[arg-type]
        ]
        parents.sort(key=lambda text: -ipaddress.ip_network(text).prefixlen)
        containment[network_text] = parents
    return containment


def annotate_known_hosts(
    claims: list[NetworkClaim], addresses: list[str]
) -> int:
    """Fill each claim's ``known_hosts`` from an address list; returns matched.

    The matcher is the point: a discovered /14 that already contains the
    addresses the names stage resolved is *confirmed* territory, while a
    discovered /14 with zero known hosts is the interesting case — space the
    target owns that DNS has never pointed at.
    """
    matched = 0
    networks = [(claim, ipaddress.ip_network(claim.network)) for claim in claims]
    for address_text in addresses:
        try:
            address = ipaddress.ip_address(address_text)
        except ValueError:
            continue
        for claim, network in networks:
            claim_network = ipaddress.ip_network(claim.network)
            if claim_network.version == address.version and address in claim_network:
                claim.known_hosts.append(address_text)
                matched += 1
                break
    return matched
