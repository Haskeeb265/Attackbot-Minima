"""S15 — the Scope Engine: is this candidate ours to touch?

The safety chokepoint between *discovery* and *action*.  Every candidate asset
gets a :class:`ScopeState`, and every active decision (scan, crawl, recurse)
reads that state through :class:`ScopeEngine` — never its own judgement.

Three decisions the engine can make (and the report's vocabulary for them):

- ``in_scope``      — declared by the program (the strongest claim) or a
                      subdomain/containment of a declared asset; active work
                      may proceed through the dispatcher.
- ``needs_review``  — *discovered* but not declared: ASN/CIDR-derived
                      networks (the design's §5.4 rule: announced ≠ owned),
                      properties of the org that DNS never pointed at, or
                      anything the engine refused to auto-claim.  Nothing
                      active without an operator moving it.
- ``out_of_scope``  — provably outside (different org, private space, refused
                      ranges).  Reported, never touched.

The engine is conservative by construction: it auto-claims only what DNS
arithmetic proves (subdomains of declared domains, addresses inside declared
CIDRs).  Everything else it discovered lands in ``needs_review`` — being
conservative here is free, and the cost of wrongly claiming someone else's
host is not.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

IN_SCOPE = "in_scope"
NEEDS_REVIEW = "needs_review"
OUT_OF_SCOPE = "out_of_scope"


def _most_specific_containing(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address, candidates: set[str]
) -> str | None:
    """The tightest network in *candidates* that contains *ip*, or ``None``.

    Two things depend on this being a *rule* rather than "the first one the set
    happened to yield": the answer is the same in every process (Python's string
    hashing is randomised per process, so a set's order is not stable), and the
    reason names the network that actually says something.  An address inside
    both a ``/12`` and a ``/19`` of the same provider is inside the ``/19``; the
    ``/12`` is true but tells the operator less.
    """
    best: ipaddress.IPv4Network | ipaddress.IPv6Network | None = None
    for text in candidates:
        try:
            network = ipaddress.ip_network(text)
        except ValueError:  # unparseable registrations are the caller's problem
            continue
        if ip.version != network.version or ip not in network:
            continue
        if best is None or (network.prefixlen, str(network)) > (best.prefixlen, str(best)):
            best = network
    return str(best) if best is not None else None


@dataclass(frozen=True)
class ScopeDecision:
    """The outcome of one scope question — always with its reason."""

    state: str
    reason: str

    @property
    def active_allowed(self) -> bool:
        return self.state == IN_SCOPE

    def to_dict(self) -> dict[str, str]:
        return {"state": self.state, "reason": self.reason}


@dataclass
class ScopeEngine:
    """Declared assets in, scope decisions out.

    Built once per run from the operator's declared scope (domains, CIDRs,
    addresses) plus any ``discovered`` networks handed over by the
    ``asn_cidr`` pipeline; those stay ``needs_review`` by definition.
    """

    declared_domains: set[str] = field(default_factory=set)
    declared_networks: set[str] = field(default_factory=set)
    declared_addresses: set[str] = field(default_factory=set)
    #: Networks discovered by pipelines (asn_cidr) — never auto-claimed.
    discovered_networks: set[str] = field(default_factory=set)
    #: Out-of-scope refusals recorded by the seed stage (refused ranges).
    refused: dict[str, str] = field(default_factory=dict)

    # ------------------------------------------------------------------ #
    # construction
    # ------------------------------------------------------------------ #

    @classmethod
    def from_domain(cls, apex: str) -> "ScopeEngine":
        """A scope of exactly one declared apex domain."""
        from .common.normalize import canonicalize_host

        canonical = canonicalize_host(apex)
        return cls(declared_domains={canonical} if canonical else set())

    def add_declared_domain(self, domain: str) -> bool:
        from .common.normalize import canonicalize_host

        canonical = canonicalize_host(domain)
        if canonical is None:
            return False
        self.declared_domains.add(canonical)
        return True

    def add_declared_network(self, token: str) -> tuple[bool, str]:
        """Declare a CIDR/range; refuses what is not a valid network."""
        try:
            network = ipaddress.ip_network(token.strip(), strict=False)
        except (ValueError, AttributeError):
            return False, f"not a valid network: {token!r}"
        self.declared_networks.add(str(network))
        return True, ""

    def add_declared_address(self, address: str) -> bool:
        from .common.normalize import canonicalize_ip

        canonical = canonicalize_ip(address)
        if canonical is None:
            return False
        self.declared_addresses.add(canonical)
        return True

    def add_discovered_network(self, network: str) -> None:
        """Register a pipeline-discovered network — stays ``needs_review``."""
        canonical = network.strip()
        if canonical:
            self.discovered_networks.add(canonical)

    # ------------------------------------------------------------------ #
    # the three questions
    # ------------------------------------------------------------------ #

    def check_host(self, host: str) -> ScopeDecision:
        """Scope state for a hostname."""
        from .common.normalize import canonicalize_host, is_ip_literal, is_subdomain_of

        canonical = canonicalize_host(host)
        if canonical is None:
            return ScopeDecision(OUT_OF_SCOPE, f"not a valid host: {host!r}")
        if is_ip_literal(canonical):
            return self.check_address(canonical)
        # The most specific declared domain that covers it, so the answer (and
        # its wording) does not depend on set iteration order.
        declared_matches = sorted(
            (d for d in self.declared_domains if is_subdomain_of(canonical, d)),
            key=lambda domain: (len(domain), domain),
            reverse=True,
        )
        if declared_matches:
            declared = declared_matches[0]
            if canonical == declared:
                return ScopeDecision(IN_SCOPE, f"declared domain: {declared}")
            return ScopeDecision(IN_SCOPE, f"subdomain of declared domain {declared}")
        return ScopeDecision(
            NEEDS_REVIEW,
            f"discovered host outside declared domains: {canonical}",
        )

    def check_address(self, address: str) -> ScopeDecision:
        """Scope state for an IP address."""
        from .common.normalize import canonicalize_ip, is_scannable

        canonical = canonicalize_ip(address)
        if canonical is None:
            return ScopeDecision(OUT_OF_SCOPE, f"not a valid address: {address!r}")
        if canonical in self.declared_addresses:
            return ScopeDecision(IN_SCOPE, "declared address")
        if canonical in self.refused:
            return ScopeDecision(OUT_OF_SCOPE, self.refused[canonical])
        if not is_scannable(canonical):
            return ScopeDecision(OUT_OF_SCOPE, "not globally routable")
        ip = ipaddress.ip_address(canonical)
        declared_match = _most_specific_containing(ip, self.declared_networks)
        if declared_match is not None:
            return ScopeDecision(IN_SCOPE, f"inside declared network {declared_match}")
        discovered_match = _most_specific_containing(ip, self.discovered_networks)
        if discovered_match is not None:
            return ScopeDecision(
                NEEDS_REVIEW,
                f"inside discovered (not declared) network {discovered_match}",
            )
        return ScopeDecision(NEEDS_REVIEW, "address outside declared networks")

    def check_network(self, network: str) -> ScopeDecision:
        """Scope state for a CIDR — the §5.4 question the asn_cidr output poses.

        Declared networks are ``in_scope``; discovered ones are **always**
        ``needs_review`` (announced ≠ owned ≠ in-scope); anything else is
        ``out_of_scope``.
        """
        try:
            ip_network = ipaddress.ip_network(network.strip(), strict=False)
        except (ValueError, AttributeError):
            return ScopeDecision(OUT_OF_SCOPE, f"not a valid network: {network!r}")
        canonical = str(ip_network)
        if canonical in self.declared_networks:
            return ScopeDecision(IN_SCOPE, "declared network")
        if canonical in self.discovered_networks:
            return ScopeDecision(
                NEEDS_REVIEW,
                "discovered network - operator must move it into declared scope",
            )
        containers = []
        for declared_text in self.declared_networks:
            declared = ipaddress.ip_network(declared_text)
            if ip_network.subnet_of(declared):  # type: ignore[arg-type]
                containers.append(declared)
        if containers:
            # The tightest declaration that covers it, so the reason says
            # something and does not depend on iteration order.
            declared = min(containers, key=lambda network: (-network.prefixlen, str(network)))
            return ScopeDecision(IN_SCOPE, f"contained in declared network {declared}")
        return ScopeDecision(OUT_OF_SCOPE, "network outside declared scope")

    # ------------------------------------------------------------------ #
    # reporting
    # ------------------------------------------------------------------ #

    def summary(self) -> dict[str, object]:
        return {
            "declared_domains": sorted(self.declared_domains),
            "declared_networks": sorted(self.declared_networks),
            "declared_addresses": sorted(self.declared_addresses),
            "discovered_networks": len(self.discovered_networks),
            "refused": len(self.refused),
        }
