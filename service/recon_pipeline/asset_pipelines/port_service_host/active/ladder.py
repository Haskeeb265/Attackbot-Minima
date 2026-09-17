"""The scan ladder: what, if anything, each address has earned.

Full-range scanning of every address is the amateur default and the fastest route
to a blackhole.  This module is the policy that prevents it, and it is pure — no
network, no Docker, no clock — because the rule that decides how much of someone
else's network gets touched is worth testing on its own, and worth being able to
*read* on its own.

Five rungs, and the escalation between them is one-way and always recorded::

    L0   skip                  nothing at all (a CDN address with probing disabled)
    L1   passive-only          record "unknown, unscanned" and send no packet
    L2   top-N                 naabu over the top ports (the default)
    L2b  CDN web probe         httpx on 80/443 only — never a port scan
    L3   full range            naabu over 1-65535, only for addresses that earned it

The cost model is what makes the ladder matter.  At a realistic single-target
scale (~350 scan-eligible addresses after CDN collapse, per ``DESIGN.md`` §7):

=============================== ========================== ==================
strategy                        probes                     wall time @1k pps
=============================== ========================== ==================
all-L3 (65,535 ports × 350)     ~22.9M                     ~6.4 h
this ladder (L2, plus escalation ~3.6M                     ~1 h
only where L2 found something)
passive-only                    0                          minutes
=============================== ========================== ==================

The ~65× gap is spent only on addresses that produced evidence.  Nothing here is
a heuristic on a whim: every rung's condition is a fact the passive layer
gathered or the operator declared.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from ..classify.cdn import VERDICT_CDN, VERDICT_HOSTED, CdnVerdict
from ..settings import (
    SCAN_LEVEL_FULL,
    SCAN_LEVEL_L2,
    SCAN_LEVEL_PASSIVE,
    scan_level as _normalise_scan_level,
)

#: Rung identifiers.  Strings, not ints: the report is read by people, and
#: ``L2b`` sorts next to ``L2`` rather than mysteriously before ``L3``.
RUNG_SKIP = "L0"
RUNG_PASSIVE = "L1"
RUNG_TOP = "L2"
RUNG_CDN = "L2b"
RUNG_FULL = "L3"

ALL_RUNGS: tuple[str, ...] = (RUNG_SKIP, RUNG_PASSIVE, RUNG_TOP, RUNG_CDN, RUNG_FULL)

#: What the rung actually asks the scanner for.
PORTS_NONE = "none"
PORTS_TOP = "top"
PORTS_WEB = "web"
PORTS_FULL = "full"

#: Rungs that send packets at the address.  Used by the report to separate "we
#: looked and found nothing" from "we never looked" — the distinction the design's
#: output contract requires.
ACTIVE_RUNGS = frozenset({RUNG_TOP, RUNG_CDN, RUNG_FULL})


@dataclass(frozen=True)
class Rung:
    """One address's place on the ladder, and why."""

    ip: str
    level: str
    reason: str
    ports: str = PORTS_NONE
    provider: str = ""
    escalated: bool = False

    @property
    def active(self) -> bool:
        return self.level in ACTIVE_RUNGS

    @property
    def scanned_by_naabu(self) -> bool:
        return self.level in (RUNG_TOP, RUNG_FULL)

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "ip": self.ip,
            "level": self.level,
            "ports": self.ports,
            "reason": self.reason,
        }
        if self.provider:
            payload["provider"] = self.provider
        if self.escalated:
            payload["escalated"] = True
        return payload


def decide(
    ip: str,
    *,
    verdict: CdnVerdict | None = None,
    intel: object | None = None,
    in_scope: bool = False,
    scope_declared: bool = False,
    scan_level: str = SCAN_LEVEL_L2,
    cdn_probe: bool = True,
    escalated: bool = False,
    passive_only: bool = False,
) -> Rung:
    """Place one address on the ladder.

    Parameters
    ----------
    verdict:
        The :mod:`..classify.cdn` verdict for this address.  A CDN verdict
        short-circuits everything else — shared edge infrastructure is never port
        scanned, whatever else is true about it.
    intel:
        The passive intel record, if any.  Its existence is evidence that the
        address does something, which is what separates L2 from L1 for an address
        we have no scope claim over.
    in_scope:
        One of the target's own names resolves here.
    scope_declared:
        The address is inside an explicitly declared CIDR/IP scope.
    escalated:
        An L2 pass already found an open port here, which is the only way to earn
        L3 without a scope declaration.
    passive_only:
        The run has (or has been forced into) passive-only mode.  Every address
        drops to L1 regardless of evidence — including CDN addresses, because an
        HTTP probe is still a request to someone else's infrastructure.

    The order of the checks *is* the policy: mode first (an operator override
    outranks evidence), then CDN (never port-scan edge infrastructure), then L3
    (the expensive rung, only on a positive claim), then the default L2 for
    anything with a reason to look.
    """
    level = _normalise_scan_level(scan_level)

    if passive_only:
        return Rung(
            ip=ip,
            level=RUNG_PASSIVE,
            ports=PORTS_NONE,
            reason="passive-only mode: no packet is sent to any address",
        )

    if level == SCAN_LEVEL_PASSIVE:
        return Rung(
            ip=ip,
            level=RUNG_PASSIVE,
            ports=PORTS_NONE,
            reason="scan level 'passive': intel and ownership only",
        )

    if verdict is not None and verdict.verdict == VERDICT_CDN:
        if not cdn_probe:
            return Rung(
                ip=ip,
                level=RUNG_SKIP,
                ports=PORTS_NONE,
                provider=verdict.provider,
                reason="CDN/WAF address and the CDN web probe is disabled",
            )
        return Rung(
            ip=ip,
            level=RUNG_CDN,
            ports=PORTS_WEB,
            provider=verdict.provider,
            reason=(
                f"CDN/WAF address ({verdict.provider or 'provider unidentified'}) - "
                "HTTP probe on 80/443 only, never a port scan"
            ),
        )

    if escalated:
        # Earned by evidence: an L2 pass found an open port here.  One-way, and
        # recorded, so the report shows the escalation rather than only its result.
        # A hosted verdict refuses this rung even when an L2 port was found — what
        # the L2 finding means there is "the platform's edge answered", not "the
        # target's own server is worth 65,535 probes" (measured on qbsco.net:
        # 13 minutes of full-range SYN at Microsoft's addresses re-found nothing).
        if verdict is not None and verdict.verdict == VERDICT_HOSTED:
            return Rung(
                ip=ip,
                level=RUNG_TOP,
                ports=PORTS_TOP,
                provider=verdict.provider,
                reason=(
                    f"hosted on {verdict.provider or 'a third-party platform'} (CNAME chain) - "
                    "top-N result stands, escalation to a full-range scan is refused"
                ),
            )
        return Rung(
            ip=ip,
            level=RUNG_FULL,
            ports=PORTS_FULL,
            escalated=True,
            reason="escalated: an L2 pass found at least one open port",
        )

    if level == SCAN_LEVEL_FULL and (scope_declared or in_scope):
        return Rung(
            ip=ip,
            level=RUNG_FULL,
            ports=PORTS_FULL,
            reason=(
                "scan level 'full' with a positive scope claim ("
                + ("declared scope" if scope_declared else "in-scope name")
                + ")"
            ),
        )

    if scope_declared:
        return Rung(
            ip=ip,
            level=RUNG_TOP,
            ports=PORTS_TOP,
            reason="declared-scope address: top-N scan",
        )

    if in_scope:
        # A hosted verdict keeps the address on the top-N rung — a tenant endpoint
        # can still expose the target's own ports — but the escalation check above
        # refuses L3 for it, so a finding here never becomes a full-range sweep of
        # somebody else's platform.
        return Rung(
            ip=ip,
            level=RUNG_TOP,
            ports=PORTS_TOP,
            provider=verdict.provider if verdict is not None and verdict.verdict == VERDICT_HOSTED else "",
            reason=(
                f"hosted on {verdict.provider} (the target's name resolves through its "
                "tenant naming) - top-N scan, never escalated"
                if verdict is not None and verdict.verdict == VERDICT_HOSTED
                else "one of the target's names resolves here: top-N scan"
            ),
        )

    if getattr(intel, "indexed", False):
        return Rung(
            ip=ip,
            level=RUNG_TOP,
            ports=PORTS_TOP,
            reason="passive intel has a record for this address: top-N scan",
        )

    return Rung(
        ip=ip,
        level=RUNG_PASSIVE,
        ports=PORTS_NONE,
        reason=(
            "no passive intel, no scope declaration and no in-scope name - "
            "nothing justifies a packet"
        ),
    )


def plan(
    ips: Iterable[str],
    *,
    verdicts: Mapping[str, CdnVerdict] | None = None,
    intel: Mapping[str, object] | None = None,
    in_scope: Iterable[str] = (),
    scope_declared: Iterable[str] = (),
    scan_level: str = SCAN_LEVEL_L2,
    cdn_probe: bool = True,
    escalated: Iterable[str] = (),
    passive_only: bool = False,
) -> list[Rung]:
    """Place many addresses on the ladder, in the order given."""
    verdicts = verdicts or {}
    intel = intel or {}
    scope = set(in_scope)
    declared = set(scope_declared)
    upgraded = set(escalated)
    return [
        decide(
            address,
            verdict=verdicts.get(address),
            intel=intel.get(address),
            in_scope=address in scope,
            scope_declared=address in declared,
            scan_level=scan_level,
            cdn_probe=cdn_probe,
            escalated=address in upgraded,
            passive_only=passive_only,
        )
        for address in dict.fromkeys(ips)
    ]


def by_level(rungs: Iterable[Rung]) -> dict[str, list[str]]:
    """``{level: [ips]}`` in rung order, for the report."""
    buckets: dict[str, list[str]] = {level: [] for level in ALL_RUNGS}
    for rung in rungs:
        buckets.setdefault(rung.level, []).append(rung.ip)
    return {level: addresses for level, addresses in buckets.items() if addresses}


def ips_for(rungs: Iterable[Rung], level: str) -> list[str]:
    """The addresses on one rung, in input order."""
    return [rung.ip for rung in rungs if rung.level == level]


def summarise(rungs: Iterable[Rung]) -> dict[str, object]:
    """The report block for one ladder plan."""
    rungs = list(rungs)
    levels = by_level(rungs)
    return {
        "addresses": len(rungs),
        "by_level": {level: len(addresses) for level, addresses in levels.items()},
        "active": sum(1 for rung in rungs if rung.active),
        "unscanned": sum(1 for rung in rungs if not rung.active),
        "escalated": [rung.ip for rung in rungs if rung.escalated],
        "decisions": [rung.to_dict() for rung in rungs],
    }


__all__ = [
    "ACTIVE_RUNGS",
    "ALL_RUNGS",
    "PORTS_FULL",
    "PORTS_NONE",
    "PORTS_TOP",
    "PORTS_WEB",
    "RUNG_CDN",
    "RUNG_FULL",
    "RUNG_PASSIVE",
    "RUNG_SKIP",
    "RUNG_TOP",
    "Rung",
    "by_level",
    "decide",
    "ips_for",
    "plan",
    "summarise",
]
