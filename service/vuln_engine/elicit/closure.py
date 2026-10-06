"""The closure pass: measure what the world has not established, then re-offer.

Backward chaining, as a bounded loop (``RND_dynamic_preconditions.md`` §3.4):

1. collect the capabilities every technique's ``surfaces()`` gate actually reads
   (``observed_gates`` — the one place the engine inspects technique behavior,
   because a gate that demands a claim nobody can measure is a silent arm);
2. for each surface and each unmet-but-gated capability, find the elicitor that
   can establish it, and run its probes through the ordinary PolicyGate;
3. interpret the answers as an :class:`~service.vuln_engine.elicit.common.Elicitation`;
   a positive becomes a ``CapabilityFact`` appended to the world log as
   ``capability.measured``;
4. rebuild the seed with each surface's ``capabilities`` set widened by the facts
   established for it, and return it — the ordinary pass then runs unchanged.

Bounds: an elicitor runs at most once per surface per run for a capability it
already answered (established *or* measured-negative); a negative is not retried
inside the same run. The world log carries both answers, so a reader can see what
was asked and what came back.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..kernel.capability import (
    EVENT_CAPABILITY_FACT,
    CapabilityFact,
    CapabilityFacts,
    declared_facts,
)
from ..kernel.technique import CAPABILITIES, EngagementSeed, Surface
from ..policy.gate import PolicyGate
from ..registry import TechniqueRegistry
from ..world.log import WorldLog
from .common import Elicitation
from .registry import ElicitorRegistry

#: Every capability a technique's ``surfaces()`` gate reads, collected once per
#: run. The mechanism deliberately does NOT hardcode this: a new technique that
#: gates on a new capability widens the closure question by existing, provided
#: an elicitor for that capability exists (or is added later — a technique that
#: gates on an unelicit-able capability is reported, not silently ignored).
def observed_gates(registry: TechniqueRegistry) -> frozenset[str]:
    """The capability strings the registered techniques' gates actually read.

    Five of the eight techniques gate differently from their manifest: the
    XSS pair and the timing pair declare ``gate_capabilities`` (their
    ``surfaces()`` reads a different tuple than the manifest's
    ``preconditions``), and the OR-gate derives its eligibility from the plan
    table — so the manifest's ``preconditions`` alone is not the truth about
    what opens a door (pinned by ``tests/vuln_engine/test_inventory_pins.py``).
    A technique MAY declare ``gate_capabilities`` on itself — the exact tuple
    its ``surfaces()`` reads — and when it does, that declaration wins;
    otherwise the manifest's ``preconditions`` stands in. This is one
    attribute read off the technique, not introspection, and a technique that
    adds it widens the closure question by existing.
    """
    wanted: set[str] = set()
    for registration in registry.all():
        declared_gate = getattr(registration.technique, "gate_capabilities", None)
        sources = declared_gate if declared_gate else registration.manifest.preconditions
        for capability in sources:
            if capability in CAPABILITIES:
                wanted.add(capability)
    return frozenset(wanted)


@dataclass
class ClosureReport:
    """What the closure pass did, as plain data for the run report."""

    #: ``capability.measured`` rows appended (established facts only).
    established: list[dict] = field(default_factory=list)
    #: Measured negatives, with their reasons — the questions asked that came
    #: back "no" or "inconclusive".
    negatives: list[dict] = field(default_factory=list)
    #: Elicitor × surface pairs skipped because an answer was already on file.
    skipped_known: int = 0
    #: Probes the gate refused (nothing was sent for them).
    refused: int = 0

    def to_dict(self) -> dict:
        return {
            "established": list(self.established),
            "negatives": list(self.negatives),
            "skipped_known": self.skipped_known,
            "refused": self.refused,
        }


def run_closure(
    seed: EngagementSeed,
    *,
    gate: PolicyGate,
    registry: TechniqueRegistry,
    log: WorldLog,
    clock,
    elicit_registry: ElicitorRegistry | None = None,
) -> tuple[EngagementSeed, ClosureReport]:
    """Elicit what the techniques need, and return the enriched seed.

    The gate is the only network door here exactly as everywhere else: elicitor
    probes are ordinary ``http.request`` effects, logged, scoped, breaker-counted.
    The OOB read for the remote-fetch elicitor is an internal effect, as it is
    for the verifier.
    """
    report = ClosureReport()
    if not seed.surfaces:
        return seed, report

    elicitors = elicit_registry or ElicitorRegistry.discover(strict=False)
    if len(elicitors) == 0:
        return seed, report

    facts = CapabilityFacts(declared=declared_facts(seed))
    gates = observed_gates(registry)
    # The ledger wins here too: a ``capability.measured`` row already on file
    # (this run, or a previous run of a resumable engagement) *is* the answer,
    # and asking again would be the spend the receipts ledger exists to
    # prevent. Declared claims enter the same set — a declared claim is an
    # answer, just one nobody measured.
    known: dict[str, set[str]] = {}
    for surface in seed.surfaces:
        known.setdefault(surface.key, set())
        if surface.capability:
            known[surface.key].add(surface.capability)
    for row in log.events(EVENT_CAPABILITY_FACT):
        key = str(row.get("surface_key", ""))
        capability = str(row.get("capability", ""))
        if key and capability:
            known.setdefault(key, set()).add(capability)

    enriched: dict[str, frozenset[str]] = {}
    for surface in seed.surfaces:
        established = known.setdefault(surface.key, set())
        for capability in sorted(gates):
            if capability in established:
                report.skipped_known += 1
                continue
            candidates = elicitors.for_capability(capability)
            if not candidates:
                continue  # nobody can measure this: reported by the caller's tools
            registration = candidates[0]
            elicitor = registration.elicitor
            if not elicitor.applies(surface):
                continue
            # ---- run the elicitor's probes through the gate ----
            observations = _run_probes(
                elicitor.name,
                surface,
                elicitor.probes(surface),
                gate=gate,
                log=log,
                clock=clock,
                report=report,
            )
            answer: Elicitation = elicitor.measure(surface, observations, at=clock())
            if answer.fact is None:
                report.negatives.append(
                    {
                        "elicitor": elicitor.name,
                        "surface": surface.key,
                        "capability": capability,
                        "reason": answer.reason,
                    }
                )
                continue
            fact: CapabilityFact = answer.fact
            log.append(
                EVENT_CAPABILITY_FACT,
                at=clock(),
                surface_key=fact.surface_key,
                capability=fact.capability,
                grade=fact.evidence_grade,
                probe=fact.probe,
                elicitor=elicitor.name,
            )
            report.established.append(fact.to_dict())
            established.add(capability)
        enriched[surface.key] = frozenset(established)

    new_seed = _rebuild(seed, enriched)
    return new_seed, report


def _rebuild(
    seed: EngagementSeed, enriched: dict[str, frozenset[str]]
) -> EngagementSeed:
    """The seed with each surface's ``capabilities`` widened by what was measured."""
    surfaces: list[Surface] = []
    for surface in seed.surfaces:
        extra = enriched.get(surface.key, frozenset())
        declared_only = frozenset({surface.capability} if surface.capability else set())
        merged = declared_only | extra
        if merged == surface.capabilities:
            surfaces.append(surface)
            continue
        surfaces.append(
            Surface(
                url=surface.url,
                host=surface.host,
                param=surface.param,
                where=surface.where,
                capability=surface.capability,
                label=surface.label,
                companions=dict(surface.companions),
                read_back=surface.read_back,
                capabilities=merged,
            )
        )
    return EngagementSeed(target=seed.target, surfaces=tuple(surfaces))


def _run_probes(
    technique: str,
    surface: Surface,
    specs: list[dict],
    *,
    gate: PolicyGate,
    log: WorldLog,
    clock,
    report: ClosureReport,
):
    """Execute an elicitor's probe specs through the gate; collect observations.

    The one piece of driver-like machinery elicitation needs: OOB sentinel
    substitution (the same rule the driver applies — the sentinel in the URL or
    body becomes a real per-probe collaborator URL, logged as an internal
    effect) and, for the remote-fetch elicitor, a collaborator *read* (also
    internal) whose interactions become the observations the elicitor
    interprets. Both are the driver's own documented mechanics, reused rather
    than reinvented.
    """
    from ..kernel.technique import ProbeSpec, oob_sentinel
    from ..kernel.exchange import RawHttpExchange
    from ..kernel.observation import Observation
    from ..policy.gate import EffectRequest
    from ..world.observe import http_observations, oob_observations

    observations: list[Observation] = []
    oob_probes: list[str] = []
    for spec in specs:
        detail = dict(spec.get("detail") or {})
        probe_id = str(spec.get("id") or "")
        sentinel = oob_sentinel(probe_id)
        if sentinel in (str(detail.get("url", "")) + str(detail.get("content", ""))):
            collaborator = gate.allocate_oob(probe_id)
            detail["url"] = str(detail["url"]).replace(sentinel, collaborator)
            if "content" in detail:
                detail["content"] = str(detail["content"]).replace(
                    sentinel, collaborator
                )
            oob_probes.append(probe_id)
        probe_spec = ProbeSpec(
            id=probe_id,
            kind=str(spec.get("kind") or "http.request"),
            host=str(spec.get("host") or surface.host),
            detail=detail,
            canary=str(spec.get("canary") or ""),
            mark=str(spec.get("mark") or ""),
        )
        request = EffectRequest(
            kind=probe_spec.kind,
            host=probe_spec.host,
            detail=detail,
            technique=technique,
            probe=probe_spec.id,
        )
        outcome = gate.run(request)
        at = gate.now()
        if not outcome.executed:
            report.refused += 1
            continue
        if probe_spec.kind == "http.request":
            exchange: RawHttpExchange = outcome.effect
            observations.extend(
                http_observations(
                    exchange,
                    probe=probe_spec.id,
                    canary=probe_spec.canary,
                    mark=probe_spec.mark,
                    at=at,
                    timing_class=str(spec.get("population") or ""),
                )
            )
    for probe_id in oob_probes:
        fetched = gate.read_oob(probe_id, wait=True)
        if fetched.error:
            continue  # an unreadable collaborator is inconclusive, not a negative
        at = gate.now()
        observations.extend(oob_observations(fetched, at=at))
    return observations
