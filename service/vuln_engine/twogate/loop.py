"""The proposal → verification loop.

This is the end-to-end flow:

    recon seed ─▶ capability prober ─▶ capability agent
                    ▲                     │ proposals
                    │ observations        ▼
                    └── loop-back ◀── confirmation runner ◀── verifier agent ◀── planner

A surface's capabilities are *measured* first (so a technique is never starved
for a claim nobody supplied). The capability agent proposes candidate bugs that
the measured capabilities admit; the planner routes each to a routine and
enforces independence; the verifier agent writes a declarative spec; the
deterministic runner executes it through the policy gate and applies the oracle.
A proven oracle is a finding. A refutation loops back — the capability agent is
asked for a *different* label on the same surface, bounded by the stopping
criteria.

Every step lands in the append-only world log. Confirmed candidates are written
as ordinary ``candidate`` + ``verdict`` rows, so :mod:`..world.views` derives
findings, leads and report lines with no change.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..kernel.evidence import EVIDENCE_HYPOTHESIS, Evidence
from ..kernel.observation import OBS_HTTP_RESPONSE
from ..kernel.technique import EngagementSeed, Surface
from ..kernel.verdict import Candidate, Verdict
from ..policy.gate import PolicyGate
from ..world import views
from ..world.log import EVENT_CANDIDATE, EVENT_VERDICT, WorldLog
from .agents import (
    CapabilityAgent,
    CapabilityAdvisor,
    ConfirmationPlanner,
    Lead,
    Proposal,
    VerifierAdvisor,
    VerifierAgent,
)
from .capability import CapabilityProber, CapabilityReport
from .runner import ConfirmationSpecRunner
from .spec import ConfirmationResult, ConfirmationSpec
from ..techniques.common import with_parameter

#: Ledger row types the two-gate flow adds. Kept here (its own vocabulary) rather
#: than in ``world/log.py`` so the generic appender stays generic.
EVENT_LOOP_ROUND = "loop.round"
EVENT_LOOP_STOPPED = "loop.stopped"
EVENT_PLANNED = "confirmation.planned"
EVENT_SPEC = "confirmation.spec"
EVENT_EXECUTED = "confirmation.executed"
EVENT_REFUSED = "confirmation.refused"
EVENT_LEAD = "lead.classified"


@dataclass(frozen=True)
class StoppingCriteria:
    """Pre-declared bounds, logged at ``run.begin`` so a run cannot exceed them."""

    max_rounds_per_surface: int = 3
    max_candidates_per_surface: int = 12
    max_capabilities_per_surface: int = 8

    def to_dict(self) -> dict:
        return {
            "max_rounds_per_surface": self.max_rounds_per_surface,
            "max_candidates_per_surface": self.max_candidates_per_surface,
            "max_capabilities_per_surface": self.max_capabilities_per_surface,
        }


@dataclass
class TwoGateReport:
    """What the loop did, as plain data the CLI embeds."""

    target: str
    started_at: float = 0.0
    finished_at: float = 0.0
    capabilities: dict = field(default_factory=dict)
    rounds: list[dict] = field(default_factory=list)
    stops: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    leads: list[str] = field(default_factory=list)
    report_lines: list[str] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    gate: dict = field(default_factory=dict)
    log_path: str = ""

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "capabilities": self.capabilities,
            "rounds": self.rounds,
            "stops": self.stops,
            "findings": self.findings,
            "leads": self.leads,
            "report_lines": self.report_lines,
            "counts": self.counts,
            "gate": self.gate,
            "log": self.log_path,
        }


class TwoGateLoop:
    """Runs the measured-capability → proposal → verification flow over a seed."""

    EVENT_BEGIN = "run.begin"
    EVENT_END = "run.end"

    def __init__(
        self,
        seed: EngagementSeed,
        *,
        gate: PolicyGate,
        log: WorldLog | None = None,
        criteria: StoppingCriteria | None = None,
        capability_advisor: CapabilityAdvisor | None = None,
        verifier_advisor: VerifierAdvisor | None = None,
    ) -> None:
        self.seed = seed
        self.gate = gate
        self.log = log if log is not None else gate.log
        self.criteria = criteria or StoppingCriteria()
        self.prober = CapabilityProber(gate)
        self.capability_agent = CapabilityAgent(capability_advisor)
        self.verifier_agent = VerifierAgent(verifier_advisor)
        self.runner = ConfirmationSpecRunner(gate)
        self.planner = ConfirmationPlanner()
        self.planner.transports_from_gate(gate)

    # ------------------------------------------------------------------ #

    def run(self) -> TwoGateReport:
        started = self.gate.now()
        self.log.append(
            self.EVENT_BEGIN,
            at=started,
            target=self.seed.target,
            surfaces=[surface.to_dict() for surface in self.seed.surfaces],
            criteria=self.criteria.to_dict(),
            capabilities=self.gate.capabilities(),
        )
        this_run = self.log.since(started)

        counts: dict[str, int] = {
            "surfaces": 0,
            "capabilities_measured": 0,
            "rounds": 0,
            "proposals": 0,
            "planned": 0,
            "confirmation_specs": 0,
            "executions": 0,
            "proven": 0,
            "refuted": 0,
            "leads": 0,
        }

        report = self.prober.measure(self.seed.surfaces, log=self.log)
        counts["surfaces"] = len(report.by_surface)
        counts["capabilities_measured"] = sum(len(caps) for caps in report.by_surface.values())

        rounds: list[dict] = []
        stops: list[dict] = []
        for surface in self.seed.surfaces:
            self._run_surface(surface, report, counts, rounds, stops)

        finished = self.gate.now()
        self.log.append(self.EVENT_END, at=finished, counts=dict(counts))

        found = views.findings(this_run)
        return TwoGateReport(
            target=self.seed.target,
            started_at=started,
            finished_at=finished,
            capabilities=report.to_dict(),
            rounds=rounds,
            stops=stops,
            findings=[finding.to_dict() for finding in found],
            leads=[str(row.get("id", "")) for row in views.leads(this_run)],
            report_lines=views.report_lines(this_run),
            counts=counts,
            gate=views.gate_audit(this_run),
            log_path=self.log.path.as_posix() if self.log.path else "",
        )

    # ------------------------------------------------------------------ #

    def _run_surface(
        self,
        surface: Surface,
        report: CapabilityReport,
        counts: dict[str, int],
        rounds: list[dict],
        stops: list[dict],
    ) -> None:
        capabilities = report.measured(surface.key)
        self.planner.transports_from_gate(self.gate)
        history: list[str] = []
        for round_index in range(1, self.criteria.max_rounds_per_surface + 1):
            counts["rounds"] += 1
            proposals = self.capability_agent.propose(surface, capabilities, history)
            fresh = [item for item in proposals if item.label not in history]
            self.log.append(
                EVENT_LOOP_ROUND,
                at=self.gate.now(),
                surface_key=surface.key,
                round=round_index,
                proposed=len(proposals),
                fresh=len(fresh),
                history=list(history),
            )
            rounds.append(
                {
                    "surface": surface.key,
                    "round": round_index,
                    "proposed": len(proposals),
                    "fresh": len(fresh),
                }
            )
            if not fresh:
                reason = (
                    "surface exhausted: the capability agent proposed no new label"
                    if history
                    else "no capability admitted a candidate on this surface"
                )
                self._stop(stops, surface.key, round_index, "no_new_candidate", reason)
                return

            if len(history) >= self.criteria.max_candidates_per_surface:
                self._stop(
                    stops, surface.key, round_index, "max_candidates",
                    "the per-surface candidate budget was reached",
                )
                return
            # One candidate per round: a refutation loops back and the next round
            # hypothesises a *different* bug, which is the behaviour the flow is
            # built around. Trying every admitted label at once would hide the
            # loop and spend probe budget a refutation did not earn.
            proposal = fresh[0]
            history.append(proposal.label)
            counts["proposals"] += 1
            if self._try_proposal(surface, proposal, capabilities, counts):
                self._stop(
                    stops, surface.key, round_index, "confirmed",
                    "a candidate on this surface was proven",
                )
                return

        self._stop(
            stops, surface.key, self.criteria.max_rounds_per_surface, "max_rounds",
            "the per-surface round budget was reached without a confirmation",
        )

    def _stop(
        self, stops: list[dict], surface_key: str, round_index: int, reason: str, detail: str
    ) -> None:
        self.log.append(
            EVENT_LOOP_STOPPED,
            at=self.gate.now(),
            surface_key=surface_key,
            round=round_index,
            reason=reason,
            detail=detail,
        )
        stops.append({"surface": surface_key, "round": round_index, "reason": reason})

    def _try_proposal(
        self,
        surface: Surface,
        proposal: Proposal,
        capabilities: frozenset[str],
        counts: dict[str, int],
    ) -> bool:
        """Route, spec, execute, judge one proposal. Returns whether it proved."""
        planned = self.planner.plan(proposal, capabilities)
        if isinstance(planned, Lead):
            counts["leads"] += 1
            self.log.append(
                EVENT_LEAD,
                at=self.gate.now(),
                surface_key=surface.key,
                proposal_id=proposal.id,
                label=proposal.label,
                reason=planned.reason,
            )
            return False
        counts["planned"] += 1
        routine = planned.routine
        self.log.append(
            EVENT_PLANNED,
            at=self.gate.now(),
            surface_key=surface.key,
            proposal_id=proposal.id,
            label=proposal.label,
            confirm_kind=routine.confirm_kind,
            routine_id=routine.routine_id,
            oracle=routine.oracle,
        )
        spec = self.verifier_agent.spec_for(proposal, routine, surface)
        counts["confirmation_specs"] += 1
        self.log.append(
            EVENT_SPEC, at=self.gate.now(), surface_key=surface.key, spec=spec.to_dict()
        )
        result = self.runner.run(spec)
        counts["executions"] += 1
        self._record_confirmation(surface, proposal, spec, result, counts)
        return result.proven

    def _record_confirmation(
        self,
        surface: Surface,
        proposal: Proposal,
        spec: ConfirmationSpec,
        result: ConfirmationResult,
        counts: dict[str, int],
    ) -> None:
        now = self.gate.now()
        self.log.append(
            EVENT_EXECUTED,
            at=now,
            surface_key=surface.key,
            proposal_id=proposal.id,
            routine_id=spec.routine_id,
            spec_digest=spec.digest,
            proven=result.proven,
            oracle_true=result.oracle_true,
            features=result.context.to_dict() if result.context else {},
        )

        proposer_evidence = Evidence(
            kind=OBS_HTTP_RESPONSE,
            grade=EVIDENCE_HYPOTHESIS,
            payload={
                "rationale": proposal.rationale,
                "capability": proposal.capability,
                "payload_family": proposal.payload_family,
            },
            at=now,
        )
        candidate = Candidate(
            id=proposal.id,
            technique="capability_agent",
            vuln_class=proposal.vuln_class,
            surface=surface.to_dict(),
            summary=proposal.rationale,
            evidence=proposer_evidence,
            confirm=spec.to_dict(),
            payload=spec.injected_payload,
            repro_url=self._repro_url(surface, spec),
            origin=proposal.origin,
        )
        self.log.append(EVENT_CANDIDATE, at=now, arm=f"{proposal.label}@{surface.key}", **candidate.to_dict())

        if result.proven:
            counts["proven"] += 1
            verdict_evidence = Evidence(
                kind=OBS_HTTP_RESPONSE,
                grade=result.evidence_grade,
                payload=result.to_dict(),
                at=now,
                probe=spec.routine_id,
            )
            Verdict.check_independence(candidate.proposer_grade, verdict_evidence)
            verdict = Verdict(
                candidate_id=candidate.id,
                proven=True,
                evidence=verdict_evidence,
                reason=result.reason,
                proposer_grade=candidate.proposer_grade,
            )
        else:
            counts["refuted"] += 1
            verdict = Verdict(
                candidate_id=candidate.id,
                proven=False,
                reason=result.reason,
                proposer_grade=candidate.proposer_grade,
            )
            self.log.append(
                EVENT_REFUSED,
                at=now,
                surface_key=surface.key,
                proposal_id=proposal.id,
                routine_id=spec.routine_id,
                reason=result.reason,
            )
        self.log.append(
            EVENT_VERDICT, at=now, arm=f"{proposal.label}@{surface.key}", **verdict.to_dict()
        )

    @staticmethod
    def _repro_url(surface: Surface, spec: ConfirmationSpec) -> str:
        if spec.where == "body" or not surface.param:
            return surface.url
        return with_parameter(surface.url, surface.param, spec.injected_payload)


__all__ = [
    "EVENT_EXECUTED",
    "EVENT_LEAD",
    "EVENT_LOOP_ROUND",
    "EVENT_LOOP_STOPPED",
    "EVENT_PLANNED",
    "EVENT_REFUSED",
    "EVENT_SPEC",
    "StoppingCriteria",
    "TwoGateLoop",
    "TwoGateReport",
]
