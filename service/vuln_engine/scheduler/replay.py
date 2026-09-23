"""Replay: recompute a run's decisions from its log, with nothing else.

This is the payoff of "pure at the boundary", and it is the property the whole
engine's testability rests on. A run is an append-only log of observations, so the
*proposing* half of every decision can be recomputed from the log alone — no
network, no browser, no collaborator, no clock, no model.

What replay recomputes, and what it deliberately does not:

* **recomputed** — the hypotheses, the probes each one implies, the candidates
  those observations support, and the report lines. All pure functions of the log;
* **checked** — every logged verdict's independence (a confirmation in a different
  evidence class than the proposal), because that rule is the one that turns a
  candidate into a finding and a violation of it would be the engine's worst
  possible bug;
* **not recomputed** — the verifier's *evidence*. Confirming a blind fetch means
  asking our collaborator, and confirming XSS means running a browser. Those are
  effects, and an effect's result is a recorded fact, not something derivable. A
  replay that re-ran them would not be a replay;
* **not recomputed, counted separately** — the synthesize junction's candidates
  (``candidate.junction`` rows, Phase 3). A model's validated answer is recorded
  fact like an effect's result: replaying it would re-run the model, which is
  what the log's cached opinions exist to avoid. A replay lists them; it does
  not treat their absence from its own recomputation as a mismatch.

So a mismatch means one of two things, and both are worth knowing: an input to a
pure function was not fully recorded, or a pure function is not pure. Neither is a
difference of opinion.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..kernel.technique import EngagementSeed, Surface
from ..kernel.verdict import Candidate
from ..registry import TechniqueRegistry
from ..world import views
from ..world.log import EVENT_CANDIDATE, EVENT_CANDIDATE_JUNCTION, EVENT_VERDICT, WorldLog


@dataclass
class ReplayReport:
    """What a replay produced, and how it differs from what was recorded."""

    candidates_logged: int = 0
    candidates_recomputed: int = 0
    #: Phase 3: candidate ids the synthesize junction proposed (recorded fact,
    #: listed rather than recomputed — see the module docstring).
    junction_candidates: list[str] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    report_lines: list[str] = field(default_factory=list)
    #: Logged candidate ids the replay does not reproduce, and vice versa.
    mismatches: list[str] = field(default_factory=list)
    #: Verdicts whose confirmation reused the proposer's evidence class.  Empty is
    #: the only acceptable value.
    independence_violations: list[str] = field(default_factory=list)
    gate_audit: dict = field(default_factory=dict)

    @property
    def clean(self) -> bool:
        return not self.mismatches and not self.independence_violations

    def to_dict(self) -> dict:
        return {
            "candidates_logged": self.candidates_logged,
            "candidates_recomputed": self.candidates_recomputed,
            "junction_candidates": list(self.junction_candidates),
            "findings": len(self.findings),
            "mismatches": self.mismatches,
            "independence_violations": self.independence_violations,
            "report_lines": len(self.report_lines),
            "clean": self.clean,
        }


def replay(
    log: WorldLog,
    *,
    seed: EngagementSeed,
    registry: TechniqueRegistry | None = None,
) -> ReplayReport:
    """Recompute every proposing decision in *log* and compare with the record."""
    registry = registry or TechniqueRegistry.discover()
    observations = log.observations()
    by_probe: dict[str, list] = {}
    for observation in observations:
        by_probe.setdefault(observation.probe, []).append(observation)

    logged = [str(row.get("id", "")) for row in log.events(EVENT_CANDIDATE)]
    recomputed: list[Candidate] = []
    for registration in registry.all():
        technique = registration.technique
        for surface in _logged_surfaces(technique, seed):
            for hypothesis in technique.hypotheses(surface):
                specs = technique.probes(hypothesis)
                seen = [
                    observation
                    for spec in specs
                    for observation in by_probe.get(spec.id, [])
                ]
                recomputed.extend(technique.interpret(hypothesis, seen))

    recomputed_ids = [candidate.id for candidate in recomputed]
    mismatches = [
        f"logged but not recomputed: {identifier}"
        for identifier in logged
        if identifier not in recomputed_ids
    ] + [
        f"recomputed but not logged: {identifier}"
        for identifier in recomputed_ids
        if identifier not in logged
    ]

    # Phase 3: the junction's own candidates are recorded fact, not derivation
    # (see the module docstring). Listed for the audit; never a mismatch.
    junction_candidates = [
        str(row.get("id", "")) for row in log.events(EVENT_CANDIDATE_JUNCTION)
    ]

    return ReplayReport(
        candidates_logged=len(logged),
        candidates_recomputed=len(recomputed_ids),
        junction_candidates=junction_candidates,
        findings=[finding.to_dict() for finding in views.findings(log)],
        report_lines=views.report_lines(log),
        mismatches=mismatches,
        independence_violations=_independence_violations(log),
        gate_audit=views.gate_audit(log),
    )


def _logged_surfaces(technique: object, seed: EngagementSeed) -> list[Surface]:
    """The surfaces a technique would consider for this seed.

    Reads the seed rather than the log on purpose: the seed is the run's input, and
    a replay that reconstructed its own inputs would be checking itself.
    """
    return list(technique.surfaces(seed))  # type: ignore[attr-defined]


def _independence_violations(log: WorldLog) -> list[str]:
    """Every proven verdict whose confirmation reused the proposer's class."""
    violations: list[str] = []
    for row in log.events(EVENT_VERDICT):
        if not row.get("proven"):
            continue
        grade = str(row.get("grade", ""))
        proposer_grade = str(row.get("proposer_grade", ""))
        if not grade or grade == proposer_grade:
            violations.append(str(row.get("candidate", "")))
    return violations


__all__ = ["ReplayReport", "replay"]
