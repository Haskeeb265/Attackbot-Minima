"""Replay: recompute a run's decisions from its log, with nothing else.

This is the payoff of "pure at the boundary", and it is the property the whole
engine's testability rests on. A run is an append-only log of observations, so the
*proposing* half of every decision can be recomputed from the log alone — no
network, no browser, no collaborator, no clock, no model.

What replay recomputes, and what it deliberately does not:

* **recomputed** — the hypotheses, the probes each one implies, the candidates
  those observations support, and the report lines. All pure functions of the log;
* **recomputed from the abduced round too** — a ``note`` row with
  ``stage=hypothesis.abduced`` whose rule is one of the deterministic abducer's
  (``abduction/deterministic.py``) is re-derived the same way: the recorded
  anomaly is re-abduced, the proposal is matched by id, the hypothesis is
  materialized through the technique's own hook, and the candidate it implies is
  compared against the logged one. The abducer is pure, so its output is a
  function of the log's own inputs — replaying it is checking, not re-running a
  model;
* **checked** — every logged verdict's independence (a confirmation in a different
  evidence class than the proposal), because that rule is the one that turns a
  candidate into a finding and a violation of it would be the engine's worst
  possible bug;
* **not recomputed** — the verifier's *evidence*. Confirming a blind fetch means
  asking our collaborator, and confirming XSS means running a browser. Those are
  effects, and an effect's result is a recorded fact, not something derivable. A
  replay that re-ran them would not be a replay;
* **not recomputed, listed instead** — the synthesize junction's candidates
  (``candidate.junction`` rows, Phase 3) *and* the abduced rounds a model sourced
  (rows whose ``rule`` is the LLM channel's, ``llm_abduction``). A model's
  validated answer is recorded fact like an effect's result: replaying it would
  re-run the model, which is what the log's cached opinions exist to avoid. Two
  paths stay listed — the junction's rows and the model's own abductions — and
  only those; a deterministic abducer's row is never merely listed, and a
  deterministic row whose recorded input went missing is a mismatch.

So a mismatch means one of two things, and both are worth knowing: an input to a
pure function was not fully recorded, or a pure function is not pure. Neither is a
difference of opinion.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..abduction.deterministic import (
    RULE_OBJECT_READ,
    RULE_ROLE_COMPOSITION,
    abduce,
)
from ..kernel.anomaly import Anomaly, anomaly_key
from ..kernel.observation import Observation
from ..kernel.technique import EngagementSeed, Surface
from ..kernel.verdict import Candidate
from ..registry import Registration, TechniqueRegistry
from ..world import views
from ..world.log import (
    EVENT_ANOMALY_RETAINED,
    EVENT_CANDIDATE,
    EVENT_CANDIDATE_JUNCTION,
    EVENT_VERDICT,
    WorldLog,
)

#: The abducer rules whose output is a pure function of the log — the ones
#: replay re-derives. The LLM channel's rule (``llm_abduction``) is deliberately
#: absent: a model's answer is recorded fact, so its row stays listed.
DETERMINISTIC_RULES: frozenset[str] = frozenset({RULE_OBJECT_READ, RULE_ROLE_COMPOSITION})

_NOTE = "note"
_OBSERVATION = "observation"
_ABDUCED_STAGE = "hypothesis.abduced"


@dataclass
class ReplayReport:
    """What a replay produced, and how it differs from what was recorded."""

    candidates_logged: int = 0
    candidates_recomputed: int = 0
    #: Phase 3: candidate ids the synthesize junction proposed (recorded fact,
    #: listed rather than recomputed — see the module docstring).
    junction_candidates: list[str] = field(default_factory=list)
    #: The abductive loop's *logged* candidate ids (the ids the abduced round
    #: produced), whatever their source. Kept whole so a caller can see the
    #: round's output without caring how replay treated each row.
    abduced_candidates: list[str] = field(default_factory=list)
    #: Abduced candidate ids replay re-derived from the recorded anomaly — proof
    #: that the deterministic abducer's output is a function of the log.
    abduced_recomputed: list[str] = field(default_factory=list)
    #: Abduced candidate ids replay could not recompute because a model sourced
    #: them (recorded fact, like the junction's rows). Never a mismatch.
    abduced_listed: list[str] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    report_lines: list[str] = field(default_factory=list)
    #: Logged candidate ids the replay does not reproduce, and vice versa. An
    #: abduced row's reappearance here means a recorded input went missing or a
    #: pure function changed its answer.
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
            "abduced_candidates": list(self.abduced_candidates),
            "abduced_recomputed": list(self.abduced_recomputed),
            "abduced_listed": list(self.abduced_listed),
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

    # The abduced round: a deterministic rule is re-derived from the anomaly the
    # log recorded; a model-sourced row is listed (recorded fact). See the module
    # docstring for why those are the only two buckets.
    abduced_recomputed, abduced_listed, abduced_mismatches = _recompute_abduced(
        log, seed=seed, registry=registry
    )
    recomputed_ids.extend(abduced_recomputed)

    listed = set(abduced_listed)
    mismatches = [
        f"logged but not recomputed: {identifier}"
        for identifier in logged
        if identifier not in recomputed_ids and identifier not in listed
    ] + [
        f"recomputed but not logged: {identifier}"
        for identifier in recomputed_ids
        if identifier not in logged
    ] + abduced_mismatches

    # Phase 3: the junction's own candidates are recorded fact, not derivation
    # (see the module docstring). Listed for the audit; never a mismatch.
    junction_candidates = [
        str(row.get("id", "")) for row in log.events(EVENT_CANDIDATE_JUNCTION)
    ]
    abduced_ids = _abduced_candidate_ids(log)

    return ReplayReport(
        candidates_logged=len(logged),
        candidates_recomputed=len(recomputed_ids),
        junction_candidates=junction_candidates,
        abduced_candidates=[identifier for identifier in logged if identifier in abduced_ids],
        abduced_recomputed=abduced_recomputed,
        abduced_listed=abduced_listed,
        findings=[finding.to_dict() for finding in views.findings(log)],
        report_lines=views.report_lines(log),
        mismatches=mismatches,
        independence_violations=_independence_violations(log),
        gate_audit=views.gate_audit(log),
    )


def _recompute_abduced(
    log: WorldLog,
    *,
    seed: EngagementSeed,
    registry: TechniqueRegistry,
) -> tuple[list[str], list[str], list[str]]:
    """Re-derive the deterministic abduced round, and list the model-sourced one.

    Returns ``(recomputed candidate ids, listed candidate ids, mismatches)``. Each
    ``note stage=hypothesis.abduced`` row is treated on its own evidence: a row
    whose ``rule`` is not one of the deterministic abducer's came from the model
    channel, so it is recorded fact and goes to the listed bucket. A deterministic
    row is re-abduced from the anomaly the ledger holds, the proposal matched by
    id, and the candidate it implies recomputed against that experiment's *own*
    observations (the window between this note row and the next). A deterministic
    row whose recorded input has gone missing — no anomaly, no proposal, no
    materializable hypothesis — is a mismatch, not a silent listing.
    """
    anomalies = _recorded_anomalies(log)
    recomputed: list[str] = []
    listed: list[str] = []
    mismatches: list[str] = []
    for row, experiments in _abduced_windows(log):
        rule = str(row.get("rule", ""))
        identifier = str((row.get("hypothesis") or {}).get("id", ""))
        proposal_id = str(row.get("proposal_id", ""))
        if rule not in DETERMINISTIC_RULES:
            listed.append(identifier)
            continue
        anomaly = anomalies.get(str(row.get("witness", "")))
        if anomaly is None:
            mismatches.append(
                f"abduced round row {proposal_id}: its retained anomaly "
                f"({row.get('witness', '')}) is not in the log"
            )
            continue
        proposals = abduce(anomaly, list(seed.surfaces))
        proposal = next((item for item in proposals if item.id == proposal_id), None)
        if proposal is None:
            mismatches.append(
                f"abduced round row {proposal_id}: the deterministic abducer no "
                "longer produces this proposal from its recorded anomaly"
            )
            continue
        registration = _registration(registry, proposal.technique)
        if registration is None:
            mismatches.append(
                f"abduced round row {proposal_id}: technique "
                f"{proposal.technique!r} is no longer registered"
            )
            continue
        materialize = getattr(registration.technique, "hypothesis_for_proposal", None)
        hypothesis = materialize(proposal) if materialize is not None else None
        if hypothesis is None:
            mismatches.append(
                f"abduced round row {proposal_id}: the technique can no longer "
                "materialize this proposal"
            )
            continue
        specs = registration.technique.probes(hypothesis)
        seen = [
            observation
            for spec in specs
            for observation in experiments.get(spec.id, [])
        ]
        for candidate in registration.technique.interpret(hypothesis, seen):
            recomputed.append(str(candidate.id))
    return recomputed, listed, mismatches


def _registration(registry: TechniqueRegistry, name: str) -> Registration | None:
    try:
        return registry.get(name)
    except KeyError:
        return None


def _recorded_anomalies(log: WorldLog) -> dict[str, Anomaly]:
    """``{anomaly key: Anomaly}`` for every ``anomaly.retained`` row.

    Rebuilt the same way ``world/anomalies.py`` rebuilds its store: the row's
    technique, arm and deviation dict run through ``anomaly_key``. That key is
    what the abduced note row's ``witness`` carries, which is the join.
    """
    anomalies: dict[str, Anomaly] = {}
    for row in log.events(EVENT_ANOMALY_RETAINED):
        technique = str(row.get("technique", ""))
        arm = str(row.get("arm", ""))
        for deviation in row.get("deviations") or []:
            key = anomaly_key(technique, arm, deviation)
            anomalies[key] = Anomaly(
                key=key,
                technique=technique,
                arm=arm,
                deviation=dict(deviation),
            )
    return anomalies


def _abduced_windows(log: WorldLog) -> list[tuple[dict, dict[str, list[Observation]]]]:
    """Each ``hypothesis.abduced`` note row, with its own experiment's observations.

    The driver appends a note row, runs that experiment's probes (observations),
    judges, and moves to the next one; so the observations between this note row
    and the next belong to this experiment. Scoping matters: an abduced plan can
    share probe ids with the ordinary pass (the object-read row fires twice: once
    per pass), and the merged log's first answer is not necessarily this
    experiment's.
    """
    rows = log.rows
    starts = [
        index
        for index, row in enumerate(rows)
        if str(row.get("type", "")) == _NOTE and row.get("stage") == _ABDUCED_STAGE
    ]
    windows: list[tuple[dict, dict[str, list[Observation]]]] = []
    for position, start in enumerate(starts):
        end = starts[position + 1] if position + 1 < len(starts) else len(rows)
        by_probe: dict[str, list[Observation]] = {}
        for row in rows[start + 1 : end]:
            if str(row.get("type", "")) != _OBSERVATION:
                continue
            observation = _observation(row)
            by_probe.setdefault(observation.probe, []).append(observation)
        windows.append((rows[start], by_probe))
    return windows


def _observation(row: dict) -> Observation:
    return Observation.from_dict(
        {
            "kind": row.get("kind", ""),
            "payload": row.get("payload") or {},
            "probe": row.get("probe", ""),
            "at": row.get("at", 0.0),
        }
    )


def _abduced_candidate_ids(log: WorldLog) -> set[str]:
    """Candidate ids the abduced round produced, read from its note rows.

    The abduced round logs one ``note`` row per materialized hypothesis
    (``stage=hypothesis.abduced``) carrying the hypothesis dict; a technique's
    candidate id is its hypothesis id for the plan-table technique, which is
    what makes this join exact. Nothing here runs an abducer — the rows are the
    record of what ran.
    """
    ids: set[str] = set()
    for row in log.events("note"):
        if row.get("stage") != _ABDUCED_STAGE:
            continue
        hypothesis = row.get("hypothesis") or {}
        identifier = str(hypothesis.get("id", ""))
        if identifier:
            ids.add(identifier)
    return ids


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


__all__ = ["DETERMINISTIC_RULES", "ReplayReport", "replay"]
