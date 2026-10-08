"""The Phase 1 scheduler: deterministic enumeration, not intelligence.

UCB, the attack tree and the noise objective are Phase 2. What Phase 1 needs is
something that can be *proved*: enumerate the eligible ``(technique × surface)``
pairs from declared preconditions, execute them in a declared order, and stop.

The order is the design's one nod to cost, and it is a hard rule rather than a
score: **cheap probes before loud ones**. Requests go first (one canary per
surface, no browser), and a browser probe runs only when a probe that already ran
established the context it declared a requirement for. A scheduler with no
intelligence can still be *sequential in the right direction*, and being able to
say "no browser ran on a surface whose context nobody had measured" is worth more
in Phase 1 than a clever ranking.

What the driver owns, and what it deliberately leaves alone:

* it owns the clock — every ``at`` in the log comes from one callable, so a run is
  reproducible and a replay can assert on a frozen clock;
* it owns the receipts ledger — a probe whose answer is conclusive is not paid for
  twice, a probe that *errored* is not recorded as an answer at all (``platform.receipt``'s
  rule, which is why ``failed`` is a distinct outcome and the next run is free to try
  again), and a probe the gate *refused* files no attempt whatsoever — nothing was
  sent, so there is nothing the ledger could honestly say about the target;
* it owns nothing about vulnerability classes.  It never looks inside a
  hypothesis, a probe or a candidate; if it needed to, the contract would be
  broken and the technique's folder would no longer be removable.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from ..kernel.evidence import FINDING_GRADES
from ..kernel.observation import (
    CONTEXT_DOM_ABSENT,
    CONTEXT_DOM_UNKNOWN,
    OBS_DOM_PLACEMENT,
    OBS_REFLECTION,
    OBS_SCRIPT_EXECUTION,
    Observation,
)
from ..kernel.prediction import Deviation, evaluate
from ..kernel.technique import (
    KIND_BROWSER,
    KIND_HTTP,
    PURPOSE_CONFIRM,
    EngagementSeed,
    Hypothesis,
    ProbeSpec,
    Surface,
    oob_sentinel,
)
from ..kernel.verdict import Candidate, Verdict
from ..memory.anomaly import corroborated
from ..policy.gate import EffectRequest, PolicyGate
from ..registry import Registration, TechniqueRegistry
from ..verification import VerificationLayer
from ..world import novelty
from ..world import views
from ..world.log import (
    EVENT_ABDUCTION_PROPOSED,
    EVENT_ABDUCTION_VALIDATED,
    EVENT_ANOMALY_RETAINED,
    EVENT_BEGIN,
    EVENT_CANDIDATE,
    EVENT_CANDIDATE_JUNCTION,
    EVENT_END,
    EVENT_HOLDING_PEN_ENTRY,
    EVENT_NOTE,
    EVENT_RECEIPT,
    EVENT_VERDICT,
    WorldLog,
)
from ..world.observe import browser_observations, http_observations

if TYPE_CHECKING:
    from ..abduction.proposal import Proposal
    from ..abduction.validator import Validator
    from ..elicit.registry import ElicitorRegistry
    from ..kernel.anomaly import Anomaly
    from ..llm.wiring import Advisory
    from ..world.holding_pen import HoldingPen
    from .pool import HypothesisPool

#: The driver's bound on reflected rounds per hypothesis (junction 5). Duplicated
#: from ``llm/reflect.py``'s ``MAX_REFLECT_ROUNDS`` deliberately — the driver
#: cannot import the llm layer at module level (the import graph is one-way:
#: llm → kernel/world, never kernel/scheduler → llm) — and the two are pinned
#: to each other by a test, the same convention as the timing verifier's
#: fallback payload table.
REFLECT_ROUNDS = 2

#: Attempt outcomes, mirroring ``platform.receipt``'s vocabulary.  ``none`` and
#: ``found`` are conclusive; ``failed`` is not, so a later run tries again.
OUTCOME_NONE = "none"
OUTCOME_FOUND = "found"
OUTCOME_FAILED = "failed"
#: A probe the gate refused.  Not recorded as an attempt at all: nothing was
#: learned about the target, and recording it would be the receipt inventing
#: knowledge — the same mistake as treating an error as an answer.
OUTCOME_REFUSED = "refused"#: A probe the driver never ran because its declared context was not observed.
OUTCOME_GATED = "gated"

#: Contexts that describe the *lens*, not a placement — collected by no gate.
_LENS_CONTEXTS = (CONTEXT_DOM_ABSENT, CONTEXT_DOM_UNKNOWN)


@dataclass
class ProbeRun:
    """One probe's execution, as the driver needs to see it."""

    spec: ProbeSpec
    outcome: str = OUTCOME_NONE
    verb: str = ""
    reason: str = ""
    observations: list[Observation] = field(default_factory=list)

    @property
    def conclusive(self) -> bool:
        return self.outcome in (OUTCOME_NONE, OUTCOME_FOUND)

    @property
    def contexts(self) -> set[str]:
        """The contexts this probe established, from either instrument.

        A byte-level reflection names its context (the wire lens); a DOM
        placement names its context (the browser lens). Both feed the same
        ``requires_context`` gate, because the gate's question — "has this
        context been *observed* here?" — does not care which instrument saw
        it. ``dom_absent``/``dom_unknown`` never enter: they are answers about
        the lens, not placements.
        """
        return {
            item.context
            for item in self.observations
            if item.context
            and item.kind in (OBS_REFLECTION, OBS_DOM_PLACEMENT)
            and item.context not in _LENS_CONTEXTS
        }


@dataclass
class RunReport:
    """What a run is, in plain data — the machine report a caller embeds."""

    target: str
    started_at: float = 0.0
    finished_at: float = 0.0
    techniques: list[dict] = field(default_factory=list)
    surfaces: list[dict] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    gate: dict = field(default_factory=dict)
    receipts: dict = field(default_factory=dict)
    findings: list[dict] = field(default_factory=list)
    leads: list[str] = field(default_factory=list)
    report_lines: list[str] = field(default_factory=list)
    capabilities: dict = field(default_factory=dict)
    problems: list[str] = field(default_factory=list)
    #: Phase 3: the model's health and say, as plain data. ``{}`` when no
    #: advisory was wired (which is the ordinary no-key run).
    advisory: dict = field(default_factory=dict)
    #: Phase 9: ``{candidate_id: {level, name, label, reason}}`` for every
    #: proven finding, computed from the log's own provenance (world/novelty.py).
    novelty: dict = field(default_factory=dict)
    #: Capability Closure's report (``ClosureReport.to_dict()``), or ``{}`` when
    #: the closure pass did not run.
    closure: dict = field(default_factory=dict)
    #: The holding-pen backlog (``views.holding_pen_summary``): held hypotheses
    #: grouped by ``(needs_verifier, vuln_class | claim_shape)``, descending by
    #: count. This run's window over the ledger, with the pen passed in so an
    #: entry that has since been promoted or demoted is not counted as waiting.
    holding_pen: dict = field(default_factory=dict)
    #: Per-surface coverage (``views.coverage``): the last attempt's outcome
    #: per ``(surface, technique)`` from the receipts ledger, conclusive or not.
    coverage: dict = field(default_factory=dict)
    #: The abductive junction's ledger (``views.abduction_summary``): proposals
    #: and validator verdicts, counted by verdict and grouped by needs_verifier.
    abduction: dict = field(default_factory=dict)
    #: ``findings`` collapsed to the strongest per ``(surface, vuln_class)``
    #: (``views.findings_deduplicated``), the losers' ids carried in
    #: ``duplicate_ids``. The raw ``findings`` list above stays untouched.
    findings_deduplicated: list[dict] = field(default_factory=list)
    #: What the model channel cost (``views.llm_cost_summary``, item 4.2): call
    #: counts, token totals, worst latency and summed cost over this run's
    #: ``llm.junction`` rows. All zeros on a keyless run — the deterministic
    #: engine's model spend is exactly nothing, and the report says so.
    llm_cost: dict = field(default_factory=dict)
    #: The joined abduction economics (``views.abduction_cost_summary``, H3):
    #: proposal → verdict → abduced experiment → candidate → finding, with the
    #: channel's cost split by rule — the LLM abduction channel's spend against
    #: the deterministic abducer's zero. ``{}``-shaped plain data, derived.
    abduction_cost: dict = field(default_factory=dict)
    log_path: str = ""

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "techniques": self.techniques,
            "surfaces": self.surfaces,
            "counts": self.counts,
            "gate": self.gate,
            "receipts": self.receipts,
            "findings": self.findings,
            "leads": self.leads,
            "report_lines": self.report_lines,
            "capabilities": self.capabilities,
            "problems": self.problems,
            "advisory": self.advisory,
            "novelty": self.novelty,
            "closure": self.closure,
            "holding_pen": self.holding_pen,
            "coverage": self.coverage,
            "abduction": self.abduction,
            "findings_deduplicated": self.findings_deduplicated,
            "llm_cost": self.llm_cost,
            "abduction_cost": self.abduction_cost,
            "log": self.log_path,
        }


class Engine:
    """The Phase 1 run loop: enumerate, gate, observe, interpret, verify, record."""

    def __init__(
        self,
        seed: EngagementSeed,
        *,
        gate: PolicyGate,
        registry: TechniqueRegistry | None = None,
        log: WorldLog | None = None,
        verification: VerificationLayer | None = None,
        receipt: Any = None,
        clock: Callable[[], float] | None = None,
        force: bool = False,
        advisory: Advisory | None = None,
        abducer: Callable[["Anomaly", Sequence[Surface]], list["Proposal"]] | None = None,
        validator: "Validator | None" = None,
        pen: "HoldingPen | None" = None,
        pool: "HypothesisPool | None" = None,
        elicit: bool = False,
        elicit_registry: "ElicitorRegistry | None" = None,
        anomaly_memory: dict | None = None,
    ) -> None:
        self.seed = seed
        self.gate = gate
        self.registry = registry or TechniqueRegistry.discover()
        self.log = log if log is not None else gate.log
        self.verification = verification or VerificationLayer(gate)
        #: ``platform.receipt.Receipt`` — the punch card that stops a conclusive
        #: attempt being paid for twice.
        self.receipt = receipt
        self.clock = clock or _wall_clock
        #: Ignore the receipts ledger and re-probe everything (an operator's flag,
        #: and the only way to re-ask a question whose answer is stale).
        self.force = force
        #: Phase 3's advisory junctions, or ``None``. Everything the engine does
        #: is identical without one; an advisory can only add a synthesized
        #: probe spec through the same gate every other probe passes.
        self.advisory = advisory
        #: Phase 4's abductive loop, or ``None``. With no abducer the engine is
        #: byte-for-byte the one that retains anomalies and stops there; with one,
        #: a retained surprise is explained, validated, and either logged for the
        #: pool (Phase 5) or held in the pen. Nothing the abducer produces is ever
        #: a finding: it must earn one through the ordinary gate and verifier.
        self.abducer = abducer
        self.validator = validator
        self.pen = pen
        #: The Phase 5 hypothesis pool, or ``None``. Expressible abductions are
        #: added here; unprovable ones go to the pen. Empty pool = the same
        #: behavior as no pool at all.
        self.pool = pool
        #: Capability Closure (``elicit/closure.py``), off by default: when on,
        #: the run first *measures* the preconditions the techniques gate on
        #: (through the ordinary gate, via the elicitor corpus) and widens each
        #: surface's ``capabilities`` with the measured facts before the ordinary
        #: pass enumerates. A technique's gate then reads a measured fact instead
        #: of only an operator's declaration. With the flag off the run is
        #: byte-for-byte the declared-claims-only engine.
        self.elicit = elicit
        self.elicit_registry = elicit_registry
        #: The cross-engagement anomaly distillate (``memory/anomaly.py``, H1),
        #: or ``None``. Read-only and advisory: a predicate family a prior
        #: engagement retained ranks this run's matching proposals ahead of the
        #: rest in the abduced round, and rides the LLM abduction junction's
        #: prompt. It never bypasses the validator's three-valued check and
        #: never promotes anything on its own — nothing here can become a
        #: finding except through the ordinary gate and verifier. ``None`` (the
        #: default) is the byte-for-byte memoryless engine of every batch
        #: before this one.
        self.anomaly_memory = anomaly_memory

    # ------------------------------------------------------------------ #
    # the run
    # ------------------------------------------------------------------ #

    def run(self) -> RunReport:
        """Run every eligible technique × surface, and report what happened."""
        started = self.clock()
        self.log.append(
            EVENT_BEGIN,
            at=started,
            target=self.seed.target,
            techniques=self.registry.names(),
            surfaces=[surface.to_dict() for surface in self.seed.surfaces],
            capabilities=self.gate.capabilities(),
        )
        # The report describes *this run*, not the ledger: the file a run appends
        # to may already hold earlier runs (an engagement is resumable by design),
        # so every view below reads through a window that starts at this run's
        # begin row. Reporting through the whole log would let a second run resell
        # the first run's findings as its own.
        this_run = self.log.since(started)

        counts: dict[str, int] = {
            "arms": 0,
            "hypotheses": 0,
            "probes": 0,
            "probes_run": 0,
            "probes_gated": 0,
            "probes_for_verifier": 0,
            "probes_refused": 0,
            "probes_failed": 0,
            "candidates": 0,
            "findings": 0,
            "leads": 0,
            "skipped_conclusive": 0,
        }

        closure_report: dict = {}
        if self.elicit:
            # Capability Closure runs *before* the ordinary pass: elicitors ask
            # the cheap questions the techniques' gates depend on, and the
            # enriched seed is what every ``surfaces()`` call below reads. The
            # closure answers are ordinary log rows (``capability.measured``),
            # so a replay sees exactly what was measured and why a door opened.
            from ..elicit.closure import run_closure

            self.seed, closure = run_closure(
                self.seed,
                gate=self.gate,
                registry=self.registry,
                log=self.log,
                clock=self.clock,
                elicit_registry=self.elicit_registry,
            )
            closure_report = closure.to_dict()
            counts["closure_established"] = len(closure.established)
            counts["closure_negatives"] = len(closure.negatives)
            counts["closure_refused"] = closure.refused

        for registration in self.registry.all():
            for surface in registration.technique.surfaces(self.seed):
                self._run_surface(registration, surface, counts)

        # A3's second channel (PRD §6.5, implementation 3): properties proposed
        # from static context, with no anomaly to trigger them. Pools the
        # expressible ones so the abduced round runs them exactly like an
        # anomaly-driven explanation. No advisory/key = a no-op.
        self._propose_properties(counts)
        # The loop closes (PRD §6.5): an expressible explanation of a retained
        # surprise becomes a real experiment. Runs once, after the ordinary
        # pass, through the ordinary path — same gate, same interpret, same
        # independent verifier. A surprise here is not re-abduced.
        self._run_abduced(counts)

        # A refusal caused only by a missing second session is an operator fix,
        # not a dead end. Count them from the log (the ledger is the truth) and
        # split them into capability checks vs candidate verifications, so the
        # CLI can say which knob unlocks what.
        session_b = views.blocked_on_session_b_split(this_run)
        counts["blocked_on_session_b"] = session_b["total"]
        counts["blocked_on_session_b_capability_checks"] = session_b["capability_checks"]
        counts["blocked_on_session_b_candidates"] = session_b["candidates"]

        finished = self.clock()
        self.log.append(EVENT_END, at=finished, counts=dict(counts))

        audit = views.gate_audit(this_run)
        found = views.findings(this_run)
        return RunReport(
            target=self.seed.target,
            started_at=started,
            finished_at=finished,
            techniques=self.registry.describe(),
            surfaces=[surface.to_dict() for surface in self.seed.surfaces],
            counts=counts,
            gate=audit,
            receipts=views.receipts_by_arm(this_run),
            findings=[finding.to_dict() for finding in found],
            novelty=novelty.levels_for_log(this_run),
            leads=[str(row.get("id", "")) for row in views.leads(this_run)],
            report_lines=views.report_lines(this_run),
            capabilities=self.gate.capabilities(),
            problems=self.registry.problems,
            advisory=self._advisory_report(),
            closure=closure_report,
            holding_pen=views.holding_pen_summary(this_run, pen=self.pen),
            coverage=views.coverage(this_run),
            abduction=views.abduction_summary(this_run),
            findings_deduplicated=views.findings_deduplicated(this_run),
            llm_cost=views.llm_cost_summary(this_run),
            abduction_cost=views.abduction_cost_summary(this_run),
            log_path=self.log.path.as_posix() if self.log.path else "",
        )

    # ------------------------------------------------------------------ #
    # one technique × surface
    # ------------------------------------------------------------------ #

    def _run_surface(
        self, registration: Registration, surface: Surface, counts: dict[str, int]
    ) -> None:
        technique = registration.technique
        for hypothesis in technique.hypotheses(surface):
            counts["arms"] += 1
            counts["hypotheses"] += 1
            # The arm names the *hypothesis's* surface, not the loop's: an
            # adapter may emit seed-level plans from one call (generic_differential
            # does), and labelling a report-surface hypothesis with the invoice
            # surface's arm would file the wrong receipt and misattribute the
            # anomaly the reports surface produced.
            arm = f"{registration.name}@{hypothesis.surface.key}"
            # The *receipt* is scoped to the hypothesis, not the arm: a technique
            # that emits several hypotheses on one surface (the plan tables do)
            # must not have its second question silenced by the first one's
            # conclusive answer. The UCB arm stays surface-scoped (the selector's
            # economics), while the ledger's settle rule is exactly as wide as
            # the question that was asked.
            operation = f"{registration.name}:{hypothesis.id}"
            self.log.append(
                EVENT_NOTE,
                at=self.clock(),
                stage="hypothesis",
                arm=arm,
                hypothesis=hypothesis.to_dict(),
            )
            if self._already_settled(arm, operation):
                counts["skipped_conclusive"] += 1
                continue
            observations, failures, executed = self._run_probes(registration, hypothesis, counts)
            # The third interpret outcome (PRD §6.3): before reading the
            # technique's candidates, run the hypothesis's own expectation
            # against what was measured. Measurements that matched nothing and
            # violated a prediction are retained anomalies — advisory data for
            # the abducer, never evidence, never a finding. The technique's
            # candidates take priority when they exist: an explained surprise
            # is not an unexplained one.
            deviations: list[Deviation] = evaluate(hypothesis.expectation, observations)
            candidates = list(technique.interpret(hypothesis, observations))
            if deviations and not candidates and observations:
                counts["anomalies_retained"] = counts.get("anomalies_retained", 0) + 1
                self.log.append(
                    EVENT_ANOMALY_RETAINED,
                    at=self.clock(),
                    arm=arm,
                    hypothesis_id=hypothesis.id,
                    technique=registration.name,
                    deviations=[deviation.to_dict() for deviation in deviations],
                )
                # The loop closes (PRD §6.5): explain the surprise with known
                # predicates, route the explanation three-valued (PRD §6.6).
                # Optional — absent an abducer this is the one-pass engine.
                self._abduce(registration, arm, deviations, counts)
            # Junction 5 (reflect): when the pass measured something but the
            # deterministic interpretation came back empty, the model may
            # direct a bounded re-ask of a probe this pass already ran — a
            # jitter check on an anomalous timing pair, a fresh sample after a
            # flaky failure. Degraded (no advisory, no key, a refused answer,
            # or "stop" every round) the loop never spins: the behavior is
            # byte-for-byte the one-pass engine. A recheck names a probe id
            # from *this pass's own grammar* — validated at the junction and
            # re-checked here — and every re-executed probe goes through the
            # ordinary gate with the ordinary receipt consequences.
            if (
                self.advisory is not None
                and self.advisory.available
                and not candidates
                and observations
            ):
                specs = technique_probes(registration, hypothesis)
                propose_specs = {
                    spec.id: spec for spec in specs if spec.purpose != PURPOSE_CONFIRM
                }
                probe_rows = [
                    {"id": spec.id, "purpose": spec.purpose, "oracle": spec.oracle}
                    for spec in propose_specs.values()
                ]
                hypothesis_dict = hypothesis.to_dict()
                for reflect_round in range(REFLECT_ROUNDS):
                    decision = self.advisory.reflected_decision(
                        hypothesis=hypothesis_dict,
                        probe_rows=probe_rows,
                        observations_summary=self._observation_summaries(observations),
                        log_handle=self.log,
                        now=self.clock(),
                    )
                    if not decision.recheck:
                        break
                    spec = propose_specs.get(decision.probe_id)
                    if spec is None:
                        # Defense in depth: the junction validated the id, and
                        # the driver re-checks it. Either way the loop ends.
                        break
                    counts["probes"] += 1
                    counts["probes_reflected"] = counts.get("probes_reflected", 0) + 1
                    self.log.append(
                        EVENT_NOTE,
                        at=self.clock(),
                        stage="reflect.recheck",
                        arm=arm,
                        probe=spec.id,
                        round=reflect_round + 1,
                        reason=decision.reason,
                        source=decision.source,
                    )
                    run = self._execute(registration, spec)
                    if run.outcome == OUTCOME_REFUSED:
                        counts["probes_refused"] += 1
                        break  # the gate said no: the loop stops here
                    counts["probes_run"] += 1
                    executed += 1
                    if run.outcome == OUTCOME_FAILED:
                        counts["probes_failed"] += 1
                        failures += 1
                    observations.extend(run.observations)
                    candidates = list(technique.interpret(hypothesis, observations))
                    if candidates:
                        break  # the re-ask produced something to judge
            counts["candidates"] += len(candidates)
            self._judge(arm, operation, candidates, failures, counts, executed=executed)
            self._synthesize(arm, registration, hypothesis, observations, counts)

    @staticmethod
    def _observation_summaries(observations: list[Observation]) -> list[dict]:
        """Typed, whitelisted summaries for the reflect junction's input.

        The same fields ``reflect.OBSERVATION_FIELDS`` names — statuses, elapsed
        times, timing classes, contexts — and nothing else. A response body is
        never a summary field: the model reflects on measurements, not on what
        the target said.
        """
        from ..llm.reflect import OBSERVATION_FIELDS

        summaries: list[dict] = []
        for item in observations:
            summary: dict = {"probe": item.probe}
            for field_name in OBSERVATION_FIELDS:
                if field_name in item.payload:
                    summary[field_name] = item.payload[field_name]
            summaries.append(summary)
        return summaries

    def _abduce(
        self,
        registration: Registration,
        arm: str,
        deviations: list[Deviation],
        counts: dict[str, int],
    ) -> None:
        """Explain a just-retained surprise; route the explanation three-valued.

        Advisory throughout: a proposal is logged and validated, an
        unprovable one is held, and an expressible one is logged for the
        hypothesis pool. None of it can become a finding without a probe and
        an independent verifier.
        """
        from ..abduction.validator import Validator
        from ..kernel.anomaly import Anomaly, anomaly_key

        model = self.advisory is not None and self.advisory.available
        if self.abducer is None and not model:
            return
        validator = self.validator or Validator()
        for deviation in deviations:
            deviation_dict = deviation.to_dict()
            key = anomaly_key(registration.name, arm, deviation_dict)
            anomaly = Anomaly(
                key=key,
                technique=registration.name,
                arm=arm,
                deviation=deviation_dict,
                at=self.clock(),
            )
            memory_backed = bool(self.anomaly_memory) and corroborated(
                self.anomaly_memory, anomaly
            )
            for proposal in self._proposals_for(
                anomaly,
                arm,
                model,
                memory_backed=memory_backed,
            ):
                self._consider(
                    proposal,
                    arm=arm,
                    anomaly=key,
                    counts=counts,
                    validator=validator,
                    memory_backed=memory_backed,
                )

    def _proposals_for(
        self, anomaly: "Anomaly", arm: str, model: bool, *, memory_backed: bool = False
    ) -> list["Proposal"]:
        """Every explanation for one anomaly: deterministic first, model second.

        The deterministic abducer is the control arm; the LLM channel (A3) is
        the primary novelty source. Both emit the same ``Proposal`` shape over
        the same plan table, so everything downstream — validation, the pool,
        the pen, the abduced round — cannot tell them apart, which is exactly
        the point: a model-proposed claim is still an experiment the verifier
        has seen.

        H1: when an anomaly distillate is wired, the LLM junction's prompt
        carries the memory cells (its ``memory`` input, plumbed and previously
        unwired), and ``memory_backed`` — the distillate corroborating this
        anomaly's predicate family — rides the proposal into the pool's
        ranking. Neither path can bypass the validator: the ranking changes
        what is tried first, never what may be believed.
        """
        proposals: list[Proposal] = []
        if self.abducer is not None:
            proposals.extend(self.abducer(anomaly, self.seed.surfaces))
        if model:
            assert self.advisory is not None
            anomaly_dict = {
                "technique": anomaly.technique,
                "arm": anomaly.arm,
                **dict(anomaly.deviation),
            }
            result = self.advisory.abduced(
                anomaly_dict,
                self.seed.surfaces,
                memory=self.anomaly_memory,
                log_handle=self.log,
                now=self.clock(),
            )
            proposals.extend(result.proposals)
        return proposals

    def _propose_properties(self, counts: dict[str, int]) -> None:
        """A3's no-anomaly channel: ask the model for properties, unasked.

        Static context only — the declared surfaces, the claim ontology. The
        junction's contract is the same as the abduction channel's: it may point
        at a declared surface with a claim shape the engine speaks, and nothing
        else. Every proposal goes through the same three-valued validator, so an
        expressible property is pooled for the abduced round to *run* and a
        model-proposed L3/L4 experiment reaches a finding only through the
        ordinary verifier. Degraded (no key, a refused answer) is a no-op, so
        the engine is byte-for-byte the one that never asked.
        """
        if self.advisory is None or not self.advisory.available:
            return
        from ..abduction.validator import Validator

        result = self.advisory.proposed_properties(
            self.seed.surfaces, log_handle=self.log, now=self.clock()
        )
        validator = self.validator or Validator()
        for proposal in result.proposals:
            counts["properties_proposed"] = counts.get("properties_proposed", 0) + 1
            self._consider(
                proposal,
                arm="property",
                anomaly="",
                counts=counts,
                validator=validator,
                source="property",
            )

    def _consider(
        self,
        proposal: "Proposal",
        *,
        arm: str,
        anomaly: str,
        counts: dict[str, int],
        validator: "Validator",
        source: str = "abduction",
        memory_backed: bool = False,
    ) -> None:
        """Log one explanation, route it three-valued, and shelve it.

        Nothing here can become a finding: an expressible proposal enters the
        pool (to be run by :meth:`_run_abduced`), a held one enters the pen,
        and an invalid one is only on the record. The validator's verdict is
        the whole influence. ``source`` records which channel asked
        (``abduction`` for an anomaly-driven explanation, ``property`` for
        A3's static-context proposal); the routing is identical. H1:
        ``memory_backed`` (the anomaly distillate corroborating the witnessing
        family) rides into the pool's ranking only — expressible or held is
        still the validator's word alone.
        """
        counts["abductions"] = counts.get("abductions", 0) + 1
        self.log.append(
            EVENT_ABDUCTION_PROPOSED,
            at=self.clock(),
            arm=arm,
            anomaly=anomaly,
            source=source,
            proposal=proposal.to_dict(),
        )
        validation = validator.validate(proposal)
        self.log.append(
            EVENT_ABDUCTION_VALIDATED,
            at=self.clock(),
            arm=arm,
            proposal_id=proposal.id,
            verdict=validation.verdict,
            reason=validation.reason,
        )
        if validation.expressible and self.pool is not None:
            self.pool.add(
                proposal,
                arm=arm,
                verdict=validation.verdict,
                source=source,
                memory_backed=memory_backed,
            )
        if validation.holds and self.pen is not None:
            self.pen.hold(
                key=proposal.id,
                hypothesis=proposal.to_dict(),
                claim_shape=proposal.claim_shape,
                needs_verifier=proposal.needs_verifier,
                at=self.clock(),
            )
            counts["held"] = counts.get("held", 0) + 1
            self.log.append(
                EVENT_HOLDING_PEN_ENTRY,
                at=self.clock(),
                arm=arm,
                proposal_id=proposal.id,
                needs_verifier=proposal.needs_verifier,
                # Carried so the pen's backlog is derivable from the log alone
                # (``world.views.holding_pen_summary``); the pen's own JSONL
                # holds the same fields, but the ledger is the only place the
                # run report reads truth from.
                claim_shape=proposal.claim_shape,
                vuln_class=proposal.vuln_class,
            )

    def _run_abduced(self, counts: dict[str, int]) -> None:
        """Close the loop: an expressible abduction becomes a real experiment.

        The flagged loose end, wired. Every expressible proposal the abducers
        produced is materialized — through the *technique's own* hook, so the
        driver never looks inside a plan — into a hypothesis and run through the
        ordinary path: the same probe grammar, the same gate, the same
        interpretation, the same independent verifier. A candidate that survives
        verification is a finding, no differently from one the first pass found;
        a candidate that does not is a lead. A surprise produced here is *not*
        re-abduced: the round is deliberately bounded to one extra pass, so the
        loop cannot spin.

        Skipped by the receipts ledger, like any other arm: an explanation whose
        experiment was already settled conclusively is not paid for twice. The
        abduced arm is keyed by the plan id, not the surface — a model that
        points at a surface the first pass already touched is asking a *different
        experiment* (`object_read:` vs `method_confusion:`), and the ledger must
        be able to tell them apart.
        """
        if self.pool is None:
            return
        from ..abduction.proposal import Proposal
        from ..kernel.plan import plan_digest

        # The ordinary pass's experiments, by content digest. A *property* that
        # merely re-proposes one of them is skipped: the ordinary pass already
        # ran it (and produced whatever it produced), so re-running would spend a
        # probe and report the same bug twice — once by the plan table, once by
        # the model. An anomaly-driven abduction is exempt: a surprise is worth
        # re-measuring.
        ordinary_digests = {
            str((row.get("hypothesis") or {}).get("plan_digest", ""))
            for row in self.log.events("note")
            if row.get("stage") == "hypothesis"
        }
        seen: set[str] = set()
        for entry in self.pool.expressible():
            registration = None
            try:
                registration = self.registry.get(entry.technique)
            except KeyError:
                registration = None
            materialize = (
                getattr(registration.technique, "hypothesis_for_proposal", None)
                if registration is not None
                else None
            )
            if registration is None or materialize is None:
                counts["abductions_unrunnable"] = counts.get("abductions_unrunnable", 0) + 1
                continue
            try:
                proposal = Proposal.from_dict(entry.proposal)
            except ValueError:
                counts["abductions_unrunnable"] = counts.get("abductions_unrunnable", 0) + 1
                continue
            if entry.source == "property":
                digest = plan_digest(entry.proposal.get("plan") or {})
                if digest in ordinary_digests:
                    counts["abductions_redundant"] = counts.get("abductions_redundant", 0) + 1
                    continue
            hypothesis = materialize(proposal)
            if hypothesis is None:
                counts["abductions_unrunnable"] = counts.get("abductions_unrunnable", 0) + 1
                continue
            plan = entry.proposal.get("plan")
            plan_id = str(plan.get("plan_id")) if isinstance(plan, dict) else ""
            arm = f"{registration.name}@{plan_id or hypothesis.surface.key}"
            if arm in seen:
                continue
            seen.add(arm)
            self.log.append(
                EVENT_NOTE,
                at=self.clock(),
                stage="hypothesis.abduced",
                arm=arm,
                proposal_id=str(entry.proposal.get("id", "")),
                witness=proposal.witness,
                rule=proposal.rule,
                claim_shape=proposal.claim_shape,
                hypothesis=hypothesis.to_dict(),
            )
            if self._already_settled(arm, f"{registration.name}:{hypothesis.id}"):
                counts["skipped_conclusive"] += 1
                continue
            counts["abductions_run"] = counts.get("abductions_run", 0) + 1
            observations, failures, executed = self._run_probes(registration, hypothesis, counts)
            candidates = list(registration.technique.interpret(hypothesis, observations))
            counts["candidates"] += len(candidates)
            self._judge(
                arm,
                f"{registration.name}:{hypothesis.id}",
                candidates,
                failures,
                counts,
                executed=executed,
            )

    def _run_probes(
        self, registration: Registration, hypothesis: Hypothesis, counts: dict[str, int]
    ) -> tuple[list[Observation], int, int]:
        """Run this hypothesis's probes in cost order.

        Returns the observations, how many probes *failed* (an error is not an
        answer, and the receipt that decides whether to try again next run depends
        on the difference), and how many probes *executed* — the receipt's own
        precondition, since an arm nothing ran against was never attempted.
        """
        specs = technique_probes(registration, hypothesis)
        counts["probes"] += len(specs)
        observations: list[Observation] = []
        failures = 0
        executed = 0
        seen_contexts: set[str] = set()
        for spec in specs:
            if spec.purpose == PURPOSE_CONFIRM:
                # The technique's own proof belongs to the verifier. Recorded rather
                # than silently dropped, so the audit shows the grammar in full and
                # where each half of it ran.
                counts["probes_for_verifier"] += 1
                self.log.append(
                    EVENT_NOTE,
                    at=self.clock(),
                    stage="probe.confirm.deferred",
                    probe=spec.id,
                    technique=registration.name,
                    reason="confirmation probes are executed by the verifier, not the driver",
                )
                continue
            gated = self._gated(spec, seen_contexts)
            if gated:
                counts["probes_gated"] += 1
                self.log.append(
                    EVENT_NOTE,
                    at=self.clock(),
                    stage="probe.gated",
                    probe=spec.id,
                    technique=registration.name,
                    reason=gated,
                    requires_context=list(spec.requires_context),
                )
                continue
            run = self._execute(registration, spec)
            if run.outcome == OUTCOME_REFUSED:
                # Not counted as run: nothing was sent, so "probes run" has to mean
                # "probes the gate cleared", or the number would overstate what an
                # engagement actually did to a target.
                counts["probes_refused"] += 1
            else:
                counts["probes_run"] += 1
                executed += 1
            if run.outcome == OUTCOME_FAILED:
                counts["probes_failed"] += 1
                failures += 1
            seen_contexts |= run.contexts
            observations.extend(run.observations)
        return observations, failures, executed

    def _gated(self, spec: ProbeSpec, seen_contexts: set[str]) -> str:
        """Why this probe must not run yet, or ``""`` when it may.

        The rule is the probe grammar's ``when``: a probe that declared a required
        context runs only on a surface where that context has been *observed*. A
        browser run is the loudest thing this engine owns, and running one without
        knowing the context would cost the most and prove the least.
        """
        if not spec.requires_context:
            return ""
        if any(context in seen_contexts for context in spec.requires_context):
            return ""
        expected = ", ".join(sorted(spec.requires_context))
        observed = ", ".join(sorted(seen_contexts)) or "nothing usable"
        return (
            f"declared context requirement not met (wants one of: {expected}; "
            f"observed: {observed})"
        )

    def _execute(self, registration: Registration, spec: ProbeSpec) -> ProbeRun:
        """Send one cleared probe through the gate and parse what came back."""
        detail = dict(spec.detail)
        sentinel = oob_sentinel(spec.id)
        if sentinel in (
            str(detail.get("url", "")) + str(detail.get("content", ""))
        ):
            # A pure technique cannot ask the OOB transport for a URL, so it emits a
            # sentinel; this is the one place it becomes real, and the allocation is
            # logged as an internal effect. The substitution covers the JSON body
            # too: a where="body" surface carries the sentinel in ``content``.
            collaborator = self.gate.allocate_oob(spec.id)
            detail["url"] = str(detail["url"]).replace(sentinel, collaborator)
            if "content" in detail:
                detail["content"] = str(detail["content"]).replace(
                    sentinel, collaborator
                )

        # ``timing_class`` is *metadata* — it labels the observation, it is not a
        # transport parameter — so it is read out of the detail here and never
        # reaches the transport's kwargs (which is where a TypeError would be the
        # symptom and the spec the cause).
        timing_class = str(detail.get("timing_class", ""))
        detail = {key: value for key, value in detail.items() if key != "timing_class"}

        request = EffectRequest(
            kind=spec.kind,
            host=spec.host,
            detail=detail,
            technique=registration.name,
            probe=spec.id,
            noise=dict(spec.noise),
        )
        outcome = self.gate.run(request)
        at = self.gate.now()
        if not outcome.executed:
            self.log.append(
                EVENT_NOTE,
                at=at,
                stage="probe.refused",
                probe=spec.id,
                technique=registration.name,
                verb=outcome.verb,
                reason=outcome.reason,
            )
            return ProbeRun(spec=spec, outcome=OUTCOME_REFUSED, verb=outcome.verb, reason=outcome.reason)

        if spec.kind == KIND_BROWSER:
            observations = browser_observations(outcome.effect, probe=spec.id, at=at)
            failed = not bool(getattr(outcome.effect, "ok", False))
            executed = any(
                item.payload.get("executed")
                for item in observations
                if item.kind == OBS_SCRIPT_EXECUTION
            )
            outcome_token = (
                OUTCOME_FAILED if failed else (OUTCOME_FOUND if executed else OUTCOME_NONE)
            )
        else:
            # A timing-differential probe names its population in the spec's
            # detail; the observation layer labels the response with it so the
            # proposer and the verifier can group the two populations apart.
            observations = http_observations(
                outcome.effect,
                probe=spec.id,
                canary=spec.canary,
                mark=spec.mark,
                at=at,
                timing_class=timing_class,
            )
            failed = not bool(getattr(outcome.effect, "ok", False))
            reflected = any(
                item.payload.get("reflected") or item.payload.get("transformed")
                for item in observations
                if item.kind == OBS_REFLECTION
            )
            outcome_token = (
                OUTCOME_FAILED if failed else (OUTCOME_FOUND if reflected else OUTCOME_NONE)
            )

        for observation in observations:
            self.log.observation(observation)
        return ProbeRun(
            spec=spec,
            outcome=outcome_token,
            verb=outcome.verb,
            reason=outcome.reason,
            observations=observations,
        )

    def _synthesize(
        self,
        arm: str,
        registration: Registration,
        hypothesis: Hypothesis,
        observations: list[Observation],
        counts: dict[str, int],
    ) -> None:
        """The synthesize junction's one extra canary, when everything lines up.

        Runs *after* the technique's own probes and interpretation, because the
        junction's input is the reflection the stock canary produced. Requires:
        an advisory wired, the technique exposing a synthesis grammar, a
        reflection observation this run actually saw, and a *validated* answer
        that does not duplicate the stock payload. The resulting spec runs
        through the ordinary ``_execute`` path — same gate, same receipt
        consequences — and any candidate it produces is recorded as a
        ``candidate.junction`` row that the verification layer refuses to
        confirm, because the model that shaped the payload must never also be
        its proof. The verifier's own confirmation, in a different class, is
        the only path to a finding — exactly as for a hand-written candidate.
        """
        advisory = self.advisory
        if advisory is None or not advisory.available:
            return
        grammar = advisory.grammar_for(registration.name)
        if grammar is None:
            return
        reflections = [
            item
            for item in observations
            if item.kind == OBS_REFLECTION and item.payload.get("reflected")
        ]
        if not reflections:
            return
        reflection = reflections[-1]
        context = str(reflection.payload.get("context") or "")
        at = self.clock()
        spec = advisory.synthesized_probe(
            registration.name,
            hypothesis,
            context,
            dict(reflection.payload),
            world=self.log,
            now=at,
        )
        if spec is None:
            return
        counts["probes"] += 1
        counts["probes_synthesized"] = counts.get("probes_synthesized", 0) + 1
        run = self._execute(registration, spec)
        if run.outcome == OUTCOME_REFUSED:
            counts["probes_refused"] += 1
            return
        counts["probes_run"] += 1
        for observation in run.observations:
            self.log.observation(observation)
        if run.outcome != OUTCOME_FOUND:
            return
        for candidate in registration.technique.interpret(hypothesis, run.observations):
            counts["candidates"] += 1
            marked = Candidate(
                **{
                    **candidate.__dict__,
                    "origin": EVENT_CANDIDATE_JUNCTION,
                }
            )
            self.log.append(
                EVENT_CANDIDATE_JUNCTION,
                at=self.clock(),
                arm=arm,
                **marked.to_dict(),
            )

    def _advisory_report(self) -> dict:
        """The advisory's health, or ``{}`` when none was wired."""
        if self.advisory is None:
            return {}
        return self.advisory.to_dict()

    # ------------------------------------------------------------------ #
    # candidates and verdicts
    # ------------------------------------------------------------------ #

    def _judge(
        self,
        arm: str,
        operation: str,
        candidates: list[Candidate],
        failures: int,
        counts: dict[str, int],
        *,
        executed: int = 0,
    ) -> None:
        """Record the candidates, verify each one, and file the receipt.

        The receipt is filed only when a probe actually executed. An arm whose
        every probe was refused (or gated) was never attempted — recording an
        attempt for it would be the receipt inventing knowledge, the same mistake
        as treating an error as an answer, and it would let the ledger claim the
        target was examined when the gate never let anything through.

        ``operation`` is hypothesis-scoped (``technique:hypothesis id``): the
        ledger's settle rule must be as wide as the question asked, never wider —
        a sibling hypothesis on the same surface is a different experiment, and
        skipping it on its neighbour's answer is the starvation the surface-level
        arm used to allow.
        """
        outcome = OUTCOME_NONE
        for candidate in candidates:
            self.log.append(
                EVENT_CANDIDATE,
                at=self.clock(),
                arm=arm,
                **candidate.to_dict(),
            )
            verdict = self.verification.verify(candidate)
            self._record_verdict(arm, verdict, counts)
            if verdict.proven:
                outcome = OUTCOME_FOUND
        if not candidates and failures:
            # No candidate *and* a probe that errored: the hypothesis was not
            # tested, it was interrupted.  ``failed`` is the only honest outcome,
            # and it is the inconclusive one — the next run tries again.
            outcome = OUTCOME_FAILED
        if executed == 0 and not candidates:
            self.log.append(
                EVENT_NOTE,
                at=self.clock(),
                stage="receipt.skipped",
                arm=arm,
                reason=(
                    "no probe was executed (every one refused or gated); no attempt "
                    "to file — the ledger records attempts, not refusals"
                ),
            )
            return
        self._file_receipt(arm, operation, outcome)

    def _record_verdict(self, arm: str, verdict: Verdict, counts: dict[str, int]) -> None:
        self.log.append(EVENT_VERDICT, at=self.clock(), arm=arm, **verdict.to_dict())
        if verdict.proven:
            counts["findings"] += 1
            if verdict.grade not in FINDING_GRADES:  # pragma: no cover - guarded by the verdict
                raise ValueError(
                    f"a proven verdict rests on {verdict.grade!r}, which cannot support "
                    "a finding"
                )
        else:
            counts["leads"] += 1

    # ------------------------------------------------------------------ #
    # receipts
    # ------------------------------------------------------------------ #

    def _already_settled(self, arm: str, operation: str) -> bool:
        """True when a *conclusive* attempt is already on file for this arm."""
        if self.receipt is None or self.force:
            return False
        if self.receipt.attempted(arm, operation):
            self.log.append(
                EVENT_NOTE,
                at=self.clock(),
                stage="arm.skipped",
                arm=arm,
                reason="a conclusive attempt is already on file (receipt)",
            )
            return True
        return False

    def _file_receipt(self, arm: str, operation: str, outcome: str) -> None:
        """Write the attempt to the receipts ledger and to the log."""
        self.log.append(
            EVENT_RECEIPT,
            at=self.clock(),
            arm=arm,
            technique=operation,
            outcome=outcome,
            conclusive=outcome != OUTCOME_FAILED,
        )
        if self.receipt is not None:
            self.receipt.record(arm, operation, outcome=outcome, at=self.clock())


def technique_probes(registration: Registration, hypothesis: Hypothesis) -> list[ProbeSpec]:
    """Every probe for one hypothesis, in the order the driver should try them.

    Cheap before loud: requests first, then browsers. Within a kind, sorted by id,
    so two runs over the same hypothesis send the same probes in the same order and
    a diff of two logs is readable. Confirmation probes are included here — this is
    the grammar in full — and the driver is what skips them.

    The Phase 3 synthesis junction is deliberately *not* part of this function:
    its input is the reflection the stock canary produces, so it can only run
    after these probes — see :meth:`Engine._synthesize`.
    """
    specs = list(registration.technique.probes(hypothesis))
    return sorted(
        specs,
        key=lambda spec: (0 if spec.kind == KIND_HTTP else 1, spec.id),
    )


def _wall_clock() -> float:
    import time

    return time.time()


__all__ = [
    "EVENT_CANDIDATE_JUNCTION",
    "Engine",
    "OUTCOME_FAILED",
    "OUTCOME_FOUND",
    "OUTCOME_GATED",
    "OUTCOME_NONE",
    "OUTCOME_REFUSED",
    "ProbeRun",
    "RunReport",
    "technique_probes",
]
