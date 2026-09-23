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

from collections.abc import Callable
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
from ..policy.gate import EffectRequest, PolicyGate
from ..registry import Registration, TechniqueRegistry
from ..verification import VerificationLayer
from ..world import views
from ..world.log import (
    EVENT_BEGIN,
    EVENT_CANDIDATE,
    EVENT_CANDIDATE_JUNCTION,
    EVENT_END,
    EVENT_NOTE,
    EVENT_RECEIPT,
    EVENT_VERDICT,
    WorldLog,
)
from ..world.observe import browser_observations, http_observations

if TYPE_CHECKING:
    from ..llm.wiring import Advisory

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

        for registration in self.registry.all():
            for surface in registration.technique.surfaces(self.seed):
                self._run_surface(registration, surface, counts)

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
            leads=[str(row.get("id", "")) for row in views.leads(this_run)],
            report_lines=views.report_lines(this_run),
            capabilities=self.gate.capabilities(),
            problems=self.registry.problems,
            advisory=self._advisory_report(),
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
            arm = f"{registration.name}@{surface.key}"
            self.log.append(
                EVENT_NOTE,
                at=self.clock(),
                stage="hypothesis",
                arm=arm,
                hypothesis=hypothesis.to_dict(),
            )
            if self._already_settled(arm, registration.name):
                counts["skipped_conclusive"] += 1
                continue
            observations, failures, executed = self._run_probes(registration, hypothesis, counts)
            candidates = list(technique.interpret(hypothesis, observations))
            counts["candidates"] += len(candidates)
            self._judge(arm, registration.name, candidates, failures, counts, executed=executed)
            self._synthesize(arm, registration, hypothesis, observations, counts)

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
        if sentinel in str(detail.get("url", "")):
            # A pure technique cannot ask the OOB transport for a URL, so it emits a
            # sentinel; this is the one place it becomes real, and the allocation is
            # logged as an internal effect.
            collaborator = self.gate.allocate_oob(spec.id)
            detail["url"] = str(detail["url"]).replace(sentinel, collaborator)

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
