"""The campaign: rounds of UCB-driven selection over the Phase 1 engine.

Phase 1's :class:`~service.vuln_engine.scheduler.driver.Engine` proved *one*
deterministic pass — enumerate, gate, observe, verify, record. Phase 2 adds the
question an operator with a real budget asks: **which arm deserves the next round?**
The campaign answers it with the selector in :mod:`.ucb`, fed by the receipts
ledger the Phase 1 driver already files.

What the campaign owns, and what it deliberately leaves alone:

* **rounds** — one round is one arm's technique × surface executed through the
  ordinary Phase 1 ``Engine`` (fresh engine, same ledger, same gate). The Engine
  is untouched: the chokepoint, the receipts rule and the world log keep their
  Phase 1 semantics, and a campaign that runs one round is exactly a Phase 1 run;
* **the decision** — :meth:`ucb.pick` is pure, so the campaign only appends the
  pick and its reason to the world log (``scheduler.pick`` rows). Recomputing the
  picks from the log must reproduce the round order offline; that is a test, not
  a hope;
* **the budget** — a declared round count or a wall-clock window (§2.5's
  hours-to-weeks, not minutes). A round in which nothing executed (every probe
  refused, the receipt rule) costs *no* budget: the gate said no, not the target.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from ..kernel.manifest import TechniqueManifest
from ..kernel.technique import EngagementSeed
from ..policy.gate import PolicyGate
from ..registry import TechniqueRegistry
from ..world.log import EVENT_NOTE, WorldLog, read_rows
from .driver import Engine, RunReport
from .ucb import Arm, arms_from_receipts, pick

if TYPE_CHECKING:
    from ..llm.wiring import Advisory


@dataclass
class CampaignReport:
    """What a campaign did, as plain data the caller embeds."""

    target: str
    rounds_planned: int
    rounds_run: int = 0
    #: One entry per round: the pick, its reason, and the round's own counts.
    rounds: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    leads: int = 0
    #: Round indices that were refused or conclusive — no budget spent on refusals.
    free_rounds: list[int] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    #: The hypothesize junction's provenance, when the operator widened this
    #: campaign's seed with ``--hypothesize-from-recon``. Recorded here (and
    #: logged once as a ``campaign.widening`` row) so a report can say which
    #: arms exist *because* the model proposed them — the round rows carry the
    #: surface keys; this carries the why. ``None`` means a plain operator seed.
    widening: dict | None = None

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "rounds_planned": self.rounds_planned,
            "rounds_run": self.rounds_run,
            "rounds": self.rounds,
            "findings": self.findings,
            "leads": self.leads,
            "free_rounds": self.free_rounds,
            "problems": self.problems,
            "widening": self.widening,
        }


@dataclass(frozen=True)
class Budget:
    """The engagement budget: §2.5's hours-to-weeks, expressed two ways.

    Either bound stops the campaign; both may be set. ``rounds`` bounds wall-clock
    attempts, ``window_seconds`` bounds the clock — the campaign checks the
    window *before* starting a round, never mid-round, because interrupting a
    round would leave an arm attempted-but-unrecorded.
    """

    rounds: int = 1
    window_seconds: float | None = None
    started_at: float = 0.0

    def expired(self, now: float) -> bool:
        if self.window_seconds is not None and now - self.started_at >= self.window_seconds:
            return True
        return False

    @property
    def rounds_left(self) -> int:
        return self.rounds


class Campaign:
    """Run rounds until the budget is spent, each round on the best-ranked arm.

    One campaign = one target, one declared seed, one receipts ledger, one world
    log — and one arm per round. The ledger is the campaign's memory: arms the
    ledger says were conclusively settled are skipped by the Phase 1 engine's own
    receipt rule, and the selector's history comes from the same rows, so the two
    can never disagree.
    """

    def __init__(
        self,
        seed: EngagementSeed,
        *,
        gate: PolicyGate,
        registry: TechniqueRegistry | None = None,
        log: WorldLog | None = None,
        receipt: object | None = None,
        clock: Callable[[], float] | None = None,
        advisory: "Advisory | None" = None,
        force: bool = False,
        widening: dict | None = None,
    ) -> None:
        self.seed = seed
        self.gate = gate
        self.registry = registry or TechniqueRegistry.discover()
        self.log = log if log is not None else gate.log
        self.receipt = receipt
        self.clock = clock or _wall_clock
        #: The hypothesize junction's provenance (``HypothesizeResult.to_dict()``
        #: shape) or ``None``. Accepted as plain data on purpose: the campaign
        #: records what it was told, it does not import the llm layer — the same
        #: TYPE_CHECKING discipline the advisory itself follows.
        #: Ignore the receipts ledger when picking arms (an operator's flag, and
        #: the only way to re-ask a question whose answer is stale). Each round's
        #: engine still gets the flag too, so previously-settled arms re-probe.
        self.force = force
        #: Phase 3's advisory junctions, or ``None``. When wired and available,
        #: the rank junction supplies each technique's prior *once, before round
        #: 1* — after that the receipts ledger is the ranking signal, and the
        #: model's static opinion cools exactly the way UCB cools everything.
        self.advisory = advisory
        self.widening = widening
        self._priors: dict[str, float] | None = None

    def run(self, budget: Budget) -> CampaignReport:
        """Spend the budget one arm at a time, logging every pick with its reason.

        Two rules keep the budget honest:

        * **settled arms are not re-picked** — an arm whose ledger shows a
          conclusive outcome (``found`` or ``none``) cannot produce new
          information without ``force``, so it is excluded before the pick. When
          nothing unsettled remains, the campaign stops early and says so;
        * **a refused round is free** — the gate's refusal means nothing reached
          the target, so the round does not consume budget (§2.5: the budget
          measures *visibility spent*, and a refused probe spends none). The
          refused arm is excluded for the rest of the campaign, and a hard
          iteration cap stops a refuse-loop from spinning forever.
        """
        report = CampaignReport(target=self.seed.target, rounds_planned=budget.rounds)
        report.widening = dict(self.widening) if self.widening else None
        # The provenance is a campaign fact, so it is logged once, before the
        # first pick: a replay reads it back from the log rather than trusting
        # the report's say-so. ``stage=campaign.widening`` rides the ordinary
        # note row — no new row type, no new reader — and carries the junction's
        # own fields verbatim (source, added, surfaces) for the report to embed.
        if report.widening:
            self.log.append(
                EVENT_NOTE,
                at=self.clock(),
                stage="campaign.widening",
                **report.widening,
            )
        started = self.clock()
        budget = Budget(
            rounds=budget.rounds,
            window_seconds=budget.window_seconds,
            started_at=started,
        )
        excluded: set[str] = set()
        iterations = 0
        max_iterations = budget.rounds * 3 + 5
        while report.rounds_run < budget.rounds:
            if budget.expired(self.clock()):
                break
            iterations += 1
            if iterations > max_iterations:  # pragma: no cover - guard rail
                report.problems.append("iteration cap hit; stopping as a guard")
                break
            pick_row = self._pick_arm(excluded=excluded)
            if pick_row is None:
                report.problems.append(
                    "no unsettled eligible arm remains; stopping early"
                )
                break
            round_index = len(report.rounds)
            arm, reason = pick_row
            round_report = self._run_round(arm)
            report.rounds.append(
                {
                    "round": round_index,
                    "arm": arm.to_dict(),
                    "reason": reason,
                    "findings": round_report.counts.get("findings", 0),
                    "leads": round_report.counts.get("leads", 0),
                    "probes_run": round_report.counts.get("probes_run", 0),
                    "probes_refused": round_report.counts.get("probes_refused", 0),
                }
            )
            report.findings.extend(round_report.findings)
            report.leads += round_report.counts.get("leads", 0)
            if round_report.counts.get("probes_run", 0) == 0:
                # Nothing executed: the gate refused every probe (a receipt skip
                # cannot happen — settled arms were excluded before the pick).
                # The target was not touched: free round, arm excluded.
                report.free_rounds.append(round_index)
                excluded.add(arm.surface)
                continue
            report.rounds_run += 1
            # One conclusive round per arm per campaign, even under ``force``:
            # force means "ignore what the ledger already knew", not "re-prove
            # the same bug every round". Without the ledger's settled-arm rule
            # (which force suspends), this exclusion is what keeps a forced
            # campaign from spending every round on the arm that finds first.
            excluded.add(arm.surface)
        return report

    # ------------------------------------------------------------------ #
    # one round
    # ------------------------------------------------------------------ #

    def _pick_arm(self, *, excluded: set[str] | None = None) -> tuple[Arm, str] | None:
        """Rank the unsettled arms and return the winner with its reason.

        Excluded arms (already settled in the ledger, or refused earlier in this
        campaign) are filtered *before* the pick, not after: a selector that
        picked a settled arm and then discarded the pick would log a decision the
        campaign never intended to honour.
        """
        noise = {
            registration.manifest.name: registration.manifest.noise
            for registration in self.registry.all()
        }
        receipts = _receipts_by_arm_from_ledger(self.log)
        priors = self._advisory_priors()
        # Eligibility from the techniques themselves, exactly as the driver reads
        # it — one authority, so the scheduler can never send a technique where
        # the technique itself would refuse to go.
        eligible = {
            registration.name: [
                surface.key for surface in registration.technique.surfaces(self.seed)
            ]
            for registration in self.registry.all()
        }
        arms = [
            arm
            for arm in arms_from_receipts(eligible, receipts, priors=priors)
            if arm.surface not in (excluded or set())
            and (self.force or not _settled(receipts.get(arm.surface, {})))
        ]
        outcome = pick(arms, noise=noise)
        if outcome is None:
            return None
        self.log.append(
            "scheduler.pick",
            at=self.clock(),
            technique=outcome.arm.technique,
            surface=outcome.arm.surface,
            score=(
                outcome.score if outcome.score != float("inf") else "untried"
            ),
            reason=outcome.reason,
            arm=outcome.arm.to_dict(),
        )
        return outcome.arm, outcome.reason

    def _advisory_priors(self) -> dict[str, float]:
        """The rank junction's priors, asked once per campaign, or ``{}``.

        Once asked (live or cached), the result is memoised for the campaign's
        lifetime: one opinion per engagement, by design — after round 1 the
        receipts ledger is the ranking signal and the model's static prior is
        noise next to measured history. With no advisory, no key, or a degraded
        opinion, this is ``{}`` and the selector runs exactly as Phase 2 ran it.
        """
        if self.advisory is None or not self.advisory.available:
            return {}
        if self._priors is None:
            self._priors = self.advisory.priors(
                self.seed,
                self.registry,
                log_handle=self.log,
                now=self.clock(),
            )
        return self._priors

    def _run_round(self, arm: Arm) -> RunReport:
        """One arm's technique × surface through the ordinary Phase 1 engine."""
        technique = next(
            (
                registration.technique
                for registration in self.registry.all()
                if registration.name == arm.technique
            ),
            None,
        )
        if technique is None:  # pragma: no cover - the pick came from this registry
            raise ValueError(f"picked {arm.technique!r}, which is not registered")
        restricted = TechniqueRegistry(
            [
                registration
                for registration in self.registry.all()
                if registration.name == arm.technique
            ]
        )
        engine = Engine(
            self.seed,
            gate=self.gate,
            registry=restricted,
            log=self.log,
            receipt=self.receipt,
            clock=self.clock,
            force=self.force,
            advisory=self.advisory,
        )
        return engine.run()


def _receipts_by_arm_from_ledger(log: WorldLog) -> dict[str, dict[str, int]]:
    """``{arm: {outcome: count}}`` from ``receipt`` rows in *log*.

    Reads the world log rather than the ``Receipt`` object on purpose: the log is
    the one record a replay has, so the selector's history must be recoverable
    from it for the round order to be reproducible offline.
    """
    summary: dict[str, dict[str, int]] = {}
    for row in log.events("receipt"):
        arm = str(row.get("arm", ""))
        outcome = str(row.get("outcome", ""))
        bucket = summary.setdefault(arm, {})
        bucket[outcome] = bucket.get(outcome, 0) + 1
    return summary


def _settled(outcomes: dict[str, int]) -> bool:
    """True when the ledger holds a conclusive answer for this arm.

    ``platform.receipt``'s vocabulary unchanged: ``found`` and ``none`` are
    conclusive, ``failed`` is not — an arm that errored stays eligible so an
    outage cannot become a permanent gap.
    """
    return bool(outcomes.get("found", 0) or outcomes.get("none", 0))


def replay_round_order(log_path: Path | str) -> list[dict]:
    """The pick rows of a logged campaign, in order — no engine, no network.

    The offline check: recomputing nothing, just reading, because the picks were
    logged with their reasons when they were made. A caller that wants to *verify*
    the order re-runs :meth:`ucb.pick` over the receipts visible before each pick;
    the test suite does exactly that.
    """
    rows = read_rows(log_path)
    return [row for row in rows if row.get("type") == "scheduler.pick"]


def _wall_clock() -> float:
    return time.time()


__all__ = [
    "Budget",
    "Campaign",
    "CampaignReport",
    "replay_round_order",
]
