"""The platform runner: discover → build context → run → score → report.

One code path runs every pipeline, which is what makes "add a folder, get a
pipeline" true end to end — the runner does not know the pipeline names.

Sequence for one run:

1. **discover** — :meth:`Registry.discover` finds qualifying pipeline folders;
2. **platform services** — scope engine (from declared scope + discovered
   networks), scoring, cache, queue, enrichment, graph sink, dispatcher; every
   one degrades gracefully and its health lands in the run record;
3. **order** — pipelines sorted by their declared ``consumes``;
4. **run** — each pipeline's declared stages execute through its
   :class:`~platform.contract.RunContext`, timed, with failures recorded
   per-stage (one stage failing does not stop the run);
5. **persist** — the stage reports, the run record (S14) and the combined
   summary are written under ``runs/<target>/<stamp>/``;
6. **report** — the same summary the CLI prints, machine-readable.

The runner owns no asset logic and never parses pipeline artifacts — that is
each pipeline's job.  It knows only the contract.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import shared.colorlog as colorlog

from . import observability
from .common.io import write_json
from .contract import RunContext
from .convergence import ConvergenceDriver, Ledger, Round, StopPolicy, token_kind
from .dispatch import DispatchPolicy, Dispatcher
from .graph.ingest import GraphSink
from .programs import ProgramScope
from .registry import Registry
from .scope import ScopeEngine

log = logging.getLogger("platform.runner")

RUNS_DIRNAME = "runs"
SUMMARY_FILE = "summary.json"
#: The convergence loop's two artifacts, written inside the run directory.
CONVERGENCE_FILE = "convergence.json"
LEDGER_FILE = "frontier_ledger.jsonl"


@dataclass
class StageOutcome:
    pipeline: str
    stage: str
    ok: bool
    seconds: float
    report: dict = field(default_factory=dict)
    error: str = ""

    def to_dict(self) -> dict:
        payload = {
            "pipeline": self.pipeline,
            "stage": self.stage,
            "ok": self.ok,
            "seconds": round(self.seconds, 2),
            **({"error": self.error} if self.error else {}),
        }
        if self.report:
            counts = self.report.get("counts")
            if isinstance(counts, dict):
                payload["counts"] = counts
        return payload


@dataclass
class RunResult:
    """Everything one platform run produced."""

    target: str
    started_at: str
    finished_at: str = ""
    seconds: float = 0.0
    ok: bool = True
    outcomes: list[StageOutcome] = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    run_dir: Path | None = None
    #: Pipelines selected for this run (all discovered when None was passed).
    pipelines_run: list[str] = field(default_factory=list)
    #: Snapshot of the scope engine after construction.
    scope_summary: dict = field(default_factory=dict)
    #: Which platform services degraded, with reasons.
    degradations: dict = field(default_factory=dict)
    #: The convergence report (rounds, verdict, ledger) — empty for a one-round
    #: run, which is what a run without ``StopPolicy`` still is.
    convergence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "seconds": round(self.seconds, 2),
            "ok": self.ok,
            "stages": [outcome.to_dict() for outcome in self.outcomes],
            **self.summary,
        }


class Runner:
    """The orchestrator.  ``run()`` is the whole show."""

    def __init__(
        self,
        registry: Registry | None = None,
        *,
        output_root: Path | str | None = None,
        policy: DispatchPolicy | None = None,
    ) -> None:
        self._registry = registry or Registry.discover()
        self._output_root = Path(output_root) if output_root else None
        self._policy = policy
        #: The shared ``runs/`` root, set by :meth:`run`; the run registry is
        #: written there (one timeline across runs), not inside a stamped dir.
        self._runs_root: Path | None = None

    @property
    def registry(self) -> Registry:
        return self._registry

    # ------------------------------------------------------------------ #
    # context construction (the platform services)
    # ------------------------------------------------------------------ #

    def build_context(
        self,
        target: str,
        *,
        env_prefix: str = "",
        output_dir: Path | None = None,
        options: dict[str, str] | None = None,
        program_scope: "ProgramScope | None" = None,
    ) -> tuple[RunContext, list]:
        """Assemble the platform services into a RunContext.

        Returns ``(context, services)`` so the caller can read health from the
        services afterwards without the pipelines seeing them mutate.

        With *program_scope*, the program's declared assets are applied to the
        scope engine on top of the target domain (S4's recon half): the run's
        declared scope is what the program says it is, not just the apex. The
        application block lands on ``context.program`` for the report, and a
        PSH-format scope file is written beside the run's artifacts for the
        port stage.
        """
        from .cache import HotCache
        from .enrich import LLMEnricher
        from .programs import apply_program_scope, write_psh_scope_file
        from .queueing import Queue

        services: list = []
        scope_engine = ScopeEngine.from_domain(target)
        program_block: dict | None = None
        if program_scope is not None:
            application = apply_program_scope(scope_engine, program_scope)
            program_block = application.to_dict()
            if output_dir is not None:
                program_block["scope_file"] = write_psh_scope_file(
                    program_scope, output_dir / "program_scope.txt"
                ).as_posix()
        scoring_mod = __import__("service.recon_pipeline.platform.scoring", fromlist=["score"])
        cache = HotCache()
        queue = Queue(
            spool_path=(output_dir / "queue_spool.jsonl") if output_dir else None
        )
        enricher = LLMEnricher()
        graph = GraphSink(
            journal_path=(output_dir / "graph_journal.jsonl") if output_dir else None,
        )
        dispatcher = Dispatcher(scope_engine, policy=self._policy)
        services = [scope_engine, cache, queue, enricher, graph, dispatcher]

        context = RunContext(
            target=target,
            scope=scope_engine,
            scoring=scoring_mod,
            cache=cache,
            graph=graph,
            dispatcher=dispatcher,
            enricher=enricher,
            queue=queue,
            env_prefix=env_prefix,
            options=dict(options or {}),
            output_dir=output_dir,
            program=program_block,
        )
        return context, services

    # ------------------------------------------------------------------ #
    # the run
    # ------------------------------------------------------------------ #

    def run(
        self,
        target: str,
        *,
        pipelines: list[str] | None = None,
        stages: list[str] | None = None,
        options: dict[str, str] | None = None,
        convergence: StopPolicy | None = None,
        program_scope: "ProgramScope | None" = None,
    ) -> RunResult:
        """Run the selected pipelines (default: all discovered) against *target*.

        Without ``convergence`` this is one round of every selected pipeline's
        declared stages — unchanged behaviour.  With it, the run loops: round 1 is
        that same pass, and every later round re-runs only the stages a pipeline
        declared as ``repeat_stages``, until
        :func:`platform.convergence.decide` stops the loop and names the reason
        (see :mod:`platform.convergence` for why only some stages may repeat).
        """
        started_wall = datetime.now(timezone.utc)
        started = time.monotonic()

        selected = pipelines or self._registry.names()
        ordered = self._registry.ordered(selected)

        stamp = started_wall.strftime("%Y%m%d_%H%M%S")
        runs_root = (self._output_root or Path.cwd() / "output") / RUNS_DIRNAME
        run_dir = runs_root / target / stamp
        run_dir.mkdir(parents=True, exist_ok=True)
        self._runs_root = runs_root

        result = RunResult(
            target=target,
            started_at=started_wall.isoformat(timespec="seconds"),
            pipelines_run=list(selected),
        )

        context, services = self.build_context(
            target, output_dir=run_dir, options=options, program_scope=program_scope
        )
        scope_engine, cache, queue, enricher, graph, dispatcher = services

        if convergence is None:
            result.outcomes = self._run_round(
                ordered, self._stage_map(ordered, stages), context, run_dir
            )
        else:
            result.outcomes, result.convergence = self._run_converged(
                ordered, stages, context, run_dir, dispatcher, convergence, target
            )
        result.ok = all(outcome.ok for outcome in result.outcomes)

        result.seconds = time.monotonic() - started
        result.finished_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        result.scope_summary = dict(scope_engine.summary())
        result.degradations = dict(
            observability.degradation_summary(
                cache=cache, queue=queue, enricher=enricher, graph=graph
            )
        )
        result.summary = self._summarise(result, dispatcher, queue, cache, graph, enricher)
        if context.program:
            result.summary["program"] = dict(context.program)
        result.run_dir = run_dir

        self._write_reports(result)
        return result

    # ------------------------------------------------------------------ #
    # rounds
    # ------------------------------------------------------------------ #

    def _stage_map(
        self, ordered: list, stages: list[str] | None
    ) -> dict[str, list[str]]:
        """Which stages each pipeline should run, honouring an operator's list."""
        return {
            registration.name: list(stages or registration.manifest.stage_names())
            for registration in ordered
        }

    def _run_round(
        self,
        selection: list,
        stage_map: dict[str, list[str]],
        context: RunContext,
        run_dir: Path,
        round_index: int | None = None,
    ) -> list[StageOutcome]:
        """Execute one round's selected stages, in registry order."""
        outcomes: list[StageOutcome] = []
        for registration in selection:
            manifest = registration.manifest
            # A round boundary is a pass boundary.  A pipeline that caches the
            # first stage's intermediate work for the second (graph_normalize's
            # collected facts, asn_cidr's already-produced artifacts) must forget
            # it here, or round 2 would re-emit round 1's output and look
            # convergent purely because it was stale.
            reset = getattr(registration.pipeline, "reset", None)
            if callable(reset):
                reset()
            for stage_name in stage_map.get(registration.name, []):
                if stage_name not in manifest.stage_names():
                    log.warning(
                        "%s: no stage %r (declared: %s)",
                        manifest.name,
                        stage_name,
                        ", ".join(manifest.stage_names()),
                    )
                    continue
                outcomes.append(
                    self._run_stage(
                        registration, stage_name, context, run_dir, round_index
                    )
                )
        return outcomes

    def _run_converged(
        self,
        ordered: list,
        stages: list[str] | None,
        context: RunContext,
        run_dir: Path,
        dispatcher,
        policy: StopPolicy,
        target: str,
    ) -> tuple[list[StageOutcome], dict]:
        """Loop rounds until the frontier stops growing, or a limit says stop."""
        driver = ConvergenceDriver(
            policy=policy,
            ledger=Ledger(run_dir / LEDGER_FILE),
            frontier_paths=self._frontier_paths(ordered),
            log_round=lambda message: colorlog.log.info(f"[convergence] {message}"),
        )
        collected: list[StageOutcome] = []

        def round_fn(index: int, found: frozenset[str]) -> Round:
            skipped: list[str] = []
            if index == 1:
                selection = ordered
                stage_map = self._stage_map(ordered, stages)
            else:
                # Only the stages a pipeline declared as repeatable: re-running an
                # apex-wide archive query or a seed-keyed registry lookup would ask
                # a question whose answer cannot have changed.
                kinds = {token_kind(token) for token in found}
                repeatable = [reg for reg in ordered if reg.manifest.repeatable]
                selection = [reg for reg in repeatable if reg.manifest.wanted_by(kinds)]
                # ...and only when the previous round put something on the table
                # that this pipeline can act on.  A round in which no new address
                # appeared spends no port-scan packets and no registry queries.
                skipped = [reg.name for reg in repeatable if reg not in selection]
                stage_map = {
                    reg.name: list(reg.manifest.repeat_stages) for reg in selection
                }
            # A gated round is not the same as a pipeline that declares no repeat
            # stages: the first has converged, the second never had a loop.
            gated = bool(skipped)
            before = self._active_actions(dispatcher)
            started = time.monotonic()
            outcomes = self._run_round(selection, stage_map, context, run_dir, index)
            collected.extend(outcomes)
            blocked, why = self._quarantine_blocked(selection)
            failed = [outcome for outcome in outcomes if not outcome.ok]
            notes = [why] if why else []
            if skipped:
                found_kinds = sorted({token_kind(token) for token in found})
                notes.append(
                    f"skipped {'/'.join(skipped)}: nothing new of kind "
                    f"{'/'.join(found_kinds) if found_kinds else 'any'} to spend on"
                )
            return Round(
                index=index,
                seconds=time.monotonic() - started,
                stages_run=len(outcomes),
                stages_failed=len(failed),
                gated=gated,
                active_actions=self._active_actions(dispatcher) - before,
                # A *partial* failure is a degradation of this round's coverage;
                # a total failure is its own stop reason.  A missing Redis or
                # Neo4j is not counted here on purpose: the collectors are
                # file-based, so a degraded service is not a degraded look at the
                # target, and treating it as one would hedge every exhaustion
                # verdict this tree produces.
                degraded=bool(failed) and len(failed) < len(outcomes),
                blocked=blocked,
                stages=[f"{outcome.pipeline}:{outcome.stage}" for outcome in outcomes],
                notes=notes,
            )

        report = driver.run(round_fn, target=target)
        payload = report.to_dict()
        write_json(run_dir / CONVERGENCE_FILE, payload)
        return collected, payload

    def _frontier_paths(self, ordered: list) -> list[Path]:
        """Absolute paths of every declared frontier artifact, in registry order."""
        paths: list[Path] = []
        for registration in ordered:
            source = getattr(registration.module, "__file__", "") or ""
            if not source:
                continue
            folder = Path(source).resolve().parent
            paths.extend(
                folder / relative
                for relative in registration.manifest.frontier_artifacts
            )
        return paths

    @staticmethod
    def _active_actions(dispatcher) -> int:
        """How many active actions the gate has allowed so far this run."""
        try:
            return int(dispatcher.summary().get("run_actions") or 0)
        except Exception:
            return 0

    def _quarantine_blocked(self, selection: list) -> tuple[bool, str]:
        """Did the stealth layer block or challenge us during this round?

        A quarantine store is the one place a block outlives the stage that
        suffered it, which is why the loop reads the stores rather than trying to
        infer a block from a stage's return value.  Every store the round's
        pipelines keep is consulted: unless ``STEALTH_QUARANTINE_FILE`` points
        them at one shared file, each active stage writes its own under its
        ``output/`` directory, and checking only the shared setting would report
        "never blocked" on the default configuration.  Best-effort by design: an
        unreadable store is not a block, and failing to check must not end a run.
        """
        try:
            from .stealth import settings as stealth_settings
            from .stealth.quarantine import blocked_state

            paths: list[Path] = []
            if stealth_settings.QUARANTINE_FILE:
                paths.append(Path(stealth_settings.QUARANTINE_FILE))
            for registration in selection:
                source = getattr(registration.module, "__file__", "") or ""
                if not source:
                    continue
                paths.extend(
                    sorted(Path(source).resolve().parent.glob("**/output/quarantine.json"))
                )
            return blocked_state(paths)
        except Exception as exc:
            log.debug("quarantine check skipped: %s", exc)
            return False, ""

    def _run_stage(
        self,
        registration,
        stage_name: str,
        context: RunContext,
        run_dir: Path,
        round_index: int | None = None,
    ) -> StageOutcome:
        manifest = registration.manifest
        started = time.monotonic()
        colorlog.log.info(f"[{manifest.name}] === {stage_name} stage ===")
        try:
            report = registration.pipeline.run(stage_name, context) or {}
            outcome = StageOutcome(
                pipeline=manifest.name,
                stage=stage_name,
                ok=bool(report.get("ok", True)),
                seconds=time.monotonic() - started,
                report=report,
            )
            if not outcome.ok:
                colorlog.log.warn(f"[{manifest.name}] {stage_name} completed with failures")
            else:
                colorlog.log.success(
                    f"[{manifest.name}] {stage_name} finished in {outcome.seconds:.1f}s"
                )
        except Exception as exc:
            outcome = StageOutcome(
                pipeline=manifest.name,
                stage=stage_name,
                ok=False,
                seconds=time.monotonic() - started,
                error=f"{type(exc).__name__}: {exc}",
            )
            colorlog.log.failed(
                f"[{manifest.name}] {stage_name} failed: {outcome.error}"
            )
        self._write_stage_report(outcome, run_dir, round_index)
        return outcome

    def _write_stage_report(
        self, outcome: StageOutcome, run_dir: Path, round_index: int | None = None
    ) -> None:
        """Snapshot one stage's report under ``runs/<target>/<stamp>/stages/``.

        The pipeline's own artifacts live in its own output directories; this
        is the platform's copy of the machine report, so a run directory is a
        complete record of what happened without reading any pipeline code.
        """
        import json

        base = run_dir / "stages"
        if round_index:
            # Round-scoped: one stage report per round, never overwritten, so the
            # run directory shows what round 3 actually did to round 1's surface.
            base = base / f"round-{round_index}"
        stage_dir = base / outcome.pipeline
        try:
            stage_dir.mkdir(parents=True, exist_ok=True)
            payload: dict = {
                "pipeline": outcome.pipeline,
                "stage": outcome.stage,
                "ok": outcome.ok,
                "seconds": round(outcome.seconds, 2),
            }
            if outcome.error:
                payload["error"] = outcome.error
            if outcome.report:
                payload["report"] = outcome.report
            (stage_dir / f"{outcome.stage}.json").write_text(
                json.dumps(payload, indent=2, sort_keys=False),
                encoding="utf-8",
                newline="\n",
            )
        except OSError as exc:
            log.warning("stage report write failed: %s", exc)

    def _summarise(self, result: "RunResult", dispatcher, queue, cache, graph, enricher) -> dict:
        summary = {
            "counts": {
                "stages_run": len(result.outcomes),
                "stages_ok": sum(1 for o in result.outcomes if o.ok),
                "stages_failed": sum(1 for o in result.outcomes if not o.ok),
            },
            "gate": observability.gate_metrics(dispatcher),
            "queue": queue.health.to_dict(),
            "graph": graph.health.to_dict(),
            "cache": cache.health.to_dict(),
            "enrichment": enricher.health.to_dict(),
            "pipelines_run": list(result.pipelines_run),
            "scope": dict(result.scope_summary),
        }
        if result.convergence:
            # Only a converged run carries this, so a one-round run's summary is
            # exactly what it always was.
            summary["convergence"] = result.convergence
        return summary

    def _write_reports(self, result: RunResult) -> None:
        import json

        if result.run_dir is None:
            return
        summary_path = result.run_dir / SUMMARY_FILE
        try:
            summary_path.write_text(
                json.dumps(result.to_dict(), indent=2, sort_keys=False),
                encoding="utf-8",
                newline="\n",
            )
        except OSError as exc:
            log.warning("summary write failed: %s", exc)

        # Run registry (S14): one row per run, best-effort.
        record = observability.RunRecord(
            target=result.target,
            started_at=result.started_at,
            finished_at=result.finished_at,
            seconds=result.seconds,
            ok=result.ok,
            pipelines=result.summary.get("pipelines_run", []),
            stages=[
                observability.StageMetric(
                    pipeline=outcome.pipeline,
                    stage=outcome.stage,
                    seconds=outcome.seconds,
                    ok=outcome.ok,
                    counts=outcome.report.get("counts", {}) if isinstance(outcome.report, dict) else {},
                    error=outcome.error,
                )
                for outcome in result.outcomes
            ],
            degradations=result.summary.get("graph", {}),
            gate=result.summary.get("gate", {}),
            queue=result.summary.get("queue", {}),
            convergence=result.convergence,
        )
        # The registry lives at the runs/ root, not inside a stamped run dir:
        # ``--history`` reads the timeline across all runs, not one run's copy.
        observability.RunRegistry(self._runs_root or result.run_dir).append(record)
