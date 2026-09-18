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
from .contract import RunContext
from .dispatch import DispatchPolicy, Dispatcher
from .graph.ingest import GraphSink, connect_repository
from .registry import Registry
from .scope import ScopeEngine

log = logging.getLogger("platform.runner")

RUNS_DIRNAME = "runs"
SUMMARY_FILE = "summary.json"


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
    ) -> tuple[RunContext, list]:
        """Assemble the platform services into a RunContext.

        Returns ``(context, services)`` so the caller can read health from the
        services afterwards without the pipelines seeing them mutate.
        """
        from .cache import HotCache
        from .enrich import LLMEnricher
        from .queueing import Queue

        services: list = []
        scope_engine = ScopeEngine.from_domain(target)
        scoring_mod = __import__("service.recon_pipeline.platform.scoring", fromlist=["score"])
        cache = HotCache()
        queue = Queue(
            spool_path=(output_dir / "queue_spool.jsonl") if output_dir else None
        )
        enricher = LLMEnricher()
        repository = connect_repository()
        graph = GraphSink(
            repository=repository,
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
    ) -> RunResult:
        """Run the selected pipelines (default: all discovered) against *target*."""
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
            target, output_dir=run_dir, options=options
        )
        scope_engine, cache, queue, enricher, graph, dispatcher = services

        for registration in ordered:
            manifest = registration.manifest
            wanted = stages or list(manifest.stage_names())
            for stage_name in wanted:
                if stage_name not in manifest.stage_names():
                    log.warning(
                        "%s: no stage %r (declared: %s)",
                        manifest.name,
                        stage_name,
                        ", ".join(manifest.stage_names()),
                    )
                    continue
                outcome = self._run_stage(registration, stage_name, context, run_dir)
                result.outcomes.append(outcome)
                if not outcome.ok:
                    result.ok = False

        result.seconds = time.monotonic() - started
        result.finished_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        result.scope_summary = dict(scope_engine.summary())
        result.degradations = dict(
            observability.degradation_summary(
                cache=cache, queue=queue, enricher=enricher, graph=graph
            )
        )
        result.summary = self._summarise(result, dispatcher, queue, cache, graph, enricher)
        result.run_dir = run_dir

        self._write_reports(result)
        return result

    def _run_stage(self, registration, stage_name: str, context: RunContext, run_dir: Path) -> StageOutcome:
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
        self._write_stage_report(outcome, run_dir)
        return outcome

    def _write_stage_report(self, outcome: StageOutcome, run_dir: Path) -> None:
        """Snapshot one stage's report under ``runs/<target>/<stamp>/stages/``.

        The pipeline's own artifacts live in its own output directories; this
        is the platform's copy of the machine report, so a run directory is a
        complete record of what happened without reading any pipeline code.
        """
        import json

        stage_dir = run_dir / "stages" / outcome.pipeline
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
        return {
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
        )
        # The registry lives at the runs/ root, not inside a stamped run dir:
        # ``--history`` reads the timeline across all runs, not one run's copy.
        observability.RunRegistry(self._runs_root or result.run_dir).append(record)
