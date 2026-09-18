"""S14 — observability: the run registry, per-stage metrics, DLQ surface.

The plan's S14 minus the alerting plumbing (no external sinks exist in this
tree).  Three artifacts:

* **run registry** — one JSONL row per pipeline run: target, pipelines run,
  stage timings, ok-ness, service degradations.  The runner appends here; the
  CLI's ``--history`` reads it.  This is what turns "runs" into a timeline.
* **metrics** — the counts the plans' S14 names: assets discovered, scored,
  allowed/denied/deferred by the gate, messages published/dropped/dead.
  Aggregated per run, embedded in the report.
* **DLQ surface** — a read of the dead-letter stream with the last error per
  message, so queue ops is ``python -m service.recon_pipeline dlq`` rather
  than a Redis CLI session.

The registry is file-backed (append-only) and never raises on write failure:
telemetry must not take a run down.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

from .common.io import read_jsonl

log = logging.getLogger("platform.observability")

REGISTRY_FILE = "runs.jsonl"


@dataclass
class StageMetric:
    stage: str
    pipeline: str
    seconds: float = 0.0
    ok: bool = True
    counts: dict = field(default_factory=dict)
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "pipeline": self.pipeline,
            "stage": self.stage,
            "seconds": round(self.seconds, 2),
            "ok": self.ok,
            "counts": self.counts,
            **({"error": self.error} if self.error else {}),
        }


@dataclass
class RunRecord:
    """One recon run's telemetry row."""

    target: str
    started_at: str
    finished_at: str = ""
    seconds: float = 0.0
    ok: bool = True
    pipelines: list[str] = field(default_factory=list)
    stages: list[StageMetric] = field(default_factory=list)
    degradations: dict = field(default_factory=dict)
    gate: dict = field(default_factory=dict)
    queue: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "seconds": round(self.seconds, 2),
            "ok": self.ok,
            "pipelines": self.pipelines,
            "stages": [stage.to_dict() for stage in self.stages],
            "degradations": self.degradations,
            "gate": self.gate,
            "queue": self.queue,
        }


class RunRegistry:
    """Append-only run history, backed by one JSONL file."""

    def __init__(self, directory: Path | str) -> None:
        self._path = Path(directory) / REGISTRY_FILE
        self._directory = Path(directory)
        self._directory.mkdir(parents=True, exist_ok=True)

    @property
    def path(self) -> Path:
        return self._path

    def append(self, record: RunRecord) -> bool:
        """Append one run row; telemetry failure must not fail the run."""
        try:
            body = json.dumps(record.to_dict(), sort_keys=False) + "\n"
            with self._path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(body)
            return True
        except OSError as exc:
            log.warning("registry append failed: %s", exc)
            return False

    def history(self, limit: int = 20) -> list[dict]:
        """The last *limit* runs, newest first."""
        rows = read_jsonl(self._path)
        return list(reversed(rows[-limit:]))

    def last_for(self, target: str) -> dict | None:
        """The most recent row for *target*, or None."""
        for row in reversed(read_jsonl(self._path)):
            if row.get("target") == target:
                return row
        return None


def gate_metrics(dispatcher) -> dict:
    """The dispatcher's decision counters, report-shaped."""
    try:
        return dispatcher.summary()
    except Exception as exc:  # telemetry never raises
        return {"error": str(exc)}


def degradation_summary(cache=None, queue=None, enricher=None, graph=None) -> dict:
    """Which platform services degraded this run, and why."""
    out: dict[str, object] = {}
    if cache is not None and hasattr(cache, "health"):
        out["cache"] = cache.health.to_dict()
    if queue is not None and hasattr(queue, "health"):
        out["queue"] = queue.health.to_dict()
    if enricher is not None and hasattr(enricher, "health"):
        out["enrichment"] = enricher.health.to_dict()
    return out


def dlq_summary(client) -> list[dict]:
    """The DLQ's contents, newest last (queue-ops surface).

    ``client`` is a redis client; when it is None or unreachable the answer is
    an empty list with a degraded marker — the CLI prints that as-is.
    """
    if client is None:
        return [{"degraded": True, "reason": "redis unavailable"}]
    try:
        rows = client.xrange("asm:dlq", count=100)
        out: list[dict] = []
        for _message_id, fields in rows or []:
            try:
                envelope = json.loads((fields or {}).get("envelope", "{}"))
                out.append(
                    {
                        "asset": f"{envelope.get('asset_type')}:{envelope.get('canonical_value')}",
                        "source": envelope.get("source"),
                        "error": envelope.get("error", ""),
                    }
                )
            except (json.JSONDecodeError, AttributeError):
                continue
        return out
    except Exception as exc:
        return [{"degraded": True, "reason": str(exc)}]
