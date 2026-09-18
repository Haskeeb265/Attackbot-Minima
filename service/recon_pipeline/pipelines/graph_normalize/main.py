"""Orchestrator: read the siblings' artifacts → merge into the model → emit.

Three stages, each independently runnable and each a pure function of its
inputs, which is what lets the pipeline be exercised in tests and in the
platform without a network or a database:

``collect``  read every configured sibling artifact (files only)
``merge``    normalise the rows into nodes and edges, annotate scope
``emit``     write ``nodes.jsonl`` / ``edges.jsonl`` / ``vocabulary.json`` /
             ``report.json``

Nothing here writes to the graph database, and the report says so in a field
rather than a comment: ``graph_written: false`` plus the reason.  See
:mod:`~.vocabulary` for the single place to change when the schema is final.

The honest failure modes are the sibling pipelines' own:

* a sibling that has not run means missing artifacts — a smaller model, reported
  per artifact, not an exception;
* **every** enabled source missing means the operator asked for a model with
  nothing to build it from, and that *is* a failed run (``ok: false``);
* a malformed artifact line costs that line and is counted, never the run.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import emit, merge as merge_mod, settings, sources
from . import vocabulary as vocab

log = logging.getLogger("graph_normalize.main")

DEFAULT_TARGET = "unknown"


@dataclass
class GraphNormalizeReport:
    """The machine-readable run report."""

    target: str
    started_at: str
    finished_at: str = ""
    seconds: float = 0.0
    ok: bool = True
    counts: dict[str, object] = field(default_factory=dict)
    by_kind: dict[str, int] = field(default_factory=dict)
    by_type: dict[str, int] = field(default_factory=dict)
    by_trust: dict[str, int] = field(default_factory=dict)
    sources: list[dict] = field(default_factory=list)
    orphans: dict[str, object] = field(default_factory=dict)
    conflicts: list[dict] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    outputs: dict[str, str] = field(default_factory=dict)
    #: Always false until the schema is final — stated as data, not prose.
    graph_written: bool = vocab.GRAPH_WRITTEN
    schema_note: str = vocab.SCHEMA_NOTE

    def to_dict(self) -> dict[str, object]:
        return {
            "target": self.target,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "seconds": round(self.seconds, 2),
            "ok": self.ok,
            "graph_written": self.graph_written,
            "schema_note": self.schema_note,
            "counts": self.counts,
            "nodes_by_kind": self.by_kind,
            "edges_by_type": self.by_type,
            "nodes_by_trust": self.by_trust,
            "sources": self.sources,
            "orphans": self.orphans,
            "conflicts": self.conflicts,
            "notes": self.notes,
            "outputs": self.outputs,
        }


def collect(
    *,
    names_dir: Path | str = settings.NAMES_DIR,
    ports_dir: Path | str = settings.PORTS_DIR,
    urls_dir: Path | str = settings.URLS_DIR,
    networks_dir: Path | str = settings.NETWORKS_DIR,
    include_names: bool = settings.INCLUDE_NAMES,
    include_ports: bool = settings.INCLUDE_PORTS,
    include_urls: bool = settings.INCLUDE_URLS,
    include_networks: bool = settings.INCLUDE_NETWORKS,
) -> list[sources.SourceFacts]:
    """Read every configured sibling artifact.  No network, no siblings run."""
    return sources.read_all(
        names_root=Path(names_dir),
        ports_root=Path(ports_dir),
        urls_root=Path(urls_dir),
        networks_root=Path(networks_dir),
        include_names=include_names,
        include_ports=include_ports,
        include_urls=include_urls,
        include_networks=include_networks,
    )


def build_report(
    target: str,
    *,
    facts: list[sources.SourceFacts],
    result: merge_mod.MergeResult,
    started_at: str | None = None,
    seconds: float = 0.0,
    max_orphans: int = settings.MAX_ORPHANS,
) -> GraphNormalizeReport:
    """Build the run report from a finished merge.

    Split out so the platform contract and the standalone run write *one* report
    shape: a second, slimmer report built next to this one would drift the
    moment either changed.
    """
    model = result.model
    report = GraphNormalizeReport(
        target=target,
        started_at=started_at or _utc_now(),
        seconds=seconds,
        graph_written=vocab.GRAPH_WRITTEN,
    )
    report.sources = [source.to_dict() for source in facts]
    report.notes.extend(result.notes)

    enabled = [source for source in facts if source.enabled]
    if enabled and not any(source.rows_read for source in enabled):
        report.ok = False
        report.notes.append(
            "no sibling artifacts were readable — run the pipelines (or point "
            "GN_*_DIR at their output) before normalising"
        )

    orphan_total, orphan_sample = model.orphan_ids(limit=max_orphans)
    report.orphans = {
        "total": orphan_total,
        "sample": orphan_sample,
        **({"truncated": True} if orphan_total > len(orphan_sample) else {}),
    }
    report.conflicts = model.conflicts
    report.by_kind = model.counts_by_kind()
    report.by_type = model.counts_by_type()
    report.by_trust = model.counts_by_trust()

    scoped_kinds = (vocab.DOMAIN, vocab.IP, vocab.NETWORK)
    report.counts = {
        "nodes": len(model.nodes),
        "edges": len(model.edges),
        "sources_read": sum(1 for source in enabled if source.rows_read),
        "sources_missing": sum(1 for source in enabled if not source.rows_read),
        "sources_skipped": sum(1 for source in facts if not source.enabled),
        "rows_read": sum(source.rows_read for source in enabled),
        "malformed_lines": sum(source.malformed for source in enabled),
        "unlinked_parameters": len(result.unlinked),
        "orphan_nodes": orphan_total,
        "endpoint_only_nodes": len(set(model.endpoint_only)),
        "property_conflicts": len(model.conflicts),
        "registered_networks": result.registered_networks,
        "scope_annotated": (
            sum(count for kind, count in report.by_kind.items() if kind in scoped_kinds)
            if result.scope_applied
            else 0
        ),
        "wildcard_edges_withheld": result.wildcard_edges_truncated,
        "truncated_nodes": model.truncated_nodes,
        "truncated_edges": model.truncated_edges,
        "graph_written": 0,
    }
    return report


def run_pipeline(
    target: str = DEFAULT_TARGET,
    *,
    output_dir: Path | str = settings.OUTPUT_DIR,
    names_dir: Path | str = settings.NAMES_DIR,
    ports_dir: Path | str = settings.PORTS_DIR,
    urls_dir: Path | str = settings.URLS_DIR,
    networks_dir: Path | str = settings.NETWORKS_DIR,
    include_names: bool = settings.INCLUDE_NAMES,
    include_ports: bool = settings.INCLUDE_PORTS,
    include_urls: bool = settings.INCLUDE_URLS,
    include_networks: bool = settings.INCLUDE_NETWORKS,
    scope=None,
    max_nodes: int | None = settings.MAX_NODES,
    max_edges: int | None = settings.MAX_EDGES,
    max_evidence: int = settings.MAX_EVIDENCE,
    max_wildcard_edges: int = settings.MAX_WILDCARD_EDGES,
    max_orphans: int = settings.MAX_ORPHANS,
) -> GraphNormalizeReport:
    """Run all three stages and write the model artifacts."""
    started = time.monotonic()
    started_at = _utc_now()
    facts = collect(
        names_dir=names_dir,
        ports_dir=ports_dir,
        urls_dir=urls_dir,
        networks_dir=networks_dir,
        include_names=include_names,
        include_ports=include_ports,
        include_urls=include_urls,
        include_networks=include_networks,
    )
    result = merge_mod.build_model(
        facts,
        target=target,
        scope=scope,
        max_nodes=max_nodes,
        max_edges=max_edges,
        max_evidence=max_evidence,
        max_wildcard_edges=max_wildcard_edges,
    )
    report = build_report(
        target,
        facts=facts,
        result=result,
        started_at=started_at,
        max_orphans=max_orphans,
    )

    outputs = emit.write_model(output_dir, result.model)
    report.outputs = {name: str(path) for name, path in outputs.items()}

    report.finished_at = _utc_now()
    report.seconds = time.monotonic() - started

    emit.write_json(Path(output_dir) / emit.REPORT_FILE, report.to_dict())
    return report


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
