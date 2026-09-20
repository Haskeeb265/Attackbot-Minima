"""Orchestrator: read the siblings' artifacts → merge into the model → emit.

Three stages, each independently runnable and each a pure function of its
inputs, which is what lets the pipeline be exercised in tests and in the
platform without a network or a database:

``collect``  read every configured sibling artifact (files only)
``merge``    normalise the rows into nodes and edges, annotate scope
``emit``     write ``nodes.jsonl`` / ``edges.jsonl`` / ``vocabulary.json`` /
             ``scoring.json`` / ``graph_state.json`` (the handoff document) /
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

import argparse
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import emit, measurement, merge as merge_mod, settings, sources, state
from . import normalize as norm
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
    #: The S2 scoring pass: band distribution, top-scoring nodes, penalties.
    scoring: dict[str, object] = field(default_factory=dict)
    #: What the escalation policy decided, per operation (the graph's answer to
    #: "which assets deserve active validation next?").
    escalation: dict[str, object] = field(default_factory=dict)
    #: Networks by relevance state (``discovered`` … ``active_candidate``).
    networks_by_relevance: dict[str, int] = field(default_factory=dict)
    #: The run's progression accounting, per stage (see :mod:`~.measurement`):
    #: how many candidates each stage saw, how many it refused and by which rule.
    measurement: dict[str, object] = field(default_factory=dict)
    #: One row per refused candidate.  Deliberately *not* in :meth:`to_dict`:
    #: it has its own artifact (``escalation_refusals.jsonl``) and inlining
    #: thousands of rows into ``report.json`` would write the same data twice in
    #: one directory.  The counts that summarise it are in ``escalation``.
    escalation_refusal_rows: list[dict] = field(default_factory=list, repr=False)
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
            "scoring": self.scoring,
            "escalation": self.escalation,
            "networks_by_relevance": self.networks_by_relevance,
            "measurement": self.measurement,
            "notes": self.notes,
            "outputs": self.outputs,
        }


def collect(
    *,
    names_dir: Path | str = settings.NAMES_DIR,
    ports_dir: Path | str = settings.PORTS_DIR,
    urls_dir: Path | str = settings.URLS_DIR,
    networks_dir: Path | str = settings.NETWORKS_DIR,
    cloud_dir: Path | str = settings.CLOUD_DIR,
    include_names: bool = settings.INCLUDE_NAMES,
    include_ports: bool = settings.INCLUDE_PORTS,
    include_urls: bool = settings.INCLUDE_URLS,
    include_networks: bool = settings.INCLUDE_NETWORKS,
    include_cloud: bool = settings.INCLUDE_CLOUD,
) -> list[sources.SourceFacts]:
    """Read every configured sibling artifact.  No network, no siblings run."""
    return sources.read_all(
        names_root=Path(names_dir),
        ports_root=Path(ports_dir),
        urls_root=Path(urls_dir),
        networks_root=Path(networks_dir),
        cloud_root=Path(cloud_dir),
        include_names=include_names,
        include_ports=include_ports,
        include_urls=include_urls,
        include_networks=include_networks,
        include_cloud=include_cloud,
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
    stats = result.score_stats
    report.scoring = (
        stats.to_dict() if stats is not None else {"skipped": "the scoring pass did not run"}
    )
    report.escalation = result.escalation
    report.networks_by_relevance = result.networks_by_relevance
    report.escalation_refusal_rows = result.escalation_refusals
    # Measured from the finished model, before any artifact is written, so the
    # report and ``measurement.json`` are the same numbers by construction.
    report.measurement = measurement.measure(result)

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
        "parameter_observations": result.parameter_observations,
        "parameters_with_provenance": len(result.parameter_urls),
        "url_validations": result.url_validations,
        "urls_live": result.urls_live,
        "urls_dead": result.urls_dead,
        "orphan_nodes": orphan_total,
        "endpoint_only_nodes": len(set(model.endpoint_only)),
        "property_conflicts": len(model.conflicts),
        "registered_networks": result.registered_networks,
        "scope_annotated": (
            sum(count for kind, count in report.by_kind.items() if kind in scoped_kinds)
            if result.scope_applied
            else 0
        ),
        # Read from the stats object, not back out of the report dict, so the
        # counts cannot disagree with the distribution below them.
        "nodes_scored": stats.scored if stats is not None else 0,
        "nodes_unscored": stats.unscored if stats is not None else 0,
        "nodes_penalised": stats.penalised if stats is not None else 0,
        "wildcard_edges_withheld": result.wildcard_edges_truncated,
        "active_candidates": len(result.active_candidates),
        "escalation_refusals": len(result.escalation_refusals),
        "dns_scoped_addresses": result.dns_scoped_addresses,
        "networks_relevant": sum(
            count
            for state, count in result.networks_by_relevance.items()
            if state not in ("discovered",)
        ),
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
    cloud_dir: Path | str = settings.CLOUD_DIR,
    include_names: bool = settings.INCLUDE_NAMES,
    include_ports: bool = settings.INCLUDE_PORTS,
    include_urls: bool = settings.INCLUDE_URLS,
    include_networks: bool = settings.INCLUDE_NETWORKS,
    include_cloud: bool = settings.INCLUDE_CLOUD,
    scope=None,
    max_nodes: int | None = settings.MAX_NODES,
    max_edges: int | None = settings.MAX_EDGES,
    max_evidence: int = settings.MAX_EVIDENCE,
    max_wildcard_edges: int = settings.MAX_WILDCARD_EDGES,
    max_orphans: int = settings.MAX_ORPHANS,
    scored: bool = settings.SCORE_MODEL,
    max_score_audit: int = settings.MAX_SCORE_AUDIT,
    top_scored: int = settings.MAX_TOP_SCORED,
    plan_escalation: bool = settings.PLAN_ESCALATION,
    allow_needs_review: bool = settings.ESCALATION_ALLOW_NEEDS_REVIEW,
) -> GraphNormalizeReport:
    """Run all three stages and write the model artifacts."""
    started = time.monotonic()
    started_at = _utc_now()
    facts = collect(
        names_dir=names_dir,
        ports_dir=ports_dir,
        urls_dir=urls_dir,
        networks_dir=networks_dir,
        cloud_dir=cloud_dir,
        include_names=include_names,
        include_ports=include_ports,
        include_urls=include_urls,
        include_networks=include_networks,
        include_cloud=include_cloud,
    )
    result = merge_mod.build_model(
        facts,
        target=target,
        scope=scope,
        max_nodes=max_nodes,
        max_edges=max_edges,
        max_evidence=max_evidence,
        max_wildcard_edges=max_wildcard_edges,
        scored=scored,
        max_score_audit=max_score_audit,
        top_scored=top_scored,
        plan_escalation=plan_escalation,
        allow_needs_review=allow_needs_review,
    )
    report = build_report(
        target,
        facts=facts,
        result=result,
        started_at=started_at,
        max_orphans=max_orphans,
    )

    report.finished_at = _utc_now()
    report.seconds = time.monotonic() - started
    write_outputs(output_dir, result.model, report)
    return report


def write_outputs(
    output_dir: Path | str, model: norm.Model, report: GraphNormalizeReport
) -> dict[str, str]:
    """Write every artifact of a run; returns ``{name: path}``.

    **One function for both entry points.**  The standalone run and the platform
    contract must produce identically-populated output directories: when the
    contract wrote the model and the report itself while this function also wrote
    the graph state, a platform run silently omitted the handoff document — a
    live run caught it, which is exactly the kind of drift the shared report was
    meant to prevent.  Now neither path can write a partial set.
    """
    directory = Path(output_dir)
    if not report.finished_at:
        report.finished_at = _utc_now()
    outputs = {
        name: str(path)
        for name, path in emit.write_model(
            directory,
            model,
            active_candidates=report_escalation_queue(report),
            refusals=report_escalation_refusals(report),
            measurement=report.measurement or None,
            target=report.target,
        ).items()
    }
    # The handoff document for downstream consumers (the vulnerability finder
    # engine).  Built before the report so the report can name it as an output;
    # it carries the run's own accounting, so a consumer needs no sibling file.
    outputs["graph_state"] = str(
        state.write_graph_state(
            directory,
            model,
            target=report.target,
            generated_at=report.finished_at,
            report=report.to_dict(),
        )
    )
    report.outputs = outputs
    outputs["report"] = str(emit.write_json(directory / emit.REPORT_FILE, report.to_dict()))
    report.outputs = outputs
    return outputs


def report_escalation_queue(report: GraphNormalizeReport) -> list[dict] | None:
    """The escalation queue carried by *report*, or ``None`` when none ran.

    Read back out of the report so the artifact is literally the same rows the
    report counted — one decision, two views of it.
    """
    if not report.escalation:
        return None
    queue: list[dict] = []
    for block in report.escalation.values():
        if isinstance(block, dict):
            rows = block.get("queue")
            if isinstance(rows, list):
                queue.extend(row for row in rows if isinstance(row, dict))
    return queue


def report_escalation_refusals(report: GraphNormalizeReport) -> list[dict] | None:
    """Every refused candidate, or ``None`` when the escalation pass did not run.

    Taken straight off the report so the artifact *is* the rows the report
    counted — one decision, two views of it (the same rule the queue follows).
    """
    if not report.escalation:
        return None
    return list(report.escalation_refusal_rows)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --------------------------------------------------------------------------- #
# CLI — the standalone entry point, for a run outside the platform
# --------------------------------------------------------------------------- #


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m service.recon_pipeline.pipelines.graph_normalize.main",
        description=(
            "Normalise the sibling pipelines' artifacts into one node/edge model "
            "and write it as the final graph state. Reads files only: no network, "
            "no database writes."
        ),
    )
    parser.add_argument(
        "-t", "--target", default=DEFAULT_TARGET, help="apex domain the run is about"
    )
    parser.add_argument("--output-dir", default=str(settings.OUTPUT_DIR), help="output directory")
    for stream, attribute in (
        ("names", "NAMES_DIR"),
        ("ports", "PORTS_DIR"),
        ("urls", "URLS_DIR"),
        ("networks", "NETWORKS_DIR"),
    ):
        parser.add_argument(
            f"--{stream}-dir",
            default=str(getattr(settings, attribute)),
            help=f"{stream} artifacts (default: this checkout's sibling pipeline)",
        )
    parser.add_argument(
        "--no-score",
        action="store_true",
        help="skip the S2 scoring pass (the model carries no score/band fields)",
    )
    parser.add_argument(
        "--no-scope",
        action="store_true",
        help="do not annotate the model with scope verdicts (they are on by default)",
    )
    parser.add_argument("--max-nodes", type=int, default=settings.MAX_NODES, help="node cap")
    parser.add_argument("--max-edges", type=int, default=settings.MAX_EDGES, help="edge cap")
    parser.add_argument("--max-evidence", type=int, default=settings.MAX_EVIDENCE)
    parser.add_argument("--max-wildcard-edges", type=int, default=settings.MAX_WILDCARD_EDGES)
    parser.add_argument("--max-orphans", type=int, default=settings.MAX_ORPHANS, help="orphan ids in the report")
    parser.add_argument("--max-score-audit", type=int, default=settings.MAX_SCORE_AUDIT)
    parser.add_argument("--top-scored", type=int, default=settings.MAX_TOP_SCORED)
    parser.add_argument(
        "--no-escalation-plan",
        action="store_true",
        help="skip the S16 escalation pass (no active_candidates.jsonl)",
    )
    parser.add_argument(
        "--allow-needs-review",
        action="store_true",
        help="let the escalation policy promote assets the scope engine put in needs_review",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point.  Returns a process exit code."""
    args = _build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)-7s %(name)s: %(message)s",
    )

    # The scope engine is built here exactly as the platform runner builds it
    # (`ScopeEngine.from_domain(target)`), so a standalone run and a platform run
    # produce the same model.  Without this the CLI wrote a document with no
    # scope verdict at all, which is the one field a consumer must have before
    # touching anything.
    scope = None
    if not args.no_scope:
        from service.recon_pipeline.platform.programs import scope_from_environment
        from service.recon_pipeline.platform.scope import ScopeEngine

        scope = ScopeEngine.from_domain(args.target)
        # A program run (--program via either entry point) hands its declared
        # scope down as a snapshot; apply it so this standalone build gates on
        # the program's scope, not just the apex (S4). The verdicts reach the
        # state document through the node annotations, as always.
        scope_from_environment(scope)

    report = run_pipeline(
        args.target,
        output_dir=args.output_dir,
        names_dir=args.names_dir,
        ports_dir=args.ports_dir,
        urls_dir=args.urls_dir,
        networks_dir=args.networks_dir,
        scope=scope,
        scored=not args.no_score,
        plan_escalation=not args.no_escalation_plan,
        allow_needs_review=args.allow_needs_review,
        max_nodes=args.max_nodes,
        max_edges=args.max_edges,
        max_evidence=args.max_evidence,
        max_wildcard_edges=args.max_wildcard_edges,
        max_orphans=args.max_orphans,
        max_score_audit=args.max_score_audit,
        top_scored=args.top_scored,
    )

    counts = report.counts
    log.info(
        "%s nodes / %s edges from %s row(s) in %.2fs — %s scored, %s unscored, %s orphan(s)",
        counts.get("nodes"),
        counts.get("edges"),
        counts.get("rows_read"),
        report.seconds,
        counts.get("nodes_scored"),
        counts.get("nodes_unscored"),
        counts.get("orphan_nodes"),
    )
    log.info(
        "graph state (handoff document): %s — %s node(s) with a scope verdict",
        report.outputs.get("graph_state"),
        counts.get("scope_annotated"),
    )
    for operation, block in (report.escalation or {}).items():
        if not isinstance(block, dict):
            continue
        codes = block.get("refusal_codes")
        log.info(
            "escalation %-20s %s eligible / %s considered — refusals: %s",
            operation,
            block.get("eligible"),
            block.get("considered"),
            ", ".join(
                f"{code}×{count}"
                for code, count in (codes.items() if isinstance(codes, dict) else ())
            )
            or "none",
        )
    ip_port = report.measurement.get("ip_port")
    if isinstance(ip_port, dict):
        log.info(
            "measurement: %s address(es) — %s dedicated, %s unclassified, "
            "%s eligible for active work",
            ip_port.get("addresses"),
            ip_port.get("hosting_dedicated"),
            ip_port.get("hosting_unclassified"),
            ip_port.get("eligible"),
        )
    for note in report.notes:
        log.warning(note)
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
