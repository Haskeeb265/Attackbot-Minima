"""Pipeline contract module — the only registration point for this pipeline.

Unlike the sibling pipelines this one has genuinely separable stages, so each
declared stage does one thing and keeps its output for the next: ``collect``
reads the artifacts, ``merge`` builds the model, ``emit`` writes it.  Asking for
a later stage on its own runs the earlier ones first (and says so in its
``note``), so ``-s emit`` is never a half-run.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from service.recon_pipeline.platform.contract import BasePipeline, Manifest, RunContext, Stage

MANIFEST = Manifest(
    name="graph_normalize",
    title="Graph normalization — four pipelines' artifacts → one node/edge model",
    asset_types=("Correlation",),
    description=(
        "Reads the sibling pipelines' artifacts (files only) and normalises every "
        "row into one model of typed nodes and edges, each carrying its "
        "provenance, its trust class and (when a scope engine is present) its "
        "scope verdict. Emits files only — no graph writes, because the schema is "
        "not final."
    ),
    provides=(
        "Domain",
        "Subdomain",
        "Wildcard",
        "IP",
        "Service",
        "URL",
        "Parameter",
        "ASN",
        "CIDR",
        "Organization",
    ),
    consumes=(
        "subdomain_domain_wildcards",
        "port_service_host",
        "url_endpoint",
        "asn_cidr",
    ),
    stages=(
        Stage("collect", "read every configured sibling artifact"),
        Stage("merge", "normalise rows into nodes and edges, annotate scope"),
        Stage("emit", "write nodes.jsonl / edges.jsonl / vocabulary.json / report.json"),
    ),
    passive_only=True,
)


class GraphNormalizePipeline(BasePipeline):
    """Stage-wise adapter over :mod:`~.main`'s pure functions."""

    def __init__(self) -> None:
        self._facts: list[Any] | None = None
        self._result: Any = None

    # ------------------------------------------------------------------ #

    def run(self, stage: str, context: RunContext) -> dict[str, Any]:
        if stage == "collect":
            return self._collect(context)
        if stage == "merge":
            prelude = self._collect(context) if self._facts is None else {}
            return {**self._merge(context), **prelude}
        if stage == "emit":
            earlier: dict[str, Any] = {}
            if self._facts is None:
                earlier = self._collect(context)
            if self._result is None:
                earlier = {**earlier, **self._merge(context)}
            return {**earlier, **self._emit(context)}
        raise ValueError(
            f"graph_normalize has no stage {stage!r}; declared: collect, merge, emit"
        )

    # ------------------------------------------------------------------ #

    def _collect(self, context: RunContext) -> dict[str, Any]:
        from .main import collect

        self._facts = collect(**self._dir_options(context.options))
        rows = sum(source.rows_read for source in self._facts)
        missing = sum(1 for source in self._facts for _ in source.missing)
        return {
            "ok": True,
            "counts": {
                "sources": len(self._facts),
                "rows_read": rows,
                "artifacts_missing": missing,
            },
        }

    def _merge(self, context: RunContext) -> dict[str, Any]:
        from . import merge as merge_mod

        assert self._facts is not None  # _collect ran immediately before
        self._result = merge_mod.build_model(
            self._facts, target=context.target, scope=context.scope
        )
        model = self._result.model
        return {
            "ok": True,
            "counts": {
                "nodes": len(model.nodes),
                "edges": len(model.edges),
                "scope_annotated": self._result.scope_applied,
                "unlinked_parameters": len(self._result.unlinked),
            },
        }

    def _emit(self, context: RunContext) -> dict[str, Any]:
        from . import emit, main, settings

        assert self._result is not None  # _merge ran immediately before
        output_dir = Path(context.options.get("output_dir") or settings.OUTPUT_DIR)
        written = emit.write_model(output_dir, self._result.model)
        outputs = {name: str(path) for name, path in written.items()}

        # One report shape for both entry points: the standalone run and this
        # contract build it with the same function, so they cannot drift.
        report = main.build_report(
            context.target,
            facts=self._facts or [],
            result=self._result,
            max_orphans=settings.MAX_ORPHANS,
        )
        report.outputs = outputs
        report_path = emit.write_json(output_dir / emit.REPORT_FILE, report.to_dict())
        outputs["report"] = str(report_path)
        return {
            "ok": report.ok,
            "counts": {
                "nodes": len(self._result.model.nodes),
                "edges": len(self._result.model.edges),
                "orphan_nodes": report.counts.get("orphan_nodes"),
                "scope_annotated": report.counts.get("scope_annotated"),
            },
            "outputs": outputs,
            "notes": report.notes,
        }


    @staticmethod
    def _dir_options(options: dict[str, str]) -> dict[str, Any]:
        """Let ``--set <stream>_dir=…`` point the readers at another checkout."""
        mapping = {
            "names": "names_dir",
            "ports": "ports_dir",
            "urls": "urls_dir",
            "networks": "networks_dir",
        }
        resolved: dict[str, Path] = {}
        for key, argument in mapping.items():
            value = options.get(f"{key}_dir")
            if value:
                resolved[argument] = Path(value)
        return resolved


PIPELINE = GraphNormalizePipeline()
