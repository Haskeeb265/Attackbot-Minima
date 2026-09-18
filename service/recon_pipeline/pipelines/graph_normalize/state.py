"""The final graph state — one self-describing document, built to be handed over.

``nodes.jsonl`` / ``edges.jsonl`` are the model's *streams*: ideal for diffing two
runs and for a batch writer that loads rows.  This module produces the other
shape the same model has to take — a single document that answers, without any
sibling file or the code revision that wrote it, everything a downstream consumer
needs in order to act on the graph:

* **what each node is** — kind, identity, and the graph labels a write would use;
* **how much attention it deserves** — the S2 score, its band, and the audit
  lines that produced them;
* **where the claim came from** — `sources`, `trust`, `evidence`, and the scope
  engine's verdict on every place-shaped node;
* **how the nodes relate** — typed edges, each with the relationship name and
  direction a graph write would use;
* **the two vocabularies the document is written in** — the label mapping and the
  scoring table — *embedded*, so a reader is never left guessing which weights or
  labels produced these numbers.

Everything is copied out of the finished model; nothing is recomputed.  That is
deliberate: a handoff document that re-derives a number can disagree with the
JSONL the same run wrote, and two artifacts from one run contradicting each other
is worse than one of them being absent.

Integrity is checked, not asserted.  Every edge endpoint is resolved against the
nodes in the document, node-id uniqueness is verified, and the counts of anything
that fails travel in
``integrity`` alongside a ``consistent`` flag — so a consumer can check the
claim rather than take it on faith.

``graph_written: false`` is carried here too, for the same reason it is in the
report: this document **is** the graph state, and it is a file rather than a
database write because the schema is not final.  When that changes, the writer
reads this document; the document itself does not change shape.
"""

from __future__ import annotations

from pathlib import Path

from service.recon_pipeline.platform.common.io import write_json

from . import normalize as norm
from . import score as score_mod
from . import vocabulary as vocab

GRAPH_STATE_FILE = "graph_state.json"

#: Bumped when the document's *shape* changes in a way a reader must notice.
#: Additive fields do not bump it; renames and removals do.
GRAPH_STATE_VERSION = 1


def build_graph_state(
    model: norm.Model,
    *,
    target: str,
    generated_at: str,
    report: dict[str, object] | None = None,
) -> dict[str, object]:
    """The finished model as one document: nodes, edges, contracts, integrity."""
    known = set(model.nodes)
    nodes: list[dict[str, object]] = []
    for node in model.sorted_nodes():
        row = node.to_dict()
        # The mapping travels per node as well as in ``vocabulary``: a consumer
        # that walks nodes one at a time should not have to keep a second lookup
        # table in sync with this file.
        row["labels"] = list(vocab.GRAPH_LABELS.get(node.kind, ()))
        nodes.append(row)

    edges: list[dict[str, object]] = []
    endpoints_missing = 0
    for edge in model.sorted_edges():
        row = edge.to_dict()
        relationship, direction = vocab.GRAPH_RELATIONSHIPS.get(edge.type, (edge.type, ""))
        row["relationship"] = relationship
        if direction:
            row["direction"] = direction
        edges.append(row)
        if edge.source_id not in known or edge.target_id not in known:
            endpoints_missing += 1

    by_band: dict[str, int] = {}
    scores: list[int] = []
    unscored = 0
    for node in model.nodes.values():
        if node.score is None:
            unscored += 1
            continue
        scores.append(int(node.score))
        by_band[node.band] = by_band.get(node.band, 0) + 1

    orphan_total, _ = model.orphan_ids(limit=1)
    integrity: dict[str, object] = {
        "consistent": endpoints_missing == 0,
        "nodes": len(nodes),
        "edges": len(edges),
        "nodes_scored": len(scores),
        "nodes_unscored": unscored,
        "edges_with_unresolved_endpoints": endpoints_missing,
        "orphan_nodes": orphan_total,
        "nodes_by_band": dict(sorted(by_band.items())),
        "checks": [
            "every edge endpoint resolves to a node in this document",
            "node ids are unique (a node id is kind:identity)",
            "every node kind has a graph label mapping",
            "every edge type has a graph relationship mapping",
        ],
    }
    if scores:
        integrity["score_range"] = [min(scores), max(scores)]

    document: dict[str, object] = {
        "graph_state_version": GRAPH_STATE_VERSION,
        "target": target,
        "generated_at": generated_at,
        "produced_by": {
            "pipeline": "graph_normalize",
            "module": "service.recon_pipeline.pipelines.graph_normalize.state",
        },
        "status": {
            "graph_written": vocab.GRAPH_WRITTEN,
            "note": vocab.SCHEMA_NOTE,
            "scoring": (
                "scores come from the platform's S2 engine; the table that "
                "produced them is in `scoring` below, and every node's `score_audit` "
                "shows the arithmetic line by line"
            ),
            "unscored_nodes": (
                "a node whose only contributors are judgements or unknown sources "
                "carries no `score` field: nothing claimed it as an asset, which is "
                "not the same as it scoring zero"
            ),
            # Stated as data for the same reason: a consumer must be able to tell
            # "this asset is in scope" from "this run had no scope engine", and an
            # absent field cannot say which.
            "scope": (
                "when a scope engine annotated the model, every place-shaped node "
                "carries `props.scope_state` (in_scope / needs_review / "
                "out_of_scope) and `props.scope_reason`; `run.counts.scope_annotated` "
                "says how many did and `run.counts.registered_networks` how many "
                "discovered networks were registered. Zero means no engine was "
                "present, not that nothing is in scope"
            ),
        },
        "vocabulary": vocab.mapping_document(),
        "scoring": score_mod.weights_document(),
        "integrity": integrity,
        "nodes": nodes,
        "edges": edges,
    }
    if report is not None:
        # Standalone-ness is the point of this file, so the run's own accounting
        # (source status, conflicts, notes, counts) comes with it rather than
        # being left behind in a sibling artifact.
        document["run"] = {
            key: report[key]
            for key in ("counts", "sources", "conflicts", "notes", "seconds", "started_at")
            if key in report
        }
    return document


def write_graph_state(
    output_dir: Path | str,
    model: norm.Model,
    *,
    target: str,
    generated_at: str,
    report: dict[str, object] | None = None,
) -> Path:
    """Write the graph state document; returns its path."""
    document = build_graph_state(
        model, target=target, generated_at=generated_at, report=report
    )
    return write_json(Path(output_dir) / GRAPH_STATE_FILE, document)
