"""Write the model — files only, and deliberately no graph writes.

The artifacts of one run, all deterministic so two runs over the same sibling
outputs are byte-identical (which is what makes the model diffable between runs):

* ``nodes.jsonl`` — one node per line: id, kind, identity, trust, score, band,
  sources, props and the evidence behind it.
* ``edges.jsonl`` — one relationship per line: type, endpoints, trust, sources,
  props and evidence.
* ``vocabulary.json`` — the label/relationship mapping used for this run, with
  the provisional-schema note.  Written so an artifact set records *which*
  vocabulary produced it; when the schema settles, old sets are still readable.
* ``scoring.json`` — the S2 weights, bands and the penalties this run applied,
  for the same reason: a score in ``nodes.jsonl`` is only meaningful next to the
  table that produced it.
* ``graph_state.json`` — the handoff document (:mod:`~.state`): the same nodes and
  edges plus both contracts and a computed integrity check, in one file, for a
  consumer that should not have to join four artifacts to act.
* ``report.json`` — counts, source status, orphans, conflicts, the score
  distribution and the explicit statement that nothing was written to a database.

**No Cypher, no driver, no ``GraphSink``.**  The graph schema is not final, so
this pipeline's output is a decision-ready model rather than a database write.
The platform's sink is one call away when that changes — and the only thing that
needs editing then is :mod:`~.vocabulary`.
"""

from __future__ import annotations

from pathlib import Path

from service.recon_pipeline.platform.common.io import (
    write_json,
    write_jsonl,
    write_lines,
)
from . import normalize as norm
from . import vocabulary as vocab

NODES_FILE = "nodes.jsonl"
EDGES_FILE = "edges.jsonl"
VOCABULARY_FILE = "vocabulary.json"
SCORING_FILE = "scoring.json"
REPORT_FILE = "report.json"
#: The policy's answer to "what deserves active validation next?" — one row per
#: eligible (asset, operation) pair, best-first, each with the reason it was
#: allowed.  Written as an artifact so the decision is inspectable and can be fed
#: to an active stage, rather than only existing inside a report's prose.
ACTIVE_CANDIDATES_FILE = "active_candidates.jsonl"
#: One row per *refused* (asset, operation) pair: verb, code, reason, and the
#: evidence that produced it.  The companion to ``active_candidates.jsonl`` — the
#: refusals are where the diagnosis lives, and on a measured run they outnumber the
#: queue by two orders of magnitude.
REFUSALS_FILE = "escalation_refusals.jsonl"
#: The run's progression accounting (:mod:`~.measurement`), as JSON and markdown:
#: how many candidates each stage saw, how many it refused, and by which rule.
MEASUREMENT_FILE = "measurement.json"
MEASUREMENT_REPORT_FILE = "measurement.md"
#: Networks by relevance state, for the ASN/CIDR question the graph has to answer.
RELEVANCE_FILE = "network_relevance.jsonl"
#: A plain-text index of node ids, for eyeballing a run without a JSON reader.
NODE_INDEX_FILE = "nodes.txt"


def node_rows(model: norm.Model) -> list[dict]:
    return [node.to_dict() for node in model.sorted_nodes()]


def edge_rows(model: norm.Model) -> list[dict]:
    return [edge.to_dict() for edge in model.sorted_edges()]


def relevance_rows(model: norm.Model) -> list[dict]:
    """One row per network: where it sits in the relevance progression, and why."""
    rows: list[dict] = []
    from . import merge as merge_mod

    for node in model.sorted_nodes():
        if node.kind != vocab.NETWORK:
            continue
        operations = merge_mod.derived_operations(model, node)
        rows.append(
            {
                "id": node.id,
                "network": node.identity,
                "relevance_state": str(node.props.get("relevance_state", "")),
                "relevance_reason": str(node.props.get("relevance_reason", "")),
                "scope_state": str(node.props.get("scope_state", "")),
                "known_hosts": node.props.get("known_hosts", 0),
                "classes": node.props.get("classes", []),
                "operations": sorted(operations),
                **({"score": node.score, "band": node.band} if node.score is not None else {}),
            }
        )
    return rows


def write_model(
    output_dir: Path | str,
    model: norm.Model,
    *,
    active_candidates: list[dict] | None = None,
    refusals: list[dict] | None = None,
    measurement: dict | None = None,
    target: str = "",
) -> dict[str, Path]:
    """Write the model artifacts; returns the paths written.

    *active_candidates*, *refusals* and *measurement* are the escalation policy's
    answers (see :func:`..merge.build_model`); they are passed in rather than
    recomputed so the artifacts and the report can never disagree about what was
    decided.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    nodes = node_rows(model)
    edges = edge_rows(model)
    from . import score as score_mod

    outputs = {
        "nodes": write_jsonl(output_dir / NODES_FILE, nodes),
        "edges": write_jsonl(output_dir / EDGES_FILE, edges),
        "vocabulary": write_json(output_dir / VOCABULARY_FILE, vocab.mapping_document()),
        # The scoring contract travels with the scores for the same reason the
        # label mapping does: an artifact set should say how its numbers were made.
        "scoring": write_json(output_dir / SCORING_FILE, score_mod.weights_document()),
        "node_index": write_lines(
            output_dir / NODE_INDEX_FILE, [str(row["id"]) for row in nodes]
        ),
        "network_relevance": write_jsonl(
            output_dir / RELEVANCE_FILE, relevance_rows(model)
        ),
    }
    if active_candidates is not None:
        outputs["active_candidates"] = write_jsonl(
            output_dir / ACTIVE_CANDIDATES_FILE, active_candidates
        )
    if refusals is not None:
        outputs["escalation_refusals"] = write_jsonl(
            output_dir / REFUSALS_FILE, refusals
        )
    if measurement is not None:
        from . import measurement as measure_mod

        outputs["measurement"] = write_json(
            output_dir / MEASUREMENT_FILE, measurement
        )
        outputs["measurement_report"] = write_lines(
            output_dir / MEASUREMENT_REPORT_FILE,
            measure_mod.render(measurement, target=target).splitlines(),
        )
    return outputs
