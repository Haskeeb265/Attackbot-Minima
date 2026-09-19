"""The LLM tool layer — how a vuln-engine model touches the graph.

**The contract this module enforces:** the model never receives the graph,
only *views* served through ``GraphBackend``. Each tool's JSON schema and its
runtime share one definition (``SPEC``), so the schema the model is shown and
the code the dispatcher runs cannot drift apart. Every response is
budget-checked by ``reader`` — a tool physically cannot return 500 KB of JSON.

**The interface promise:** the schemas below are the LLM-facing API. When a
Neo4j backend lands behind ``GraphBackend``, none of this changes — which is
the point of the seam.
"""

from __future__ import annotations

import json
from typing import Any

from service.recon_pipeline.platform.graph.neo4j_backend import Neo4jUnavailable
from service.recon_pipeline.platform.graph.reader import (
    BudgetExceeded,
    GraphBackend,
    _within_budget,
    compact_edge,
    compact_node,
)

# --------------------------------------------------------------------------- #
# tool specs: one definition per tool — schema shown to the model, dispatcher
# below runs exactly what the schema describes.
# --------------------------------------------------------------------------- #

STATS_SPEC: dict[str, Any] = {
    "name": "graph_stats",
    "description": (
        "Overview of the recon graph for the current target: node/edge counts, "
        "assets by kind, assets by score band, and when it was generated. "
        "Call this first to size up the attack surface."
    ),
    "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
}

TOP_SPEC: dict[str, Any] = {
    "name": "graph_top_assets",
    "description": (
        "Highest-priority assets from the recon graph, scored by the recon "
        "pipeline's S2 engine. Use to pick investigation targets. Optional "
        "filters: score band (core/high/medium/low/dead), asset kind, minimum "
        "score. Rows are sorted best-first; the response states if it was "
        "truncated."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "limit": {
                "type": "integer",
                "description": "How many assets to return (default 20, max 100).",
                "minimum": 1,
                "maximum": 100,
            },
            "band": {
                "type": "string",
                "description": "Only assets in this score band.",
            },
            "kind": {
                "type": "string",
                "description": "Only assets of this kind (domain, ip, url, cloud, ...).",
            },
            "min_score": {
                "type": "integer",
                "description": "Only assets scoring at least this value (0-100).",
                "minimum": 0,
                "maximum": 100,
            },
        },
        "additionalProperties": False,
    },
}

NODE_SPEC: dict[str, Any] = {
    "name": "graph_get_node",
    "description": (
        "Full record of one asset by its graph id (e.g. 'domain:autodiscover."
        "example.com', 'cloud:gcs:acme-docs'). Includes scoring audit trail, "
        "evidence and properties."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "node_id": {"type": "string", "description": "The graph id, 'kind:identity'."},
        },
        "required": ["node_id"],
        "additionalProperties": False,
    },
}

NEIGHBORS_SPEC: dict[str, Any] = {
    "name": "graph_neighbors",
    "description": (
        "Assets adjacent to one asset: what it resolves to, what hosts it, "
        "which organization owns it, its URLs, etc. This is how you traverse "
        "the graph — expand one interesting asset, then another. Each returned "
        "row includes the edges connecting it to the start node."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "node_id": {"type": "string", "description": "The graph id to expand."},
            "edge_type": {
                "type": "string",
                "description": "Only traverse this edge type (resolves_to, has_url, cname_points_to, ...).",
            },
            "direction": {
                "type": "string",
                "enum": ["out", "in", "both"],
                "description": "Edge direction relative to the node (default both).",
            },
            "depth": {
                "type": "integer",
                "minimum": 1,
                "maximum": 4,
                "description": "Hops to traverse (default 1, max 4). Depth 2 from a hub can be large — prefer depth 1 for first look.",
            },
            "limit": {
                "type": "integer",
                "minimum": 1,
                "maximum": 100,
                "description": "Max assets to return (default 25).",
            },
        },
        "required": ["node_id"],
        "additionalProperties": False,
    },
}

SEARCH_SPEC: dict[str, Any] = {
    "name": "graph_search",
    "description": (
        "Find assets by substring across ids and properties — e.g. search "
        "'s3' for cloud buckets, 'wordpress' for technologies, 'admin' for "
        "interesting paths. Returns the same priority-sorted rows as "
        "graph_top_assets."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "Case-insensitive substring."},
            "limit": {
                "type": "integer",
                "minimum": 1,
                "maximum": 100,
                "description": "Max assets to return (default 20).",
            },
        },
        "required": ["query"],
        "additionalProperties": False,
    },
}

ALL_SPECS: tuple[dict[str, Any], ...] = (
    STATS_SPEC,
    TOP_SPEC,
    NODE_SPEC,
    NEIGHBORS_SPEC,
    SEARCH_SPEC,
)


def tool_schemas() -> list[dict[str, Any]]:
    """OpenAI-style tool schemas to hand to the model."""
    return [
        {"type": "function", "function": {"name": spec["name"], "description": spec["description"], "parameters": spec["parameters"]}}
        for spec in ALL_SPECS
    ]


# --------------------------------------------------------------------------- #
# dispatcher
# --------------------------------------------------------------------------- #


def dispatch(backend: GraphBackend, name: str, arguments: dict[str, Any], *, budget_tokens: int = 8_000) -> str:
    """Run one tool call and return its budget-checked JSON view.

    This is the only function an agent loop needs: wire it to your model's
    tool-call callback with a backend instance and you are done.
    """
    try:
        if name == STATS_SPEC["name"]:
            return _stats(backend, budget_tokens)
        if name == TOP_SPEC["name"]:
            return _top(backend, arguments, budget_tokens)
        if name == NODE_SPEC["name"]:
            return _node(backend, arguments, budget_tokens)
        if name == NEIGHBORS_SPEC["name"]:
            return _neighbors(backend, arguments, budget_tokens)
        if name == SEARCH_SPEC["name"]:
            return _search(backend, arguments, budget_tokens)
        return json.dumps({"error": f"unknown tool: {name}"})
    except BudgetExceeded as exc:
        # Even the error path is honest and small.
        return json.dumps({"error": str(exc)})
    except Neo4jUnavailable as exc:
        # A down store is a small, actionable error — never a hang, never a
        # traceback in the model's context.
        return json.dumps({"error": str(exc), "hint": "the graph store is unreachable; fall back to file-based views or retry later"})


def _stats(backend: GraphBackend, budget_tokens: int) -> str:
    stats = backend.stats()
    return _within_budget([stats], {"note": "one-row overview"}, STATS_SPEC["name"], budget_tokens).to_json()


def _top(backend: GraphBackend, args: dict[str, Any], budget_tokens: int) -> str:
    rows = backend.top_by_score(
        limit=int(args.get("limit", 20)),
        band=args.get("band"),
        kind=args.get("kind"),
        min_score=args.get("min_score"),
    )
    meta = {
        "filters": {k: args[k] for k in ("band", "kind", "min_score") if args.get(k) is not None},
        "usage": "Expand any row with graph_neighbors; ids are 'kind:identity'.",
    }
    return _render_nodes(backend, TOP_SPEC["name"], rows, meta, budget_tokens)


def _node(backend: GraphBackend, args: dict[str, Any], budget_tokens: int) -> str:
    node_id = str(args["node_id"])
    node = backend.node(node_id)
    if node is None:
        return json.dumps({"error": f"no node with id {node_id!r}", "hint": "use graph_search to find ids"})
    payload = {"view": NODE_SPEC["name"], "node": node}
    return json.dumps(payload)  # single node: always small by construction


def _neighbors(backend: GraphBackend, args: dict[str, Any], budget_tokens: int) -> str:
    node_id = str(args["node_id"])
    if backend.node(node_id) is None:
        return json.dumps({"error": f"no node with id {node_id!r}", "hint": "use graph_search to find ids"})
    rows = backend.neighbors(
        node_id,
        edge_type=args.get("edge_type"),
        direction=args.get("direction", "both"),
        depth=int(args.get("depth", 1)),
    )
    rows = rows[: max(1, int(args.get("limit", 25)))]
    edges = [
        compact_edge(e)
        for e in backend.edges_of(node_id)
        if args.get("edge_type") is None or e["type"] == args["edge_type"]
    ]
    meta = {
        "expanded": node_id,
        "depth": int(args.get("depth", 1)),
        "connecting_edges": edges,
        "usage": "Rows are adjacent assets sorted by score; call graph_neighbors on any row to go deeper.",
    }
    return _render_nodes(backend, NEIGHBORS_SPEC["name"], rows, meta, budget_tokens)


def _search(backend: GraphBackend, args: dict[str, Any], budget_tokens: int) -> str:
    query = str(args.get("query", ""))
    rows = backend.search(query, limit=int(args.get("limit", 20)))
    meta = {"query": query, "usage": "Ids are 'kind:identity'; use graph_get_node for full records."}
    return _render_nodes(backend, SEARCH_SPEC["name"], rows, meta, budget_tokens)


def _render_nodes(
    backend: GraphBackend, view_name: str, rows: list[dict[str, Any]], meta: dict[str, Any], budget_tokens: int
) -> str:
    scored = sum(1 for r in rows if r.get("score") is not None)
    view = _within_budget(
        [compact_node(r) for r in rows],
        {**meta, "rows_matched": len(rows)},
        view_name,
        budget_tokens,
    )
    return view.to_json()
