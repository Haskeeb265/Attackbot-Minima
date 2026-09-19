"""The graph read side — storage-agnostic queries under a token budget.

**Why this module exists.** The LLM's world is its context window. The
converged qbsco.net graph is ~400k lines of pretty-printed JSON (~900k tokens
minified); feeding it to a model burns the budget on a task models are bad at
(needle-in-a-haystack). The fix is a division of labor: *code navigates, the
model reasons.* This module is the navigation half.

**The seam.** ``GraphBackend`` is a read-only protocol. The file backend over
``graph_state.json`` ships today; a Neo4j backend can implement the same six
methods later without any caller changing — the vuln engine's tool layer
(see ``tools.py``) speaks only this protocol, so swapping storage is invisible
to the LLM interface.

**Budgets.** Every serialized view counts its bytes (4 bytes/token rule of
thumb) and refuses to exceed the cap, trimming lowest-priority rows first.
A tool that silently returned 500 KB of JSON would burn the same credits the
full-graph dump would — so it can't.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

# Serialization budget rules: views never exceed these without raising or
# trimming, so a runaway query is a cheap error, not an expensive context bomb.
DEFAULT_VIEW_BUDGET_TOKENS = 8_000
_BYTES_PER_TOKEN = 4
# A view with no scoring context is useless for prioritization; keep the
# priority fields on every row even in the most compact shape.
_COMPACT_NODE_FIELDS = ("id", "kind", "score", "band", "trust")


# --------------------------------------------------------------------------- #
# the seam
# --------------------------------------------------------------------------- #


@runtime_checkable
class GraphBackend(Protocol):
    """Read-only view of a property graph. The only surface callers may use.

    Implementations: ``JsonFileBackend`` (today), ``Neo4jBackend`` (the graphdb
    migration). The protocol is deliberately small: seven questions — node,
    edges, neighbors, priority, search, stats, and the self-describing header.
    If a new storage engine cannot answer these, the tool layer should not
    grow to accommodate it.
    """

    def node(self, node_id: str) -> dict[str, Any] | None: ...

    def neighbors(
        self,
        node_id: str,
        *,
        edge_type: str | None = None,
        direction: str = "both",
        depth: int = 1,
    ) -> list[dict[str, Any]]: ...

    def edges_of(self, node_id: str) -> list[dict[str, Any]]: ...

    def top_by_score(
        self,
        *,
        limit: int = 20,
        band: str | None = None,
        kind: str | None = None,
        min_score: int | None = None,
    ) -> list[dict[str, Any]]: ...

    def search(self, query: str, *, limit: int = 20) -> list[dict[str, Any]]: ...

    def stats(self) -> dict[str, Any]: ...

    def header(self) -> dict[str, Any]: ...


# --------------------------------------------------------------------------- #
# budget-guarded serialization
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class View:
    """A serialized, budget-checked slice of the graph.

    ``rows`` are compact node dicts; ``meta`` carries the view's own accounting
    (truncation, token estimate) so a caller — or the LLM — can see whether it
    got the whole picture or a bounded window onto it.
    """

    view: str
    rows: list[dict[str, Any]]
    meta: dict[str, Any]

    def to_json(self) -> str:
        return json.dumps({"view": self.view, "rows": self.rows, "meta": self.meta})


class BudgetExceeded(RuntimeError):
    """A view's bytes could not fit the token budget even after trimming."""


def _estimate_tokens(payload: str) -> int:
    return len(payload) // _BYTES_PER_TOKEN


def _within_budget(
    rows: list[dict[str, Any]],
    meta: dict[str, Any],
    view_name: str,
    budget_tokens: int,
) -> View:
    """Serialize rows, trimming the tail until the view fits its budget.

    Trimming drops the lowest-priority rows (``rows`` are expected sorted
    best-first), and the meta block always reports honestly what happened.
    """
    def render(selected: list[dict[str, Any]], truncated: bool, dropped: int = 0) -> View:
        meta_out = {**meta, "truncated": truncated}
        if truncated:
            meta_out["rows_dropped"] = dropped
        payload = json.dumps({"view": view_name, "rows": selected, "meta": meta_out})
        return View(
            view=view_name,
            rows=selected,
            meta={**meta_out, "tokens": _estimate_tokens(payload)},
        )

    if _estimate_tokens(json.dumps({"rows": rows, "meta": meta})) <= budget_tokens:
        return render(rows, truncated=False)

    # Trim from the end (rows are sorted best-first) until it fits; keep at
    # least one row so a view is never vacuously empty.
    for keep in range(len(rows) - 1, 0, -1):
        candidate = rows[:keep]
        if _estimate_tokens(json.dumps({"rows": candidate})) <= budget_tokens:
            return render(candidate, truncated=True, dropped=len(rows) - keep)
    raise BudgetExceeded(
        f"view {view_name!r} cannot fit {budget_tokens}-token budget even with 1 row"
    )


def compact_node(node: dict[str, Any]) -> dict[str, Any]:
    """The LLM-facing shape: identity, priority, trust, facts — no scaffolding.

    ``score_audit`` (the scoring engine's reasoning chain) and ``labels``/
    ``evidence_state`` bookkeeping are omitted: they exist for code and for
    humans auditing a single node, not for a model scanning 20 rows.
    """
    out: dict[str, Any] = {k: node[k] for k in _COMPACT_NODE_FIELDS if k in node}
    if node.get("evidence_state") not in (None, "unverified"):
        out["evidence_state"] = node["evidence_state"]
    props = node.get("props") or {}
    if props:
        out["props"] = props
    return out


def compact_edge(edge: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": edge["type"],
        "from": edge["from"],
        "to": edge["to"],
        **({"props": edge["props"]} if edge.get("props") else {}),
    }


# --------------------------------------------------------------------------- #
# the file backend
# --------------------------------------------------------------------------- #


class JsonFileBackend:
    """``GraphBackend`` over a ``graph_state.json`` snapshot.

    Loads the document once, indexes it in memory, and serves queries from the
    indexes. A read lock guards lazy index builds; queries themselves are pure
    reads of immutable structures.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._lock = threading.Lock()
        self._doc: dict[str, Any] | None = None
        self._nodes: dict[str, dict[str, Any]] | None = None
        self._adj: dict[str, list[dict[str, Any]]] | None = None
        self._search_index: dict[str, str] | None = None

    # -- loading ------------------------------------------------------------

    def _load(self) -> tuple[dict[str, Any], dict[str, dict[str, Any]], dict[str, list[dict[str, Any]]]]:
        if self._doc is not None:
            return self._doc, self._nodes or {}, self._adj or {}
        with self._lock:
            if self._doc is None:
                doc = json.loads(self._path.read_text(encoding="utf-8"))
                nodes = {n["id"]: n for n in doc.get("nodes", [])}
                adj: dict[str, list[dict[str, Any]]] = {}
                for edge in doc.get("edges", []):
                    for endpoint in (edge["from"], edge["to"]):
                        adj.setdefault(endpoint, []).append(edge)
                self._doc = doc
                self._nodes = nodes
                self._adj = adj
                self._search_index = None
        return self._doc, self._nodes or {}, self._adj or {}

    def _doc_loaded(self) -> dict[str, Any]:
        return self._load()[0]

    def _nodes_loaded(self) -> dict[str, dict[str, Any]]:
        return self._load()[1]

    def _adj_loaded(self) -> dict[str, list[dict[str, Any]]]:
        return self._load()[2]

    # -- GraphBackend ---------------------------------------------------------

    def node(self, node_id: str) -> dict[str, Any] | None:
        return self._nodes_loaded().get(node_id)

    def edges_of(self, node_id: str) -> list[dict[str, Any]]:
        return list(self._adj_loaded().get(node_id, ()))

    def neighbors(
        self,
        node_id: str,
        *,
        edge_type: str | None = None,
        direction: str = "both",
        depth: int = 1,
    ) -> list[dict[str, Any]]:
        """Node rows for everything reachable within ``depth`` hops.

        Depth > 1 walks the adjacency breadth-first; visited-set guarded, so
        rotational-IP hubs (round 2 taught us: one domain -> 12 addresses)
        cannot fan out into the whole network kind.
        """
        if node_id not in self._nodes_loaded():
            return []
        depth = max(1, min(depth, 4))
        frontier = {node_id}
        visited = {node_id}
        out: dict[str, dict[str, Any]] = {}
        for _ in range(depth):
            nxt: set[str] = set()
            for current in frontier:
                for edge in self._adj_loaded().get(current, ()):
                    if edge_type is not None and edge["type"] != edge_type:
                        continue
                    other = edge["to"] if edge["from"] == current else edge["from"]
                    if direction == "out" and edge["from"] != current:
                        continue
                    if direction == "in" and edge["to"] != current:
                        continue
                    if other not in visited and other in self._nodes_loaded():
                        out[other] = self._nodes_loaded()[other]
                        visited.add(other)
                        nxt.add(other)
            frontier = nxt
            if not frontier:
                break
        return _sorted_rows(out.values())

    def top_by_score(
        self,
        *,
        limit: int = 20,
        band: str | None = None,
        kind: str | None = None,
        min_score: int | None = None,
    ) -> list[dict[str, Any]]:
        rows = [
            n
            for n in self._nodes_loaded().values()
            if n.get("score") is not None
            and (band is None or n.get("band") == band)
            and (kind is None or n["kind"] == kind)
            and (min_score is None or (n.get("score") or 0) >= min_score)
        ]
        return _sorted_rows(rows)[: max(1, limit)]

    def search(self, query: str, *, limit: int = 20) -> list[dict[str, Any]]:
        """Case-insensitive substring match over id + identity + props.

        A cheap inverted-ish index: one lowercased blob per node, built once.
        """
        q = query.lower().strip()
        if not q:
            return []
        index = self._search_index
        if index is None:
            index = {
                nid: json.dumps([nid, n.get("identity", ""), n.get("props", {})]).lower()
                for nid, n in self._nodes_loaded().items()
            }
            self._search_index = index
        hits = [
            self._nodes_loaded()[nid]
            for nid, blob in index.items()
            if q in blob
        ]
        return _sorted_rows(hits)[: max(1, limit)]

    def stats(self) -> dict[str, Any]:
        doc, nodes, adj = self._load()
        by_kind: dict[str, int] = {}
        by_band: dict[str, int] = {}
        for n in nodes.values():
            by_kind[n["kind"]] = by_kind.get(n["kind"], 0) + 1
            if n.get("band"):
                by_band[n["band"]] = by_band.get(n["band"], 0) + 1
        return {
            "target": doc.get("target"),
            "generated_at": doc.get("generated_at"),
            "node_count": len(nodes),
            "edge_count": len(doc.get("edges", ())),
            "nodes_by_kind": by_kind,
            "nodes_by_band": by_band,
        }

    # -- header passthrough (the self-describing part) ------------------------

    def header(self) -> dict[str, Any]:
        """The document's own contract: vocabulary, scoring, integrity.

        The vuln engine reads this first — it tells the model (and the code)
        what node kinds and edge types exist and how scores were derived.
        """
        doc = self._doc_loaded()
        return {
            "target": doc.get("target"),
            "generated_at": doc.get("generated_at"),
            "vocabulary": doc.get("vocabulary"),
            "scoring": doc.get("scoring"),
            "integrity": doc.get("integrity"),
        }


# --------------------------------------------------------------------------- #
# row ordering
# --------------------------------------------------------------------------- #


def _sorted_rows(rows: Any) -> list[dict[str, Any]]:
    """Score desc, then id — deterministic order so views are stable."""
    return sorted(
        rows,
        key=lambda n: (-(n.get("score") or 0), n["id"]),
    )
