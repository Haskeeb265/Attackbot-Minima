"""The Neo4j read side — the first ``GraphBackend`` that is not a file.

**The seam holds.** ``GraphBackend`` (``reader.py``) was written so a real
store could arrive without the vuln engine's interface changing. This module
implements the same methods in Cypher; nothing above the protocol — not
``tools.py``, not the future agent loop — changes by a line.

**Identity, not insertion.** The one mechanic the write seam kept from the
pre-run schema is honored here: nodes merge on their canonical ``id``
(``kind:identity`` — the same identity the journal and the file model use), so
re-loading a snapshot or replaying a journal *upserts* rather than duplicates.
Time follows the model: ``first_seen`` is write-once (``coalesce``),
``last_seen`` ratchets forward (a ``CASE`` max), and everything else is
latest-wins. A graph that spans runs is the point of a database.

**The whitelist is the schema.** Relationship types are not interpolated into
Cypher from input — every type is checked against the settled vocabulary
(``graph_normalize.vocabulary.GRAPH_RELATIONSHIPS``) and an unknown type fails
loudly. A store that silently invented a relationship type would be worse than
no store.

**Degradation, read-side edition.** A store that is down must be a clean,
honest error — never a hang, never a partial answer dressed as truth.
``Neo4jUnavailable`` carries the reason; callers (the tool dispatcher) turn it
into a small JSON error the model can act on.
"""

from __future__ import annotations

import json
import logging
from typing import Any

log = logging.getLogger("platform.graph.neo4j")

#: The meta node that carries the file header's self-describing contract.
_META_ID = "target"

# Query-building helpers are pure so the whitelist and pattern rules can be
# tested hermetically, without a server.


def _rel_type_for(edge_type: str) -> str:
    """Map a neutral edge type to its relationship name — or refuse.

    The lazy import keeps ``platform/`` independent of ``pipelines/`` at module
    load time; the vocabulary is a constant, not runtime coupling.
    """
    from service.recon_pipeline.pipelines.graph_normalize.vocabulary import (
        GRAPH_RELATIONSHIPS,
    )

    if edge_type not in GRAPH_RELATIONSHIPS:
        raise ValueError(
            f"edge type {edge_type!r} is not in the settled vocabulary; "
            "refusing to invent a relationship type"
        )
    return GRAPH_RELATIONSHIPS[edge_type][0]


def _neighbor_pattern(
    edge_type: str | None, direction: str, depth: int
) -> str:
    """The Cypher bracket segment for one ``neighbors`` call.

    Returns only the relationship hop (``-[:REL*1..d]->``) — the caller binds
    the starting node itself, so the pattern composes as one path:
    ``MATCH (a:Asset {id: $id})<segment>(b:Asset)``. (Declaring ``(a)`` twice
    juxtaposes two patterns, which is a Cypher syntax error — the live run
    caught exactly that.) Depth is clamped to the same 1..4 window the file
    backend uses and interpolated as a validated integer; the type comes from
    the whitelist.
    """
    depth = max(1, min(int(depth), 4))
    rel_part = f":{_rel_type_for(edge_type)}" if edge_type is not None else ""
    if direction == "out":
        return f"-[{rel_part}*1..{depth}]->"
    if direction == "in":
        return f"<-[{rel_part}*1..{depth}]-"
    return f"-[{rel_part}*1..{depth}]-"


_NODE_UPSERT = """
MERGE (n:Asset {id: $id})
SET n.kind = $kind,
    n.identity = $identity,
    n.trust = $trust,
    n.score = $score,
    n.band = $band,
    n.evidence_state = $evidence_state,
    n.props = $props,
    n.sources = $sources,
    n.labels = $labels,
    n.score_audit = $score_audit,
    n.search_blob = $search_blob,
    n.first_seen = coalesce(n.first_seen, $first_seen),
    n.last_seen = CASE
        WHEN n.last_seen IS NULL OR ($last_seen IS NOT NULL AND n.last_seen < $last_seen)
        THEN $last_seen ELSE n.last_seen END
"""


def _node_upsert_query() -> str:
    """The batched node upsert: ``row.*`` fields, the identity merge, time rules.

    Built once from the single-row template by naming the parameters — the
    template stays readable and the batched form stays exactly parallel to it.
    """
    return "UNWIND $rows AS row " + (
        _NODE_UPSERT
        .replace("$id", "row.id")
        .replace("$kind", "row.kind")
        .replace("$identity", "row.identity")
        .replace("$trust", "row.trust")
        .replace("$score", "row.score")
        .replace("$band", "row.band")
        .replace("$evidence_state", "row.evidence_state")
        .replace("$props", "row.props")
        .replace("$sources", "row.sources")
        .replace("$labels", "row.labels")
        .replace("$score_audit", "row.score_audit")
        .replace("$search_blob", "row.search_blob")
        .replace("$first_seen", "row.first_seen")
        .replace("$last_seen", "row.last_seen")
    )


def _node_params(row: dict[str, Any]) -> dict[str, Any]:
    props = row.get("props") or {}
    return {
        "id": row["id"],
        "kind": row.get("kind"),
        "identity": row.get("identity"),
        "trust": row.get("trust"),
        "score": row.get("score"),
        "band": row.get("band"),
        "evidence_state": row.get("evidence_state"),
        "props": json.dumps(props, ensure_ascii=False) if props else None,
        "sources": list(row.get("sources") or ()),
        "labels": list(row.get("labels") or ()),
        "score_audit": list(row.get("score_audit") or ()),
        "search_blob": json.dumps(props, ensure_ascii=False).lower() if props else "",
        "first_seen": row.get("first_seen"),
        "last_seen": row.get("last_seen"),
    }


def _edge_params(edge: dict[str, Any]) -> dict[str, Any]:
    props = edge.get("props") or {}
    return {
        "src": edge["from"],
        "dst": edge["to"],
        "trust": edge.get("trust"),
        "props": json.dumps(props, ensure_ascii=False) if props else None,
        "sources": list(edge.get("sources") or ()),
        "evidence": list(edge.get("evidence") or ()),
        "first_seen": edge.get("first_seen"),
        "last_seen": edge.get("last_seen"),
    }


_EDGE_UPSERT = """
MATCH (a:Asset {id: $src}), (b:Asset {id: $dst})
MERGE (a)-[r:{rel}]->(b)
SET r.trust = $trust,
    r.props = $props,
    r.sources = $sources,
    r.evidence = $evidence,
    r.first_seen = coalesce(r.first_seen, $first_seen),
    r.last_seen = CASE
        WHEN r.last_seen IS NULL OR ($last_seen IS NOT NULL AND r.last_seen < $last_seen)
        THEN $last_seen ELSE r.last_seen END
"""


#: The batched node upsert, built once at import (pure string work).
_EDGE_PARAM_NAMES = ("src", "dst", "trust", "props", "sources", "evidence", "first_seen", "last_seen")
_NODE_UPSERT_BATCHED = _node_upsert_query()


def _edge_upsert_batched(rel: str) -> str:
    """The batched edge upsert for one whitelist-validated relationship type.

    Same rewrite as the node query: ``row.*`` fields so one ``UNWIND`` batch
    shares the parameters. Built per type and cached by the loader.
    """
    q = _EDGE_UPSERT.replace("{rel}", rel)
    for name in _EDGE_PARAM_NAMES:
        q = q.replace(f"${name}", f"row.{name}")
    return "UNWIND $rows AS row " + q


class Neo4jUnavailable(RuntimeError):
    """The store is unreachable, unconfigured, or the driver is missing."""


class Neo4jBackend:
    """``GraphBackend`` over a live Neo4j — same six answers, Cypher underneath.

    Construction is lazy: no connection is attempted until the first query, so
    building a backend is always safe and *using* one degrades cleanly.
    """

    def __init__(
        self,
        uri: str,
        username: str,
        password: str,
        database: str | None = None,
    ) -> None:
        self._uri = uri
        self._auth = (username, password)
        self._database = database or None
        self._driver: Any = None

    # -- connection ----------------------------------------------------------

    def _require_driver(self) -> Any:
        if self._driver is not None:
            return self._driver
        try:
            from neo4j import GraphDatabase  # noqa: PLC0415 — lazy: optional dep
        except ImportError as exc:
            raise Neo4jUnavailable(
                "the neo4j driver is not installed (pip install neo4j)"
            ) from exc
        try:
            driver = GraphDatabase.driver(self._uri, auth=self._auth)
            driver.verify_connectivity()
        except Exception as exc:  # driver raises several types; all mean "down"
            raise Neo4jUnavailable(f"neo4j at {self._uri} is unreachable: {exc}") from exc
        self._driver = driver
        return driver

    def _run(self, query: str, **params: Any) -> list[dict[str, Any]]:
        driver = self._require_driver()
        try:
            with driver.session(
                database=self._database,
                notifications_min_severity="WARNING",
            ) as session:
                return [dict(record) for record in session.run(query, **params)]
        except Neo4jUnavailable:
            raise
        except Exception as exc:
            raise Neo4jUnavailable(f"neo4j query failed: {exc}") from exc

    def close(self) -> None:
        if self._driver is not None:
            self._driver.close()
            self._driver = None

    # -- GraphBackend ----------------------------------------------------------

    def node(self, node_id: str) -> dict[str, Any] | None:
        rows = self._run(
            "MATCH (n:Asset {id: $id}) RETURN n LIMIT 1", id=node_id
        )
        if not rows:
            return None
        return _node_from_record(rows[0]["n"])

    def edges_of(self, node_id: str) -> list[dict[str, Any]]:
        rows = self._run(
            """
            MATCH (a:Asset {id: $id})-[r]-(b:Asset)
            RETURN type(r) AS type,
                   startNode(r).id AS from, endNode(r).id AS to,
                   r.trust AS trust, r.sources AS sources,
                   r.props AS props, r.evidence AS evidence
            """,
            id=node_id,
        )
        return [_edge_from_record(row) for row in rows]

    def neighbors(
        self,
        node_id: str,
        *,
        edge_type: str | None = None,
        direction: str = "both",
        depth: int = 1,
    ) -> list[dict[str, Any]]:
        pattern = _neighbor_pattern(edge_type, direction, depth)
        rows = self._run(
            f"""
            MATCH (a:Asset {{id: $id}}){pattern}(b:Asset)
            WHERE b.id <> $id
            RETURN DISTINCT b ORDER BY coalesce(b.score, -1) DESC, b.id
            """,
            id=node_id,
        )
        return [_node_from_record(row["b"]) for row in rows]

    def top_by_score(
        self,
        *,
        limit: int = 20,
        band: str | None = None,
        kind: str | None = None,
        min_score: int | None = None,
    ) -> list[dict[str, Any]]:
        rows = self._run(
            """
            MATCH (n:Asset)
            WHERE n.score IS NOT NULL
              AND ($band IS NULL OR n.band = $band)
              AND ($kind IS NULL OR n.kind = $kind)
              AND ($min_score IS NULL OR n.score >= $min_score)
            RETURN n
            ORDER BY n.score DESC, n.id
            LIMIT $limit
            """,
            band=band,
            kind=kind,
            min_score=min_score,
            limit=max(1, int(limit)),
        )
        return [_node_from_record(row["n"]) for row in rows]

    def search(self, query: str, *, limit: int = 20) -> list[dict[str, Any]]:
        q = query.lower().strip()
        if not q:
            return []
        rows = self._run(
            """
            MATCH (n:Asset)
            WHERE toLower(n.id) CONTAINS $q
               OR toLower(coalesce(n.identity, '')) CONTAINS $q
               OR (n.search_blob IS NOT NULL AND n.search_blob CONTAINS $q)
            RETURN n
            ORDER BY coalesce(n.score, -1) DESC, n.id
            LIMIT $limit
            """,
            q=q,
            limit=max(1, int(limit)),
        )
        return [_node_from_record(row["n"]) for row in rows]

    def stats(self) -> dict[str, Any]:
        counts = self._run(
            """
            MATCH (n:Asset)
            RETURN count(n) AS node_count,
                   count(n.kind) AS kinds_seen
            """
        )
        by_kind = self._run(
            "MATCH (n:Asset) RETURN n.kind AS kind, count(*) AS c ORDER BY c DESC"
        )
        by_band = self._run(
            """
            MATCH (n:Asset) WHERE n.band IS NOT NULL
            RETURN n.band AS band, count(*) AS c ORDER BY c DESC
            """
        )
        edges = self._run("MATCH ()-[r]->() RETURN count(r) AS c")
        meta = self._run(
            f"MATCH (m:GraphMeta {{id: '{_META_ID}'}}) "
            "RETURN m.target AS target, m.generated_at AS generated_at"
        )
        m = meta[0] if meta else {}
        return {
            "target": m.get("target"),
            "generated_at": m.get("generated_at"),
            "node_count": counts[0]["node_count"] if counts else 0,
            "edge_count": edges[0]["c"] if edges else 0,
            "nodes_by_kind": {row["kind"]: row["c"] for row in by_kind if row["kind"]},
            "nodes_by_band": {row["band"]: row["c"] for row in by_band},
        }

    def header(self) -> dict[str, Any]:
        rows = self._run(
            f"MATCH (m:GraphMeta {{id: '{_META_ID}'}}) "
            "RETURN m.target AS target, m.generated_at AS generated_at, "
            "m.vocabulary AS vocabulary, m.scoring AS scoring, "
            "m.integrity AS integrity"
        )
        if not rows:
            return {}
        r = rows[0]
        return {
            "target": r.get("target"),
            "generated_at": r.get("generated_at"),
            "vocabulary": _maybe_json(r.get("vocabulary")),
            "scoring": _maybe_json(r.get("scoring")),
            "integrity": _maybe_json(r.get("integrity")),
        }


# --------------------------------------------------------------------------- #
# record decoding — the store stores strings where the model has structures
# --------------------------------------------------------------------------- #


def _maybe_json(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (TypeError, ValueError):
            return value
    return value


def _node_from_record(n: Any) -> dict[str, Any]:
    out = dict(n)
    out["props"] = _maybe_json(out.get("props")) or {}
    return out


def _edge_from_record(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": row.get("type"),
        "from": row.get("from"),
        "to": row.get("to"),
        "trust": row.get("trust"),
        "sources": row.get("sources") or [],
        "props": _maybe_json(row.get("props")) or {},
        "evidence": row.get("evidence") or [],
    }


# --------------------------------------------------------------------------- #
# the write side of the migration: constraints + snapshot load
# --------------------------------------------------------------------------- #


def ensure_constraints(db: Neo4jBackend) -> None:
    """The whole index set — four constraints, nothing speculative.

    ``Asset.id`` uniqueness is the identity mechanic; the property indexes make
    the backend's own queries (kind/band filters, meta lookup) cheap. Creating
    constraints is idempotent (``IF NOT EXISTS``).
    """
    for stmt in (
        "CREATE CONSTRAINT asset_id IF NOT EXISTS FOR (n:Asset) REQUIRE n.id IS UNIQUE",
        "CREATE CONSTRAINT graph_meta_id IF NOT EXISTS FOR (m:GraphMeta) REQUIRE m.id IS UNIQUE",
        "CREATE INDEX asset_kind IF NOT EXISTS FOR (n:Asset) ON (n.kind)",
        "CREATE INDEX asset_band IF NOT EXISTS FOR (n:Asset) ON (n.band)",
    ):
        db._run(stmt)


def load_snapshot(
    db: Neo4jBackend,
    doc: dict[str, Any],
    *,
    batch_size: int = 500,
) -> dict[str, int]:
    """Load one ``graph_state.json`` document into the store — the migration.

    Merges by canonical id (identity, not insertion); unknown edge types are
    refused (the whitelist is the schema); the header's self-describing
    contract lands on a single ``GraphMeta`` node so ``header()`` works.
    """
    nodes = list(doc.get("nodes") or ())
    edges = list(doc.get("edges") or ())
    rel_cache: dict[str, str] = {}

    db._run(
        f"MERGE (m:GraphMeta {{id: '{_META_ID}'}}) "
        "SET m.target = $target, m.generated_at = $generated_at, "
        "m.vocabulary = $vocabulary, m.scoring = $scoring, m.integrity = $integrity",
        target=doc.get("target"),
        generated_at=doc.get("generated_at"),
        vocabulary=json.dumps(doc.get("vocabulary"), ensure_ascii=False),
        scoring=json.dumps(doc.get("scoring"), ensure_ascii=False),
        integrity=json.dumps(doc.get("integrity"), ensure_ascii=False),
    )

    for i in range(0, len(nodes), batch_size):
        batch = [_node_params(n) for n in nodes[i : i + batch_size]]
        db._run(_NODE_UPSERT_BATCHED, rows=batch)

    loaded_edges = 0
    for i in range(0, len(edges), batch_size):
        batch = edges[i : i + batch_size]
        # One statement per relationship type in the batch: the type is the
        # whitelist-validated literal, the rows carry only endpoints/props.
        by_type: dict[str, list[dict[str, Any]]] = {}
        for edge in batch:
            etype = edge["type"]
            if etype not in rel_cache:
                rel_cache[etype] = _rel_type_for(etype)
            by_type.setdefault(rel_cache[etype], []).append(_edge_params(edge))
        for rel, rows in by_type.items():
            db._run(_edge_upsert_batched(rel), rows=rows)
            loaded_edges += len(rows)

    return {"nodes": len(nodes), "edges": loaded_edges}


# --------------------------------------------------------------------------- #
# the migration CLI — env-gated, honest about what it did
# --------------------------------------------------------------------------- #


def main() -> int:
    """Load the current ``graph_state.json`` into the configured Neo4j.

    Reads the same ``NEO4J_*`` settings the compose stack and the old
    ``config.py`` contract use. Refuses to guess credentials: no env, no run,
    exit code 2 and a message saying exactly what is missing.
    """
    import os
    import sys
    from pathlib import Path

    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

    uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    username = os.getenv("NEO4J_USERNAME")
    password = os.getenv("NEO4J_PASSWORD")
    database = os.getenv("NEO4J_DATABASE") or None
    if not username or not password:
        print(
            "NEO4J_USERNAME / NEO4J_PASSWORD are not set — refusing to guess "
            "credentials. Export them (compose .env has them) and retry.",
            file=sys.stderr,
        )
        return 2

    from service.recon_pipeline.pipelines.graph_normalize import settings as gn_settings

    state_path = Path(gn_settings.OUTPUT_DIR) / "graph_state.json"
    if not state_path.exists():
        print(f"no graph_state.json at {state_path} — run graph_normalize first", file=sys.stderr)
        return 2

    db = Neo4jBackend(uri, username, password, database)
    try:
        ensure_constraints(db)
    except Neo4jUnavailable as exc:
        print(str(exc), file=sys.stderr)
        return 1

    doc = json.loads(state_path.read_text(encoding="utf-8"))
    counts = load_snapshot(db, doc)
    stats = db.stats()
    log.info(
        "loaded %d nodes / %d edges; store now holds %d nodes / %d edges for target %s",
        counts["nodes"],
        counts["edges"],
        stats["node_count"],
        stats["edge_count"],
        stats["target"],
    )
    db.close()
    return 0


if __name__ == "__main__":  # pragma: no cover — manual migration entry point
    raise SystemExit(main())
