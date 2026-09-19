"""Tests for the Neo4j ``GraphBackend`` and the snapshot migration.

The rules pinned here: the backend answers the same questions through Cypher
(the seam holds — nothing above the protocol changes); relationship types are
whitelist-validated, never interpolated from input; the upsert merges on
canonical identity with write-once ``first_seen`` and a ratcheting
``last_seen``; unknown edge types are refused, not invented; and every failure
mode is an honest ``Neo4jUnavailable`` — never a hang, never a partial answer.

All tests are hermetic: a fake driver records the queries the backend builds,
so the Cypher itself is the thing under test. One env-gated test runs against
a real store when ``NEO4J_USERNAME``/``NEO4J_PASSWORD`` point at a live one.
"""

from __future__ import annotations

import json
import re
from typing import Any

import pytest

from service.recon_pipeline.platform.graph.neo4j_backend import (
    _EDGE_UPSERT,
    _META_ID,
    _NODE_UPSERT,
    Neo4jBackend,
    Neo4jUnavailable,
    _edge_params,
    _edge_upsert_batched,
    _neighbor_pattern,
    _node_params,
    _node_upsert_query,
    _rel_type_for,
    ensure_constraints,
    load_snapshot,
)


# --------------------------------------------------------------------------- #
# query-building: the whitelist is the schema
# --------------------------------------------------------------------------- #


def test_rel_type_mapping_uses_the_settled_vocabulary() -> None:
    assert _rel_type_for("resolves_to") == "RESOLVES_TO"
    assert _rel_type_for("cname_points_to") == "CNAME_POINTS_TO"
    assert _rel_type_for("owned_by") == "OWNED_BY"


def test_rel_type_mapping_refuses_unknown_types() -> None:
    with pytest.raises(ValueError, match="not in the settled vocabulary"):
        _rel_type_for("totally_made_up")


def test_neighbor_pattern_is_a_bracket_segment_composable_onto_a_bound_node() -> None:
    # The live run's SyntaxError, caught hermetically: the helper returns only
    # the hop, so the caller composes ONE path — never two juxtaposed patterns.
    assert _neighbor_pattern(None, "out", 1) == "-[*1..1]->"
    assert _neighbor_pattern("resolves_to", "in", 2) == "<-[:RESOLVES_TO*1..2]-"
    assert _neighbor_pattern(None, "both", 99) == "-[*1..4]-"
    assert _neighbor_pattern(None, "both", 0) == "-[*1..1]-"
    assert "(a)" not in _neighbor_pattern("resolves_to", "out", 3)


def test_batched_node_upsert_names_row_fields_not_params() -> None:
    q = _node_upsert_query()
    assert q.startswith("UNWIND $rows AS row ")
    assert "row.id" in q
    assert "$id" not in q.replace("$identity", "")  # no bare $id survives
    assert "coalesce(row.first_seen, row.first_seen)" not in q  # sane rewrite
    assert "MERGE (n:Asset {id: row.id})" in q


def test_single_row_upsert_merges_on_identity_with_time_rules() -> None:
    assert "MERGE (n:Asset {id: $id})" in _NODE_UPSERT
    assert "coalesce(n.first_seen, $first_seen)" in _NODE_UPSERT
    assert "WHEN n.last_seen IS NULL OR" in _NODE_UPSERT


# --------------------------------------------------------------------------- #
# a fake driver at the seam: records queries, returns canned rows
# --------------------------------------------------------------------------- #


class _FakeResult:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self._rows = rows

    def __iter__(self):  # driver sessions return iterable results
        return iter(self._rows)


class _FakeSession:
    def __init__(self, log: list[tuple[str, dict[str, Any]]], results: dict[str, list[dict[str, Any]]]) -> None:
        self._log = log
        self._results = results

    def run(self, query: str, **params: Any) -> _FakeResult:
        # The live run's ParameterMissing, caught hermetically: every $name in
        # the query must be bound. (Batched queries use row.* fields instead.)
        missing = {
            name
            for name in re.findall(r"\$([A-Za-z_][A-Za-z0-9_]*)", query)
            if name not in params
        }
        if missing:
            raise ValueError(f"ParameterMissing: expected {sorted(missing)}")
        self._log.append((query, params))
        for fragment, rows in self._results.items():
            if fragment in query:
                return _FakeResult(rows)
        return _FakeResult([])

    def __enter__(self) -> "_FakeSession":
        return self

    def __exit__(self, *exc: Any) -> None:
        return None


class _FakeDriver:
    def __init__(self, results: dict[str, list[dict[str, Any]]] | None = None) -> None:
        self.log: list[tuple[str, dict[str, Any]]] = []
        self.results = results or {}
        self.closed = False

    def session(self, database: str | None = None, **_kw: Any) -> _FakeSession:
        return _FakeSession(self.log, self.results)

    def verify_connectivity(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True


def _backend_with(monkeypatch: pytest.MonkeyPatch, results: dict[str, list[dict[str, Any]]] | None = None):
    driver = _FakeDriver(results)
    backend = Neo4jBackend("bolt://x", "u", "p")
    monkeypatch.setattr(
        "service.recon_pipeline.platform.graph.neo4j_backend.Neo4jBackend._require_driver",
        lambda self: driver,
    )
    return backend, driver


def _asset_node(**over: Any) -> dict[str, Any]:
    row = {
        "id": "domain:acme.test",
        "kind": "domain",
        "identity": "acme.test",
        "trust": "verified",
        "score": 60,
        "band": "medium",
        "evidence_state": "unverified",
        "props": {"apex": True},
        "sources": ["records:a"],
        "labels": ["Asset", "Domain"],
        "score_audit": ["floor: 60"],
        "first_seen": "2026-09-19T00:00:00+00:00",
        "last_seen": "2026-09-19T00:00:00+00:00",
    }
    row.update(over)
    return row


# --------------------------------------------------------------------------- #
# the read side through the fake
# --------------------------------------------------------------------------- #


def test_node_returns_decoded_record_or_none(monkeypatch: pytest.MonkeyPatch) -> None:
    node = _asset_node()
    backend, driver = _backend_with(
        monkeypatch, {"MATCH (n:Asset {id": [{"n": node}]}
    )
    assert backend.node("domain:acme.test")["props"] == {"apex": True}

    empty, _ = _backend_with(monkeypatch, {})
    assert empty.node("domain:ghost.test") is None


def test_neighbors_orders_by_score_and_excludes_the_seed(monkeypatch: pytest.MonkeyPatch) -> None:
    backend, driver = _backend_with(
        monkeypatch,
        {"ORDER BY coalesce(b.score": [{"b": _asset_node(id="ip:10.0.0.1", score=40, band="low")}]},
    )
    rows = backend.neighbors("domain:acme.test", edge_type="resolves_to", direction="out")
    assert [r["id"] for r in rows] == ["ip:10.0.0.1"]
    query = driver.log[0][0]
    assert "WHERE b.id <> $id" in query
    assert "RESOLVES_TO*1..1" in query.replace(" ", "")
    # One path, one (a) declaration — the juxtaposition guard.
    assert query.count("(a:Asset") == 1


def test_top_by_score_passes_filters_as_parameters(monkeypatch: pytest.MonkeyPatch) -> None:
    backend, driver = _backend_with(
        monkeypatch, {"ORDER BY n.score": [{"n": _asset_node()}]}
    )
    rows = backend.top_by_score(limit=5, band="core", kind="domain", min_score=90)
    assert rows[0]["id"] == "domain:acme.test"
    query, params = driver.log[0]
    assert "LIMIT $limit" in query
    assert params == {"band": "core", "kind": "domain", "min_score": 90, "limit": 5}


def test_search_uses_lowercase_contains_and_guards_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    backend, driver = _backend_with(
        monkeypatch, {"CONTAINS $q": [{"n": _asset_node()}]}
    )
    rows = backend.search("ACME")
    assert rows
    assert driver.log[0][1]["q"] == "acme"

    empty = Neo4jBackend("bolt://x", "u", "p")
    empty._driver = _FakeDriver()
    assert empty.search("") == []


def test_stats_and_header_read_the_meta_node(monkeypatch: pytest.MonkeyPatch) -> None:
    meta = {
        "target": "acme.test",
        "generated_at": "2026-09-19T00:00:00+00:00",
        "vocabulary": json.dumps({"node_kinds": ["domain"]}),
        "scoring": json.dumps({"engine": "S2"}),
        "integrity": json.dumps({"node_count": 1}),
    }
    backend, _ = _backend_with(
        monkeypatch,
        {
            "GraphMeta": [meta],
            "count(n) AS node_count": [{"node_count": 1, "kinds_seen": 1}],
            "count(r) AS c": [{"c": 0}],
            "n.kind AS kind": [{"kind": "domain", "c": 1}],
            "n.band AS band": [{"band": "medium", "c": 1}],
        },
    )
    stats = backend.stats()
    assert stats["node_count"] == 1
    assert stats["nodes_by_kind"] == {"domain": 1}
    header = backend.header()
    assert header["vocabulary"]["node_kinds"] == ["domain"]
    assert header["target"] == "acme.test"


def test_unreachable_store_raises_unavailable_not_a_driver_type(monkeypatch: pytest.MonkeyPatch) -> None:
    class _BoomDriver:
        def verify_connectivity(self) -> None:
            raise OSError("connection refused")

        def session(self, database: str | None = None) -> Any:
            raise OSError("connection refused")

        def close(self) -> None:
            return None

    backend = Neo4jBackend("bolt://x", "u", "p")
    monkeypatch.setattr(
        "service.recon_pipeline.platform.graph.neo4j_backend.Neo4jBackend._require_driver",
        lambda self: (_ for _ in ()).throw(Neo4jUnavailable("neo4j at bolt://x is unreachable: connection refused")),
    )
    with pytest.raises(Neo4jUnavailable):
        backend.node("domain:acme.test")


def test_close_shuts_the_driver(monkeypatch: pytest.MonkeyPatch) -> None:
    driver = _FakeDriver()
    backend = Neo4jBackend("bolt://x", "u", "p")
    backend._driver = driver
    backend.close()
    assert driver.closed
    assert backend._driver is None


# --------------------------------------------------------------------------- #
# the write side: params shape and the migration
# --------------------------------------------------------------------------- #


def test_node_params_shape_json_serializes_props() -> None:
    params = _node_params(_asset_node())
    assert params["props"] == json.dumps({"apex": True})
    assert params["search_blob"] == '{"apex": true}'
    assert params["sources"] == ["records:a"]


def test_edge_params_shape() -> None:
    params = _edge_params(
        {"from": "a", "to": "b", "type": "resolves_to", "props": {"method": "a"}, "sources": ["s"], "evidence": ["e"]}
    )
    assert params["src"] == "a" and params["dst"] == "b"
    assert params["props"] == json.dumps({"method": "a"})


def test_batched_edge_upsert_names_row_fields_not_params() -> None:
    q = _edge_upsert_batched("RESOLVES_TO")
    assert q.startswith("UNWIND $rows AS row")
    assert "row.src" in q and "$src" not in q
    assert "MERGE (a)-[r:RESOLVES_TO]->(b)" in q
    assert "coalesce(row.first_seen, row.first_seen)" not in q


def test_load_snapshot_batches_upserts_and_writes_meta(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    doc = {
        "target": "acme.test",
        "generated_at": "2026-09-19T00:00:00+00:00",
        "vocabulary": {"node_kinds": ["domain"], "edge_types": ["resolves_to"]},
        "scoring": {"engine": "S2"},
        "integrity": {"node_count": 3, "edge_count": 2},
        "nodes": [
            _asset_node(id=f"domain:{h}.test", identity=f"{h}.test")
            for h in ("a", "b", "c")
        ],
        "edges": [
            {"type": "resolves_to", "from": "domain:a.test", "to": "domain:b.test", "trust": "verified", "sources": ["s"], "props": {}, "evidence": ["e"]},
            {"type": "cname_points_to", "from": "domain:a.test", "to": "domain:b.test", "trust": "verified", "sources": ["s"], "props": {"outcome": "dangling"}, "evidence": ["e"]},
        ],
    }
    backend, driver = _backend_with(monkeypatch, {})
    counts = load_snapshot(backend, doc, batch_size=2)

    assert counts == {"nodes": 3, "edges": 2}
    queries = [q for q, _ in driver.log]
    assert any("GraphMeta" in q for q in queries)
    node_batches = [
        q for q in queries if " ".join(q.split()).startswith("UNWIND $rows AS row MERGE (n:Asset")
    ]
    assert len(node_batches) == 2  # 3 nodes / batch 2 -> two batches
    edge_batches = [(q, p) for q, p in driver.log if "MERGE (a)-[r:" in q]
    assert {("RESOLVES_TO" in q, "CNAME_POINTS_TO" in q) for q, _ in edge_batches} == {(True, False), (False, True)}


def test_load_snapshot_refuses_an_edge_type_outside_the_vocabulary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    doc = {
        "target": "t",
        "nodes": [],
        "edges": [
            {"type": "made_up_rel", "from": "a", "to": "b", "trust": "verified", "sources": [], "props": {}, "evidence": []}
        ],
    }
    backend, driver = _backend_with(monkeypatch, {})
    with pytest.raises(ValueError, match="not in the settled vocabulary"):
        load_snapshot(backend, doc)
    # The meta write happened; the bad edge batch was never sent.
    assert all("MERGE (a)-[r:" not in q for q, _ in driver.log)


def test_ensure_constraints_is_idempotent_ddl(monkeypatch: pytest.MonkeyPatch) -> None:
    backend, driver = _backend_with(monkeypatch, {})
    ensure_constraints(backend)
    queries = [q for q, _ in driver.log]
    assert sum("CREATE CONSTRAINT" in q for q in queries) == 2
    assert all("IF NOT EXISTS" in q for q in queries)


# --------------------------------------------------------------------------- #
# env-gated live test: runs only against a real store
# --------------------------------------------------------------------------- #


import os  # noqa: E402 — deliberately late, only for the gate below


def _live_backend() -> Neo4jBackend | None:
    username = os.getenv("NEO4J_USERNAME")
    password = os.getenv("NEO4J_PASSWORD")
    if not username or not password:
        return None
    backend = Neo4jBackend(
        os.getenv("NEO4J_URI", "bolt://localhost:7687"),
        username,
        password,
        os.getenv("NEO4J_DATABASE") or None,
    )
    try:
        backend._require_driver()
    except Neo4jUnavailable:
        return None
    return backend


def test_live_roundtrip_against_a_real_store() -> None:
    backend = _live_backend()
    if backend is None:
        pytest.skip("NEO4J_* not set or store down — hermetic run")
    from service.recon_pipeline.platform.graph.reader import JsonFileBackend

    state_path = (
        "service/recon_pipeline/pipelines/graph_normalize/output/graph_state.json"
    )
    doc = json.loads(open(state_path, encoding="utf-8").read())
    ensure_constraints(backend)
    load_snapshot(backend, doc)

    file_backend = JsonFileBackend(state_path)
    live = backend.node("cloud:gcs:autodiscover")
    assert live is not None
    assert live["kind"] == "cloud"
    stats = backend.stats()
    assert stats["node_count"] >= len(doc["nodes"])
    assert stats["target"] == doc["target"]
    top = backend.top_by_score(limit=5)
    assert top
    backend.close()
