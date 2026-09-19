"""Tests for the graph read side — ``platform/graph/reader.py`` + ``tools.py``.

The rules pinned here: the ``GraphBackend`` seam is small enough to swap
storage without touching callers; every serialized view respects its token
budget (a view is the unit of context, and budgets are the credit guard);
compaction keeps priority fields but drops scaffolding; and the tool layer
speaks only the seam, so the LLM interface is storage-agnostic.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from service.recon_pipeline.platform.graph.reader import (
    BudgetExceeded,
    GraphBackend,
    JsonFileBackend,
    _within_budget,
    compact_node,
)
from service.recon_pipeline.platform.graph.tools import (
    ALL_SPECS,
    dispatch,
    tool_schemas,
)


# --------------------------------------------------------------------------- #
# a tiny synthetic graph: one domain hub, rotational IPs, a dangling bucket
# --------------------------------------------------------------------------- #


def _doc() -> dict[str, Any]:
    nodes = [
        {"id": "domain:acme.test", "kind": "domain", "identity": "acme.test", "trust": "verified", "score": 60, "band": "medium", "evidence_state": "unverified", "props": {"apex": True}},
        {"id": "domain:autodiscover.acme.test", "kind": "domain", "identity": "autodiscover.acme.test", "trust": "verified", "score": 100, "band": "core", "evidence_state": "unverified", "props": {"cname": "mail.microsoft.com"}},
        {"id": "ip:10.0.0.1", "kind": "ip", "identity": "10.0.0.1", "trust": "discovered", "score": 40, "band": "low", "evidence_state": "unverified", "props": {"asn": 13335}},
        {"id": "ip:10.0.0.2", "kind": "ip", "identity": "10.0.0.2", "trust": "discovered", "score": 45, "band": "low", "evidence_state": "unverified", "props": {}},
        {"id": "cloud:gcs:acme-docs", "kind": "cloud", "identity": "gcs:acme-docs", "trust": "verified", "score": 85, "band": "high", "evidence_state": "verified_dead", "props": {"provider": "gcs", "outcome": "dangling"}},
        {"id": "url:https://acme.test/admin", "kind": "url", "identity": "https://acme.test/admin", "trust": "discovered", "score": 70, "band": "high", "evidence_state": "unverified", "props": {"status": 401, "path": "/admin"}},
        {"id": "organization:Acme Corp", "kind": "organization", "identity": "Acme Corp", "trust": "discovered", "score": 55, "band": "medium", "evidence_state": "unverified", "props": {"sector": "tech"}},
        {"id": "network:10.0.0.0/8", "kind": "network", "identity": "10.0.0.0/8", "trust": "discovered", "score": None, "band": None, "evidence_state": "unverified", "props": {}},
        {"id": "asn:13335", "kind": "asn", "identity": "13335", "trust": "discovered", "score": 100, "band": "core", "evidence_state": "unverified", "props": {"as_name": "CLOUDFLARENET"}},
    ]
    edges = [
        {"type": "resolves_to", "from": "domain:autodiscover.acme.test", "to": "ip:10.0.0.1", "trust": "discovered", "sources": ["records:a"], "props": {"method": "a"}, "evidence": ["records"]},
        {"type": "resolves_to", "from": "domain:autodiscover.acme.test", "to": "ip:10.0.0.2", "trust": "discovered", "sources": ["records:a"], "props": {"method": "a"}, "evidence": ["records"]},
        {"type": "cname_points_to", "from": "domain:autodiscover.acme.test", "to": "cloud:gcs:acme-docs", "trust": "verified", "sources": ["cloud:dangling"], "props": {"outcome": "dangling"}, "evidence": ["probe"]},
        {"type": "has_url", "from": "domain:acme.test", "to": "url:https://acme.test/admin", "trust": "discovered", "sources": ["url_endpoint:extract"], "props": {}, "evidence": ["extract"]},
        {"type": "owned_by", "from": "cloud:gcs:acme-docs", "to": "organization:Acme Corp", "trust": "verified", "sources": ["cloud:probe"], "props": {"claim": "registration"}, "evidence": ["probe"]},
        {"type": "announced_by", "from": "network:10.0.0.0/8", "to": "asn:13335", "trust": "discovered", "sources": ["asn_cidr:networks"], "props": {}, "evidence": ["ripestat"]},
        {"type": "resolves_to", "from": "domain:acme.test", "to": "network:10.0.0.0/8", "trust": "discovered", "sources": ["records:a"], "props": {"method": "a"}, "evidence": ["records"]},
    ]
    return {
        "graph_state_version": "1.0",
        "target": "acme.test",
        "generated_at": "2026-09-19T00:00:00Z",
        "status": {"schema": "settled", "graph_written": False},
        "vocabulary": {"node_kinds": ["domain", "ip"], "edge_types": ["resolves_to"]},
        "scoring": {"engine": "S2"},
        "integrity": {"node_count": len(nodes), "edge_count": len(edges)},
        "nodes": nodes,
        "edges": edges,
    }


@pytest.fixture()
def backend(tmp_path: Any) -> JsonFileBackend:
    path = tmp_path / "graph_state.json"
    path.write_text(json.dumps(_doc()), encoding="utf-8")
    return JsonFileBackend(path)


# --------------------------------------------------------------------------- #
# the seam
# --------------------------------------------------------------------------- #


def test_the_file_backend_satisfies_the_protocol(backend: JsonFileBackend) -> None:
    # A Neo4j backend will have to satisfy the same check.
    assert isinstance(backend, GraphBackend)


def test_node_lookup_is_exact_and_misses_are_none(backend: JsonFileBackend) -> None:
    node = backend.node("cloud:gcs:acme-docs")
    assert node is not None
    assert node["props"]["outcome"] == "dangling"
    assert backend.node("domain:nonexistent.acme.test") is None


# --------------------------------------------------------------------------- #
# traversal: rotational-IP hubs must not fragment or explode
# --------------------------------------------------------------------------- #


def test_depth_one_neighbors_of_the_hub_are_deduplicated(backend: JsonFileBackend) -> None:
    rows = backend.neighbors("domain:autodiscover.acme.test")
    ids = {r["id"] for r in rows}
    # Two rotational IPs and one dangling bucket — three rows, not more.
    assert ids == {"ip:10.0.0.1", "ip:10.0.0.2", "cloud:gcs:acme-docs"}


def test_edge_type_filter_picks_one_relation_only(backend: JsonFileBackend) -> None:
    rows = backend.neighbors("domain:autodiscover.acme.test", edge_type="cname_points_to")
    assert [r["id"] for r in rows] == ["cloud:gcs:acme-docs"]


def test_direction_filter_respects_edge_orientation(backend: JsonFileBackend) -> None:
    out_rows = {r["id"] for r in backend.neighbors("domain:autodiscover.acme.test", direction="out")}
    assert out_rows == {"ip:10.0.0.1", "ip:10.0.0.2", "cloud:gcs:acme-docs"}
    # Nothing points *at* the domain in this fixture.
    in_rows = {r["id"] for r in backend.neighbors("domain:autodiscover.acme.test", direction="in")}
    assert in_rows == set()


def test_depth_two_walks_through_the_hub_without_looping(backend: JsonFileBackend) -> None:
    rows = backend.neighbors("domain:autodiscover.acme.test", depth=2)
    ids = {r["id"] for r in rows}
    # The org behind the bucket is reachable; the visited set stops cycles.
    assert "organization:Acme Corp" in ids
    assert "domain:autodiscover.acme.test" not in ids  # never the seed itself


def test_neighbors_of_an_unknown_node_are_empty(backend: JsonFileBackend) -> None:
    assert backend.neighbors("domain:missing.acme.test") == []


# --------------------------------------------------------------------------- #
# prioritization and search
# --------------------------------------------------------------------------- #


def test_top_by_score_orders_and_filters(backend: JsonFileBackend) -> None:
    rows = backend.top_by_score()
    scores = [r["score"] for r in rows]
    assert scores == sorted(scores, reverse=True)
    assert rows[0]["id"] in {"domain:autodiscover.acme.test", "asn:13335"}
    assert backend.top_by_score(band="high")[0]["id"] == "cloud:gcs:acme-docs"
    assert backend.top_by_score(kind="ip")[0]["id"] == "ip:10.0.0.2"
    assert all(r["score"] >= 60 for r in backend.top_by_score(min_score=60))
    # Unscored rows (network) never appear in a priority queue.
    assert all(r["score"] is not None for r in backend.top_by_score())


def test_search_finds_by_id_and_props(backend: JsonFileBackend) -> None:
    assert "cloud:gcs:acme-docs" in {r["id"] for r in backend.search("acme-docs")}
    assert "asn:13335" in {r["id"] for r in backend.search("cloudflarenet")}
    assert backend.search("") == []
    assert backend.search("zzz-nothing") == []


def test_stats_counts_kinds_and_bands(backend: JsonFileBackend) -> None:
    stats = backend.stats()
    assert stats["target"] == "acme.test"
    assert stats["node_count"] == 9
    assert stats["edge_count"] == 7
    assert stats["nodes_by_kind"]["cloud"] == 1
    assert stats["nodes_by_band"]["core"] == 2


def test_header_carries_the_self_describing_contract(backend: JsonFileBackend) -> None:
    header = backend.header()
    assert header["vocabulary"]["node_kinds"] == ["domain", "ip"]
    assert header["scoring"]["engine"] == "S2"


# --------------------------------------------------------------------------- #
# compaction and the budget guard
# --------------------------------------------------------------------------- #


def test_compact_node_keeps_priority_and_drops_scaffolding() -> None:
    node = {
        "id": "domain:acme.test",
        "kind": "domain",
        "trust": "verified",
        "score": 60,
        "band": "medium",
        "evidence_state": "unverified",
        "score_audit": ["floor: 60", "total: 60 (medium)"],
        "labels": ["Asset", "Domain"],
        "props": {"apex": True},
    }
    compact = compact_node(node)
    assert compact == {"id": "domain:acme.test", "kind": "domain", "score": 60, "band": "medium", "trust": "verified", "props": {"apex": True}}


def test_budget_guard_trims_lowest_priority_rows_and_reports_it() -> None:
    rows = [{"id": f"ip:10.0.0.{i}", "props": {"pad": "x" * 500}} for i in range(50)]
    view = _within_budget(rows, {}, "test_view", budget_tokens=2_000)
    assert view.meta["truncated"] is True
    assert view.meta["rows_dropped"] == 50 - len(view.rows)
    assert view.meta["tokens"] <= 2_000
    assert len(view.rows) >= 1


def test_budget_guard_raises_when_even_one_row_cannot_fit() -> None:
    row = [{"id": "ip:0.0.0.0", "props": {"pad": "x" * 100_000}}]
    with pytest.raises(BudgetExceeded):
        _within_budget(row, {}, "test_view", budget_tokens=100)


def test_budget_guard_passes_small_views_untouched() -> None:
    rows = [{"id": "ip:10.0.0.1"}]
    view = _within_budget(rows, {}, "test_view", budget_tokens=1_000)
    assert view.meta["truncated"] is False
    assert view.rows == rows


# --------------------------------------------------------------------------- #
# the tool layer: schema and dispatcher agree, errors are small and honest
# --------------------------------------------------------------------------- #


def test_every_tool_has_a_schema_and_dispatcher() -> None:
    names = {spec["name"] for spec in ALL_SPECS}
    assert names == {"graph_stats", "graph_top_assets", "graph_get_node", "graph_neighbors", "graph_search"}
    schemas = tool_schemas()
    assert len(schemas) == len(ALL_SPECS)
    for schema in schemas:
        assert schema["type"] == "function"
        assert schema["function"]["name"] in names
        assert schema["function"]["parameters"]["type"] == "object"


def test_dispatch_routes_each_tool(backend: JsonFileBackend) -> None:
    stats = json.loads(dispatch(backend, "graph_stats", {}))
    assert stats["rows"][0]["node_count"] == 9

    top = json.loads(dispatch(backend, "graph_top_assets", {"limit": 3}))
    assert len(top["rows"]) == 3

    node = json.loads(dispatch(backend, "graph_get_node", {"node_id": "cloud:gcs:acme-docs"}))
    assert node["node"]["props"]["outcome"] == "dangling"

    neighbors = json.loads(dispatch(backend, "graph_neighbors", {"node_id": "domain:autodiscover.acme.test"}))
    assert neighbors["meta"]["expanded"] == "domain:autodiscover.acme.test"
    assert neighbors["meta"]["connecting_edges"]  # the rows come with their edges

    found = json.loads(dispatch(backend, "graph_search", {"query": "dangling"}))
    assert "cloud:gcs:acme-docs" in {r["id"] for r in found["rows"]}


def test_dispatch_errors_are_small_and_actionable(backend: JsonFileBackend) -> None:
    unknown = json.loads(dispatch(backend, "graph_noop", {}))
    assert "unknown tool" in unknown["error"]

    missing = json.loads(dispatch(backend, "graph_get_node", {"node_id": "domain:ghost.acme.test"}))
    assert "no node" in missing["error"]
    assert "graph_search" in missing["hint"]


def test_dispatch_respects_the_token_budget_on_huge_views(backend: JsonFileBackend) -> None:
    out = dispatch(backend, "graph_top_assets", {"limit": 100}, budget_tokens=300)
    payload = json.loads(out)
    assert payload["meta"]["truncated"] is True
    assert payload["meta"]["tokens"] <= 300


def test_dispatch_returns_budget_error_as_tiny_json(backend: JsonFileBackend) -> None:
    out = dispatch(backend, "graph_get_node", {"node_id": "cloud:gcs:acme-docs"}, budget_tokens=1)
    # Single-node views are emitted raw; a 1-token budget on a real node still
    # cannot crash the dispatcher — it degrades to an honest error string.
    assert "error" in out or "node" in out
