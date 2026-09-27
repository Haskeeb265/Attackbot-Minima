"""Graph-derived seed construction, hermetically.

The derivation runs over a real ``JsonFileBackend`` reading a tiny
``graph_state.json`` on disk, so the whole read path is exercised — the same
reader (and, behind the protocol, the same Neo4j) the engine uses. The rules
pinned here: only in-scope URLs become surfaces, out-of-scope and needs-review
are filtered and counted, URL-shaped parameter names claim the remote-fetch
capability, and the order is deterministic.
"""

from __future__ import annotations

import json
from pathlib import Path

from service.recon_pipeline.platform.graph.reader import JsonFileBackend
from service.vuln_engine.kernel.technique import CAP_INFLUENCE_REMOTE_FETCH, CAP_PUBLIC_PARAM
from service.vuln_engine.seed import derive_surfaces, graph_context_rows, merge_surfaces


def _document() -> dict:
    def url(label: str, url: str, score: int) -> dict:
        return {
            "id": f"url:{url}",
            "kind": "url",
            "identity": url,
            "score": score,
            "band": "high",
            "trust": "observed",
            "props": {"url": url, "label": label},
        }

    def param(name: str) -> dict:
        return {"id": f"parameter:{name}", "kind": "parameter", "identity": name, "score": 40}

    nodes = [
        url("search", "https://www.acme.test/search?q=x", 80),
        param("q"),
        url("proxy", "https://www.acme.test/proxy?url=http%3A%2F%2Fx", 70),
        param("url"),
        url("excluded", "https://excluded.acme.test/admin?a=1", 90),
        param("a"),
        url("foreign", "https://thirdparty.example.net/y?b=2", 60),
        param("b"),
    ]
    edges = [
        {"type": "observed_parameter", "from": "url:https://www.acme.test/search?q=x", "to": "parameter:q", "props": {}},
        {"type": "observed_parameter", "from": "url:https://www.acme.test/proxy?url=http%3A%2F%2Fx", "to": "parameter:url", "props": {}},
        {"type": "observed_parameter", "from": "url:https://excluded.acme.test/admin?a=1", "to": "parameter:a", "props": {}},
        {"type": "observed_parameter", "from": "url:https://thirdparty.example.net/y?b=2", "to": "parameter:b", "props": {}},
    ]
    return {"target": "acme.test", "nodes": nodes, "edges": edges}


def _backend(tmp_path: Path) -> JsonFileBackend:
    path = tmp_path / "graph_state.json"
    path.write_text(json.dumps(_document()), encoding="utf-8")
    return JsonFileBackend(path)


def test_surfaces_are_derived_with_a_capability_per_parameter(tmp_path: Path) -> None:
    derived = derive_surfaces(_backend(tmp_path))

    by_key = {(s.url, s.param): s for s in derived.surfaces}
    assert by_key[("https://www.acme.test/search?q=x", "q")].capability == CAP_PUBLIC_PARAM
    assert (
        by_key[("https://www.acme.test/proxy?url=http%3A%2F%2Fx", "url")].capability
        == CAP_INFLUENCE_REMOTE_FETCH
    )
    assert len(derived.surfaces) == 4


def test_the_derivation_is_deterministic_and_score_ordered(tmp_path: Path) -> None:
    first = derive_surfaces(_backend(tmp_path)).surfaces
    second = derive_surfaces(_backend(tmp_path)).surfaces

    assert [(s.url, s.param) for s in first] == [(s.url, s.param) for s in second]
    # Highest-scoring URL first.
    assert first[0].url.startswith("https://excluded.acme.test")


def test_out_of_scope_and_needs_review_are_filtered_and_counted(tmp_path: Path) -> None:
    def scope_state(host: str) -> str:
        if host == "excluded.acme.test":
            return "out_of_scope"
        if host == "thirdparty.example.net":
            return "needs_review"
        return "in_scope"

    derived = derive_surfaces(_backend(tmp_path), scope_state=scope_state)

    hosts = {s.host for s in derived.surfaces}
    assert hosts == {"www.acme.test"}
    assert derived.report["skipped_out_of_scope"] == 1
    assert derived.report["skipped_needs_review"] == 1


def test_the_cap_marks_the_result_truncated(tmp_path: Path) -> None:
    derived = derive_surfaces(_backend(tmp_path), max_surfaces=2)

    assert len(derived.surfaces) == 2
    assert derived.report["truncated"] is True
    assert derived.report["dropped"] == 2


def test_remote_fetch_inference_can_be_turned_off(tmp_path: Path) -> None:
    derived = derive_surfaces(_backend(tmp_path), infer_remote_fetch=False)

    assert all(s.capability == CAP_PUBLIC_PARAM for s in derived.surfaces)
    assert derived.report["remote_fetch_claims"] == 0


def test_graph_context_rows_expose_the_same_candidates_for_the_junction(tmp_path: Path) -> None:
    rows = graph_context_rows(_backend(tmp_path), max_rows=2)

    assert len(rows) == 2
    top = rows[0]
    assert {"node_id", "url", "host", "param", "capability", "score", "band"} <= set(top)
    # Same deterministic order as the derived surfaces.
    assert top["url"].startswith("https://excluded.acme.test")


def test_graph_context_rows_respect_the_scope_pre_filter(tmp_path: Path) -> None:
    def scope_state(host: str) -> str:
        return "out_of_scope" if host == "excluded.acme.test" else "in_scope"

    rows = graph_context_rows(_backend(tmp_path), scope_state=scope_state)

    assert all(row["host"] != "excluded.acme.test" for row in rows)


def test_merge_lets_the_operator_win_on_a_collision(tmp_path: Path) -> None:
    from service.vuln_engine.kernel.technique import Surface

    declared = [
        Surface(
            url="https://www.acme.test/search?q=x",
            host="www.acme.test",
            param="q",
            capability=CAP_INFLUENCE_REMOTE_FETCH,
            label="operator",
        )
    ]
    derived = derive_surfaces(_backend(tmp_path)).surfaces

    merged = merge_surfaces(declared, derived)

    keys = [(s.url, s.param) for s in merged]
    assert len(keys) == len(set(keys))  # no duplicate arm
    winner = next(s for s in merged if s.param == "q")
    assert winner.label == "operator"
    assert winner.capability == CAP_INFLUENCE_REMOTE_FETCH
