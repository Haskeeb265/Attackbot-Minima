"""The graph agent against the *tool layer's real dispatch* and the Neo4j store.

Two layers are pinned here that the hermetic ``test_graph_nav.py`` cannot see:

* **the seam through ``tools.dispatch``** — the loop wired to the real tool
  dispatcher over a ``JsonFileBackend``, with a scripted model caller: schema
  names, budget-checked views and node expansion all cooperating, no model, no
  store;
* **the Neo4j path** (env-gated, skip-if-down like
  ``test_graph_neo4j_backend.py``'s live test) — the agent and the expansion
  against a real store, asserting the seam holds when ``--graph-neo4j`` is what
  the operator passed.

The discipline under test is the one the CLI relies on: the model answers one
JSON decision per step, the tool layer returns budget-checked views, and the
selected ids are expanded under the ordinary whole-graph rules — an id the
store does not hold expands to nothing, on Neo4j exactly as on the file
backend.
"""

from __future__ import annotations

import json
import os

import pytest

from service.recon_pipeline.platform.graph.reader import JsonFileBackend
from service.recon_pipeline.platform.graph.tools import dispatch as graph_dispatch
from service.recon_pipeline.platform.graph.tools import tool_schemas
from service.vuln_engine.llm.client import LLMClient
from service.vuln_engine.llm.runtime import GraphNavigator
from service.vuln_engine.seed import candidates_for_nodes

STATE_PATH = "service/recon_pipeline/pipelines/graph_normalize/output/graph_state.json"

TOOLS = [schema["function"]["name"] for schema in tool_schemas()]


def _scripted(answers: list[str]) -> LLMClient:
    """A model that replays ``answers`` in order, then stops with no nodes."""
    queue = list(answers)

    def call(prompt: str, system: str) -> str:
        if queue:
            return queue.pop(0)
        return json.dumps({"action": "stop", "nodes": [], "reason": "done"})

    return LLMClient(api_key="test", api_url="http://test.invalid", caller=call)


# --------------------------------------------------------------------------- #
# the real dispatch seam (hermetic)
# --------------------------------------------------------------------------- #


def test_the_agent_runs_the_real_tool_dispatcher_end_to_end() -> None:
    backend = JsonFileBackend(STATE_PATH)
    seen: list[tuple[str, dict]] = []
    navigator = GraphNavigator(
        _scripted(
            [
                json.dumps({"action": "call", "tool": "graph_stats", "arguments": {}, "reason": "size up"}),
                json.dumps({"action": "call", "tool": "graph_search", "arguments": {"query": "example", "limit": 5}, "reason": "find urls"}),
            ]
        )
    )

    result = navigator.navigate(
        "find endpoints",
        tool_names=TOOLS,
        dispatch=lambda name, arguments: (seen.append((name, arguments)), graph_dispatch(backend, name, arguments))[1],
        max_steps=3,
    )

    assert result.source == "stop" or result.source in ("live", "cached")
    assert [tool for tool, _ in seen] == ["graph_stats", "graph_search"]
    assert result.observations == 2
    # The scripted stop carried no nodes, so nothing was selected.
    assert result.selected_nodes == ()
    # The observations are readable text, not raw JSON payloads.
    assert all(not step["observation"].startswith('{"view"') for step in result.steps)


def test_an_unknown_tool_id_through_the_real_dispatcher_is_an_error_view_not_a_crash() -> None:
    backend = JsonFileBackend(STATE_PATH)
    navigator = GraphNavigator(
        _scripted(
            [
                # The model names a node id that does not exist — the tool layer
                # answers with an error view, and the loop carries it as an
                # observation the next step can react to.
                json.dumps({"action": "call", "tool": "graph_get_node", "arguments": {"node_id": "url:https://no-such-host.invalid/x"}, "reason": "probe"}),
                json.dumps({"action": "stop", "nodes": ["url:https://no-such-host.invalid/x"], "reason": "picked"}),
            ]
        )
    )

    result = navigator.navigate(
        "find endpoints",
        tool_names=TOOLS,
        dispatch=lambda name, arguments: graph_dispatch(backend, name, arguments),
        max_steps=3,
    )

    assert result.observations == 1
    assert result.steps[0]["observation"].startswith("error:")
    # The invented id was selected — and the expansion correctly refuses it.
    assert result.selected_nodes == ("url:https://no-such-host.invalid/x",)
    expansion = candidates_for_nodes(backend, result.selected_nodes)
    assert expansion.surfaces == []
    assert expansion.report["skipped_not_url"] + expansion.report["skipped_no_param"] >= 1


def test_selection_through_the_real_dispatcher_expands_only_parameterised_urls() -> None:
    backend = JsonFileBackend(STATE_PATH)
    # Pick ids straight from the store so the expansion result is meaningful.
    urls = [row["id"] for row in backend.top_by_score(kind="url", limit=50) if row.get("id")]
    parameterised = [
        node_id
        for node_id in urls
        if backend.neighbors(node_id, edge_type="observed_parameter", direction="out", depth=1)
    ]
    assert parameterised, "fixture graph_state.json holds no parameterised URL — update the fixture"
    picked = parameterised[0]

    navigator = GraphNavigator(
        _scripted(
            [
                json.dumps({"action": "call", "tool": "graph_neighbors", "arguments": {"node_id": picked, "edge_type": "observed_parameter"}, "reason": "params"}),
                json.dumps({"action": "stop", "nodes": [picked], "reason": "the one"}),
            ]
        )
    )
    result = navigator.navigate(
        "find endpoints",
        tool_names=TOOLS,
        dispatch=lambda name, arguments: graph_dispatch(backend, name, arguments),
        max_steps=3,
    )

    expansion = candidates_for_nodes(backend, result.selected_nodes)
    assert expansion.report["surfaces"] >= 1
    surface = expansion.surfaces[0]
    assert surface.url.startswith("http")
    assert surface.param
    assert surface.label.startswith("graph:")


# --------------------------------------------------------------------------- #
# env-gated: the same walk against a live Neo4j store, skip-if-down
# --------------------------------------------------------------------------- #


def _live_neo4j_backend():
    username = os.getenv("NEO4J_USERNAME")
    password = os.getenv("NEO4J_PASSWORD")
    if not username or not password:
        return None
    from service.recon_pipeline.platform.graph.neo4j_backend import Neo4jBackend, Neo4jUnavailable

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


def test_live_neo4j_agent_walk_matches_the_file_backend_semantics() -> None:
    backend = _live_neo4j_backend()
    if backend is None:
        pytest.skip("NEO4J_* not set or store down — hermetic run")
    try:
        # The walk must answer the same questions through Cypher: stats, a
        # search, and a neighbors expansion — one scripted pass over real rows.
        navigator = GraphNavigator(
            _scripted(
                [
                    json.dumps({"action": "call", "tool": "graph_stats", "arguments": {}, "reason": "size up"}),
                    json.dumps({"action": "call", "tool": "graph_top_assets", "arguments": {"kind": "url", "limit": 5}, "reason": "urls"}),
                ]
            )
        )
        result = navigator.navigate(
            "find endpoints",
            tool_names=TOOLS,
            dispatch=lambda name, arguments: graph_dispatch(backend, name, arguments),
            max_steps=3,
        )
        assert result.observations == 2
        stats_text = result.steps[0]["observation"]
        assert "node_count" in stats_text

        # The expansion seam: a real id from the store expands (or refuses)
        # under the same rules the file backend follows.
        urls = [row["id"] for row in backend.top_by_score(kind="url", limit=50) if row.get("id")]
        picked = urls[0] if urls else "url:https://no-such-host.invalid/x"
        expansion = candidates_for_nodes(backend, [picked, "url:https://invented.invalid/x"])
        # The invented id contributed nothing; the real one may or may not
        # carry parameters, but the report must account for both.
        assert expansion.report["skipped_not_url"] <= 1
        assert expansion.report["urls_considered"] >= 1
    finally:
        backend.close()


def test_live_neo4j_unknown_node_refuses_cleanly() -> None:
    backend = _live_neo4j_backend()
    if backend is None:
        pytest.skip("NEO4J_* not set or store down — hermetic run")
    try:
        navigator = GraphNavigator(
            _scripted(
                [
                    json.dumps({"action": "call", "tool": "graph_get_node", "arguments": {"node_id": "url:https://invented.invalid/x"}, "reason": "probe"}),
                ]
            )
        )
        result = navigator.navigate(
            "find endpoints",
            tool_names=TOOLS,
            dispatch=lambda name, arguments: graph_dispatch(backend, name, arguments),
            max_steps=2,
        )
        assert result.steps[0]["observation"].startswith("error:")
        expansion = candidates_for_nodes(backend, ["url:https://invented.invalid/x"])
        assert expansion.surfaces == []
    finally:
        backend.close()
