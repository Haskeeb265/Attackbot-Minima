"""Junction 6 — graph navigation: bounded, validated, replayable.

The contract being tested:

* **one validated decision per step** — an action outside the vocabulary, or a
  tool the composition root did not offer, is refused and the loop stops;
* **bounded** — at most ``MAX_STEPS`` tool calls, and a stop selects at most
  ``MAX_SELECTED_NODES`` node ids;
* **logged per step** — every step is an ``llm.junction`` row keyed by content
  digest, so a replay reproduces the whole navigation with the key removed;
* **bounded observations** — a tool view is summarized and truncated before it
  enters the next prompt/digest;
* **degrades to no navigation** — an unavailable client stops immediately with
  the reason, never raising.
"""

from __future__ import annotations

import json

from service.vuln_engine.llm import graph_nav
from service.vuln_engine.llm.client import EVENT_LLM_JUNCTION, LLMClient, _unwrap_tool_envelope
from service.vuln_engine.llm.runtime import GRAPH_NAV_NAME, GraphNavigator
from service.vuln_engine.world.log import WorldLog


TOOLS = ["graph_stats", "graph_top_assets", "graph_search", "graph_get_node", "graph_neighbors"]


def _call(tool: str, arguments: dict | None = None, reason: str = "explore") -> str:
    return json.dumps({"action": "call", "tool": tool, "arguments": arguments or {}, "reason": reason})


def _stop(nodes: list[str] | None = None, reason: str = "enough") -> str:
    return json.dumps({"action": "stop", "nodes": nodes or [], "reason": reason})


def _scripted(answer: str) -> LLMClient:
    return LLMClient(api_key="test", api_url="http://test.invalid", caller=lambda prompt, system: answer)


class _Scripted:
    """A caller that returns queued answers in order, then a stop."""

    def __init__(self, answers: list[str]) -> None:
        self._answers = list(answers)
        self.prompts: list[str] = []

    def __call__(self, prompt: str, system: str) -> str:
        self.prompts.append(prompt)
        if self._answers:
            return self._answers.pop(0)
        return _stop()


def _dispatch(seen: list[tuple[str, dict]]):
    def call(tool: str, arguments: dict) -> str:
        seen.append((tool, arguments))
        return json.dumps(
            {
                "view": tool,
                "rows": [
                    {"id": "url:https://www.acme.test/search?q=x", "kind": "url", "score": 80, "props": {"url": "https://www.acme.test/search?q=x"}},
                    {"id": "parameter:q", "kind": "parameter", "score": 40},
                ],
                "meta": {},
            }
        )

    return call


# --------------------------------------------------------------------------- #
# the pure half
# --------------------------------------------------------------------------- #


def test_build_input_keeps_a_deterministic_transcript() -> None:
    transcript = [
        {"step": 1, "tool": "graph_stats", "arguments": {}, "observation": " 42 nodes "},
        {"step": 2, "tool": "graph_search", "arguments": {"query": "search"}, "observation": "x" * 5000},
    ]

    input = graph_nav.build_input("goal", ["graph_search", "graph_stats"], transcript)

    assert input["tools"] == ["graph_search", "graph_stats"]  # sorted, deterministic
    assert input["steps"][0]["observation"] == "42 nodes"
    assert len(input["steps"][1]["observation"]) <= graph_nav.MAX_OBSERVATION_CHARS + 40


def test_build_prompt_lists_only_offered_tools_and_the_transcript() -> None:
    input = graph_nav.build_input("find idors", ["graph_stats"], [])
    prompt, system = graph_nav.build_prompt(input)

    assert "- graph_stats:" in prompt
    assert "- graph_neighbors:" not in prompt  # not offered (the example JSON still names it)
    assert "find idors" in prompt
    assert "JSON" in system or "JSON" in prompt


def test_validate_refuses_unknown_tools_and_actions() -> None:
    validator = graph_nav.validate_answer({"graph_stats"})
    try:
        validator(json.loads(_call("totally_made_up")))
    except ValueError as exc:
        assert "not one of the offered tools" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("an unknown tool must be refused")

    try:
        validator({"action": "explode"})
    except ValueError as exc:
        assert "action" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("an unknown action must be refused")


def test_validate_caps_selected_nodes() -> None:
    validator = graph_nav.validate_answer({"graph_stats"})
    over = {"action": "stop", "nodes": [f"url:{i}" for i in range(graph_nav.MAX_SELECTED_NODES + 1)]}
    try:
        validator(over)
    except ValueError as exc:
        assert "over the" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("over-cap node selection must be refused")


def test_extract_returns_stop_for_an_unusable_answer() -> None:
    action, tool, args, reason, nodes = graph_nav.extract({"action": "nonsense"}, {"graph_stats"})
    assert (action, tool, args, nodes) == ("stop", "", {}, [])


def test_summarize_tool_result_compacts_rows_and_errors() -> None:
    rows = graph_nav.summarize_tool_result(
        json.dumps({"view": "top", "rows": [{"id": "url:https://x.test/a", "kind": "url", "score": 90}], "meta": {}})
    )
    assert "url:https://x.test/a" in rows and "score=90" in rows

    assert graph_nav.summarize_tool_result(json.dumps({"error": "store down"})).startswith("error:")
    assert "node:" in graph_nav.summarize_tool_result(json.dumps({"node": {"id": "domain:x", "kind": "domain"}}))


# --------------------------------------------------------------------------- #
# the runtime loop
# --------------------------------------------------------------------------- #


def test_the_loop_calls_tools_then_stops_with_selected_nodes(tmp_path) -> None:
    log = WorldLog(tmp_path / "world.jsonl")
    seen: list[tuple[str, dict]] = []
    caller = _Scripted(
        [
            _call("graph_stats"),
            _call("graph_neighbors", {"node_id": "url:https://www.acme.test/search?q=x"}),
            _stop(["url:https://www.acme.test/search?q=x"]),
        ]
    )
    navigator = GraphNavigator(LLMClient(api_key="k", api_url="http://t", caller=caller))

    result = navigator.navigate(
        "find endpoints", tool_names=TOOLS, dispatch=_dispatch(seen), world=log, now=1.0
    )

    assert [tool for tool, _ in seen] == ["graph_stats", "graph_neighbors"]
    assert result.selected_nodes == ("url:https://www.acme.test/search?q=x",)
    assert result.observations == 2
    assert result.source == "live"
    # One logged opinion per step (three: two calls and the stop).
    rows = log.events(EVENT_LLM_JUNCTION)
    assert len(rows) == 3
    assert all(row["junction"] == GRAPH_NAV_NAME for row in rows)


def test_the_step_budget_bounds_the_loop(tmp_path) -> None:
    seen: list[tuple[str, dict]] = []
    caller = _Scripted([_call("graph_stats")] * 20)  # never stops
    navigator = GraphNavigator(LLMClient(api_key="k", api_url="http://t", caller=caller))

    result = navigator.navigate(
        "loop forever", tool_names=TOOLS, dispatch=_dispatch(seen), max_steps=3
    )

    assert len(seen) == 3
    assert result.source == "budget"
    assert result.selected_nodes == ()


def test_an_invalid_tool_ends_the_navigation_rather_than_spinning(tmp_path) -> None:
    seen: list[tuple[str, dict]] = []
    navigator = GraphNavigator(_scripted(_call("rm_rf")))

    result = navigator.navigate("x", tool_names=TOOLS, dispatch=_dispatch(seen))

    assert seen == []
    assert result.selected_nodes == ()
    assert result.source == "degraded"
    assert "offered tools" in result.reason


def test_a_replay_finds_cached_opinions(tmp_path) -> None:
    log = WorldLog(tmp_path / "world.jsonl")
    answers = [_call("graph_stats"), _stop(["url:https://www.acme.test/x"])]
    first = GraphNavigator(LLMClient(api_key="k", api_url="http://t", caller=_Scripted(list(answers))))
    result1 = first.navigate("g", tool_names=TOOLS, dispatch=_dispatch([]), world=log, now=1.0)
    second = GraphNavigator(LLMClient(api_key="k", api_url="http://t", caller=_Scripted(list(answers))))
    result2 = second.navigate("g", tool_names=TOOLS, dispatch=_dispatch([]), world=log, now=2.0)

    assert result1.selected_nodes == result2.selected_nodes
    assert result2.source == "cached"
    # The replay added no new junction rows.
    assert len(log.events(EVENT_LLM_JUNCTION)) == 2


def test_an_unavailable_client_is_no_navigation_not_an_error() -> None:
    # ``api_key=""`` pins health to unavailable regardless of any key the
    # ambient environment (a full-suite run leaks ``.env``) might carry.
    navigator = GraphNavigator(LLMClient(api_key=""))
    result = navigator.navigate("x", tool_names=TOOLS, dispatch=_dispatch([]))
    assert result.source == "degraded"
    assert result.steps == ()
    assert result.reason


def test_a_native_tool_call_envelope_is_unwrapped_not_refused() -> None:
    """Regression: a tool-calling model (Groq gpt-oss-20b) sometimes renders the
    junction's answer inside a function-call envelope even when the request
    declared no tools — the provider rejects the generation with 400
    ``tool_use_failed``, and the caller salvages the model's text from the
    error body.  The envelope must be unwrapped and validated, not refused:
    the model's intent is intact one level down."""
    wrapped = {
        "name": "graph_stats",
        "arguments": {"action": "call", "tool": "graph_stats", "arguments": {}, "reason": "size up"},
    }
    unwrapped = _unwrap_tool_envelope(wrapped)
    assert unwrapped["action"] == "call" and unwrapped["tool"] == "graph_stats"

    # An answer that already has its action at the top level passes through.
    plain = {"action": "stop", "nodes": [], "reason": "done"}
    assert _unwrap_tool_envelope(plain) is plain
    # Only the exact envelope shape is unwrapped: arguments must be an object.
    broken = {"name": "graph_stats", "arguments": "call graph_stats"}
    assert _unwrap_tool_envelope(broken) is broken

    # And the unwrapped answer flows through the junction's real validator.
    validated = graph_nav.validate_answer({"graph_stats"})(unwrapped)
    assert validated == "validated (call)"


def test_the_advisory_passes_the_operator_step_budget_through() -> None:
    from service.vuln_engine.llm.wiring import graph_navigation_advisory

    seen: dict[str, int] = {}

    class FakeAdvisory:
        def navigate_graph(self, goal, *, tool_names, dispatch, log_handle=None, now=0.0, max_steps=0):
            seen["max_steps"] = max_steps
            return "sentinel"

    assert (
        graph_navigation_advisory(
            FakeAdvisory(), "g", tool_names=["graph_stats"], dispatch=_dispatch([]), max_steps=4
        )
        == "sentinel"
    )
    assert seen["max_steps"] == 4
    # No advisory at all degrades instead of raising.
    assert (
        graph_navigation_advisory(None, "g", tool_names=["graph_stats"], dispatch=_dispatch([])).source
        == "degraded"
    )
