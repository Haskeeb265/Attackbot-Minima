"""Junction 4 with graph context: the recon graph feeds the advisory widener.

The deterministic seed (``seed/from_graph.py``) already derives surfaces without
a model. This suite pins the *advisory* extension: the same scope-filtered graph
candidates become rows in the hypothesize junction's input, a proposal may widen
the seed with a graph-linked URL, and the URL-honesty rule still holds — the
graph widens what recon observed, it never lets the model invent a target.
"""

from __future__ import annotations

import json

from service.vuln_engine.kernel.technique import CAP_PUBLIC_PARAM, EngagementSeed, Surface
from service.vuln_engine.llm import hypothesize
from service.vuln_engine.llm.client import LLMClient
from service.vuln_engine.llm.runtime import HypothesisJunction

from tests.vuln_engine.conftest import FIXTURE_BASE, FIXTURE_HOST


def _scripted(answer: str) -> LLMClient:
    return LLMClient(api_key="test", api_url="http://test.invalid", caller=lambda prompt, system: answer)


def _graph_context() -> list[dict]:
    return [
        {
            "node_id": f"url:{FIXTURE_BASE}/graph-only",
            "url": f"{FIXTURE_BASE}/graph-only",
            "host": FIXTURE_HOST,
            "param": "id",
            "capability": CAP_PUBLIC_PARAM,
            "score": 88,
            "band": "core",
        }
    ]


def _seed() -> EngagementSeed:
    return EngagementSeed(
        target=FIXTURE_HOST,
        surfaces=(
            Surface(url=f"{FIXTURE_BASE}/search", host=FIXTURE_HOST, param="q", capability=CAP_PUBLIC_PARAM),
        ),
    )


def test_build_input_carries_bounded_deterministic_graph_rows() -> None:
    input = hypothesize.build_input([], [], graph_context=_graph_context())

    assert input["graph_context"][0]["url"] == f"{FIXTURE_BASE}/graph-only"
    assert input["graph_context"][0]["param"] == "id"
    assert input["graph_context"][0]["score"] == 88

    # Deterministic digest for the same graph context.
    again = hypothesize.build_input([], [], graph_context=list(reversed(_graph_context())))
    assert hypothesize.build_input([], [], graph_context=_graph_context()) == input
    assert again["graph_context"] == input["graph_context"]


def test_graph_rows_are_capped_and_whitelisted() -> None:
    rows = [
        {"url": f"{FIXTURE_BASE}/p{index}", "param": "p", "score": index, "secret": "x"}
        for index in range(hypothesize.MAX_INPUT_GRAPH + 5)
    ]

    input = hypothesize.build_input([], [], graph_context=rows)

    assert len(input["graph_context"]) == hypothesize.MAX_INPUT_GRAPH
    assert "secret" not in input["graph_context"][0]
    # Highest score first, deterministically.
    assert input["graph_context"][0]["score"] == hypothesize.MAX_INPUT_GRAPH + 4


def test_a_graph_linked_url_is_a_valid_proposal_target() -> None:
    input = hypothesize.build_input([], [], graph_context=_graph_context())
    known = {entry["url"] for entry in input["graph_context"]}

    validator = hypothesize.validate_answer(known)
    label = validator(
        {
            "surfaces": [
                {
                    "url": f"{FIXTURE_BASE}/graph-only",
                    "param": "id",
                    "where": "query",
                    "capability": CAP_PUBLIC_PARAM,
                }
            ]
        }
    )

    assert "validated" in label


def test_an_invented_url_is_still_refused_with_graph_context() -> None:
    input = hypothesize.build_input([], [], graph_context=_graph_context())
    known = {entry["url"] for entry in input["graph_context"]}

    validator = hypothesize.validate_answer(known)
    try:
        validator({"surfaces": [{"url": "https://evil.example.com/x", "param": "id", "where": "query", "capability": CAP_PUBLIC_PARAM}]})
    except ValueError as exc:
        assert "recon did not observe" in str(exc)
    else:  # pragma: no cover - the assertion is the contract
        raise AssertionError("an invented URL must be refused")


def test_the_junction_widens_the_seed_with_a_graph_linked_surface() -> None:
    answer = json.dumps(
        {
            "surfaces": [
                {
                    "url": f"{FIXTURE_BASE}/graph-only",
                    "param": "id",
                    "where": "query",
                    "capability": CAP_PUBLIC_PARAM,
                    "label": "graph-linked parameter",
                }
            ]
        }
    )
    junction = HypothesisJunction(_scripted(answer))

    result = junction.propose_surfaces(
        _seed(), parameters_rows=[], alive_urls=[], graph_context=_graph_context()
    )

    assert result.added == 1
    assert result.seed.surfaces[0] == _seed().surfaces[0]  # operator head intact
    assert f"{FIXTURE_BASE}/graph-only#id" in [s.key for s in result.seed.surfaces]


def test_without_graph_context_a_graph_only_url_cannot_be_proposed() -> None:
    answer = json.dumps(
        {"surfaces": [{"url": f"{FIXTURE_BASE}/graph-only", "param": "id", "where": "query", "capability": CAP_PUBLIC_PARAM}]}
    )
    junction = HypothesisJunction(_scripted(answer))

    result = junction.propose_surfaces(_seed(), parameters_rows=[], alive_urls=[])

    assert result.added == 0
    assert "recon did not observe" in result.reason
