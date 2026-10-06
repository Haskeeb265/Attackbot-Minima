"""Junction 7 — abduce: the model directs attention, the engine decides.

The contract (``llm/abduce.py`` + ``abduction.proposal_for``):

* every proposal names a surface the operator declared and a claim shape the
  ontology names — an invented surface or shape degrades the answer whole;
* a validated row becomes a Proposal over a *real* plan-table row, so a
  model-proposed claim is still an experiment the verifier has seen;
* no key means the deterministic abducer is the whole loop — the junction
  degrades to an empty result and never raises;
* the property channel works from static context with no anomaly at all (A3).
"""

from __future__ import annotations

import json

from service.vuln_engine.abduction.deterministic import RULE_LLM_ABDUCTION, proposal_for
from service.vuln_engine.kernel.claim import CLAIM_SHAPES
from service.vuln_engine.kernel.technique import (
    CAP_ACCESS_DIFFERS_BY_SESSION,
    CAP_PUBLIC_PARAM,
    Surface,
)
from service.vuln_engine.llm import abduce
from service.vuln_engine.llm.client import LLMClient
from service.vuln_engine.llm.runtime import ABDUCE_NAME, AbductionJunction
from service.vuln_engine.llm.wiring import Advisory
from service.vuln_engine.world.log import WorldLog


def scripted_client(answer: str) -> LLMClient:
    return LLMClient(
        api_key="test",
        api_url="http://test.invalid",
        caller=lambda prompt, system: answer,
    )


def _surfaces() -> tuple[Surface, ...]:
    return (
        Surface(
            url="http://127.0.0.1:8080/api/invoices/4821",
            host="127.0.0.1",
            param="4821",
            capability=CAP_ACCESS_DIFFERS_BY_SESSION,
            label="invoice object",
        ),
        Surface(
            url="http://127.0.0.1:8080/api/admin/promote",
            host="127.0.0.1",
            param="user_id",
            capability=CAP_PUBLIC_PARAM,
            label="method_role=target",
        ),
        Surface(
            url="http://127.0.0.1:8080/api/account",
            host="127.0.0.1",
            param="email",
            capability=CAP_PUBLIC_PARAM,
            label="method_role=victim",
        ),
    )


def _keys() -> set[str]:
    return {surface.key for surface in _surfaces()}


def _anomaly() -> dict:
    return {
        "technique": "generic_differential",
        "arm": f"generic_differential@{_surfaces()[0].key}",
        "kind": "observation_outside_expected",
        "expected": {
            "probe_suffix": ":other_read",
            "field": "status",
            "within": [401, 403, 404],
        },
        "observed": {"value": 500},
    }


# --------------------------------------------------------------------------- #
# the pure half
# --------------------------------------------------------------------------- #


def test_the_ontology_only_offers_shapes_the_engine_speaks() -> None:
    assert {row["claim_shape"] for row in abduce.ontology_rows()} == set(CLAIM_SHAPES)


def test_a_valid_answer_extracts_rows() -> None:
    answer = {
        "hypotheses": [
            {
                "surface_key": next(iter(_keys())),
                "claim_shape": "object_read",
                "vuln_class": "object-access",
                "summary": "the object may be readable",
                "why": "500 on the denied read",
            }
        ]
    }
    rows = abduce.extract(
        answer, list_name="hypotheses", cap=abduce.MAX_ABDUCED, known_surface_keys=_keys()
    )
    assert len(rows) == 1 and rows[0]["claim_shape"] == "object_read"


def test_an_invented_surface_or_shape_degrades_the_answer_whole() -> None:
    for bad in (
        {"surface_key": "http://evil/", "claim_shape": "object_read", "vuln_class": "x-y"},
        {"surface_key": next(iter(_keys())), "claim_shape": "teleportation", "vuln_class": "x-y"},
        {"surface_key": next(iter(_keys())), "claim_shape": "object_read", "vuln_class": "Not A Class"},
    ):
        answer = {"hypotheses": [bad]}
        assert (
            abduce.extract(
                answer, list_name="hypotheses", cap=abduce.MAX_ABDUCED, known_surface_keys=_keys()
            )
            == []
        )


def test_an_over_cap_answer_is_refused() -> None:
    key = next(iter(_keys()))
    answer = {
        "hypotheses": [
            {"surface_key": key, "claim_shape": "object_read", "vuln_class": "a-b"}
            for _ in range(abduce.MAX_ABDUCED + 1)
        ]
    }
    assert (
        abduce.extract(
            answer, list_name="hypotheses", cap=abduce.MAX_ABDUCED, known_surface_keys=_keys()
        )
        == []
    )


# --------------------------------------------------------------------------- #
# proposal_for: a validated row becomes a real plan row
# --------------------------------------------------------------------------- #


def test_proposal_for_object_read_builds_a_plan_row() -> None:
    surface = _surfaces()[0]
    proposal = proposal_for(
        surface=surface,
        surfaces=_surfaces(),
        claim_shape="object_read",
        witness="cell:1",
        vuln_class="object-access",
    )
    assert proposal is not None
    assert proposal.rule == RULE_LLM_ABDUCTION
    assert proposal.plan["plan_id"].startswith("object_read:")
    assert proposal.needs_verifier == "authorization.differential"


def test_proposal_for_state_change_finds_the_composition() -> None:
    target, victim = _surfaces()[1], _surfaces()[2]
    proposal = proposal_for(
        surface=victim,
        surfaces=_surfaces(),
        claim_shape="state_change",
        witness="cell:2",
    )
    assert proposal is not None
    assert proposal.claim_shape == "state_change"
    assert proposal.needs_verifier == "authorization.state_change"


# --------------------------------------------------------------------------- #
# the junction
# --------------------------------------------------------------------------- #


def test_the_junction_turns_a_validated_answer_into_proposals() -> None:
    answer = json.dumps(
        {
            "hypotheses": [
                {
                    "surface_key": _surfaces()[0].key,
                    "claim_shape": "object_read",
                    "vuln_class": "object-access",
                    "summary": "readable",
                    "why": "500",
                }
            ]
        }
    )
    junction = AbductionJunction(scripted_client(answer))
    result = junction.explain(_anomaly(), _surfaces(), world=WorldLog(), now=1.0)
    assert result.proposed == 1
    assert result.proposals[0].plan["plan_id"].startswith("object_read:")
    assert result.source == "live"


def test_the_junction_degrades_without_a_key() -> None:
    junction = AbductionJunction(LLMClient())
    result = junction.explain(_anomaly(), _surfaces())
    assert result.proposed == 0 and result.source == "degraded"


def test_the_property_channel_works_with_no_anomaly() -> None:
    answer = json.dumps(
        {
            "properties": [
                {
                    "surface_key": _surfaces()[0].key,
                    "claim_shape": "object_read",
                    "vuln_class": "object-access",
                    "why": "sequential invoice ids",
                }
            ]
        }
    )
    junction = AbductionJunction(scripted_client(answer))
    result = junction.propose_properties(_surfaces(), world=WorldLog(), now=1.0)
    assert result.proposed == 1
    assert result.proposals[0].rule == RULE_LLM_ABDUCTION


def test_the_advisory_wrapper_degrades_to_empty() -> None:
    advisory = Advisory.from_env()  # no key in the test environment
    assert advisory.abduced(_anomaly(), _surfaces()).proposed == 0
    assert advisory.proposed_properties(_surfaces()).proposed == 0
