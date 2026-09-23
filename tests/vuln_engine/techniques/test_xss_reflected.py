"""``xss_reflected`` as a set of pure functions over recorded observations.

No I/O, no browser, no network: the technique's whole value is that it can be read
and tested without any of them, which is what makes it safe to add, delete or
rewrite. The tests are grouped by the three things a technique does — hypothesise,
propose probes, interpret — and the interpretation group is the one that matters:
it is where a lead, a refusal and a candidate have to be told apart.
"""

from __future__ import annotations

from urllib.parse import unquote

from service.vuln_engine.kernel.evidence import (
    EVIDENCE_REFLECTION,
    EVIDENCE_SEMANTIC,
    Evidence,
)
from service.vuln_engine.kernel.observation import (
    CONTEXT_DOUBLE_QUOTED_ATTRIBUTE,
    CONTEXT_IN_TAG,
    CONTEXT_RAW_HTML,
    CONTEXT_UNKNOWN,
    OBS_REFLECTION,
    Observation,
)
from service.vuln_engine.kernel.technique import (
    KIND_BROWSER,
    KIND_HTTP,
    PURPOSE_CONFIRM,
    PURPOSE_PROPOSE,
    Surface,
)
from service.vuln_engine.techniques.xss_reflected import TECHNIQUE
from service.vuln_engine.techniques.xss_reflected import hypothesis as hypothesis_mod
from service.vuln_engine.techniques.xss_reflected import interpret as interpret_mod
from service.vuln_engine.techniques.xss_reflected import probes as probe_grammar


def _surface(**overrides) -> Surface:
    fields = {
        "url": "http://fixture.test/search",
        "host": "fixture.test",
        "param": "q",
        "capability": "public_param",
    }
    fields.update(overrides)
    return Surface(**fields)  # type: ignore[arg-type]


def _reflection(**payload_overrides) -> Observation:
    payload = {
        "reflected": True,
        "occurrences": 1,
        "context": CONTEXT_DOUBLE_QUOTED_ATTRIBUTE,
        "contexts": [CONTEXT_DOUBLE_QUOTED_ATTRIBUTE],
    }
    payload.update(payload_overrides)
    return Observation(
        kind=OBS_REFLECTION,
        probe="xss_reflected:canary",
        at=10.0,
        payload=payload,
    )


# --------------------------------------------------------------------------- #
# hypotheses
# --------------------------------------------------------------------------- #


def test_a_parameterised_surface_produces_one_hypothesis() -> None:
    hypotheses = hypothesis_mod.hypotheses(_surface())
    assert len(hypotheses) == 1
    assert hypotheses[0].rests_on == "http_response_reflects_input"
    assert hypotheses[0].preconditions == ("public_param",)


def test_a_surface_with_no_parameter_is_not_ours() -> None:
    assert hypothesis_mod.hypotheses(_surface(param="")) == []


def test_the_technique_ignores_surfaces_that_claim_another_purpose() -> None:
    # A capability claim has to mean something in both directions: a surface
    # declared as "the server fetches this" is not declared as reflective.
    from service.vuln_engine.kernel.technique import CAP_INFLUENCE_REMOTE_FETCH, EngagementSeed

    seed = EngagementSeed(
        target="fixture.test",
        surfaces=(
            _surface(),
            _surface(url="http://fixture.test/fetch", param="url", capability=CAP_INFLUENCE_REMOTE_FETCH),
        ),
    )
    assert [surface.param for surface in TECHNIQUE.surfaces(seed)] == ["q"]


# --------------------------------------------------------------------------- #
# probes
# --------------------------------------------------------------------------- #


def test_the_probe_grammar_is_a_canary_plus_one_confirmation_per_context() -> None:
    specs = TECHNIQUE.probes(hypothesis_mod.hypotheses(_surface())[0])
    canaries = [spec for spec in specs if spec.oracle == "reflection_at_least_once"]
    confirmations = [spec for spec in specs if spec.oracle == "script_execution"]
    assert len(canaries) == 1
    assert len(confirmations) == 4  # one per executable context
    assert canaries[0].kind == KIND_HTTP and canaries[0].purpose == PURPOSE_PROPOSE
    assert all(spec.kind == KIND_BROWSER and spec.purpose == PURPOSE_CONFIRM for spec in confirmations)


def test_the_canary_carries_the_characters_that_decide_everything() -> None:
    canary = TECHNIQUE.probes(hypothesis_mod.hypotheses(_surface())[0])[0]
    assert canary.canary == probe_grammar.CANARY
    assert canary.mark in canary.canary
    assert set("\"'<>") <= set(canary.canary)
    assert unquote(canary.detail["url"]).endswith(f"q={probe_grammar.CANARY}")


def test_a_confirmation_declares_the_context_it_is_only_valid_in() -> None:
    specs = TECHNIQUE.probes(hypothesis_mod.hypotheses(_surface())[0])
    for spec in specs:
        if spec.purpose != PURPOSE_CONFIRM:
            continue
        assert len(spec.requires_context) == 1
        assert spec.requires_context[0] in spec.id
        assert spec.noise["requires_browser"] is True


def test_a_payload_sets_a_marker_and_opens_a_dialog_we_recognise() -> None:
    specs = TECHNIQUE.probes(hypothesis_mod.hypotheses(_surface())[0])
    exec_spec = next(spec for spec in specs if spec.id.endswith(CONTEXT_DOUBLE_QUOTED_ATTRIBUTE))
    url = unquote(str(exec_spec.detail["url"]))
    assert url.startswith('http://fixture.test/search?q="><script>')
    assert probe_grammar.DIALOG_TEXT in url
    markers = exec_spec.detail["markers"]
    marker_name = probe_grammar.marker_name(CONTEXT_DOUBLE_QUOTED_ATTRIBUTE)
    assert markers[marker_name] == probe_grammar.marker_expression(CONTEXT_DOUBLE_QUOTED_ATTRIBUTE)
    # The marker the expression checks is the one the payload sets.
    assert probe_grammar.marker_identifier(CONTEXT_DOUBLE_QUOTED_ATTRIBUTE) in exec_spec.payload


def test_each_context_gets_the_payload_that_breaks_out_of_it() -> None:
    payloads = {
        context: probe_grammar.payload_for(hypothesis_mod.hypotheses(_surface())[0], context)
        for context in (CONTEXT_DOUBLE_QUOTED_ATTRIBUTE, "single_quoted_attribute", "unquoted_attribute", CONTEXT_RAW_HTML)
    }
    assert payloads[CONTEXT_DOUBLE_QUOTED_ATTRIBUTE].startswith('">')
    assert payloads["single_quoted_attribute"].startswith("'>")
    assert payloads["unquoted_attribute"].startswith(">")
    assert payloads[CONTEXT_RAW_HTML].startswith("<script>")


# --------------------------------------------------------------------------- #
# interpretation
# --------------------------------------------------------------------------- #


def test_no_reflection_is_no_candidate() -> None:
    hypothesis = hypothesis_mod.hypotheses(_surface())[0]
    assert interpret_mod.candidates(hypothesis, []) == []


def test_an_escaped_reflection_is_a_negative_result_not_a_lead() -> None:
    hypothesis = hypothesis_mod.hypotheses(_surface())[0]
    escaped = _reflection(reflected=False, escaped_verbatim=True)
    assert interpret_mod.candidates(hypothesis, [escaped]) == []


def test_a_transformed_only_reflection_is_not_a_candidate() -> None:
    hypothesis = hypothesis_mod.hypotheses(_surface())[0]
    transformed = _reflection(reflected=False, transformed=True)
    assert interpret_mod.candidates(hypothesis, [transformed]) == []


def test_an_executable_context_produces_a_candidate_with_a_confirmation_spec() -> None:
    hypothesis = hypothesis_mod.hypotheses(_surface())[0]
    candidates = interpret_mod.candidates(hypothesis, [_reflection()])
    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.proposer_grade == EVIDENCE_SEMANTIC
    assert candidate.confirm["kind"] == "browser.run"
    assert candidate.confirm["context"] == CONTEXT_DOUBLE_QUOTED_ATTRIBUTE
    assert candidate.confirm["dialog"] == probe_grammar.DIALOG_TEXT
    assert candidate.repro_url.startswith("http://fixture.test/search?q=%22%3E%3Cscript%3E")
    assert candidate.payload.startswith('">')


def test_a_context_nothing_can_be_confirmed_from_is_a_lead() -> None:
    # A candidate with no confirmation spec is a *lead*: the verifier refuses it,
    # the refusal is logged, and it never becomes a finding.
    hypothesis = hypothesis_mod.hypotheses(_surface())[0]
    candidates = interpret_mod.candidates(hypothesis, [_reflection(context=CONTEXT_IN_TAG)])
    assert len(candidates) == 1
    assert candidates[0].confirm == {}
    assert candidates[0].proposer_grade == EVIDENCE_SEMANTIC
    assert "no confirmation payload" in candidates[0].summary


def test_a_javascript_string_is_a_lead_rather_than_a_finding() -> None:
    # The context is executable in principle, but Phase 1 has no payload that breaks
    # out of a JS string — and saying so is better than a silence or a guess.
    hypothesis = hypothesis_mod.hypotheses(_surface())[0]
    candidates = interpret_mod.candidates(
        hypothesis, [_reflection(context="js_string", contexts=["js_string"])]
    )
    assert candidates and candidates[0].confirm == {}
    assert "js string" in candidates[0].summary


def test_an_unplaceable_reflection_is_reported_as_a_reflection_grade_lead() -> None:
    hypothesis = hypothesis_mod.hypotheses(_surface())[0]
    candidates = interpret_mod.candidates(
        hypothesis, [_reflection(context=CONTEXT_UNKNOWN, contexts=[CONTEXT_UNKNOWN])]
    )
    assert candidates[0].proposer_grade == EVIDENCE_REFLECTION
    assert candidates[0].evidence is not None
    assert candidates[0].evidence.grade == EVIDENCE_REFLECTION


def test_the_candidate_id_is_deterministic() -> None:
    hypothesis = hypothesis_mod.hypotheses(_surface())[0]
    first = interpret_mod.candidates(hypothesis, [_reflection()])[0]
    second = interpret_mod.candidates(hypothesis, [_reflection(at=99.0)])[0]
    assert first.id == second.id


def test_the_proposer_evidence_is_the_reflection_never_the_execution_class() -> None:
    hypothesis = hypothesis_mod.hypotheses(_surface())[0]
    candidate = interpret_mod.candidates(hypothesis, [_reflection()])[0]
    assert candidate.evidence is not None
    assert candidate.evidence.grade in (EVIDENCE_REFLECTION, EVIDENCE_SEMANTIC)
    assert not candidate.evidence.sufficient_for_finding


def test_an_unrelated_evidence_object_cannot_be_smuggled_in_as_semantic() -> None:
    # A guard against the cheapest possible mistake: naming the class by hand.
    with __import__("pytest").raises(ValueError):
        Evidence(kind="observation.reflection", grade="looks-fine")
