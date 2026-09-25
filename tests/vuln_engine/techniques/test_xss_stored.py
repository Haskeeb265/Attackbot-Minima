"""``xss_stored`` as a set of pure functions over recorded observations.

The stored sibling of the ``xss_reflected`` test file, with the two shapes that
make the class different exercised where they live: the probe grammar is a
*pair* (inject then read-back, in that order), and the candidate's confirmation
spec is the two-step one — because no URL carries a POST-stored payload, the
verifier must be told how to put the payload back.

No I/O, no browser, no network. Everything here runs on recorded observations.
"""

from __future__ import annotations

from urllib.parse import parse_qs, unquote

from service.vuln_engine.kernel.evidence import EVIDENCE_REFLECTION, EVIDENCE_SEMANTIC
from service.vuln_engine.kernel.observation import (
    CONTEXT_IN_TAG,
    CONTEXT_JSON_VALUE,
    CONTEXT_RAW_HTML,
    CONTEXT_UNKNOWN,
    OBS_REFLECTION,
    Observation,
)
from service.vuln_engine.kernel.technique import (
    CAP_INFLUENCE_REMOTE_FETCH,
    CAP_PERSISTENT_STORAGE,
    CONFIRM_STORED_EXECUTE,
    EngagementSeed,
    KIND_HTTP,
    ORACLE_REFLECTION,
    PURPOSE_PROPOSE,
    Surface,
)
from service.vuln_engine.techniques.xss_stored import TECHNIQUE
from service.vuln_engine.techniques.xss_stored import hypothesis as hypothesis_mod
from service.vuln_engine.techniques.xss_stored import interpret as interpret_mod
from service.vuln_engine.techniques.xss_stored import probes as probe_grammar
from service.vuln_engine.techniques.xss_reflected import probes as reflected_grammar


def _surface(**overrides) -> Surface:
    fields = {
        "url": "http://fixture.test/comment",
        "host": "fixture.test",
        "param": "text",
        "where": "body",
        "capability": CAP_PERSISTENT_STORAGE,
        "companions": {"sign": "1"},
        "read_back": "http://fixture.test/comments",
    }
    fields.update(overrides)
    return Surface(**fields)  # type: ignore[arg-type]


def _seed(*surfaces: Surface) -> EngagementSeed:
    return EngagementSeed(target="fixture.test", surfaces=tuple(surfaces or (_surface(),)))


def _reflection(**payload_overrides) -> Observation:
    payload = {
        "reflected": True,
        "occurrences": 1,
        "context": CONTEXT_RAW_HTML,
        "contexts": [CONTEXT_RAW_HTML],
    }
    payload.update(payload_overrides)
    return Observation(
        kind=OBS_REFLECTION,
        probe="xss_stored:readback",
        at=10.0,
        payload=payload,
    )


# --------------------------------------------------------------------------- #
# hypotheses and the territory split
# --------------------------------------------------------------------------- #


def test_a_body_surface_with_storage_claim_produces_one_hypothesis() -> None:
    hypotheses = hypothesis_mod.hypotheses(_surface())
    assert len(hypotheses) == 1
    assert hypotheses[0].rests_on == CAP_PERSISTENT_STORAGE
    assert hypotheses[0].preconditions == (CAP_PERSISTENT_STORAGE,)
    assert "stored" in hypotheses[0].claim


def test_a_query_surface_is_not_ours() -> None:
    # A query parameter reflects; the wire lens owns it. The stored class needs
    # a *body* submission to a *storing* surface.
    assert hypothesis_mod.hypotheses(_surface(where="query")) == []


def test_a_surface_with_no_parameter_is_not_ours() -> None:
    assert hypothesis_mod.hypotheses(_surface(param="")) == []


def test_the_technique_only_takes_surfaces_declared_as_storing() -> None:
    seed = _seed(
        _surface(),
        _surface(url="http://fixture.test/search", param="q", where="query", capability="public_param", companions={}, read_back=""),
        _surface(url="http://fixture.test/fetch", param="url", where="query", capability=CAP_INFLUENCE_REMOTE_FETCH, companions={}, read_back=""),
    )
    assert [surface.param for surface in TECHNIQUE.surfaces(seed)] == ["text"]


# --------------------------------------------------------------------------- #
# probes
# --------------------------------------------------------------------------- #


def test_the_probe_grammar_is_an_inject_then_a_read_back() -> None:
    specs = probe_grammar.probes(hypothesis_mod.hypotheses(_surface())[0])
    assert [spec.id for spec in specs] == ["xss_stored:inject", "xss_stored:readback"]
    assert all(spec.kind == KIND_HTTP for spec in specs)
    assert all(spec.purpose == PURPOSE_PROPOSE for spec in specs)


def test_the_inject_carries_the_canary_and_the_companions() -> None:
    spec = probe_grammar.inject_spec(hypothesis_mod.hypotheses(_surface())[0], "text", probe_grammar.CANARY)
    assert spec.detail["method"] == "POST"
    body = parse_qs(str(spec.detail["content"]), keep_blank_values=True)
    assert body["text"] == [probe_grammar.CANARY]
    # The companion field is the form's protocol — without it, "nothing stored"
    # would be indistinguishable from "nothing submitted".
    assert body["sign"] == ["1"]


def test_the_inject_does_not_duplicate_the_param_as_a_companion() -> None:
    surface = _surface(companions={"text": "oops", "sign": "1"})
    spec = probe_grammar.inject_spec(hypothesis_mod.hypotheses(surface)[0], "text", "v")
    body = parse_qs(str(spec.detail["content"]), keep_blank_values=True)
    assert body["text"] == ["v"]


def test_the_read_back_is_a_quiet_get_of_the_rendering_page() -> None:
    spec = probe_grammar.read_back_spec(hypothesis_mod.hypotheses(_surface())[0])
    assert spec.detail["method"] == "GET"
    assert spec.detail["url"] == "http://fixture.test/comments"
    assert spec.oracle == ORACLE_REFLECTION
    assert spec.canary == probe_grammar.CANARY
    assert spec.mark == probe_grammar.MARK


def test_a_surface_without_read_back_reads_back_from_itself() -> None:
    # The common "post and the list re-renders" shape: one page is both.
    surface = _surface(read_back="")
    spec = probe_grammar.read_back_spec(hypothesis_mod.hypotheses(surface)[0])
    assert spec.detail["url"] == "http://fixture.test/comment"


# --------------------------------------------------------------------------- #
# interpretation
# --------------------------------------------------------------------------- #


def test_no_reflection_is_no_candidate() -> None:
    hypothesis = hypothesis_mod.hypotheses(_surface())[0]
    assert interpret_mod.candidates(hypothesis, []) == []


def test_an_escaped_rendering_is_a_negative_result_not_a_lead() -> None:
    hypothesis = hypothesis_mod.hypotheses(_surface())[0]
    escaped = _reflection(reflected=False, escaped_verbatim=True)
    assert interpret_mod.candidates(hypothesis, [escaped]) == []


def test_a_transformed_only_rendering_is_not_a_candidate() -> None:
    hypothesis = hypothesis_mod.hypotheses(_surface())[0]
    transformed = _reflection(reflected=False, transformed=True)
    assert interpret_mod.candidates(hypothesis, [transformed]) == []


def test_an_executable_context_produces_a_two_step_confirmation_spec() -> None:
    hypothesis = hypothesis_mod.hypotheses(_surface())[0]
    candidates = interpret_mod.candidates(hypothesis, [_reflection()])
    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.proposer_grade == EVIDENCE_SEMANTIC
    assert candidate.confirm["kind"] == CONFIRM_STORED_EXECUTE
    # The spec carries the *whole* second inject: payload as the param, the
    # form's companions, and the page the browser must run.
    inject = candidate.confirm["inject"]
    body = parse_qs(str(inject["content"]), keep_blank_values=True)
    assert unquote(body["text"][0]).startswith("<script>")
    assert body["sign"] == ["1"]
    assert inject["method"] == "POST"
    assert candidate.confirm["read_back"] == "http://fixture.test/comments"
    # The markers are the reflected grammar's — the context decides the payload,
    # not the transport that delivered it.
    marker_name = reflected_grammar.marker_name(CONTEXT_RAW_HTML)
    assert candidate.confirm["markers"][marker_name] == reflected_grammar.marker_expression(CONTEXT_RAW_HTML)
    assert candidate.confirm["dialog"] == reflected_grammar.DIALOG_TEXT
    assert candidate.repro_url == "http://fixture.test/comments"


def test_a_context_nothing_can_be_confirmed_from_is_a_lead() -> None:
    hypothesis = hypothesis_mod.hypotheses(_surface())[0]
    candidates = interpret_mod.candidates(hypothesis, [_reflection(context=CONTEXT_IN_TAG, contexts=[CONTEXT_IN_TAG])])
    assert len(candidates) == 1
    assert candidates[0].confirm == {}
    assert "no confirmation payload" in candidates[0].summary


def test_a_json_rendering_is_a_lead_pointing_at_the_dom_lens() -> None:
    hypothesis = hypothesis_mod.hypotheses(_surface())[0]
    candidates = interpret_mod.candidates(hypothesis, [_reflection(context=CONTEXT_JSON_VALUE, contexts=[CONTEXT_JSON_VALUE])])
    assert candidates and candidates[0].confirm == {}
    assert "DOM lens" in candidates[0].summary


def test_an_unplaceable_rendering_is_reported_as_a_reflection_grade_lead() -> None:
    hypothesis = hypothesis_mod.hypotheses(_surface())[0]
    candidates = interpret_mod.candidates(hypothesis, [_reflection(context=CONTEXT_UNKNOWN, contexts=[CONTEXT_UNKNOWN])])
    assert candidates[0].proposer_grade == EVIDENCE_REFLECTION


def test_the_candidate_id_is_deterministic() -> None:
    hypothesis = hypothesis_mod.hypotheses(_surface())[0]
    first = interpret_mod.candidates(hypothesis, [_reflection()])[0]
    second = interpret_mod.candidates(hypothesis, [_reflection(at=99.0)])[0]
    assert first.id == second.id


def test_the_proposer_evidence_is_never_the_execution_class() -> None:
    hypothesis = hypothesis_mod.hypotheses(_surface())[0]
    candidate = interpret_mod.candidates(hypothesis, [_reflection()])[0]
    assert candidate.evidence is not None
    assert candidate.evidence.grade in (EVIDENCE_REFLECTION, EVIDENCE_SEMANTIC)
    assert not candidate.evidence.sufficient_for_finding
