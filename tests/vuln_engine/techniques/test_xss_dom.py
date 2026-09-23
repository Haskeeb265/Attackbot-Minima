"""``xss_dom`` as a set of pure functions over recorded observations.

Same discipline as the sibling technique's suite: no I/O, no browser, no
network. The groups follow the technique contract — hypothesise, propose,
interpret — and the interpretation group carries the rules the sketch pinned:
placement is a lead unless a payload family owns the context, the
``dom_url_attribute`` placement never auto-confirms, and a wire-lens reflection
on the same surface dedupes the DOM candidate away.
"""

from __future__ import annotations

from service.vuln_engine.kernel.evidence import EVIDENCE_SEMANTIC
from service.vuln_engine.kernel.observation import (
    CONTEXT_DOM_ABSENT,
    CONTEXT_DOM_TEXT,
    CONTEXT_DOM_URL_ATTRIBUTE,
    CONTEXT_DOUBLE_QUOTED_ATTRIBUTE,
    CONTEXT_RAW_HTML,
    OBS_DOM_PLACEMENT,
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
from service.vuln_engine.techniques.xss_dom import TECHNIQUE
from service.vuln_engine.techniques.xss_dom import hypothesis as hypothesis_mod
from service.vuln_engine.techniques.xss_dom import interpret as interpret_mod
from service.vuln_engine.techniques.xss_dom import probes as probe_grammar
from service.vuln_engine.techniques.common import (
    DOM_MARKER_PREFIX,
    DOM_Q_HTML,
    DOM_Q_PRESENT,
    DOM_Q_SCRIPT,
    DOM_Q_TEXT,
    DOM_Q_URLATTR,
    dom_marker,
)
from service.vuln_engine.techniques.xss_reflected import probes as reflected


def _surface(**overrides) -> Surface:
    fields = {
        "url": "http://fixture.test/app",
        "host": "fixture.test",
        "param": "q",
        "capability": "public_param",
    }
    fields.update(overrides)
    return Surface(**fields)  # type: ignore[arg-type]


def _hypothesis(**overrides):
    from service.vuln_engine.kernel.technique import Hypothesis

    fields = {
        "id": "xss_dom:fixture.test:app:q",
        "technique": "xss_dom",
        "surface": _surface(),
        "claim": "the page renders q",
    }
    fields.update(overrides)
    return Hypothesis(**fields)  # type: ignore[arg-type]


def _placement(context: str, *, question: str = "", at: float = 10.0) -> Observation:
    return Observation(
        kind=OBS_DOM_PLACEMENT,
        probe="xss_dom:placement",
        at=at,
        payload={"context": context, "question": question or context},
    )


# --------------------------------------------------------------------------- #
# hypotheses
# --------------------------------------------------------------------------- #


def test_a_parameterised_surface_produces_one_hypothesis() -> None:
    hypotheses = hypothesis_mod.hypotheses(_surface())
    assert len(hypotheses) == 1
    assert hypotheses[0].rests_on == "public_param"
    assert "renders" in hypotheses[0].claim


def test_a_surface_with_no_parameter_is_not_ours() -> None:
    assert hypothesis_mod.hypotheses(_surface(param="")) == []


# --------------------------------------------------------------------------- #
# probes — the three families, in order
# --------------------------------------------------------------------------- #


def test_the_grammar_is_canary_then_placement_then_payloads() -> None:
    specs = probe_grammar.probes(_hypothesis())
    assert [spec.kind for spec in specs] == [
        KIND_HTTP,
        KIND_BROWSER,
        KIND_BROWSER,
        KIND_BROWSER,
        KIND_BROWSER,
    ]
    assert specs[0].purpose == PURPOSE_PROPOSE
    assert specs[1].purpose == PURPOSE_PROPOSE
    assert all(spec.purpose == PURPOSE_CONFIRM for spec in specs[2:])
    # The payload probes are gated: a browser never runs on an unmeasured
    # placement.
    assert [spec.requires_context for spec in specs[2:]] == [
        (CONTEXT_RAW_HTML,),
        ("js_code",),
        (CONTEXT_DOM_URL_ATTRIBUTE,),
    ]


def test_the_canary_reuses_the_sibling_grammars_spelling() -> None:
    # One canary vocabulary across both lenses: half the visibility cost, and
    # the two techniques' surfaces can be compared row for row.
    specs = probe_grammar.probes(_hypothesis())
    assert specs[0].canary == reflected.CANARY
    assert specs[0].mark == reflected.MARK


def test_placement_markers_are_boolean_dom_questions() -> None:
    specs = probe_grammar.probes(_hypothesis())
    markers = specs[1].detail["markers"]
    expected = {
        dom_marker(reflected.MARK, DOM_Q_PRESENT),
        dom_marker(reflected.MARK, DOM_Q_TEXT),
        dom_marker(reflected.MARK, DOM_Q_URLATTR),
        dom_marker(reflected.MARK, DOM_Q_HTML),
        dom_marker(reflected.MARK, DOM_Q_SCRIPT),
    }
    assert set(markers) == expected
    # The string-lookup questions mention the canary needle; the markup
    # question looks for the custom element the canary value appends — the
    # element only materialises if the page parsed our bytes as markup.
    needle = reflected.CANARY.replace('"', '\\"')
    string_questions = {
        dom_marker(reflected.MARK, DOM_Q_PRESENT),
        dom_marker(reflected.MARK, DOM_Q_TEXT),
        dom_marker(reflected.MARK, DOM_Q_URLATTR),
        dom_marker(reflected.MARK, DOM_Q_SCRIPT),
    }
    assert all(needle in markers[name] for name in string_questions)
    assert f"ve-{reflected.MARK}" in markers[dom_marker(reflected.MARK, DOM_Q_HTML)]
    # The canary value arms every question: plain canary plus markup probe.
    assert specs[0].payload == probe_grammar.CANARY_VALUE
    assert probe_grammar.MARKUP_PROBE in probe_grammar.CANARY_VALUE


# --------------------------------------------------------------------------- #
# interpretation — the five honest outcomes
# --------------------------------------------------------------------------- #


def test_no_placement_rows_means_no_candidates() -> None:
    assert interpret_mod.candidates(_hypothesis(), []) == []


def test_value_present_but_nowhere_live_is_a_recorded_negative() -> None:
    # present answered true but no placement row followed: the DOM parsed the
    # value nowhere live. That is dom_absent as a *fact*, not a silence.
    rows = [_placement(CONTEXT_DOM_ABSENT, question=DOM_Q_PRESENT)]
    out = interpret_mod.candidates(_hypothesis(), rows)
    assert len(out) == 1
    assert out[0].confirm == {}  # a lead, never auto-confirmed
    assert out[0].evidence.payload["context"] == CONTEXT_DOM_ABSENT


def test_text_and_unclassified_attribute_placements_are_leads() -> None:
    for context in (CONTEXT_DOM_TEXT, "dom_attribute"):
        out = interpret_mod.candidates(_hypothesis(), [_placement(context)])
        assert len(out) == 1
        assert out[0].confirm == {}
        assert out[0].evidence.grade == EVIDENCE_SEMANTIC


def test_the_url_attribute_placement_is_a_lead_documenting_the_payload() -> None:
    # javascript: in a page-parsed attribute executes on user interaction,
    # which no verifier in this phase simulates — so this placement must never
    # carry a confirmation spec, whatever the payload grammar contains.
    out = interpret_mod.candidates(_hypothesis(), [_placement(CONTEXT_DOM_URL_ATTRIBUTE)])
    assert len(out) == 1
    assert out[0].confirm == {}
    assert "user interaction" in out[0].summary


def test_a_markup_placement_produces_a_verifiable_candidate() -> None:
    out = interpret_mod.candidates(_hypothesis(), [_placement(CONTEXT_RAW_HTML)])
    assert len(out) == 1
    confirm = out[0].confirm
    assert confirm["kind"] == "browser.run"
    assert confirm["context"] == CONTEXT_RAW_HTML
    assert confirm["dialog"] == reflected.DIALOG_TEXT
    assert confirm["markers"]
    assert out[0].repro_url.startswith("http://fixture.test/app?")


def test_a_wire_reflection_dedupes_the_dom_candidate() -> None:
    # Same attack path, two lenses: when the wire lens already found an
    # unescaped executable reflection on this surface, the DOM technique
    # claims no candidate for it.
    wire = Observation(
        kind=OBS_REFLECTION,
        probe="xss_reflected:canary",
        at=9.0,
        payload={
            "reflected": True,
            "occurrences": 1,
            "context": CONTEXT_DOUBLE_QUOTED_ATTRIBUTE,
        },
    )
    assert interpret_mod.candidates(
        _hypothesis(), [wire, _placement(CONTEXT_RAW_HTML)]
    ) == []


def test_an_escaped_wire_reflection_does_not_dedupe() -> None:
    # The server escaped the reflection: the wire lens's path is dead, and the
    # DOM placement (if any) is this technique's to propose.
    wire = Observation(
        kind=OBS_REFLECTION,
        probe="xss_reflected:canary",
        at=9.0,
        payload={
            "reflected": True,
            "occurrences": 1,
            "context": CONTEXT_DOUBLE_QUOTED_ATTRIBUTE,
            "escaped_verbatim": True,
        },
    )
    out = interpret_mod.candidates(_hypothesis(), [wire, _placement(CONTEXT_RAW_HTML)])
    assert len(out) == 1
    assert out[0].technique == "xss_dom"


# --------------------------------------------------------------------------- #
# the adapter
# --------------------------------------------------------------------------- #


def test_the_technique_takes_ordinary_public_param_surfaces() -> None:
    from service.vuln_engine.kernel.technique import CAP_INFLUENCE_REMOTE_FETCH, EngagementSeed

    seed = EngagementSeed(
        target="fixture.test",
        surfaces=(
            _surface(),
            _surface(url="http://fixture.test/fetch", param="url", capability=CAP_INFLUENCE_REMOTE_FETCH),
        ),
    )
    assert [surface.param for surface in TECHNIQUE.surfaces(seed)] == ["q"]
