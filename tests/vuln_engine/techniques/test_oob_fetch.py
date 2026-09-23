"""``oob_fetch``: a claimed capability, a sentinel, and a correlation that must match.

Three things are worth testing here and each has a failure mode that would be
invisible in production:

* the hypothesis fires **only** on the claimed capability — otherwise the engine
  asks every server on the engagement to fetch our collaborator;
* the probe carries a *sentinel* rather than a URL, because a pure technique cannot
  ask a transport for anything, and the sentinel has to survive percent-encoding or
  the driver will never find it again;
* the proposer's evidence is tied to **its own probe's** echo. An echo from
  another probe would be a cross-attribution nobody would notice until a blind
  finding was reported against the wrong surface.
"""

from __future__ import annotations

from urllib.parse import unquote

from service.vuln_engine.kernel.evidence import EVIDENCE_REFLECTION
from service.vuln_engine.kernel.observation import OBS_REFLECTION, Observation
from service.vuln_engine.kernel.technique import (
    CAP_INFLUENCE_REMOTE_FETCH,
    KIND_HTTP,
    OOB_URL_SENTINEL_PREFIX,
    PURPOSE_PROPOSE,
    Surface,
    oob_sentinel,
)
from service.vuln_engine.techniques.oob_fetch import TECHNIQUE
from service.vuln_engine.techniques.oob_fetch import hypothesis as hypothesis_mod
from service.vuln_engine.techniques.oob_fetch import interpret as interpret_mod
from service.vuln_engine.techniques.oob_fetch import probes as probe_grammar


def _surface(**overrides) -> Surface:
    fields = {
        "url": "http://fixture.test/fetch",
        "host": "fixture.test",
        "param": "url",
        "capability": CAP_INFLUENCE_REMOTE_FETCH,
    }
    fields.update(overrides)
    return Surface(**fields)  # type: ignore[arg-type]


def _hypothesis():
    return hypothesis_mod.hypotheses(_surface())[0]


def _echo(probe: str, **overrides) -> Observation:
    payload = {"reflected": True, "occurrences": 1, "context": "raw_html"}
    payload.update(overrides)
    return Observation(kind=OBS_REFLECTION, probe=probe, at=5.0, payload=payload)


# --------------------------------------------------------------------------- #
# hypothesis
# --------------------------------------------------------------------------- #


def test_the_hypothesis_fires_on_a_claimed_capability() -> None:
    hypotheses = hypothesis_mod.hypotheses(_surface())
    assert len(hypotheses) == 1
    assert hypotheses[0].rests_on == CAP_INFLUENCE_REMOTE_FETCH
    assert "claimed capability" in hypotheses[0].claim


def test_the_hypothesis_does_not_fire_on_a_plain_parameter() -> None:
    # The whole reason the capability exists: a parameter is not an invitation.
    assert hypothesis_mod.hypotheses(_surface(capability="public_param")) == []
    assert hypothesis_mod.hypotheses(_surface(capability="")) == []


# --------------------------------------------------------------------------- #
# probe
# --------------------------------------------------------------------------- #


def test_the_probe_carries_a_sentinel_that_survives_url_encoding() -> None:
    spec = probe_grammar.probes(_hypothesis())[0]
    probe = probe_grammar.probe_id(_hypothesis())
    sentinel = oob_sentinel(probe)
    assert spec.kind == KIND_HTTP and spec.purpose == PURPOSE_PROPOSE
    assert sentinel.startswith(OOB_URL_SENTINEL_PREFIX)
    assert sentinel.isalnum() and sentinel.islower() or "_" in sentinel
    # The driver finds it by literal replacement, so the encoded URL has to contain
    # it unchanged: that is why the sentinel is alphanumeric-only.
    assert sentinel in str(spec.detail["url"])
    assert unquote(str(spec.detail["url"])).endswith(f"url={sentinel}")


def test_the_canary_is_the_collaborators_own_answer_for_this_probe() -> None:
    spec = probe_grammar.probes(_hypothesis())[0]
    probe = probe_grammar.probe_id(_hypothesis())
    assert spec.canary == probe_grammar.echo_token(probe)
    assert probe in spec.canary
    assert spec.mark == probe_grammar.COLLABORATOR_TOKEN


def test_the_expected_interaction_path_is_derived_from_the_probe() -> None:
    probe = probe_grammar.probe_id(_hypothesis())
    assert probe_grammar.collaborator_path(probe) == f"/oob/{probe}"


# --------------------------------------------------------------------------- #
# interpretation
# --------------------------------------------------------------------------- #


def test_no_echo_is_no_candidate() -> None:
    assert interpret_mod.candidates(_hypothesis(), []) == []


def test_an_echo_from_this_probe_proposes_a_candidate() -> None:
    probe = probe_grammar.probe_id(_hypothesis())
    candidate = interpret_mod.candidates(_hypothesis(), [_echo(probe)])[0]
    assert candidate.proposer_grade == EVIDENCE_REFLECTION
    assert candidate.confirm["kind"] == "oob.read"
    assert candidate.confirm["probe"] == probe
    assert candidate.confirm["path"] == probe_grammar.collaborator_path(probe)
    assert candidate.confirm["token"] == probe_grammar.echo_token(probe)


def test_an_echo_from_another_probe_is_not_this_surface_s_evidence() -> None:
    candidate = interpret_mod.candidates(_hypothesis(), [_echo("oob_fetch:other:param")])
    assert candidate == []


def test_the_summary_never_claims_the_fetch_happened() -> None:
    # The proposer's evidence class cannot support a finding, and its own words
    # must not pretend otherwise: "would explain" is the honest phrasing.
    probe = probe_grammar.probe_id(_hypothesis())
    candidate = interpret_mod.candidates(_hypothesis(), [_echo(probe)])[0]
    assert "would explain" in candidate.summary
    assert candidate.evidence is not None
    assert not candidate.evidence.sufficient_for_finding


def test_the_repro_url_shows_where_the_collaborator_url_went() -> None:
    probe = probe_grammar.probe_id(_hypothesis())
    candidate = interpret_mod.candidates(_hypothesis(), [_echo(probe)])[0]
    assert candidate.repro_url.endswith(f"url={oob_sentinel(probe)}")


def test_a_transformed_echo_is_not_an_echo() -> None:
    probe = probe_grammar.probe_id(_hypothesis())
    transformed = _echo(probe, reflected=False, transformed=True)
    assert interpret_mod.candidates(_hypothesis(), [transformed]) == []


def test_the_technique_matches_the_hypothesis_module() -> None:
    spec = TECHNIQUE.probes(TECHNIQUE.hypotheses(_surface())[0])[0]
    assert spec.oracle == "reflection_at_least_once"
    assert spec.produces == "reflection"
