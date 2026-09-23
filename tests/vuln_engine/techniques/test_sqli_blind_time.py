"""The timing technique: populations as data, the margin, and independence.

These tests hold the technique to its own declared rules:

* it fires **only** on a surface the operator claimed as ``delayed_response`` —
  the loudest probe set in the engine must not spend itself on ordinary
  parameters (the noise-budget rule, made concrete);
* the grammar is symmetric and alternating — baseline, injected, baseline,
  injected — so drifting server load hits both populations instead of posing as
  an injection;
* the proposer requires complete populations and the declared margin before it
  will even propose; and
* the verifier measures **fresh** — its numbers come from its own gate runs, and
  a refusal names the numbers that failed it.
"""

from __future__ import annotations

import time

import pytest

from service.vuln_engine.kernel.exchange import RawHttpExchange
from service.vuln_engine.kernel.technique import (
    CAP_DELAYED_RESPONSE,
    CAP_PUBLIC_PARAM,
    EngagementSeed,
    Surface,
)
from service.vuln_engine.scheduler.driver import Engine
from service.vuln_engine.verification.timing_verifier import CONFIRM_KIND
from service.vuln_engine.techniques import sqli_blind_time as technique_mod
from service.vuln_engine.techniques.sqli_blind_time import probes as grammar
from service.vuln_engine.techniques.sqli_blind_time.interpret import MARGIN_SECONDS
from service.vuln_engine.world import observe

from tests.vuln_engine.conftest import FakeHttpEffect


def _seed(capability: str) -> EngagementSeed:
    return EngagementSeed(
        target="127.0.0.1",
        surfaces=(
            Surface(
                url="http://127.0.0.1:8080/delay",
                host="127.0.0.1",
                param="q",
                capability=capability,
            ),
        ),
    )


def _timed_exchange(url: str, delay: float) -> RawHttpExchange:
    if grammar.SLEEP_PAYLOAD in url:
        time.sleep(delay)  # the fixture's own behaviour, replayed locally
    return RawHttpExchange(url=url, status=200, body=b"ok", headers={}, elapsed=delay)


# --------------------------------------------------------------------------- #
# surfaces — the noise-budget rule
# --------------------------------------------------------------------------- #


def test_it_fires_only_on_a_declared_delayed_response_surface() -> None:
    technique = technique_mod.SqliBlindTime()
    assert [s.param for s in technique.surfaces(_seed(CAP_DELAYED_RESPONSE))] == ["q"]
    assert technique.surfaces(_seed(CAP_PUBLIC_PARAM)) == []
    assert technique.surfaces(_seed("")) == []


# --------------------------------------------------------------------------- #
# the grammar
# --------------------------------------------------------------------------- #


def test_the_grammar_alternates_populations() -> None:
    surface = _seed(CAP_DELAYED_RESPONSE).surfaces[0]
    hypothesis = technique_mod.hypothesis_mod.hypotheses(surface)[0]
    specs = grammar.probes(hypothesis)
    assert len(specs) == grammar.SAMPLES_PER_POPULATION * 2
    classes = [spec.detail["timing_class"] for spec in specs]
    assert classes == ["baseline", "injected"] * grammar.SAMPLES_PER_POPULATION


def test_the_two_populations_differ_only_in_the_payload() -> None:
    surface = _seed(CAP_DELAYED_RESPONSE).surfaces[0]
    hypothesis = technique_mod.hypothesis_mod.hypotheses(surface)[0]
    specs = grammar.probes(hypothesis)
    first_baseline = specs[0].detail
    first_injected = specs[1].detail
    assert first_baseline["url"].replace(grammar.QUIET_PAYLOAD, "X") == (
        first_injected["url"].replace(grammar.SLEEP_PAYLOAD, "X")
    )


# --------------------------------------------------------------------------- #
# interpretation — complete populations and the declared margin
# --------------------------------------------------------------------------- #


def _observations_for(specs, delays: dict[str, float]) -> list:
    observations = []
    for spec in specs:
        exchange = _timed_exchange(spec.detail["url"], delays.get(spec.detail["timing_class"], 0.0))
        observations.extend(
            observe.http_observations(
                exchange, probe=spec.id, at=1.0, timing_class=spec.detail["timing_class"]
            )
        )
    return observations


def test_a_beyond_margin_gap_proposes_a_candidate() -> None:
    surface = _seed(CAP_DELAYED_RESPONSE).surfaces[0]
    hypothesis = technique_mod.hypothesis_mod.hypotheses(surface)[0]
    observations = _observations_for(
        grammar.probes(hypothesis),
        {grammar.TIMING_BASELINE: 0.1, grammar.TIMING_INJECTED: 0.1 + MARGIN_SECONDS + 0.5},
    )
    candidates = technique_mod.interpret_mod.candidates(hypothesis, observations)
    assert len(candidates) == 1
    assert candidates[0].confirm["kind"] == CONFIRM_KIND
    assert candidates[0].proposer_grade == "semantic"  # never a finding grade


def test_an_undersized_gap_proposes_nothing() -> None:
    surface = _seed(CAP_DELAYED_RESPONSE).surfaces[0]
    hypothesis = technique_mod.hypothesis_mod.hypotheses(surface)[0]
    observations = _observations_for(
        grammar.probes(hypothesis),
        {grammar.TIMING_BASELINE: 0.4, grammar.TIMING_INJECTED: 0.4 + MARGIN_SECONDS / 2},
    )
    assert technique_mod.interpret_mod.candidates(hypothesis, observations) == []


def test_an_incomplete_population_proposes_nothing() -> None:
    surface = _seed(CAP_DELAYED_RESPONSE).surfaces[0]
    hypothesis = technique_mod.hypothesis_mod.hypotheses(surface)[0]
    specs = grammar.probes(hypothesis)
    observations = _observations_for(specs[:-1], {grammar.TIMING_BASELINE: 0.1, grammar.TIMING_INJECTED: 3.0})
    assert technique_mod.interpret_mod.candidates(hypothesis, observations) == []


# --------------------------------------------------------------------------- #
# the whole engine path, on the fakes
# --------------------------------------------------------------------------- #


def test_the_engine_proves_a_timing_claim_on_the_fakes(build_gate, clock) -> None:
    def fixture_delay(url: str) -> RawHttpExchange:
        delay = 0.1
        if grammar.SLEEP_PAYLOAD in url:
            delay = 0.1 + MARGIN_SECONDS + 1.0
        return RawHttpExchange(url=url, status=200, body=b"ok", headers={}, elapsed=delay)

    gate = build_gate(http=FakeHttpEffect(respond=fixture_delay))
    engine = Engine(
        _seed(CAP_DELAYED_RESPONSE),
        gate=gate,
        log=gate.log,
        clock=clock,
    )
    report = engine.run()
    assert report.counts["findings"] == 1
    finding = report.findings[0]
    assert finding["vuln_class"] == "sqli"
    assert finding["evidence_class"] == "differential"
    assert finding["independent"] is True


def test_a_uniformly_slow_target_proposes_nothing(build_gate, clock) -> None:
    """A slow target is not a finding — and it is not even a lead: the populations
    do not differ, so the proposer has nothing honest to say."""

    def slow_for_everyone(url: str) -> RawHttpExchange:
        return RawHttpExchange(url=url, status=200, body=b"ok", headers={}, elapsed=1.0)

    gate = build_gate(http=FakeHttpEffect(respond=slow_for_everyone))
    report = Engine(
        _seed(CAP_DELAYED_RESPONSE), gate=gate, log=gate.log, clock=clock
    ).run()
    assert report.counts["findings"] == 0
    assert report.counts["candidates"] == 0
    assert report.counts["probes_run"] == 4  # it measured, and measured nothing


# --------------------------------------------------------------------------- #
# the live path — the compose fixture's /delay endpoint
# --------------------------------------------------------------------------- #


def test_the_verifier_and_the_grammar_agree_on_the_spellings() -> None:
    """The verifier deliberately re-derives its payloads instead of importing the
    technique's — which makes this pin the only thing stopping the two from
    drifting apart into a confirmation that confirms nothing."""
    from service.vuln_engine.verification import timing_verifier

    surface = _seed(CAP_DELAYED_RESPONSE).surfaces[0]
    hypothesis = technique_mod.hypothesis_mod.hypotheses(surface)[0]
    candidate = technique_mod.interpret_mod.candidates(
        hypothesis,
        _observations_for(
            grammar.probes(hypothesis),
            {grammar.TIMING_BASELINE: 0.1, grammar.TIMING_INJECTED: 0.1 + MARGIN_SECONDS + 1.0},
        ),
    )[0]
    assert candidate.confirm["kind"] == timing_verifier.CONFIRM_KIND
    # The verifier's quiet payload must NOT satisfy the trigger: if the baseline
    # slept too, the differential would be zero and the verifier vacuous.
    assert grammar.QUIET_PAYLOAD not in timing_verifier._INJECTED_PAYLOAD
    assert grammar.SLEEP_PAYLOAD not in timing_verifier._BASELINE_PAYLOAD


def test_the_live_fixture_separates_the_populations() -> None:
    import httpx

    try:
        httpx.get("http://127.0.0.1:8080/healthz", timeout=2.0)
    except Exception:  # noqa: BLE001 - not being up is the answer, not an error
        pytest.skip("the fixture app is not up")

    baseline = [
        httpx.get(
            f"http://127.0.0.1:8080/delay?q={grammar.QUIET_PAYLOAD}", timeout=10.0
        ).elapsed.total_seconds()
        for _ in range(2)
    ]
    injected = [
        httpx.get(
            f"http://127.0.0.1:8080/delay?q={grammar.SLEEP_PAYLOAD}", timeout=10.0
        ).elapsed.total_seconds()
        for _ in range(2)
    ]
    assert max(baseline) < 1.0  # the quiet population is fast
    assert sum(injected) > 2.0  # the marker population slept
