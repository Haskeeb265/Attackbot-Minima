"""The timing technique: a payload family, per-variant populations, independence.

These tests hold the technique to its own declared rules:

* it fires **only** on a surface the operator claimed as ``delayed_response`` —
  the loudest probe set in the engine must not spend itself on ordinary
  parameters (the noise-budget rule, made concrete);
* the grammar alternates baseline samples through every round, and every
  injected population is a *variant* — an interpolation shape from the family —
  keyed in the probe id so two variants' samples can never merge;
* the proposer requires complete populations and the declared margin, picks the
  first separating variant in declared order, and carries **that variant's
  payloads** in the confirmation spec — the verifier re-measures the same SQL;
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
# the grammar — a family of interpolation shapes, interleaved with the baseline
# --------------------------------------------------------------------------- #


def test_the_grammar_interleaves_the_baseline_through_every_round() -> None:
    surface = _seed(CAP_DELAYED_RESPONSE).surfaces[0]
    hypothesis = technique_mod.hypothesis_mod.hypotheses(surface)[0]
    specs = grammar.probes(hypothesis)
    rounds = grammar.SAMPLES_PER_POPULATION
    assert len(specs) == rounds * (1 + len(grammar.PAYLOAD_VARIANTS))
    # Each round opens with a baseline sample and then takes one sample of every
    # variant, so a load spike mid-run hits both populations.
    per_round = len(grammar.PAYLOAD_VARIANTS) + 1
    for index in range(rounds):
        chunk = specs[index * per_round : (index + 1) * per_round]
        assert chunk[0].detail["timing_class"] == grammar.TIMING_BASELINE
        assert all(
            spec.detail["timing_class"] == grammar.TIMING_INJECTED for spec in chunk[1:]
        )


def test_every_variant_differs_from_the_baseline_only_in_the_payload() -> None:
    surface = _seed(CAP_DELAYED_RESPONSE).surfaces[0]
    hypothesis = technique_mod.hypothesis_mod.hypotheses(surface)[0]
    specs = grammar.probes(hypothesis)
    baselines = [s for s in specs if s.detail["timing_class"] == grammar.TIMING_BASELINE]
    injected = [s for s in specs if s.detail["timing_class"] == grammar.TIMING_INJECTED]
    for baseline, variant_spec in zip(baselines * len(grammar.PAYLOAD_VARIANTS), injected):
        assert variant_spec.detail["url"].split("?")[0] == baseline.detail["url"].split("?")[0]
        assert variant_spec.detail["method"] == baseline.detail["method"]


def test_the_family_covers_the_interpolation_shapes_without_naming_a_target() -> None:
    payloads = " ".join(grammar.SLEEP_PAYLOADS)
    for shape in ("numeric", "quote_closed", "quote_paren", "comment"):
        assert any(name == shape for name, _ in grammar.PAYLOAD_VARIANTS)
    # Real SQL semantics: every variant asks a parser for the delay.
    assert all("SLEEP(" in payload for payload in grammar.SLEEP_PAYLOADS)
    # No target identity anywhere in the table.
    assert "juice" not in payloads.lower() and "dvwa" not in payloads.lower()


def test_variant_payload_answers_the_table_and_nothing_else() -> None:
    assert grammar.variant_payload("numeric") == grammar.SLEEP_PAYLOADS[0]
    assert grammar.variant_payload("comment") == grammar.SLEEP_PAYLOADS[-1]
    assert grammar.variant_payload("no-such-shape") == ""


# --------------------------------------------------------------------------- #
# interpretation — complete populations, the declared margin, one winner
# --------------------------------------------------------------------------- #


def _observations_for(specs, delays: dict[str, float]) -> list:
    """Observations for *specs*, timing each population by its class/variant."""
    observations = []
    for spec in specs:
        timing_class = spec.detail["timing_class"]
        url = spec.detail["url"]
        if timing_class == grammar.TIMING_BASELINE:
            delay = delays.get(grammar.TIMING_BASELINE, 0.0)
        else:
            delay = 0.0
            for variant, _ in grammar.PAYLOAD_VARIANTS:
                if f":{variant}:" in spec.id:
                    delay = delays.get(variant, 0.0)
                    break
        observations.extend(
            observe.http_observations(
                _timed_exchange(url, delay), probe=spec.id, at=1.0, timing_class=timing_class
            )
        )
    return observations


def test_a_separating_variant_proposes_a_candidate_carrying_its_own_payload() -> None:
    surface = _seed(CAP_DELAYED_RESPONSE).surfaces[0]
    hypothesis = technique_mod.hypothesis_mod.hypotheses(surface)[0]
    winner = grammar.PAYLOAD_VARIANTS[1][0]  # quote_closed
    observations = _observations_for(
        grammar.probes(hypothesis),
        {grammar.TIMING_BASELINE: 0.1, winner: 0.1 + MARGIN_SECONDS + 0.5},
    )
    candidates = technique_mod.interpret_mod.candidates(hypothesis, observations)
    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.confirm["kind"] == CONFIRM_KIND
    assert candidate.confirm["variant"] == winner
    assert candidate.confirm["injected_payload"] == grammar.variant_payload(winner)
    assert candidate.confirm["baseline_payload"] == grammar.QUIET_PAYLOAD
    assert candidate.payload == grammar.variant_payload(winner)
    assert candidate.proposer_grade == "semantic"  # never a finding grade
    # The losing shapes stay in the evidence as the control they are.
    assert len(candidate.evidence.payload["variants_measured"]) == len(
        grammar.PAYLOAD_VARIANTS
    )


def test_the_first_declared_variant_wins_a_tie() -> None:
    surface = _seed(CAP_DELAYED_RESPONSE).surfaces[0]
    hypothesis = technique_mod.hypothesis_mod.hypotheses(surface)[0]
    slow = 0.1 + MARGIN_SECONDS + 1.0
    first, second = grammar.PAYLOAD_VARIANTS[0][0], grammar.PAYLOAD_VARIANTS[1][0]
    observations = _observations_for(
        grammar.probes(hypothesis), {grammar.TIMING_BASELINE: 0.1, first: slow, second: slow}
    )
    candidates = technique_mod.interpret_mod.candidates(hypothesis, observations)
    assert candidates[0].confirm["variant"] == first


def test_variants_never_merge_into_one_population() -> None:
    """Two fast samples of shape A and two slow of shape B: the winner is B, and
    its population is two samples — not four merged across variants."""
    surface = _seed(CAP_DELAYED_RESPONSE).surfaces[0]
    hypothesis = technique_mod.hypothesis_mod.hypotheses(surface)[0]
    first, second = grammar.PAYLOAD_VARIANTS[0][0], grammar.PAYLOAD_VARIANTS[1][0]
    observations = _observations_for(
        grammar.probes(hypothesis),
        {grammar.TIMING_BASELINE: 0.1, first: 0.1, second: 0.1 + MARGIN_SECONDS + 1.0},
    )
    candidates = technique_mod.interpret_mod.candidates(hypothesis, observations)
    assert candidates[0].confirm["variant"] == second
    assert candidates[0].evidence.payload["injected_samples"] == grammar.SAMPLES_PER_POPULATION


def test_an_undersized_gap_proposes_nothing() -> None:
    surface = _seed(CAP_DELAYED_RESPONSE).surfaces[0]
    hypothesis = technique_mod.hypothesis_mod.hypotheses(surface)[0]
    observations = _observations_for(
        grammar.probes(hypothesis),
        {grammar.TIMING_BASELINE: 0.4, **{v: 0.4 + MARGIN_SECONDS / 2 for v, _ in grammar.PAYLOAD_VARIANTS}},
    )
    assert technique_mod.interpret_mod.candidates(hypothesis, observations) == []


def test_an_incomplete_baseline_proposes_nothing() -> None:
    surface = _seed(CAP_DELAYED_RESPONSE).surfaces[0]
    hypothesis = technique_mod.hypothesis_mod.hypotheses(surface)[0]
    specs = grammar.probes(hypothesis)
    drop_first_baseline = [s for s in specs if not s.id.endswith("baseline:0")]
    observations = _observations_for(
        drop_first_baseline,
        {grammar.TIMING_BASELINE: 0.1, **{v: 3.0 for v, _ in grammar.PAYLOAD_VARIANTS}},
    )
    assert technique_mod.interpret_mod.candidates(hypothesis, observations) == []


def test_an_incomplete_variant_population_is_not_a_winner() -> None:
    """One missing sample in a variant's population means that variant measured
    nothing — the remaining variants still get their honest chance."""
    surface = _seed(CAP_DELAYED_RESPONSE).surfaces[0]
    hypothesis = technique_mod.hypothesis_mod.hypotheses(surface)[0]
    specs = grammar.probes(hypothesis)
    incomplete, complete = grammar.PAYLOAD_VARIANTS[0][0], grammar.PAYLOAD_VARIANTS[1][0]
    dropped = [s for s in specs if not (f":{incomplete}:" in s.id and s.id.endswith("0"))]
    observations = _observations_for(
        dropped,
        {
            grammar.TIMING_BASELINE: 0.1,
            incomplete: 0.1 + MARGIN_SECONDS + 1.0,  # one sample only: below MIN_SAMPLES
            complete: 0.1 + MARGIN_SECONDS + 1.0,
        },
    )
    candidates = technique_mod.interpret_mod.candidates(hypothesis, observations)
    assert candidates[0].confirm["variant"] == complete


# --------------------------------------------------------------------------- #
# the whole engine path, on the fakes
# --------------------------------------------------------------------------- #


def test_the_engine_proves_a_timing_claim_on_the_fakes(build_gate, clock) -> None:
    from urllib.parse import unquote

    numeric = grammar.variant_payload("numeric")

    def injectable_backend(url: str) -> RawHttpExchange:
        # The grammar's URLs are percent-encoded (spaces and parens in SQL); a
        # backend sees the *decoded* value, so this fake decodes too.
        delay = 0.1
        if numeric in unquote(url):
            delay = 0.1 + MARGIN_SECONDS + 1.0
        return RawHttpExchange(url=url, status=200, body=b"ok", headers={}, elapsed=delay)

    gate = build_gate(http=FakeHttpEffect(respond=injectable_backend))
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
    """A slow target is not a finding — and it is not even a lead: no variant's
    population differs from the baseline, so the proposer has nothing to say."""

    def slow_for_everyone(url: str) -> RawHttpExchange:
        return RawHttpExchange(url=url, status=200, body=b"ok", headers={}, elapsed=1.0)

    gate = build_gate(http=FakeHttpEffect(respond=slow_for_everyone))
    report = Engine(
        _seed(CAP_DELAYED_RESPONSE), gate=gate, log=gate.log, clock=clock
    ).run()
    assert report.counts["findings"] == 0
    assert report.counts["candidates"] == 0
    # It measured: two rounds of baseline plus every variant, twice.
    assert report.counts["probes_run"] == grammar.SAMPLES_PER_POPULATION * (
        1 + len(grammar.PAYLOAD_VARIANTS)
    )


# --------------------------------------------------------------------------- #
# the confirmation spec — the verifier re-measures the same SQL
# --------------------------------------------------------------------------- #


def test_the_candidate_hands_the_verifier_the_same_sql_it_proposed() -> None:
    surface = _seed(CAP_DELAYED_RESPONSE).surfaces[0]
    hypothesis = technique_mod.hypothesis_mod.hypotheses(surface)[0]
    winner = grammar.PAYLOAD_VARIANTS[2][0]  # quote_paren
    candidate = technique_mod.interpret_mod.candidates(
        hypothesis,
        _observations_for(
            grammar.probes(hypothesis),
            {grammar.TIMING_BASELINE: 0.1, winner: 0.1 + MARGIN_SECONDS + 1.0},
        ),
    )[0]
    assert candidate.confirm["kind"] == CONFIRM_KIND
    assert candidate.confirm["injected_payload"] == grammar.variant_payload(winner)
    assert candidate.confirm["baseline_payload"] == grammar.QUIET_PAYLOAD


def test_the_verifier_fallback_table_is_pinned_to_the_grammar() -> None:
    """The verifier keeps its own duplicated spellings for specs that name no
    payloads — this pin is the only thing stopping the two from drifting apart
    into a confirmation that confirms nothing."""
    from service.vuln_engine.verification import timing_verifier

    assert timing_verifier._BASELINE_PAYLOAD == grammar.QUIET_PAYLOAD
    assert timing_verifier._INJECTED_PAYLOAD == grammar.variant_payload(
        grammar.PAYLOAD_VARIANTS[0][0]
    )


# --------------------------------------------------------------------------- #
# the live path — the compose fixture's /delay endpoint, SQL-shaped
# --------------------------------------------------------------------------- #


def test_the_live_fixture_separates_the_populations() -> None:
    import httpx

    try:
        httpx.get("http://127.0.0.1:8080/healthz", timeout=2.0)
    except Exception:  # noqa: BLE001 - not being up is the answer, not an error
        pytest.skip("the fixture app is not up")

    numeric = grammar.variant_payload("numeric")

    baseline = [
        httpx.get(
            f"http://127.0.0.1:8080/delay?q={grammar.QUIET_PAYLOAD}", timeout=10.0
        ).elapsed.total_seconds()
        for _ in range(2)
    ]
    injected = [
        httpx.get(
            "http://127.0.0.1:8080/delay",
            params={"q": numeric},
            timeout=10.0,
        ).elapsed.total_seconds()
        for _ in range(2)
    ]
    assert max(baseline) < 1.0  # the quiet population is fast
    assert sum(injected) > 2.0  # the SQL-shaped payload made the backend sleep
