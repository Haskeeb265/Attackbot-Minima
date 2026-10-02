"""The command-injection technique: a shell payload family, per-variant, honest.

These tests hold the technique to its own declared rules:

* it fires **only** on a surface the operator claimed as ``delayed_response`` —
  the loudest probe set in the engine must not spend itself on ordinary
  parameters;
* the grammar alternates baseline samples through every round, and every
  injected population is a *variant* — a shell interpolation shape — keyed in
  the probe id so two variants' samples can never merge;
* the proposer requires complete populations and the declared margin, picks the
  first separating variant in declared order, and carries **that variant's
  payloads** in the confirmation spec;
* a uniformly slow target proposes nothing, because no variant separates.
"""

from __future__ import annotations

from urllib.parse import unquote

from service.vuln_engine.kernel.exchange import RawHttpExchange
from service.vuln_engine.kernel.technique import (
    CAP_DELAYED_RESPONSE,
    CAP_PUBLIC_PARAM,
    EngagementSeed,
    Surface,
)
from service.vuln_engine.scheduler.driver import Engine
from service.vuln_engine.techniques import command_injection as technique_mod
from service.vuln_engine.techniques.command_injection import probes as grammar
from service.vuln_engine.techniques.command_injection.interpret import MARGIN_SECONDS
from service.vuln_engine.verification.timing_verifier import CONFIRM_KIND
from service.vuln_engine.world import observe

from tests.vuln_engine.conftest import FakeHttpEffect


def _seed(capability: str) -> EngagementSeed:
    return EngagementSeed(
        target="127.0.0.1",
        surfaces=(
            Surface(
                url="http://127.0.0.1:8080/api/exec",
                host="127.0.0.1",
                param="host",
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
    technique = technique_mod.CommandInjection()
    assert [s.param for s in technique.surfaces(_seed(CAP_DELAYED_RESPONSE))] == ["host"]
    assert technique.surfaces(_seed(CAP_PUBLIC_PARAM)) == []
    assert technique.surfaces(_seed("")) == []


# --------------------------------------------------------------------------- #
# the grammar — shell interpolation shapes, interleaved with the baseline
# --------------------------------------------------------------------------- #


def test_the_grammar_interleaves_the_baseline_through_every_round() -> None:
    surface = _seed(CAP_DELAYED_RESPONSE).surfaces[0]
    hypothesis = technique_mod.hypothesis_mod.hypotheses(surface)[0]
    specs = grammar.probes(hypothesis)
    rounds = grammar.SAMPLES_PER_POPULATION
    assert len(specs) == rounds * (1 + len(grammar.PAYLOAD_VARIANTS))
    per_round = len(grammar.PAYLOAD_VARIANTS) + 1
    for index in range(rounds):
        chunk = specs[index * per_round : (index + 1) * per_round]
        assert chunk[0].detail["timing_class"] == grammar.TIMING_BASELINE
        assert all(
            spec.detail["timing_class"] == grammar.TIMING_INJECTED for spec in chunk[1:]
        )


def test_the_family_covers_the_shell_shapes_without_naming_a_target() -> None:
    names = [name for name, _ in grammar.PAYLOAD_VARIANTS]
    for shape in ("semicolon", "pipe", "and", "subshell", "backtick"):
        assert shape in names
    payloads = " ".join(
        grammar.variant_payload(name) for name, _ in grammar.PAYLOAD_VARIANTS
    )
    # Real shell semantics: every variant carries a metacharacter and a delay.
    assert "sleep" in payloads
    for metacharacter in (";", "|", "&&", "$(", "`"):
        assert metacharacter in payloads
    # No target identity anywhere in the table.
    assert "juice" not in payloads.lower() and "dvwa" not in payloads.lower()


def test_variant_payload_answers_the_table_and_nothing_else() -> None:
    assert "sleep" in grammar.variant_payload("semicolon")
    assert "`" in grammar.variant_payload("backtick")
    assert grammar.variant_payload("no-such-shape") == ""


# --------------------------------------------------------------------------- #
# interpretation — complete populations, the declared margin, one winner
# --------------------------------------------------------------------------- #


def _observations_for(specs, delays: dict[str, float]) -> list:
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
    winner = grammar.PAYLOAD_VARIANTS[1][0]  # pipe
    observations = _observations_for(
        grammar.probes(hypothesis),
        {grammar.TIMING_BASELINE: 0.1, winner: 0.1 + MARGIN_SECONDS + 0.5},
    )
    candidates = technique_mod.interpret_mod.candidates(hypothesis, observations)
    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.vuln_class == "command-injection"
    assert candidate.confirm["kind"] == CONFIRM_KIND
    assert candidate.confirm["variant"] == winner
    assert candidate.confirm["injected_payload"] == grammar.variant_payload(winner)
    assert candidate.confirm["baseline_payload"] == grammar.QUIET_PAYLOAD
    assert candidate.payload == grammar.variant_payload(winner)
    assert candidate.proposer_grade == "semantic"  # never a finding grade
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


def test_an_undersized_gap_proposes_nothing() -> None:
    surface = _seed(CAP_DELAYED_RESPONSE).surfaces[0]
    hypothesis = technique_mod.hypothesis_mod.hypotheses(surface)[0]
    observations = _observations_for(
        grammar.probes(hypothesis),
        {
            grammar.TIMING_BASELINE: 0.4,
            **{v: 0.4 + MARGIN_SECONDS / 2 for v, _ in grammar.PAYLOAD_VARIANTS},
        },
    )
    assert technique_mod.interpret_mod.candidates(hypothesis, observations) == []


def test_an_incomplete_variant_population_is_not_a_winner() -> None:
    surface = _seed(CAP_DELAYED_RESPONSE).surfaces[0]
    hypothesis = technique_mod.hypothesis_mod.hypotheses(surface)[0]
    specs = grammar.probes(hypothesis)
    incomplete, complete = grammar.PAYLOAD_VARIANTS[0][0], grammar.PAYLOAD_VARIANTS[1][0]
    dropped = [s for s in specs if not (f":{incomplete}:" in s.id and s.id.endswith("0"))]
    observations = _observations_for(
        dropped,
        {
            grammar.TIMING_BASELINE: 0.1,
            incomplete: 0.1 + MARGIN_SECONDS + 1.0,  # one sample only
            complete: 0.1 + MARGIN_SECONDS + 1.0,
        },
    )
    candidates = technique_mod.interpret_mod.candidates(hypothesis, observations)
    assert candidates[0].confirm["variant"] == complete


# --------------------------------------------------------------------------- #
# the whole engine path, on the fakes
# --------------------------------------------------------------------------- #


def test_the_engine_proves_a_command_injection_on_the_fakes(build_gate, clock) -> None:
    semicolon = grammar.variant_payload("semicolon")

    def injectable_backend(url: str) -> RawHttpExchange:
        delay = 0.1
        if semicolon in unquote(url):
            delay = 0.1 + MARGIN_SECONDS + 1.0
        return RawHttpExchange(url=url, status=200, body=b"ok", headers={}, elapsed=delay)

    gate = build_gate(http=FakeHttpEffect(respond=injectable_backend))
    report = Engine(
        _seed(CAP_DELAYED_RESPONSE), gate=gate, log=gate.log, clock=clock
    ).run()
    assert report.counts["findings"] == 1
    finding = report.findings[0]
    assert finding["vuln_class"] == "command-injection"
    assert finding["evidence_class"] == "differential"
    assert finding["independent"] is True


def test_a_uniformly_slow_target_proposes_nothing(build_gate, clock) -> None:
    def slow_for_everyone(url: str) -> RawHttpExchange:
        return RawHttpExchange(url=url, status=200, body=b"ok", headers={}, elapsed=1.0)

    gate = build_gate(http=FakeHttpEffect(respond=slow_for_everyone))
    report = Engine(
        _seed(CAP_DELAYED_RESPONSE), gate=gate, log=gate.log, clock=clock
    ).run()
    assert report.counts["findings"] == 0
    assert report.counts["candidates"] == 0


# --------------------------------------------------------------------------- #
# the live path — the compose fixture's /api/exec endpoint, shell-shaped
# --------------------------------------------------------------------------- #


def test_the_live_fixture_separates_the_populations() -> None:
    import httpx

    try:
        httpx.get("http://127.0.0.1:8080/healthz", timeout=2.0)
    except Exception:  # noqa: BLE001 - not being up is the answer, not an error
        import pytest

        pytest.skip("the fixture app is not up")

    semicolon = grammar.variant_payload("semicolon")
    baseline = [
        httpx.get(
            "http://127.0.0.1:8080/api/exec", params={"host": grammar.QUIET_PAYLOAD}, timeout=15.0
        ).elapsed.total_seconds()
        for _ in range(2)
    ]
    injected = [
        httpx.get(
            "http://127.0.0.1:8080/api/exec", params={"host": semicolon}, timeout=15.0
        ).elapsed.total_seconds()
        for _ in range(2)
    ]
    assert max(baseline) < 1.0
    assert sum(injected) > 2.0
