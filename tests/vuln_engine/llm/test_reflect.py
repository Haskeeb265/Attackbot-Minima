"""Junction 5 — reflect: the bounded re-ask, tested.

The contract:

* **degraded means one-pass** — no key, a refused answer, or ``stop`` leaves
  the engine's behavior byte-for-byte what it was before the junction;
* **the model can only re-ask what the pass already ran** — an invented
  probe id is a validation failure, and the driver re-checks it anyway;
* **bounded** — at most ``MAX_REFLECT_ROUNDS`` re-asks per hypothesis, and
  the driver's constant is pinned against the llm layer's;
* **never a body** — the prompt sees typed measurement fields only.
"""

from __future__ import annotations

import json

import pytest

from service.vuln_engine.kernel.observation import Observation
from service.vuln_engine.llm import reflect
from service.vuln_engine.llm.client import LLMClient
from service.vuln_engine.llm.runtime import REFLECT_NAME, ReflectJunction
from service.vuln_engine.llm.wiring import Advisory
from service.vuln_engine.world.log import WorldLog


def scripted_client(answer: str) -> LLMClient:
    return LLMClient(api_key="test", api_url="http://test.invalid", caller=lambda prompt, system: answer)


def unavailable_client() -> LLMClient:
    return LLMClient()


def json_answer(payload: dict) -> str:
    return json.dumps(payload)


PROBE_ROWS = [
    {"id": "sqli:t#id:baseline:0", "purpose": "propose", "oracle": "timing_differential"},
    {"id": "sqli:t#id:injected:comment:0", "purpose": "propose", "oracle": "timing_differential"},
]

OBS_SUMMARIES = [
    {"probe": "sqli:t#id:baseline:0", "status": 200, "elapsed": 0.21},
    {"probe": "sqli:t#id:injected:comment:0", "status": 200, "elapsed": 0.24},
]

HYPOTHESIS = {"id": "sqli:t#id", "claim": "param id delays the response", "oracle": "timing_differential"}


# --------------------------------------------------------------------------- #
# the pure module
# --------------------------------------------------------------------------- #


def test_input_is_whitelisted_and_deterministic() -> None:
    first = reflect.build_input(HYPOTHESIS, PROBE_ROWS, OBS_SUMMARIES)
    second = reflect.build_input(HYPOTHESIS, list(reversed(PROBE_ROWS)), list(reversed(OBS_SUMMARIES)))
    # Probe rows are presented in grammar order regardless of input order.
    assert [p["id"] for p in first["probes"]] == [p["id"] for p in second["probes"]]
    assert "body" not in json.dumps(first)


def test_validate_accepts_stop_and_recheck() -> None:
    known = {row["id"] for row in PROBE_ROWS}
    assert "stop" in reflect.validate_answer(known)({"action": "stop"})
    label = reflect.validate_answer(known)(
        {"action": "recheck", "probe_id": PROBE_ROWS[1]["id"], "reason": "pair too close"}
    )
    assert "recheck" in label


def test_validate_refuses_an_invented_probe_id() -> None:
    known = {row["id"] for row in PROBE_ROWS}
    with pytest.raises(ValueError, match="did not run"):
        reflect.validate_answer(known)(
            {"action": "recheck", "probe_id": "sqli:t#id:injected:never:9"}
        )


def test_validate_refuses_an_unknown_action() -> None:
    with pytest.raises(ValueError, match="neither stop nor recheck"):
        reflect.validate_answer({PROBE_ROWS[0]["id"]})({"action": "rescan everything"})


def test_extract_of_an_unusable_answer_settles() -> None:
    known = {row["id"] for row in PROBE_ROWS}
    assert reflect.extract({"action": "recheck", "probe_id": "nope"}, known) == ("stop", "", "")
    assert reflect.extract({}, known) == ("stop", "", "")
    good = {"action": "recheck", "probe_id": PROBE_ROWS[0]["id"], "reason": "flaky"}
    assert reflect.extract(good, known) == ("recheck", PROBE_ROWS[0]["id"], "flaky")


# --------------------------------------------------------------------------- #
# the runtime junction
# --------------------------------------------------------------------------- #


def test_a_recheck_decision_names_a_run_probe(tmp_path) -> None:
    log = WorldLog(tmp_path / "world.jsonl")
    junction = ReflectJunction(
        scripted_client(json_answer({"action": "recheck", "probe_id": PROBE_ROWS[1]["id"], "reason": "pair too close"}))
    )
    decision = junction.decide(
        hypothesis=HYPOTHESIS,
        probe_rows=PROBE_ROWS,
        observations_summary=OBS_SUMMARIES,
        world=log,
        now=1.0,
    )
    assert decision.recheck and decision.probe_id == PROBE_ROWS[1]["id"]
    rows = log.rows
    assert rows[0]["type"] == "llm.junction" and rows[0]["junction"] == REFLECT_NAME


def test_a_degraded_junction_stops() -> None:
    junction = ReflectJunction(unavailable_client())
    decision = junction.decide(
        hypothesis=HYPOTHESIS,
        probe_rows=PROBE_ROWS,
        observations_summary=OBS_SUMMARIES,
    )
    assert decision.action == "stop" and decision.source == "degraded"


def test_an_invented_probe_id_degrades_to_stop(tmp_path) -> None:
    log = WorldLog(tmp_path / "world.jsonl")
    junction = ReflectJunction(
        scripted_client(json_answer({"action": "recheck", "probe_id": "made:up", "reason": "because"}))
    )
    decision = junction.decide(
        hypothesis=HYPOTHESIS,
        probe_rows=PROBE_ROWS,
        observations_summary=OBS_SUMMARIES,
        world=log,
    )
    assert decision.action == "stop" and "did not run" in decision.detail


# --------------------------------------------------------------------------- #
# the driver loop
# --------------------------------------------------------------------------- #


def test_the_driver_constant_is_pinned_to_the_llm_constant() -> None:
    from service.vuln_engine.scheduler.driver import REFLECT_ROUNDS

    assert REFLECT_ROUNDS == reflect.MAX_REFLECT_ROUNDS


def test_the_reflect_loop_reasks_and_settles(build_gate, build_engine) -> None:
    """An arm whose readings look anomalous gets a bounded re-ask, then stops.

    The fixture's ``/search`` and ``/fetch`` interpretations *find* things, so
    the reflect seam is reached by whichever arm measured but concluded
    nothing. The scripted model echoes a probe id lifted from the prompt it
    is shown (a prompt always names the pass's own probes) once, then stops —
    a recheck row lands on the record, and every later ask settles.
    """
    import re

    from service.vuln_engine.scheduler.driver import REFLECT_ROUNDS

    calls = {"n": 0}

    def caller(prompt: str, system: str) -> str:
        calls["n"] += 1
        if calls["n"] > 1:
            return json_answer({"action": "stop"})
        match = re.search(r"^- (\S+) \(purpose:", prompt, flags=re.MULTILINE)
        assert match, "the reflect prompt names no probes"
        return json_answer(
            {"action": "recheck", "probe_id": match.group(1), "reason": "verify the reading"}
        )

    client = LLMClient(api_key="test", api_url="http://test.invalid", caller=caller)
    advisory = Advisory(client=client, reflect=ReflectJunction(client))
    gate = build_gate()
    engine = build_engine(gate=gate)
    engine.advisory = advisory
    log = gate.log
    report = engine.run()
    assert report.counts["findings"] == 2  # the ordinary result is untouched
    rechecks = [row for row in log.rows if row.get("stage") == "reflect.recheck"]
    assert 1 <= len(rechecks) <= REFLECT_ROUNDS
    assert all(row.get("probe") for row in rechecks)
    assert report.counts.get("probes_reflected", 0) == len(rechecks)


def test_a_degraded_advisory_never_produces_recheck_rows(build_gate, build_engine) -> None:
    advisory = Advisory.from_env()  # no key
    gate = build_gate()
    engine = build_engine(gate=gate)
    engine.advisory = advisory
    report = engine.run()
    assert report.counts["findings"] == 2
    assert report.counts.get("probes_reflected", 0) == 0


def test_observation_summaries_never_carry_bodies() -> None:
    from service.vuln_engine.scheduler.driver import Engine

    observations = [
        Observation(
            kind="http.response",
            probe="p:1",
            at=0.0,
            payload={"status": 200, "elapsed": 0.1, "body": b"should not travel", "context": "raw_html"},
        )
    ]
    summaries = Engine._observation_summaries(observations)
    assert summaries[0]["status"] == 200
    assert "body" not in json.dumps(summaries)
