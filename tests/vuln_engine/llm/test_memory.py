"""The memory record: distilled fact, fed back as input.

The contract:

* **deterministic** — the same log always yields the same record, so feeding
  it back changes the junction's digest in a reproducible way;
* **bounded and whitelisted** — a corrupt or bloated memory file cannot
  bloat the prompt or smuggle prose in;
* **an input, not a side channel** — with memory the question differs (and
  the digest says so); without it, nothing changes.
"""

from __future__ import annotations

import json

from service.vuln_engine.llm import hypothesize
from service.vuln_engine.llm.wiring import load_memory, remember
from service.vuln_engine.world.log import WorldLog


def _write_a_world_log(tmp_path):
    log = WorldLog(tmp_path / "world.jsonl")
    log.append("run.begin", at=1.0, target="t", techniques=[], surfaces=[])
    log.append("gate.decision", at=2.0, host="h", kind="http.request", technique="x", probe="p1", verb="ALLOW", reason="ok")
    log.append(
        "observation",
        at=3.0,
        kind="http.response",
        probe="xss_reflected:p1",
        payload={"status": 200, "elapsed": 0.25, "context": "raw_html"},
    )
    log.append(
        "observation",
        at=4.0,
        kind="http.response",
        probe="sqli:t#id:baseline:0",
        payload={"status": 200, "elapsed": 0.2, "timing_class": "baseline"},
    )
    log.append("receipt", at=5.0, arm="xss_reflected@u#q", technique="xss_reflected", outcome="none", conclusive=True)
    log.append("receipt", at=6.0, arm="sqli_blind_time@u#id", technique="sqli_blind_time", outcome="found", conclusive=True)
    log.append("verdict", at=7.0, arm="a", candidate="c1", proven=False, reason="lead", proposer_grade="reflection")
    log.append("run.end", at=8.0, counts={})
    return log


def test_remember_distills_arms_contexts_and_timing(tmp_path) -> None:
    _write_a_world_log(tmp_path)
    record = remember(tmp_path / "world.jsonl", "t")
    assert record["target"] == "t"
    assert record["runs"] == 1
    outcomes = {entry["arm"]: entry["outcomes"] for entry in record["arms"]}
    assert outcomes["sqli_blind_time@u#id"] == {"found": 1}
    assert outcomes["xss_reflected@u#q"] == {"none": 1}
    probes = {entry["probe"]: entry for entry in record["probes"]}
    assert probes["xss_reflected:p1"]["contexts"] == ["raw_html"]
    assert record["timing_medians"]["sqli:t#id:baseline:0:baseline"] == 0.2


def test_remember_is_deterministic(tmp_path) -> None:
    _write_a_world_log(tmp_path)
    first = remember(tmp_path / "world.jsonl", "t")
    second = remember(tmp_path / "world.jsonl", "t")
    assert first == second


def test_load_memory_survives_a_corrupt_file(tmp_path) -> None:
    (tmp_path / "memory.json").write_text("{not json", encoding="utf-8")
    assert load_memory(tmp_path / "memory.json") == {}
    assert load_memory(tmp_path / "missing.json") == {}


def test_memory_changes_the_hypothesize_question_not_its_honesty() -> None:
    rows = [
        {"parameter": "q", "url": "http://t/search", "location": "query", "kind": "page"},
    ]
    alive = ["http://t/search"]
    without = hypothesize.build_input(rows, alive)
    with_mem = hypothesize.build_input(rows, alive, {"runs": 2, "arms": [{"arm": "a", "outcomes": {"none": 1}}], "leads": ["L1"]})
    assert "memory" not in without
    assert with_mem["memory"]["runs"] == 2
    # Determinism either way.
    assert hypothesize.build_input(rows, alive, {"runs": 2, "arms": [{"arm": "a", "outcomes": {"none": 1}}], "leads": ["L1"]}) == with_mem


def test_memory_is_bounded_and_whitelisted_in_the_prompt() -> None:
    bloated = {
        "runs": 3,
        "arms": [
            {"arm": f"arm-{i}", "outcomes": {"none": 1}, "smuggled": "x" * 500}
            for i in range(hypothesize.MAX_MEMORY_ARMS + 10)
        ],
        "leads": [f"L{i}" for i in range(100)],
        "huge_field": "x" * 10000,
    }
    input = hypothesize.build_input(
        [{"parameter": "q", "url": "http://t/search", "location": "query", "kind": "page"}],
        ["http://t/search"],
        bloated,
    )
    prompt, _system = hypothesize.build_prompt(input)
    assert len(input["memory"]["arms"]) == hypothesize.MAX_MEMORY_ARMS
    assert "smuggled" not in json.dumps(input["memory"])
    assert "huge_field" not in prompt


def test_memory_survives_a_hand_edit_that_changes_shapes(tmp_path) -> None:
    (tmp_path / "memory.json").write_text(json.dumps({"arms": "not-a-list", "runs": "two"}), encoding="utf-8")
    record = load_memory(tmp_path / "memory.json")
    input = hypothesize.build_input([], [], record)
    assert input["memory"]["runs"] == 0  # wrong type → treated as absent
    assert input["memory"]["arms"] == []
