"""The world log: append-only, clock-free, and sufficient to replay a run.

The last test in this file is the one that justifies the whole architecture. It
runs an engagement, writes the log, and then recomputes the run's proposing
decisions from that log **with sockets disabled** — no fixture app, no collaborator,
no browser. If that test passes, "the log is the environment for testing" is a
measured property rather than a design aspiration.
"""

from __future__ import annotations

import socket

import pytest

from service.vuln_engine.kernel.observation import Observation
from service.vuln_engine.scheduler.replay import replay
from service.vuln_engine.world.log import EVENT_NOTE, EVENT_RECEIPT, WorldLog
from service.vuln_engine.world import views


def test_rows_are_appended_never_rewritten(tmp_path) -> None:
    path = tmp_path / "world.jsonl"
    log = WorldLog(path)
    log.append(EVENT_NOTE, at=1.0, stage="one")
    log.append(EVENT_NOTE, at=2.0, stage="two")
    assert [row["stage"] for row in WorldLog(path).events(EVENT_NOTE)] == ["one", "two"]
    assert len(WorldLog(path)) == 2


def test_the_timestamp_is_required_and_supplied_by_the_caller() -> None:
    # No default, no clock read: a module that could timestamp itself would make
    # every replay non-deterministic.
    with pytest.raises(TypeError):
        WorldLog().append(EVENT_NOTE, stage="no at")  # type: ignore[call-arg]


def test_a_row_that_cannot_be_read_back_raises_rather_than_being_escaped() -> None:
    with pytest.raises(TypeError, match="not serialisable"):
        WorldLog().append(EVENT_NOTE, at=1.0, bad=object())


def test_a_corrupt_line_costs_one_record_not_the_file(tmp_path) -> None:
    path = tmp_path / "world.jsonl"
    path.write_text(
        '{"type": "note", "at": 1.0, "stage": "first"}\nnot json at all\n'
        '{"type": "note", "at": 2.0, "stage": "third"}\n',
        encoding="utf-8",
    )
    assert [row["stage"] for row in WorldLog(path).events(EVENT_NOTE)] == ["first", "third"]


def test_observations_are_rebuilt_typed_from_the_rows() -> None:
    log = WorldLog()
    log.observation(
        Observation(
            kind="observation.reflection",
            probe="p1",
            at=5.0,
            payload={"reflected": True, "context": "double_quoted_attribute"},
        )
    )
    rebuilt = log.observations()
    assert len(rebuilt) == 1
    assert rebuilt[0].kind == "observation.reflection"
    assert rebuilt[0].context == "double_quoted_attribute"
    assert log.observations_by_probe()["p1"][0].payload["reflected"] is True


def test_summary_counts_by_row_type() -> None:
    log = WorldLog()
    log.append(EVENT_NOTE, at=1.0, stage="a")
    log.append(EVENT_RECEIPT, at=2.0, arm="x", outcome="none")
    log.append(EVENT_RECEIPT, at=3.0, arm="y", outcome="found")
    assert log.summary() == {"note": 1, "receipt": 2}


def test_a_run_replays_from_its_log_with_networking_disabled(tmp_path, build_gate, build_engine, fixture_seed) -> None:
    """The exit criterion: the log alone reproduces every proposing decision."""
    path = tmp_path / "world.jsonl"
    gate = build_gate(log=WorldLog(path))
    engine = build_engine(gate=gate)
    report = engine.run()
    assert len(report.findings) == 2  # the run itself worked

    def no_sockets(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("replay must not touch the network")

    # Both the constructor and the connect path are poisoned: a transport that got
    # as far as trying would be a bug this test is meant to catch.
    original_socket = socket.socket
    original_connect = socket.create_connection
    socket.socket = no_sockets  # type: ignore[assignment]
    socket.create_connection = no_sockets  # type: ignore[assignment]
    try:
        result = replay(WorldLog(path), seed=fixture_seed)
    finally:
        socket.socket = original_socket  # type: ignore[assignment]
        socket.create_connection = original_connect  # type: ignore[assignment]

    assert result.clean, result.mismatches
    assert result.candidates_logged == 2
    assert result.candidates_recomputed == 2
    assert len(result.findings) == 2


def test_the_replay_finds_the_report_lines_and_gate_audit(tmp_path, build_gate, build_engine, fixture_seed) -> None:
    path = tmp_path / "world.jsonl"
    gate = build_gate(log=WorldLog(path))
    build_engine(gate=gate).run()

    from_file = WorldLog(path)
    result = replay(from_file, seed=fixture_seed)
    assert result.report_lines == views.report_lines(from_file)
    assert result.gate_audit["uncleared_effects"] == 0
    assert result.independence_violations == []
