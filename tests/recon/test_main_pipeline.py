"""
Tests for the stage orchestrator (``main.py``).

The orchestrator is glue: it runs the three stages in order, reads each stage's
live-host artifact, and writes the union.  Each stage is replaced by a fake here,
so what is under test is exactly the glue — which artifacts are read, what happens
when a stage fails, and what ``output/live_hosts.txt`` ends up containing.

The union path is the reason this file exists: the permutation stage used to key
its report outputs by role (``"resolved"``) while the orchestrator looked them up
by filename (``"resolved.txt"``), so the lookup missed, the permutation stage's
hosts never reached the union, and nothing failed.  A test that asserts the union
contains every stage's hosts is what makes that impossible to reintroduce.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from service.recon_pipeline.asset_pipelines.subdomain_domain_wildcards import main
from service.recon_pipeline.asset_pipelines.subdomain_domain_wildcards.active import (
    pipeline as active_pipeline,
)
from service.recon_pipeline.asset_pipelines.subdomain_domain_wildcards.permutation import (
    pipeline as permutation_pipeline,
)

APEX = "example.com"


@dataclass
class FakeReport:
    """Stand-in for a stage report, with the fields the orchestrator reads."""

    outputs: dict[str, str] = field(default_factory=dict)
    counts: dict[str, int] = field(default_factory=dict)
    ok: bool = True
    fatal: str | None = None
    seconds: float = 0.0


def _write(path: Path, hosts: list[str]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(f"{host}\n" for host in hosts), encoding="utf-8")
    return path.as_posix()


@pytest.fixture
def wired(tmp_path, monkeypatch):
    """Replace the three stages with fakes that write real artifact files.

    Returns a factory taking the hosts each stage should "find", so a test can
    assert on the union without any DNS, Docker or network access.
    """

    def build(active_hosts=(), permutation_hosts=(), passive_hosts=()):
        state = {"fail": set()}

        def run_passive(target, **kwargs):  # noqa: ANN001
            if "passive" in state["fail"]:
                raise RuntimeError("passive exploded")
            passive_dir = tmp_path / "passive-out"
            return FakeReport(
                outputs={
                    "subdomains": _write(
                        passive_dir / "subdomains.txt", list(passive_hosts)
                    )
                },
                counts={"subdomains": len(passive_hosts)},
            )

        def run_active(target, **kwargs):  # noqa: ANN001
            if "active" in state["fail"]:
                raise RuntimeError("active exploded")
            active_dir = tmp_path / "active-out"
            return FakeReport(
                outputs={
                    active_pipeline.RESOLVED_FILE: _write(
                        active_dir / active_pipeline.RESOLVED_FILE, list(active_hosts)
                    )
                },
                counts={"resolved": len(active_hosts)},
            )

        def run_permutation(target, **kwargs):  # noqa: ANN001
            if "permutation" in state["fail"]:
                raise RuntimeError("permutation exploded")
            perm_dir = tmp_path / "perm-out"
            return FakeReport(
                outputs={
                    permutation_pipeline.RESOLVED_FILE: _write(
                        perm_dir / permutation_pipeline.RESOLVED_FILE,
                        list(permutation_hosts),
                    )
                },
                counts={"resolved": len(permutation_hosts)},
            )

        monkeypatch.setattr(main, "run_passive_stage", run_passive)
        monkeypatch.setattr(main, "run_active_stage", run_active)
        monkeypatch.setattr(main, "run_permutation_stage", run_permutation)
        return state

    return build


def _union(tmp_path: Path) -> set[str]:
    text = (tmp_path / main.LIVE_HOSTS_FILE).read_text(encoding="utf-8")
    return {line for line in text.split() if line}


def test_union_contains_every_stages_live_hosts(wired, tmp_path):
    """The permutation stage's hosts are the regression case.

    Its report keys were named by role rather than by filename, so the
    orchestrator's ``outputs[RESOLVED_FILE]`` lookup missed and its hosts were
    silently dropped from the union.
    """
    wired(
        active_hosts=[f"www.{APEX}", f"api.{APEX}"],
        permutation_hosts=[f"origin-pay.{APEX}"],
    )

    summary = main.run_pipeline(APEX, output_dir=tmp_path)

    assert summary.ok
    assert _union(tmp_path) == {f"www.{APEX}", f"api.{APEX}", f"origin-pay.{APEX}"}
    assert summary.counts["live_hosts"] == 3
    assert summary.counts["active_live"] == 2
    assert summary.counts["permutation_live"] == 1


def test_only_the_requested_stages_run(wired, tmp_path, monkeypatch):
    """``--stages passive,active`` must not drag the permutation stage in."""
    order: list[str] = []
    wired(active_hosts=[f"www.{APEX}"])

    # Wrap the fakes installed by ``wired`` (not the real stages).
    recorded = {name: getattr(main, f"run_{name}_stage") for name in main.ALL_STAGES}
    for name, stage in recorded.items():

        def wrapper(*args, _name=name, _stage=stage, **kwargs):  # noqa: ANN001
            order.append(_name)
            return _stage(*args, **kwargs)

        monkeypatch.setattr(main, f"run_{name}_stage", wrapper)

    main.run_pipeline(APEX, stages=("passive", "active"), output_dir=tmp_path)

    assert order == ["passive", "active"]


def test_one_failing_stage_does_not_stop_the_others(wired, tmp_path):
    state = wired(active_hosts=[f"www.{APEX}"], permutation_hosts=[f"api-v2.{APEX}"])
    state["fail"].add("active")

    summary = main.run_pipeline(APEX, output_dir=tmp_path)

    assert not summary.ok  # the failure is reported...
    failed = [entry for entry in summary.stages if entry["stage"] == "active"][0]
    assert failed["ok"] is False
    assert "active exploded" in failed["error"]
    # ...but the permutation stage still ran and contributed.
    assert _union(tmp_path) == {f"api-v2.{APEX}"}


def test_hosts_outside_the_apex_are_not_unioned(wired, tmp_path):
    wired(active_hosts=[f"www.{APEX}", "evil.example.net"])

    main.run_pipeline(APEX, output_dir=tmp_path)

    assert _union(tmp_path) == {f"www.{APEX}"}


def test_unknown_stage_is_rejected(wired, tmp_path):
    wired()
    with pytest.raises(ValueError, match="unknown stage"):
        main.run_pipeline(APEX, stages=("passive", "bogus"), output_dir=tmp_path)


def test_invalid_target_is_rejected(wired, tmp_path):
    wired()
    with pytest.raises(ValueError, match="not a valid domain"):
        main.run_pipeline("not a domain", output_dir=tmp_path)


def test_summary_json_matches_the_returned_summary(wired, tmp_path):
    wired(active_hosts=[f"www.{APEX}"], permutation_hosts=[f"api-v2.{APEX}"])
    summary = main.run_pipeline(APEX, output_dir=tmp_path)

    payload = json.loads((tmp_path / main.SUMMARY_FILE).read_text(encoding="utf-8"))
    assert payload["counts"] == summary.counts
    assert payload["target"] == APEX
    assert [entry["stage"] for entry in payload["stages"]] == ["passive", "active", "permutation"]


def test_a_stage_that_reports_hosts_it_did_not_write_is_flagged(
    wired, tmp_path, caplog, monkeypatch
):
    """A silently unreadable artifact must not produce a quietly short union."""
    wired()

    def run_active(target, **kwargs):  # noqa: ANN001
        return FakeReport(
            outputs={active_pipeline.RESOLVED_FILE: (tmp_path / "missing.txt").as_posix()},
            counts={"resolved": 7},
        )

    monkeypatch.setattr(main, "run_active_stage", run_active)

    import logging

    with caplog.at_level(logging.WARNING, logger=main.log.name):
        summary = main.run_pipeline(APEX, stages=("active",), output_dir=tmp_path)

    assert summary.ok  # the stage itself did not fail
    assert any("union artifact is incomplete" in record.message for record in caplog.records)


def test_passive_only_skips_the_active_and_permutation_stages(wired, tmp_path, monkeypatch):
    """PASSIVE_ONLY is a global kill switch for active technique (spec NFR).

    The stages enforce it themselves too, but the orchestrator must not even call
    them: a stage that runs and instantly aborts reads as a stage that failed.
    """
    wired(
        active_hosts=["active.example.com"],
        permutation_hosts=["perm.example.com"],
        passive_hosts=["www.example.com"],
    )
    monkeypatch.setattr(main, "PASSIVE_ONLY", True)

    summary = main.run_pipeline(APEX, output_dir=tmp_path)

    # The union is a union of *live* hosts, and only the active stages establish
    # liveness: passive subdomains are unresolved candidates.  So passive-only
    # legitimately produces an empty union, and saying so is the honest outcome.
    assert _union(tmp_path) == set()
    by_stage = {entry["stage"]: entry for entry in summary.stages}
    assert by_stage["passive"].get("skipped") is None
    for stage in ("active", "permutation"):
        assert by_stage[stage]["skipped"] == "PASSIVE_ONLY"
        assert by_stage[stage]["ok"] is True  # skipped is not failure
