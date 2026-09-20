"""Tests for the convergence loop: the frontier, the ledger, the decision, the driver.

Hermetic by construction — no network, no Docker, no Redis, no wall-clock.  The
driver takes a fake round function and an injected clock, which is what makes
"run until exhausted, but decisively" testable at all: the interesting behaviour
is *when the loop stops and why*, and that is decidable without touching a target.

The last test in the file is the one that ties it together: the real platform
runner, looping real rounds over a stub pipeline, stopping on a real fixed point
and writing the artifacts a report can read.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from service.recon_pipeline.platform.contract import (
    BasePipeline,
    Manifest,
    RunContext,
    Stage,
)
from service.recon_pipeline.platform.convergence import (
    CONTINUE,
    token_kind,
    EXHAUSTED_REASONS,
    STOP_ACTION_BUDGET,
    STOP_BLOCKED,
    STOP_DEGRADED_FIXED_POINT,
    STOP_FIXED_POINT,
    STOP_MAX_ROUNDS,
    STOP_NO_FRONTIER,
    STOP_NOTHING_TO_REPEAT,
    STOP_STAGE_FAILURE,
    STOP_TIME_BUDGET,
    ConvergenceDriver,
    Ledger,
    Round,
    StopPolicy,
    canonical_token,
    decide,
    read_frontier,
)
from service.recon_pipeline.platform.observability import RunRegistry
from service.recon_pipeline.platform.registry import Registration, Registry


# --------------------------------------------------------------------------- #
# the frontier: what an asset is
# --------------------------------------------------------------------------- #


def test_frontier_tokens_are_kind_prefixed() -> None:
    """A bucket name and a hostname are the same shape — the prefix keeps them apart."""
    assert canonical_token("API.Example.com.") == "host:api.example.com"
    assert canonical_token("qbsco-assets") == "host:qbsco-assets"
    assert canonical_token("104.21.81.2") == "ip:104.21.81.2"
    assert canonical_token("2603:1000::1") == "ip:2603:1000::1"
    assert canonical_token("103.53.44.7/22") == "net:103.53.44.0/22"
    assert canonical_token("https://App.Example.com:443/a/b?x=1#frag") == (
        "url:https://app.example.com/a/b?x=1"
    )


def test_a_network_token_clears_host_bits_so_two_spellings_are_one_asset() -> None:
    """RIPEstat and RDAP spell the same prefix differently; that is not two networks."""
    assert canonical_token("103.53.44.7/22") == canonical_token("103.53.44.0/22")


def test_frontier_tokens_never_invent_a_value() -> None:
    """An unparseable line is dropped, not trimmed into something plausible."""
    assert canonical_token("") is None
    assert canonical_token("   ") is None
    assert canonical_token("# a comment") is None
    assert canonical_token("not a host!") is None
    assert canonical_token("http://") is None
    assert canonical_token("10.0.0.1/999") is None


def test_read_frontier_separates_missing_from_empty(tmp_path: Path) -> None:
    """Absence is a state, not a zero: "not written" and "nothing found" differ."""
    present = tmp_path / "hosts.txt"
    present.write_text("a.acme.test\n104.0.0.1\n", encoding="utf-8")
    blank = tmp_path / "blank.txt"
    blank.write_text("", encoding="utf-8")
    absent = tmp_path / "absent.txt"

    result = read_frontier([present, blank, absent])

    assert result.tokens == {"host:a.acme.test", "ip:104.0.0.1"}
    assert result.measured is True
    assert [Path(path).name for path in result.read] == ["hosts.txt"]
    assert [Path(path).name for path in result.empty] == ["blank.txt"]
    assert [Path(path).name for path in result.missing] == ["absent.txt"]


def test_read_frontier_with_no_readable_artifact_is_unmeasured(tmp_path: Path) -> None:
    result = read_frontier([tmp_path / "nothing.txt"])

    assert result.measured is False
    assert result.tokens == set()


# --------------------------------------------------------------------------- #
# the ledger: what we have already seen
# --------------------------------------------------------------------------- #


def test_the_ledger_reports_each_asset_as_new_exactly_once(tmp_path: Path) -> None:
    ledger = Ledger(tmp_path / "ledger.jsonl")

    first = ledger.observe(["host:a.acme.test", "host:b.acme.test"], round_index=1)
    second = ledger.observe(["host:b.acme.test", "host:c.acme.test"], round_index=2)

    assert first == {"host:a.acme.test", "host:b.acme.test"}
    assert second == {"host:c.acme.test"}
    assert ledger.seen("host:b.acme.test") is True
    assert len(ledger) == 3


def test_the_ledger_survives_a_restart_and_records_which_round_found_what(
    tmp_path: Path,
) -> None:
    """The file is the audit trail of *when* an asset first appeared."""
    path = tmp_path / "ledger.jsonl"
    Ledger(path).observe(["host:a.acme.test"], round_index=1, at=1.0)
    Ledger(path).observe(["host:b.acme.test"], round_index=3, at=2.0)

    rows = path.read_text(encoding="utf-8").strip().splitlines()
    assert '"round": 3' in rows[1]

    reopened = Ledger(path)
    assert len(reopened) == 2
    assert reopened.observe(["host:a.acme.test"]) == set()


def test_a_corrupt_ledger_line_costs_one_record_not_the_file(tmp_path: Path) -> None:
    path = tmp_path / "ledger.jsonl"
    path.write_text(
        '{"asset": "host:a.acme.test", "round": 1}\nnot json\n{"asset": "host:b.acme.test"}\n',
        encoding="utf-8",
    )

    assert len(Ledger(path)) == 2


def test_a_ledger_without_a_path_is_memory_only() -> None:
    ledger = Ledger()

    assert ledger.observe(["host:a.acme.test"]) == {"host:a.acme.test"}
    assert ledger.to_dict()["path"] == ""


# --------------------------------------------------------------------------- #
# the decision: when to stop, and which condition gets the credit
# --------------------------------------------------------------------------- #


def _round(
    index: int,
    *,
    new: int = 0,
    stages_run: int = 1,
    stages_failed: int = 0,
    actions: int = 0,
    blocked: bool = False,
    degraded: bool = False,
    measured: bool = True,
) -> Round:
    return Round(
        index=index,
        new_assets=new,
        stages_run=stages_run,
        stages_failed=stages_failed,
        active_actions=actions,
        blocked=blocked,
        degraded=degraded,
        frontier_measured=measured,
    )


def test_no_round_means_keep_going() -> None:
    assert decide([], StopPolicy()).stop is False


def test_a_growing_frontier_keeps_the_loop_going() -> None:
    verdict = decide([_round(1, new=40)], StopPolicy())

    assert verdict.stop is False
    assert verdict.reason == CONTINUE
    assert "40 new asset(s)" in verdict.detail


def test_an_empty_round_is_exhaustion() -> None:
    verdict = decide([_round(1, new=50), _round(2, new=0)], StopPolicy())

    assert verdict.stop is True
    assert verdict.reason == STOP_FIXED_POINT
    assert verdict.exhausted is True
    assert "stopped growing" in verdict.detail


def test_a_degraded_empty_round_says_it_is_not_proof() -> None:
    """Exhausted as far as we could see is a different claim from exhausted."""
    verdict = decide(
        [_round(1, new=50), _round(2, new=0, degraded=True)], StopPolicy()
    )

    assert verdict.reason == STOP_DEGRADED_FIXED_POINT
    assert verdict.exhausted is True
    assert "not proven complete" in verdict.detail


def test_two_quiet_rounds_can_be_required() -> None:
    policy = StopPolicy(require_empty_rounds=2)

    assert decide([_round(1, new=10), _round(2, new=0)], policy).stop is False
    assert (
        decide([_round(1, new=10), _round(2, new=0), _round(3, new=0)], policy).reason
        == STOP_FIXED_POINT
    )


def test_a_round_below_the_growth_floor_is_not_growth() -> None:
    policy = StopPolicy(min_new_assets=5)

    assert decide([_round(1, new=4)], policy).reason == STOP_FIXED_POINT


def test_a_cap_outranks_the_happy_ending() -> None:
    """Running out of time with a quiet frontier must not be sold as "exhausted"."""
    verdict = decide(
        [_round(1, new=10), _round(2, new=0)], StopPolicy(time_budget_seconds=60), elapsed=120
    )

    assert verdict.reason == STOP_TIME_BUDGET
    assert verdict.exhausted is False
    assert "the frontier was quiet this round too" in verdict.detail


def test_every_stop_condition_fires_with_its_own_reason() -> None:
    policy = StopPolicy()

    assert decide([_round(1, blocked=True)], policy).reason == STOP_BLOCKED
    assert (
        decide([_round(1, stages_run=2, stages_failed=2)], policy).reason
        == STOP_STAGE_FAILURE
    )
    assert decide([_round(1, new=9), _round(2, stages_run=0)], policy).reason == (
        STOP_NOTHING_TO_REPEAT
    )
    assert decide([_round(1, actions=50)], StopPolicy(max_active_actions=50)).reason == (
        STOP_ACTION_BUDGET
    )
    assert decide([_round(1, new=9), _round(2)], StopPolicy(max_rounds=2)).reason == (
        STOP_MAX_ROUNDS
    )
    assert decide([_round(1, new=9, measured=False)], policy).reason == STOP_NO_FRONTIER
    assert decide([_round(1, new=9), _round(2, new=0)], policy).reason == STOP_FIXED_POINT


def test_exhaustion_is_the_only_reason_that_claims_the_surface_was_walked() -> None:
    """Everything else is a limit we ran into, and the report must not confuse them."""
    reasons = [
        decide([_round(1, blocked=True)], StopPolicy()).reason,
        decide([_round(1, stages_run=1, stages_failed=1)], StopPolicy()).reason,
        decide([_round(1, actions=9)], StopPolicy(max_active_actions=9)).reason,
        decide([_round(1, new=7)], StopPolicy(time_budget_seconds=1), elapsed=5).reason,
        decide([_round(1, new=7)], StopPolicy(max_rounds=1)).reason,
        decide([_round(1, new=7, measured=False)], StopPolicy()).reason,
    ]

    assert all(reason not in EXHAUSTED_REASONS for reason in reasons)


def test_a_blocked_target_stops_before_the_budget_is_even_consulted() -> None:
    """Continuing at a target that just blocked us is the least efficient move available."""
    policy = StopPolicy(max_rounds=1, max_active_actions=1)

    assert decide([_round(1, blocked=True, actions=99, new=5)], policy).reason == (
        STOP_BLOCKED
    )


def test_stopping_on_a_block_can_be_switched_off() -> None:
    verdict = decide([_round(1, blocked=True, new=5)], StopPolicy(stop_on_block=False))

    assert verdict.stop is False


# --------------------------------------------------------------------------- #
# the driver: the loop itself
# --------------------------------------------------------------------------- #


def _frozen() -> Callable[[], float]:
    return lambda: 0.0


def _stepping(step: float) -> Callable[[], float]:
    state = {"now": 0.0}

    def clock() -> float:
        current = state["now"]
        state["now"] += step
        return current

    return clock


def test_the_driver_stops_when_a_round_adds_nothing(tmp_path: Path) -> None:
    """Three rounds, the third with nothing new — the frontier is exhausted."""
    frontier = tmp_path / "hosts.txt"
    discoveries = ["a.acme.test\nb.acme.test", "c.acme.test", ""]
    calls: list[int] = []

    def round_fn(index: int, found: frozenset[str]) -> Round:
        calls.append(index)
        frontier.write_text(discoveries[index - 1], encoding="utf-8")
        return Round(index=index, stages_run=1)

    driver = ConvergenceDriver(
        policy=StopPolicy(),
        ledger=Ledger(tmp_path / "ledger.jsonl"),
        frontier_paths=[frontier],
        clock=_frozen(),
    )
    report = driver.run(round_fn, target="acme.test")

    assert calls == [1, 2, 3]
    assert report.verdict.reason == STOP_FIXED_POINT
    assert report.verdict.exhausted is True
    assert [entry.new_assets for entry in report.rounds] == [2, 1, 0]
    assert report.total_new_assets == 3
    assert report.ledger["assets_seen"] == 3
    assert report.frontier["measured"] is True


def test_the_driver_never_runs_more_than_the_round_ceiling(tmp_path: Path) -> None:
    frontier = tmp_path / "hosts.txt"
    counter = {"n": 0}

    def round_fn(index: int, found: frozenset[str]) -> Round:
        # Always something new: only the ceiling can stop this loop.
        counter["n"] += 1
        frontier.write_text(f"host-{counter['n']}.acme.test\n", encoding="utf-8")
        return Round(index=index, stages_run=1)

    report = ConvergenceDriver(
        policy=StopPolicy(max_rounds=3),
        ledger=Ledger(),
        frontier_paths=[frontier],
        clock=_frozen(),
    ).run(round_fn)

    assert counter["n"] == 3
    assert report.verdict.reason == STOP_MAX_ROUNDS
    assert len(report.rounds) == 3


def test_the_driver_stops_on_the_wall_clock(tmp_path: Path) -> None:
    frontier = tmp_path / "hosts.txt"
    counter = {"n": 0}

    def round_fn(index: int, found: frozenset[str]) -> Round:
        counter["n"] += 1
        frontier.write_text(f"host-{counter['n']}.acme.test\n", encoding="utf-8")
        return Round(index=index, stages_run=1)

    report = ConvergenceDriver(
        policy=StopPolicy(max_rounds=99, time_budget_seconds=1000),
        ledger=Ledger(),
        frontier_paths=[frontier],
        clock=_stepping(2000.0),
    ).run(round_fn)

    assert report.verdict.reason == STOP_TIME_BUDGET
    assert counter["n"] == 1


def test_the_driver_stops_when_the_frontier_cannot_be_measured(tmp_path: Path) -> None:
    """An unmeasurable loop is unbounded, not convergent — say so and stop."""
    report = ConvergenceDriver(
        policy=StopPolicy(),
        ledger=Ledger(),
        frontier_paths=[tmp_path / "never-written.txt"],
        clock=_frozen(),
    ).run(lambda index, found: Round(index=index, stages_run=1))

    assert len(report.rounds) == 1
    assert report.verdict.reason == STOP_NO_FRONTIER


def test_the_driver_measures_growth_against_everything_ever_seen(tmp_path: Path) -> None:
    """Oscillation is not convergence: a token seen in round 1 is never new again."""
    frontier = tmp_path / "hosts.txt"
    discoveries = ["a.acme.test", "b.acme.test", "a.acme.test", ""]
    counter = {"n": 0}

    def round_fn(index: int, found: frozenset[str]) -> Round:
        counter["n"] += 1
        frontier.write_text(discoveries[counter["n"] - 1], encoding="utf-8")
        return Round(index=index, stages_run=1)

    report = ConvergenceDriver(
        policy=StopPolicy(),
        ledger=Ledger(tmp_path / "ledger.jsonl"),
        frontier_paths=[frontier],
        clock=_frozen(),
    ).run(round_fn)

    # The third round re-offers an asset from round 1 — not new, so the loop stops.
    assert [entry.new_assets for entry in report.rounds] == [1, 1, 0]
    assert report.ledger["assets_seen"] == 2


def test_the_driver_renumbers_a_round_the_round_function_labeled_wrongly(
    tmp_path: Path,
) -> None:
    """Round numbering is the driver's to own: a report must not be able to fork it."""
    frontier = tmp_path / "hosts.txt"
    counter = {"n": 0}

    def round_fn(index: int, found: frozenset[str]) -> Round:
        counter["n"] += 1
        frontier.write_text(f"host-{counter['n']}.acme.test\n", encoding="utf-8")
        return Round(index=99, new_assets=5, stages_run=1)

    report = ConvergenceDriver(
        policy=StopPolicy(max_rounds=2),
        ledger=Ledger(),
        frontier_paths=[frontier],
        clock=_frozen(),
    ).run(round_fn)

    assert [entry.index for entry in report.rounds] == [1, 2]
    assert [entry.new_assets for entry in report.rounds] == [1, 1]


def test_the_report_is_report_shaped(tmp_path: Path) -> None:
    payload = ConvergenceDriver(
        policy=StopPolicy(max_rounds=1),
        ledger=Ledger(),
        frontier_paths=[],
        clock=_frozen(),
    ).run(lambda index, found: Round(index=index, new_assets=1, stages_run=1)).to_dict()

    assert payload["rounds_run"] == 1
    assert payload["verdict"]["reason"] == STOP_MAX_ROUNDS
    assert payload["exhausted"] is False
    assert payload["policy"]["max_rounds"] == 1
    assert payload["rounds"][0]["round"] == 1


# --------------------------------------------------------------------------- #
# the declarations: which pipelines may repeat, and why that is not a preference
# --------------------------------------------------------------------------- #


def test_repeat_stages_are_a_subset_of_declared_stages() -> None:
    """A manifest that names a stage it does not declare would silently do nothing."""
    for registration in Registry.discover().all():
        manifest = registration.manifest
        unknown = set(manifest.repeat_stages) - set(manifest.stage_names())
        assert not unknown, f"{manifest.name}: repeat_stages names {unknown}"


def test_frontier_artifacts_are_relative_paths_inside_the_pipeline_folder() -> None:
    for registration in Registry.discover().all():
        for relative in registration.manifest.frontier_artifacts:
            assert not Path(relative).is_absolute(), f"{registration.name}: {relative}"


def test_the_subtree_wide_passive_stage_is_not_declared_repeatable() -> None:
    """crt.sh is asked for ``%.<apex>`` and Wayback for ``matchType=domain``.

    One call already returns every depth, so re-running the passive stage
    re-queries a subset of a set we hold — the contract this pins is the same one
    ``tests/recon/test_passive_sources.py`` pins for the stage itself.  The
    generators (``active``, ``permutation``) are the ones that may repeat.
    """
    registry = Registry.discover()
    manifest = registry.get("subdomain_domain_wildcards").manifest

    assert "passive" not in manifest.repeat_stages
    assert set(manifest.repeat_stages) == {"active", "permutation"}


def test_the_per_domain_archive_pipeline_is_declared_one_shot() -> None:
    """Every url_endpoint source is queried per domain, so a repeat asks again for free."""
    manifest = Registry.discover().get("url_endpoint").manifest

    assert manifest.repeat_stages == ()
    # ...but it still contributes its surface to the frontier.
    assert manifest.frontier_artifacts


def test_run_recon_declares_the_same_frontier_as_the_manifests() -> None:
    """``run_recon.py`` mirrors the manifests by hand — pin the two together.

    The legacy driver spawns subprocesses, so it cannot read a manifest's
    ``frontier_artifacts`` at run time; a silent drift there would leave the loop
    measuring a file nobody writes any more, which reads as "converged" forever.
    """
    import run_recon

    declared = {
        (Path(directory).resolve().name, relative)
        for directory, relatives in run_recon.FRONTIER_ARTIFACTS.values()
        for relative in relatives
    }
    from_manifests = {
        (Path(registration.module.__file__).resolve().parent.name, relative)
        for registration in Registry.discover().all()
        for relative in registration.manifest.frontier_artifacts
    }

    assert from_manifests == declared
    # ...and the one-shot / repeat decisions agree too.
    assert set(run_recon.REPEAT_STAGES["names"].split(",")) == set(
        Registry.discover().get("subdomain_domain_wildcards").manifest.repeat_stages
    )
    assert "url" not in run_recon.REPEAT_STAGES
    # ...and which kinds make each repeat worth its requests agrees with the manifests.
    for label, kinds in run_recon.REPEAT_ON.items():
        name = {
            "names": "subdomain_domain_wildcards",
            "ports": "port_service_host",
            "asn": "asn_cidr",
            "cloud": "cloud_resource",
        }[label]
        assert tuple(kinds) == Registry.discover().get(name).manifest.repeat_on


def test_console_write_degrades_a_character_the_console_cannot_encode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A console write must never kill the engagement.

    A live converged run died at the cloud probe: the child printed bytes in its own
    locale encoding, the parent's UTF-8 decode turned them into U+FFFD, and the
    cp1252 console refused to encode that character — ``UnicodeEncodeError`` out of
    ``sys.stdout.write``, three-quarters of the way through round 1.  The log file
    keeps the exact text; the console loses a glyph.
    """
    import io

    import run_recon

    buffer = io.BytesIO()
    console = io.TextIOWrapper(buffer, encoding="cp1252", newline="")
    monkeypatch.setattr(run_recon.sys, "stdout", console)

    run_recon._console_write("probe \ufffd done\n")
    console.flush()

    assert buffer.getvalue() == b"probe ? done\n"


def test_children_are_told_to_speak_utf8() -> None:
    """The pipe round trip is only lossless if the child encodes as UTF-8.

    Python defaults a child's stdout to the ANSI code page on Windows, so the parent
    was decoding cp1252 bytes as UTF-8 and inventing replacement characters.  An
    operator's explicit setting still wins.
    """
    import run_recon

    env = run_recon._child_env({"PATH": "x"})
    assert env["PYTHONIOENCODING"] == "utf-8"
    assert env["PYTHONUTF8"] == "1"
    assert env["PATH"] == "x"
    assert run_recon._child_env({"PYTHONIOENCODING": "latin-1"})[
        "PYTHONIOENCODING"
    ] == "latin-1"


def test_every_declared_frontier_artifact_is_one_a_run_actually_produces() -> None:
    """A frontier artifact outside the curated lists is a typo, not a frontier.

    The tuples in ``run_recon.py`` were checked against live runs; a declaration
    outside them would have the loop measuring a file nobody writes, which reads
    as "converged" for ever.  This is what caught ``url_endpoint`` declaring
    ``output/urls.txt`` when the canonical URL union lives in ``passive/output/``.
    """
    import run_recon

    curated = {
        "subdomain_domain_wildcards": run_recon.SDW_ARTIFACTS,
        "port_service_host": run_recon.PSH_ARTIFACTS,
        "url_endpoint": run_recon.URL_ARTIFACTS,
        "asn_cidr": run_recon.ASN_ARTIFACTS,
        "cloud_resource": run_recon.CLOUD_ARTIFACTS,
    }
    registry = Registry.discover()

    for name, artifacts in curated.items():
        manifest = registry.get(name).manifest
        undeclared = set(manifest.frontier_artifacts) - set(artifacts)
        assert not undeclared, f"{name} declares frontier artifacts nobody writes: {undeclared}"


def test_run_recon_rounds_repeat_only_the_pipelines_whose_answer_can_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The legacy driver's loop, pinned: round 1 runs all five, round 2 drops ``url``."""
    import run_recon
    from service.recon_pipeline.platform.convergence import StopPolicy

    frontier = tmp_path / "frontier.txt"
    counter = {"n": 0}
    calls: list[str] = []
    receipt_env: list[str | None] = []

    monkeypatch.setattr(run_recon, "ROOT", tmp_path)
    monkeypatch.setattr(run_recon, "_frontier_paths", lambda: [frontier])
    monkeypatch.setattr(run_recon, "_blocked_state", lambda: (False, ""))

    def fake_run_streamed(command: list[str], log_path: Path, env=None) -> int:
        counter["n"] += 1
        receipt_env.append((env or {}).get("PSH_ATTEMPT_RECEIPT"))
        # Both job shapes name their pipeline in the log file, which is what the
        # driver passes through, so the label is readable without running anything.
        calls.append(
            next((name for name in ("names", "ports", "url", "asn", "cloud")
                  if name in log_path.name), "?")
        )
        # Always something new, so only the round ceiling can stop the loop.
        frontier.write_text(f"host-{counter['n']}.acme.test\n", encoding="utf-8")
        return 0

    monkeypatch.setattr(run_recon, "_run_streamed", fake_run_streamed)

    first_round_jobs = [
        (label, ["python", "-m", f"module_{label}"], tmp_path / f"{label}.log")
        for label in ("names", "ports", "url", "asn", "cloud")
    ]
    payload, exit_codes = run_recon._run_converged(
        "acme.test",
        first_round_jobs,
        stamp="20260919_000000",
        verbose=False,
        policy=StopPolicy(max_rounds=2, time_budget_seconds=0),
    )

    # Round 1: every pipeline.  Round 2: only the ones whose answer the new assets
    # can change — ``url_endpoint`` is one-shot (per-domain archives), and the fake
    # only ever produced a *host* token, so ``ports`` and ``asn`` (which need an
    # ``ip``) are skipped rather than re-scanning for nothing.
    assert calls == ["names", "ports", "url", "asn", "cloud", "names", "cloud"]
    assert payload["rounds_run"] == 2
    assert payload["verdict"]["reason"] == STOP_MAX_ROUNDS
    assert payload["rounds"][1]["stages"] == ["names", "cloud"]
    assert payload["rounds"][1]["gated"] is True
    assert "skipped asn/ports" in payload["rounds"][1]["notes"][0]
    assert payload["ledger"]["assets_seen"] == 2
    assert exit_codes == [0] * 7
    assert (tmp_path / "recon_acme.test_convergence_20260919_000000.json").is_file()
    # Every round's children are pointed at this run's own scan receipt, so an
    # engagement cannot inherit the previous one's scan history.
    assert set(receipt_env) == {
        str(tmp_path / "recon_acme.test_attempts_20260919_000000.jsonl")
    }


def test_the_model_reader_rebuilds_every_round() -> None:
    """The handoff document must describe the surface as it ended up."""
    manifest = Registry.discover().get("graph_normalize").manifest

    assert manifest.repeat_stages == ("collect", "merge", "emit", "publish")
    # It consumes the frontier; it does not feed one.
    assert manifest.frontier_artifacts == ()


# --------------------------------------------------------------------------- #
# the loop and the runner, together
# --------------------------------------------------------------------------- #


def _unused_service():
    class _Health:
        available = True
        reason = ""

        def to_dict(self) -> dict:
            return {"available": True, "reason": ""}

    class _Service:
        def __init__(self) -> None:
            self.health = _Health()

        def summary(self) -> dict:
            return {"decisions": {}, "run_actions": 0}

    return _Service()


class _FakeModule:
    """Stands in for a pipeline's contract module: the runner reads ``__file__``."""

    def __init__(self, path: Path) -> None:
        self.__file__ = str(path)


def test_the_runner_loops_real_rounds_and_writes_the_convergence_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The whole loop, through the platform: rounds, stop reason, artifacts on disk."""
    from service.recon_pipeline.platform import runner as runner_mod

    folder = tmp_path / "pipeline"
    folder.mkdir()
    frontier = folder / "output" / "hosts.txt"
    frontier.parent.mkdir()

    passes = {"n": 0}

    class _Grower(BasePipeline):
        manifest = Manifest(
            name="grower",
            title="a pipeline whose frontier stops growing on the third look",
            asset_types=("Test",),
            stages=(Stage("collect", "collect"), Stage("emit", "emit")),
            frontier_artifacts=("output/hosts.txt",),
            repeat_stages=("collect",),
            passive_only=True,
        )

        def reset(self) -> None:
            passes["n"] += 1

        def run(self, stage: str, context: RunContext) -> dict:
            discovered = {1: "a.acme.test\nb.acme.test", 2: "a.acme.test\nb.acme.test\nc.acme.test"}
            if stage == "collect":
                frontier.write_text(discovered.get(passes["n"], discovered[2]), encoding="utf-8")
            return {"ok": True, "counts": {stage: passes["n"]}}

    pipeline = _Grower()
    registry = Registry(
        [
            Registration(
                name="grower",
                manifest=pipeline.manifest,
                pipeline=pipeline,
                module=_FakeModule(folder / "contract.py"),
            )
        ]
    )

    def _stub_context(self, target, *, env_prefix="", output_dir=None, options=None, program_scope=None):
        return RunContext(target=target, output_dir=output_dir), [
            _unused_service() for _ in range(6)
        ]

    monkeypatch.setattr(runner_mod.Runner, "build_context", _stub_context)
    result = runner_mod.Runner(registry=registry, output_root=tmp_path).run(
        "acme.test", convergence=StopPolicy()
    )

    # Round 1 establishes the baseline, round 2 adds one asset, round 3 adds none.
    assert result.convergence["rounds_run"] == 3
    assert result.convergence["verdict"]["reason"] == STOP_FIXED_POINT
    assert result.convergence["exhausted"] is True
    assert [entry["new_assets"] for entry in result.convergence["rounds"]] == [2, 1, 0]
    # Round 1 runs every declared stage; later rounds only the repeatable ones.
    assert [f"{o.pipeline}:{o.stage}" for o in result.outcomes] == [
        "grower:collect",
        "grower:emit",
        "grower:collect",
        "grower:collect",
    ]
    assert "convergence" in result.summary

    run_dir = result.run_dir
    assert run_dir is not None
    assert (run_dir / runner_mod.CONVERGENCE_FILE).is_file()
    assert (run_dir / runner_mod.LEDGER_FILE).is_file()
    # Every round's stage reports are round-scoped in a converged run, so a later
    # round can never overwrite an earlier one's record of what it did.
    assert (run_dir / "stages" / "round-1" / "grower" / "collect.json").is_file()
    assert (run_dir / "stages" / "round-2" / "grower" / "collect.json").is_file()
    assert (run_dir / "stages" / "round-2" / "grower" / "emit.json").exists() is False

    rows = RunRegistry(tmp_path / runner_mod.RUNS_DIRNAME).history(limit=5)
    assert rows[0]["convergence"]["verdict"]["reason"] == STOP_FIXED_POINT


def test_a_persisted_quarantine_is_readable_as_a_block(tmp_path: Path) -> None:
    """The loop's blocked signal comes from the stores the stages actually write."""
    import json
    import time

    from service.recon_pipeline.platform.stealth.quarantine import blocked_state

    store = tmp_path / "output" / "quarantine.json"
    store.parent.mkdir()
    store.write_text(
        json.dumps(
            {
                "version": 1,
                "updated_at": 0.0,
                "entries": {
                    "host:blocked.acme.test": {
                        "scope": "host:blocked.acme.test",
                        "kind": "BLOCKED",
                        "reason": "challenge",
                        "expires_at": time.time() + 3600,
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    blocked, why = blocked_state([store])

    assert blocked is True
    assert "host:blocked.acme.test" in why


def test_an_absent_or_expired_store_is_not_a_block(tmp_path: Path) -> None:
    """A quarantine that cannot be read must never be read as "the target blocked us"."""
    import json

    from service.recon_pipeline.platform.stealth.quarantine import blocked_state

    expired = tmp_path / "quarantine.json"
    expired.write_text(
        json.dumps(
            {
                "version": 1,
                "entries": {
                    "host:blocked.acme.test": {
                        "scope": "host:blocked.acme.test",
                        "reason": "challenge",
                        "expires_at": 1.0,
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    assert blocked_state([tmp_path / "nope.json"]) == (False, "")
    assert blocked_state([expired]) == (False, "")


def test_the_runner_stops_the_loop_when_a_stage_quarantined_us(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A real store on disk, read through the runner: another round would hammer a target that said stop."""
    import json
    import time

    from service.recon_pipeline.platform import runner as runner_mod

    folder = tmp_path / "pipeline"
    store = folder / "output" / "quarantine.json"
    store.parent.mkdir(parents=True)
    store.write_text(
        json.dumps(
            {
                "version": 1,
                "entries": {
                    "global": {
                        "scope": "global",
                        "reason": "several vendors challenged us",
                        "expires_at": time.time() + 3600,
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    class _Scans(BasePipeline):
        manifest = Manifest(
            name="scans",
            title="always makes progress",
            asset_types=("Test",),
            stages=(Stage("scan", "scan"),),
            frontier_artifacts=("output/hosts.txt",),
            repeat_stages=("scan",),
            passive_only=False,
        )

        def __init__(self) -> None:
            self.calls = 0

        def run(self, stage: str, context: RunContext) -> dict:
            self.calls += 1
            (folder / "output" / "hosts.txt").write_text(
                f"host-{self.calls}.acme.test\n", encoding="utf-8"
            )
            return {"ok": True, "counts": {stage: 1}}

    pipeline = _Scans()
    registry = Registry(
        [
            Registration(
                name="scans",
                manifest=pipeline.manifest,
                pipeline=pipeline,
                module=_FakeModule(folder / "contract.py"),
            )
        ]
    )

    def _stub_context(self, target, *, env_prefix="", output_dir=None, options=None, program_scope=None):
        return RunContext(target=target, output_dir=output_dir), [
            _unused_service() for _ in range(6)
        ]

    monkeypatch.setattr(runner_mod.Runner, "build_context", _stub_context)
    result = runner_mod.Runner(registry=registry, output_root=tmp_path).run(
        "acme.test", convergence=StopPolicy()
    )

    assert pipeline.calls == 1  # the growth in round 1 did not earn a round 2
    assert result.convergence["verdict"]["reason"] == STOP_BLOCKED
    assert result.convergence["exhausted"] is False


def test_a_round_that_added_no_address_spends_no_scan_requests(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The point of the kind gate: no new address ⇒ the scanner never runs again.

    Two pipelines share the loop.  ``names`` wants new *hosts*, ``scans`` wants new
    *addresses*.  Round 1 finds a name but no address, so round 2 runs ``names``
    and skips ``scans`` entirely — no packets, no classification, no budget — and
    says in its notes why.
    """
    from service.recon_pipeline.platform import runner as runner_mod

    class _Pipeline(BasePipeline):
        def __init__(self, name: str, frontier: str, on: tuple[str, ...]) -> None:
            self.manifest = Manifest(
                name=name,
                title=f"{name} test pipeline",
                asset_types=("Test",),
                stages=(Stage("run", "run"),),
                frontier_artifacts=(frontier,),
                repeat_stages=("run",),
                repeat_on=on,
                passive_only=True,
            )
            self.calls = 0

        def run(self, stage: str, context: RunContext) -> dict:
            self.calls += 1
            return {"ok": True, "counts": {stage: self.calls}}

    names = _Pipeline("names", "out/hosts.txt", ("host",))
    scans = _Pipeline("scans", "out/ips.txt", ("ip",))
    registry = Registry(
        [
            Registration(
                name=names.manifest.name,
                manifest=names.manifest,
                pipeline=names,
                module=_FakeModule(tmp_path / "names" / "contract.py"),
            ),
            Registration(
                name=scans.manifest.name,
                manifest=scans.manifest,
                pipeline=scans,
                module=_FakeModule(tmp_path / "scans" / "contract.py"),
            ),
        ]
    )
    (tmp_path / "names" / "out").mkdir(parents=True)
    (tmp_path / "scans" / "out").mkdir(parents=True)
    # Round 1 discovers a name and no address; both rounds after that add nothing.
    (tmp_path / "names" / "out" / "hosts.txt").write_text(
        "api.acme.test\n", encoding="utf-8"
    )
    (tmp_path / "scans" / "out" / "ips.txt").write_text("", encoding="utf-8")

    def _stub_context(self, target, *, env_prefix="", output_dir=None, options=None, program_scope=None):
        return RunContext(target=target, output_dir=output_dir), [
            _unused_service() for _ in range(6)
        ]

    monkeypatch.setattr(runner_mod.Runner, "build_context", _stub_context)
    result = runner_mod.Runner(registry=registry, output_root=tmp_path).run(
        "acme.test", convergence=StopPolicy()
    )

    stages = [f"{o.pipeline}:{o.stage}" for o in result.outcomes]
    # Round 1: both. Round 2: only ``names`` — nothing new of kind ``ip`` exists.
    assert stages == ["names:run", "scans:run", "names:run"]
    assert names.calls == 2
    assert scans.calls == 1
    rounds = result.convergence["rounds"]
    assert rounds[1]["gated"] is True
    assert rounds[1]["stages"] == ["names:run"]
    assert "skipped scans" in rounds[1]["notes"][0]
    # The round that repeated ``names`` added nothing, so the loop stopped there.
    assert result.convergence["rounds_run"] == 2
    assert result.convergence["verdict"]["reason"] == STOP_FIXED_POINT


def test_a_round_with_nothing_relevant_to_run_is_convergence_not_a_broken_loop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Gated off entirely must read as exhausted, never as "no repeatable stages"."""
    from service.recon_pipeline.platform import runner as runner_mod

    class _Scans(BasePipeline):
        manifest = Manifest(
            name="scans",
            title="wants addresses",
            asset_types=("Test",),
            stages=(Stage("run", "run"),),
            frontier_artifacts=("out/hosts.txt",),
            repeat_stages=("run",),
            repeat_on=("ip",),
            passive_only=True,
        )

        def __init__(self) -> None:
            self.calls = 0

        def run(self, stage: str, context: RunContext) -> dict:
            self.calls += 1
            return {"ok": True, "counts": {stage: self.calls}}

    pipeline = _Scans()
    registry = Registry(
        [
            Registration(
                name="scans",
                manifest=pipeline.manifest,
                pipeline=pipeline,
                module=_FakeModule(tmp_path / "scans" / "contract.py"),
            )
        ]
    )
    (tmp_path / "scans" / "out").mkdir(parents=True)
    (tmp_path / "scans" / "out" / "hosts.txt").write_text("api.acme.test\n", encoding="utf-8")

    def _stub_context(self, target, *, env_prefix="", output_dir=None, options=None, program_scope=None):
        return RunContext(target=target, output_dir=output_dir), [
            _unused_service() for _ in range(6)
        ]

    monkeypatch.setattr(runner_mod.Runner, "build_context", _stub_context)
    result = runner_mod.Runner(registry=registry, output_root=tmp_path).run(
        "acme.test", convergence=StopPolicy()
    )

    assert pipeline.calls == 1  # round 2 was gated off before it could spend anything
    rounds = result.convergence["rounds"]
    assert rounds[1]["stages_run"] == 0
    assert rounds[1]["gated"] is True
    assert result.convergence["verdict"]["reason"] == STOP_FIXED_POINT
    assert result.convergence["verdict"]["reason"] != STOP_NOTHING_TO_REPEAT


def test_the_kind_gate_is_allowed_by_default() -> None:
    """Declaring nothing must never silently disable a pipeline's repeat."""
    from service.recon_pipeline.platform.contract import Manifest, Stage

    undeclared = Manifest(
        name="x",
        title="x",
        asset_types=("Test",),
        stages=(Stage("run", "run"),),
        repeat_stages=("run",),
    )
    ip_only = Manifest(
        name="y",
        title="y",
        asset_types=("Test",),
        stages=(Stage("run", "run"),),
        repeat_stages=("run",),
        repeat_on=("ip",),
    )
    one_shot = Manifest(
        name="z",
        title="z",
        asset_types=("Test",),
        stages=(Stage("run", "run"),),
    )

    assert undeclared.wanted_by({"host"}) is True
    assert undeclared.wanted_by(set()) is True  # no gate declared, no gate applied
    assert ip_only.wanted_by({"ip"}) is True
    assert ip_only.wanted_by({"host", "url"}) is False
    assert one_shot.wanted_by({"ip"}) is False


def test_every_repeat_on_kind_is_one_the_frontier_can_produce() -> None:
    """A typo in ``repeat_on`` would gate a pipeline off for ever, silently."""
    kinds = {token_kind(token) for token in (
        "host:a.test",
        "ip:104.0.0.1",
        "url:https://a.test/x",
        "net:104.0.0.0/12",
    )}

    for registration in Registry.discover().all():
        manifest = registration.manifest
        unknown = set(manifest.repeat_on) - kinds
        assert not unknown, f"{manifest.name}: repeat_on names unknown kind(s) {unknown}"


def test_the_runner_without_a_policy_still_runs_exactly_one_round(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The loop is opt-in: nothing about a plain run changes."""
    from service.recon_pipeline.platform import runner as runner_mod

    class _Once(BasePipeline):
        manifest = Manifest(
            name="once",
            title="one-shot",
            asset_types=("Test",),
            stages=(Stage("collect", "collect"),),
            frontier_artifacts=("output/hosts.txt",),
            repeat_stages=("collect",),
            passive_only=True,
        )

        def __init__(self) -> None:
            self.calls = 0

        def reset(self) -> None:
            self.calls += 1

        def run(self, stage: str, context: RunContext) -> dict:
            return {"ok": True, "counts": {stage: 1}}

    pipeline = _Once()
    registry = Registry(
        [
            Registration(
                name="once",
                manifest=pipeline.manifest,
                pipeline=pipeline,
                module=_FakeModule(tmp_path / "contract.py"),
            )
        ]
    )

    def _stub_context(self, target, *, env_prefix="", output_dir=None, options=None, program_scope=None):
        return RunContext(target=target, output_dir=output_dir), [
            _unused_service() for _ in range(6)
        ]

    monkeypatch.setattr(runner_mod.Runner, "build_context", _stub_context)
    result = runner_mod.Runner(registry=registry, output_root=tmp_path).run("acme.test")

    assert [f"{o.pipeline}:{o.stage}" for o in result.outcomes] == ["once:collect"]
    assert result.convergence == {}
    assert "convergence" not in result.summary
    run_dir = result.run_dir
    assert run_dir is not None
    assert not (run_dir / runner_mod.CONVERGENCE_FILE).exists()
