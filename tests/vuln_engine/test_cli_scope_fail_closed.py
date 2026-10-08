"""Item 2.4 — the seed is fail-closed on scope.

Three refusals, all before any socket opens:

* no target at all no longer falls back to the fixture: the compose app is a
  deliberate ``--fixture`` choice, not a default an operator can trigger by
  forgetting ``-t``;
* an operator-declared surface whose host the ScopeEngine does not call
  ``in_scope`` refuses the run at startup, naming the surface and the reason —
  instead of a run where every probe to it is refused per-request and the
  report reads like a clean negative;
* ``--allow-unscoped`` waives only the startup check: the run proceeds and the
  gate still refuses every request to those surfaces (the chokepoint
  invariant is not waived by a CLI flag), with a warning naming them.

The tests drive ``run_engine.main`` directly — the refusal paths return 2
before any effect is built, and the passing path is cut off by replacing
``run`` with a sentinel, so nothing here sends traffic.
"""

from __future__ import annotations

import re

import pytest

import run_engine


class _ReachedRun(Exception):
    """Sentinel: main() got all the way to the engine."""


_RUN_DIRS: list[str] = []


def _cut_at_run(monkeypatch, capture_dirs: bool = False) -> None:
    def _sentinel(profile, *args: object, **kwargs: object) -> run_engine.RunReport:
        if capture_dirs:
            _RUN_DIRS.append(str(kwargs["output_dir"]))
        raise _ReachedRun()

    monkeypatch.setattr(run_engine, "run", _sentinel)


def test_no_target_refuses_the_fixture_default(capsys) -> None:
    # The old default ran the local compose app whenever -t was forgotten —
    # a run nobody asked for. Now main() stops and names the three ways to
    # say what was meant.
    assert run_engine.main([]) == 2
    err = capsys.readouterr().err
    assert "--target" in err
    assert "--program" in err
    assert "--fixture" in err


def test_an_in_scope_surface_reaches_the_run(monkeypatch) -> None:
    # The control: a surface on the declared target passes the startup check.
    _cut_at_run(monkeypatch)
    with pytest.raises(_ReachedRun):
        run_engine.main(
            [
                "-t", "example.test",
                "--surface", "url=http://example.test/a;param=q",
                "--output-dir", "unused-run-is-never-reached",
            ]
        )


def test_an_unscoped_surface_refuses_at_startup(monkeypatch, capsys) -> None:
    _cut_at_run(monkeypatch)
    code = run_engine.main(
        [
            "-t", "example.test",
            "--surface", "url=http://stranger.test/a;param=q",
        ]
    )
    assert code == 2
    err = capsys.readouterr().err
    # The refusal names the surface, the scope reason, and the two outs.
    assert "stranger.test" in err
    assert "outside declared domains" in err
    assert "--declare" in err
    assert "--allow-unscoped" in err


def test_allow_unscoped_runs_and_names_what_will_be_refused(
    monkeypatch, capsys
) -> None:
    _cut_at_run(monkeypatch)
    with pytest.raises(_ReachedRun):
        run_engine.main(
            [
                "-t", "example.test",
                "--surface", "url=http://stranger.test/a;param=q",
                "--allow-unscoped",
                "--output-dir", "unused-run-is-never-reached",
            ]
        )
    out = capsys.readouterr().out
    assert "--allow-unscoped" in out
    assert "outside the declared scope" in out


# --------------------------------------------------------------------------- #
# item 2.5 — a run is a directory, and two runs are two directories
# --------------------------------------------------------------------------- #


def test_two_default_runs_get_two_directories(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(run_engine, "DEFAULT_OUTPUT_ROOT", tmp_path)
    _cut_at_run(monkeypatch, capture_dirs=True)
    with pytest.raises(_ReachedRun):
        run_engine.main(["-t", "example.test"])
    with pytest.raises(_ReachedRun):
        run_engine.main(["-t", "example.test"])
    assert len(_RUN_DIRS) == 2
    first, second = _RUN_DIRS
    assert first != second  # a second run never appends to the first's ledger
    for run_dir in (first, second):
        name = run_dir.split("\\")[-1].split("/")[-1]
        assert name.startswith("example.test-")
        assert re.search(r"\d{8}T\d{6}Z-[0-9a-f]{6}$", name)


def test_run_id_names_the_directory(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(run_engine, "DEFAULT_OUTPUT_ROOT", tmp_path)
    _cut_at_run(monkeypatch, capture_dirs=True)
    with pytest.raises(_ReachedRun):
        run_engine.main(["-t", "example.test", "--run-id", "engagement_7"])
    assert _RUN_DIRS[-1] == str(tmp_path / "engagement_7")


def test_a_destination_that_already_holds_a_log_is_refused(
    monkeypatch, tmp_path, capsys
) -> None:
    run_dir = tmp_path / "taken"
    run_dir.mkdir()
    (run_dir / "world.jsonl").write_text("", encoding="utf-8")
    _cut_at_run(monkeypatch)
    code = run_engine.main(["-t", "example.test", "--output-dir", str(run_dir)])
    assert code == 2
    err = capsys.readouterr().err
    assert "--fresh" in err
    assert "--run-id" in err


def test_fresh_appends_to_an_existing_run_deliberately(monkeypatch, tmp_path) -> None:
    run_dir = tmp_path / "taken"
    run_dir.mkdir()
    (run_dir / "world.jsonl").write_text("", encoding="utf-8")
    _cut_at_run(monkeypatch, capture_dirs=True)
    with pytest.raises(_ReachedRun):
        run_engine.main(
            ["-t", "example.test", "--output-dir", str(run_dir), "--fresh"]
        )
    assert _RUN_DIRS[-1] == str(run_dir)


def test_run_id_and_output_dir_are_refused_together(capsys) -> None:
    assert run_engine.main(
        ["-t", "example.test", "--run-id", "x", "--output-dir", "y"]
    ) == 2
    assert "--output-dir" in capsys.readouterr().err
