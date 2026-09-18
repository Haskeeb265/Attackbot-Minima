"""
Tests for the ``port_service_host`` command line.

The pipeline's own behaviour is covered by ``test_psh_pipeline.py``; what is only
true of the *CLI* is covered here — that every documented flag reaches the stage
call with the right name and polarity, that the defaults come from settings rather
than from argparse literals, that the repeatable flags accumulate instead of
overwriting, and that the exit codes mean what the README says (0 clean, 1 ran
with a failure, 2 refused).

A wrong polarity here is the kind of bug that looks like it works: ``--no-cdn-probe``
silently leaving probing *on* would scan CDN addresses that the design says to
never port-scan, and nothing but a test of the wiring would notice.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from service.recon_pipeline.pipelines.port_service_host import pipeline, settings
from service.recon_pipeline.pipelines.port_service_host.classify import cdn
from service.recon_pipeline.pipelines.port_service_host.pipeline import PshReport, main


@pytest.fixture
def captured(monkeypatch):
    """Capture the stage call instead of running it, and script its result."""

    calls: list[tuple[tuple, dict]] = []
    outcome = {"report": PshReport(target="example.com", started_at="2026-09-17T12:00:00+00:00")}

    def fake_stage(*args, **kwargs):
        calls.append((args, kwargs))
        result = outcome["report"]
        if isinstance(result, BaseException):
            raise result
        return result

    monkeypatch.setattr(pipeline, "run_port_service_host_stage", fake_stage)
    return type("Captured", (), {"calls": calls, "outcome": outcome})()


def kwargs_of(captured) -> dict:
    assert captured.calls, "the stage was never called"
    return captured.calls[-1][1]


# --------------------------------------------------------------------------- #
# Defaults
# --------------------------------------------------------------------------- #


def test_the_defaults_are_the_settings_not_argparse_literals(captured) -> None:
    """A default restated in the parser would silently drift from the settings."""
    main([])

    kwargs = kwargs_of(captured)
    assert kwargs["scan_level"] == settings.SCAN_LEVEL
    assert kwargs["rate"] == settings.MAX_RATE
    assert kwargs["scan_type"] == settings.SCAN_TYPE
    assert kwargs["max_ips"] == settings.MAX_IPS
    assert kwargs["timeout"] == settings.DEFAULT_SOURCE_TIMEOUT
    assert kwargs["output_dir"] == str(settings.OUTPUT_DIR)


def test_the_target_falls_back_to_the_environment_default(captured) -> None:
    """``pipeline.TARGET`` is the project-wide ``TARGET`` env default."""
    main([])
    assert captured.calls[-1][0][0] == pipeline.TARGET


def test_the_records_and_resolver_defaults_point_at_the_sibling_stage(captured) -> None:
    main([])
    kwargs = kwargs_of(captured)
    assert kwargs["records_file"] == str(settings.ACTIVE_RECORDS_FILE)
    assert kwargs["resolvers"] == str(settings.ACTIVE_RESOLVERS_FILE)


def test_every_layer_is_on_by_default(captured) -> None:
    """The stage is supposed to do the full job unless told otherwise."""
    main([])
    kwargs = kwargs_of(captured)
    for name in (
        "intel",
        "ownership",
        "reverse_dns",
        "resolve_uncovered",
        "services",
        "cdn_probe",
        "escalate",
    ):
        assert kwargs[name] is True, name


# --------------------------------------------------------------------------- #
# Flags
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("flag", "key"),
    [
        ("--no-intel", "intel"),
        ("--no-ownership", "ownership"),
        ("--no-ptr", "reverse_dns"),
        ("--no-resolve-uncovered", "resolve_uncovered"),
        ("--no-services", "services"),
        ("--no-cdn-probe", "cdn_probe"),
        ("--no-escalate", "escalate"),
    ],
)
def test_each_off_switch_turns_off_its_own_layer_only(captured, flag, key) -> None:
    main([flag])

    kwargs = kwargs_of(captured)
    assert kwargs[key] is False, f"{flag} did not reach {key}"
    others = [
        name
        for name in ("intel", "ownership", "reverse_dns", "resolve_uncovered", "services",
                     "cdn_probe", "escalate")
        if name != key
    ]
    assert all(kwargs[name] is True for name in others), f"{flag} turned off more than {key}"


def test_the_target_flag_wins_over_the_default(captured) -> None:
    main(["-t", "tesla.com", "--target", "ignored.example"])
    assert captured.calls[-1][0][0] == "ignored.example"


def test_the_numeric_knobs_are_passed_through(captured) -> None:
    main(["--rate", "42", "--max-ips", "7", "--timeout", "12.5", "--scan-type", "connect"])
    kwargs = kwargs_of(captured)
    assert (kwargs["rate"], kwargs["max_ips"], kwargs["timeout"], kwargs["scan_type"]) == (
        42,
        7,
        12.5,
        "connect",
    )


def test_the_scan_level_is_passed_through_and_validated(captured) -> None:
    """An unrecognised level must not be read as "scan everything"."""
    main(["--scan-level", "full"])
    assert kwargs_of(captured)["scan_level"] == "full"

    with pytest.raises(SystemExit):
        main(["--scan-level", "everything"])


def test_repeatable_flags_accumulate_in_order(captured) -> None:
    """Scope and host files are sets of inputs; the last must not win."""
    main(
        [
            "--scope", "a.txt",
            "--scope", "b.txt",
            "--host-file", "one.txt",
            "--host-file", "two.txt",
            "--address", "1.1.1.1",
            "--address", "8.8.8.8",
        ]
    )

    kwargs = kwargs_of(captured)
    assert kwargs["scope_files"] == ("a.txt", "b.txt")
    assert kwargs["host_files"] == ("one.txt", "two.txt")
    assert kwargs["addresses"] == ("1.1.1.1", "8.8.8.8")


def test_the_output_directory_can_be_moved(captured, tmp_path: Path) -> None:
    main(["--output-dir", str(tmp_path)])
    assert kwargs_of(captured)["output_dir"] == str(tmp_path)


def test_verbose_selects_debug_logging(monkeypatch, captured) -> None:
    levels: list[int] = []
    monkeypatch.setattr(logging, "basicConfig", lambda **kwargs: levels.append(kwargs["level"]))

    main([])
    main(["-v"])

    assert levels == [logging.INFO, logging.DEBUG]


# --------------------------------------------------------------------------- #
# Exit codes — the README documents 0 / 1 / 2, so they are a contract
# --------------------------------------------------------------------------- #


def test_a_clean_run_exits_zero(captured) -> None:
    assert main([]) == 0


def test_a_run_with_failures_exits_one(captured) -> None:
    """Completed-but-degraded is not the same as refused."""
    captured.outcome["report"] = PshReport(
        target="example.com", started_at="2026-09-17T12:00:00+00:00", ok=False, docker_error="no docker"
    )
    assert main([]) == 1


def test_a_refused_target_exits_two(captured) -> None:
    captured.outcome["report"] = ValueError("target is empty")
    assert main([]) == 2


def test_a_missing_key_exits_two(captured) -> None:
    captured.outcome["report"] = KeyError("records")
    assert main([]) == 2


def test_an_unexpected_failure_is_not_swallowed(captured) -> None:
    """Only the two "we understood and refuse" errors are turned into exit 2."""
    captured.outcome["report"] = RuntimeError("something else went wrong")
    with pytest.raises(RuntimeError):
        main([])


# --------------------------------------------------------------------------- #
# --list
# --------------------------------------------------------------------------- #


def test_list_prints_the_inventory_and_does_not_run_the_stage(captured, capsys) -> None:
    assert main(["--list"]) == 0

    output = capsys.readouterr().out
    assert "tools" in output
    assert "cdn/waf providers" in output
    assert "range snapshot:" in output
    for provider in cdn.PROVIDERS:
        assert provider.key in output
    assert captured.calls == [], "--list must not touch the network or Docker"


def test_list_says_how_many_ranges_are_loaded(captured, capsys) -> None:
    main(["--list"])
    table = cdn.load_ranges()
    assert f"{len(table.networks)} network(s)" in capsys.readouterr().out


def test_list_reports_a_range_file_it_could_not_fully_parse(monkeypatch, captured, capsys) -> None:
    """A stale snapshot must be visible at startup, not discovered as a miss."""
    monkeypatch.setattr(
        cdn,
        "load_ranges",
        lambda *a, **k: cdn.RangeTable(networks=[], unparsed=["bogus line", "another"]),
    )

    main(["--list"])

    output = capsys.readouterr().out
    assert "2 unparsed line(s)" in output
    assert "bogus line" in output


def test_the_listed_tools_are_the_ones_in_the_registry(captured, capsys) -> None:
    from service.recon_pipeline.pipelines.port_service_host.active import tools

    main(["--list"])
    output = capsys.readouterr().out
    for row in tools.describe_tools():
        assert row["name"] in output
