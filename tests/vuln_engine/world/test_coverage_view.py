"""The coverage view: per-surface coverage derived from the receipts ledger.

``views.coverage`` reads ``receipt`` rows (``scheduler/driver.py`` writes
``arm`` / ``technique`` / ``outcome`` / ``conclusive`` and **no** ``stage``), so
the view keys purely off the receipt's own fields: one row per
``(surface, technique)`` with the last attempt's outcome, conclusiveness and
``at``. Hypothesis-only visits — a technique that read a surface and proposed
nothing — live in ``note stage=hypothesis`` rows and are deliberately *not*
coverage here: they asked a question, they did not file an attempt.
"""

from __future__ import annotations

import run_engine
from service.vuln_engine.scheduler.driver import RunReport
from service.vuln_engine.world import views
from service.vuln_engine.world.log import EVENT_RECEIPT, WorldLog


def _receipt(
    log: WorldLog, *, at: float, arm: str, outcome: str, conclusive: bool
) -> None:
    """A receipt row in the driver's spelling (``technique`` is the operation)."""
    technique, _, _ = arm.partition("@")
    log.append(
        EVENT_RECEIPT,
        at=at,
        arm=arm,
        technique=f"{technique}:op-1",
        outcome=outcome,
        conclusive=conclusive,
    )


# --------------------------------------------------------------------------- #
# the view
# --------------------------------------------------------------------------- #


def test_coverage_keys_the_last_attempt_per_surface_and_technique() -> None:
    log = WorldLog()
    _receipt(log, at=1.0, arm="sqli_blind_time@http://h/items?id", outcome="found", conclusive=True)
    _receipt(log, at=2.0, arm="sqli_blind_time@http://h/items?id", outcome="failed", conclusive=False)
    _receipt(log, at=3.0, arm="xss_reflected@http://h/search?q", outcome="found", conclusive=True)

    coverage = views.coverage(log)
    assert coverage == {
        "http://h/items?id": {
            "sqli_blind_time": {"outcome": "failed", "conclusive": False, "at": 2.0},
        },
        "http://h/search?q": {
            "xss_reflected": {"outcome": "found", "conclusive": True, "at": 3.0},
        },
    }


def test_coverage_splits_conclusive_from_inconclusive_attempts() -> None:
    log = WorldLog()
    _receipt(log, at=1.0, arm="idor_differential@http://h/api/4821", outcome="none", conclusive=True)
    _receipt(log, at=2.0, arm="oob_fetch@http://h/fetch?url", outcome="failed", conclusive=False)

    (invoice,) = views.coverage(log)["http://h/api/4821"].values()
    (fetch,) = views.coverage(log)["http://h/fetch?url"].values()
    assert invoice["conclusive"] is True
    assert fetch["conclusive"] is False


def test_coverage_of_an_empty_log_is_empty() -> None:
    assert views.coverage(WorldLog()) == {}


# --------------------------------------------------------------------------- #
# the wiring
# --------------------------------------------------------------------------- #


def test_summary_embeds_the_coverage_view() -> None:
    log = WorldLog()
    _receipt(log, at=1.0, arm="xss_reflected@http://h/search?q", outcome="found", conclusive=True)
    assert views.summary(log)["coverage"] == views.coverage(log)


def test_the_report_carries_the_coverage_key() -> None:
    coverage = {
        "http://h/search?q": {
            "xss_reflected": {"outcome": "found", "conclusive": True, "at": 1.0}
        }
    }
    report = RunReport(target="t", coverage=coverage)
    assert report.to_dict()["coverage"] == coverage


def test_the_cli_prints_the_coverage_block(capsys) -> None:
    report = RunReport(
        target="t",
        coverage={
            "http://h/search?q": {
                "xss_reflected": {"outcome": "found", "conclusive": True, "at": 1.0}
            },
            "http://h/items?id": {
                "sqli_blind_time": {"outcome": "failed", "conclusive": False, "at": 2.0}
            },
        },
    )
    run_engine.print_coverage(report)
    printed = capsys.readouterr().out
    assert "2 technique(s) across 2 surface(s); 1 conclusive attempt(s)" in printed
    assert "covered: xss_reflected" in printed
    assert "suspected: sqli_blind_time" in printed

    run_engine.print_coverage(RunReport(target="t"))
    assert capsys.readouterr().out == ""
