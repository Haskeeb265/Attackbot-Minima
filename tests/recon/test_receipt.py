"""Tests for :mod:`platform.receipt` — the attempt receipt.

The rules worth pinning are the honesty ones: what counts as "already tried", and
what deliberately does not.  A receipt that treats a failed scan as knowledge
would turn an outage into a permanent blind spot, so most of this file is about
the boundary between an attempt that answered and one that merely happened.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from service.recon_pipeline.platform.receipt import (
    INCONCLUSIVE,
    OUTCOME_FAILED,
    OUTCOME_FOUND,
    OUTCOME_NONE,
    Receipt,
    asset_token,
)


def test_receipt_tokens_are_kind_prefixed() -> None:
    """An address and a name are different assets even when spelled alike."""
    assert asset_token("8.8.8.8") == "ip:8.8.8.8"
    assert asset_token("8.8.8.8", "ip") == "ip:8.8.8.8"
    assert asset_token("API.Example.com.") == "host:api.example.com"
    assert asset_token("2603:1000::1", "ip") == "ip:2603:1000::1"


def test_an_unparseable_asset_is_refused_rather_than_stored() -> None:
    """A token nothing can look up again is worse than no row at all."""
    assert asset_token("") is None
    assert asset_token("   ") is None
    assert asset_token("not a host!") is None

    receipt = Receipt()
    assert receipt.record("not a host!", "port_scan", outcome=OUTCOME_NONE) is False
    assert receipt.record("", "port_scan") is False
    assert receipt.record("8.8.8.8", "") is False
    assert len(receipt) == 0


# --------------------------------------------------------------------------- #
# what earns a skip
# --------------------------------------------------------------------------- #


def test_an_answered_attempt_earns_a_skip_and_adds_its_outcome() -> None:
    receipt = Receipt()

    assert receipt.record("8.8.8.8", "port_scan", outcome=OUTCOME_NONE) is True
    assert receipt.record("8.8.4.4", "port_scan", outcome=OUTCOME_FOUND) is True

    assert receipt.attempted("8.8.8.8", "port_scan") is True
    assert receipt.attempted("8.8.4.4", "port_scan") is True
    assert receipt.attempted_assets("port_scan") == {"ip:8.8.8.8", "ip:8.8.4.4"}
    assert receipt.by_operation()["port_scan"] == {"found": 1, "none": 1}


def test_a_failed_attempt_does_not_earn_a_skip() -> None:
    """An outage is not knowledge — the next pass must be free to try again."""
    receipt = Receipt()

    receipt.record("8.8.8.8", "port_scan", outcome=OUTCOME_FAILED)

    assert receipt.attempted("8.8.8.8", "port_scan") is False
    assert receipt.attempted_assets("port_scan") == frozenset()
    assert receipt.pending(["8.8.8.8"], "port_scan") == ["8.8.8.8"]
    # ...but the attempt itself is still on the record, with its outcome.
    assert receipt.attempt("8.8.8.8", "port_scan") is not None
    assert receipt.by_operation()["port_scan"] == {"failed": 1}


def test_an_outcome_must_be_stated_to_count() -> None:
    """Silence is not evidence: a row with no outcome cannot justify a skip."""
    receipt = Receipt()

    receipt.record("8.8.8.8", "port_scan")

    assert receipt.attempted("8.8.8.8", "port_scan") is False
    assert "" in INCONCLUSIVE


def test_a_later_conclusive_attempt_upgrades_an_inconclusive_one() -> None:
    receipt = Receipt()

    receipt.record("8.8.8.8", "port_scan", outcome=OUTCOME_FAILED, at=1.0)
    receipt.record("8.8.8.8", "port_scan", outcome=OUTCOME_NONE, at=2.0)

    assert receipt.attempted("8.8.8.8", "port_scan") is True
    assert receipt.attempt("8.8.8.8", "port_scan").at == 2.0


def test_a_later_failure_does_not_overwrite_an_answered_attempt() -> None:
    """Once we know, a later crash does not un-know it."""
    receipt = Receipt()

    receipt.record("8.8.8.8", "port_scan", outcome=OUTCOME_NONE, at=1.0)
    receipt.record("8.8.8.8", "port_scan", outcome=OUTCOME_FAILED, at=2.0)

    assert receipt.attempted("8.8.8.8", "port_scan") is True
    assert receipt.attempt("8.8.8.8", "port_scan").outcome == OUTCOME_NONE


# --------------------------------------------------------------------------- #
# the read a stage actually makes
# --------------------------------------------------------------------------- #


def test_pending_keeps_order_and_only_drops_what_was_answered() -> None:
    """The scan list must come back in first-seen order, minus the paid addresses."""
    receipt = Receipt()
    receipt.record("8.8.8.8", "port_scan", outcome=OUTCOME_NONE)
    receipt.record("9.9.9.9", "port_scan", outcome=OUTCOME_FAILED)

    assert receipt.pending(["8.8.8.8", "9.9.9.9", "1.1.1.1"], "port_scan") == [
        "9.9.9.9",
        "1.1.1.1",
    ]


def test_pending_accepts_tokens_and_raw_values_alike() -> None:
    receipt = Receipt()
    receipt.record("8.8.8.8", "port_scan", outcome=OUTCOME_NONE)

    assert receipt.pending(["ip:8.8.8.8", "1.1.1.1"], "port_scan") == ["1.1.1.1"]


def test_one_operation_says_nothing_about_another() -> None:
    """A receipt is only meaningful next to the question it answers."""
    receipt = Receipt()
    receipt.record("https://app.example.com/x", "url_validation", outcome=OUTCOME_NONE)

    assert receipt.attempted("https://app.example.com/x", "url_validation") is True
    assert receipt.attempted("https://app.example.com/x", "port_scan") is False


# --------------------------------------------------------------------------- #
# persistence
# --------------------------------------------------------------------------- #


def test_the_receipt_survives_a_restart(tmp_path: Path) -> None:
    path = tmp_path / "attempted.jsonl"
    Receipt(path).record("8.8.8.8", "port_scan", outcome=OUTCOME_NONE, at=1.0)

    reopened = Receipt(path)

    assert reopened.attempted("8.8.8.8", "port_scan") is True
    assert reopened.path == path
    assert reopened.to_dict()["assets"] == 1
    assert reopened.to_dict()["rows"] >= 1


def test_a_corrupt_row_costs_one_attempt_not_the_file(tmp_path: Path) -> None:
    path = tmp_path / "attempted.jsonl"
    path.write_text(
        '{"asset": "ip:8.8.8.8", "operation": "port_scan", "outcome": "none"}\n'
        "not json at all\n"
        '{"asset": "", "operation": "port_scan"}\n'
        '{"asset": "ip:1.1.1.1", "operation": "port_scan", "outcome": "found"}\n',
        encoding="utf-8",
    )

    reopened = Receipt(path)

    assert reopened.attempted_assets("port_scan") == {"ip:8.8.8.8", "ip:1.1.1.1"}


def test_a_receipt_without_a_path_is_memory_only() -> None:
    receipt = Receipt()

    receipt.record("8.8.8.8", "port_scan", outcome=OUTCOME_NONE)

    assert receipt.to_dict()["path"] == ""
    assert receipt.attempted("8.8.8.8", "port_scan") is True


def test_an_unwritable_store_is_logged_not_raised(tmp_path: Path) -> None:
    """Telemetry must never take a stage down — the run continues unanswered."""
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory", encoding="utf-8")

    receipt = Receipt(blocker / "attempted.jsonl")

    assert receipt.record("8.8.8.8", "port_scan", outcome=OUTCOME_NONE) is True
    assert receipt.attempted("8.8.8.8", "port_scan") is True  # answered in memory


def test_an_empty_ledger_is_falsy_so_callers_must_test_for_none() -> None:
    """``receipt or Receipt()`` would silently drop a file-backed store."""
    assert not Receipt()
    assert Receipt() is not None


def test_recording_is_idempotent_for_the_same_key() -> None:
    receipt = Receipt()

    assert receipt.record("8.8.8.8", "port_scan", outcome=OUTCOME_NONE) is True
    assert receipt.record("8.8.8.8", "port_scan", outcome=OUTCOME_NONE) is True

    assert receipt.attempted_assets("port_scan") == {"ip:8.8.8.8"}


@pytest.mark.parametrize("blank", ["", "  ", None])
def test_blank_assets_are_refused(blank: str | None) -> None:
    assert Receipt().record(blank, "port_scan") is False
