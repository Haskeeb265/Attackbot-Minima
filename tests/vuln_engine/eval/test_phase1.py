"""Phase 1 end to end: the exit criteria, against the compose fixture app.

This is the only test that runs the engine as an operator would — real transports,
a real fixture app, a real browser, and a collaborator that records the target's
request. It is skipped unless the harness is up, because a missing fixture must
read as "not measured" rather than as a pass.

What it asserts is exactly the checklist's criteria 1–6:

1. reflected XSS found and verified by **browser execution** (``grade=execution``),
   blind fetch found and verified by an **OOB interaction** (``grade=oob``);
2. report lines carry the evidence class and a reproducible URL;
3. the run replays offline from its own JSONL — asserted with sockets disabled;
4. the gate audit shows zero out-of-scope requests and zero uncleared effects;
5. no LLM key is configured anywhere, and no junction code exists to read one;
6. the suite is green and mypy-clean (those are the other two criteria, measured by
   the project's own tooling rather than here).

The fixture is *declared in scope* — as an address, by the operator — which is what
lets criteria 1 and 4 both hold. If the declaration were removed, the scope engine
would refuse every request and the run would produce nothing; there is a test for
that in ``policy/test_gate.py``.

Run it with::

    docker compose up -d fixture_app oob_collaborator
    pytest tests/vuln_engine/eval/test_phase1.py -v
"""

from __future__ import annotations

import json
import socket
from pathlib import Path

import httpx
import pytest

import run_engine
from service.vuln_engine.scheduler.replay import replay
from service.vuln_engine.transports.browser import BrowserEffect
from service.vuln_engine.world.log import WorldLog

FIXTURE = "http://127.0.0.1:8080/healthz"
COLLABORATOR = "http://127.0.0.1:9009/healthz"


def _up(url: str) -> bool:
    try:
        return httpx.get(url, timeout=2.0).status_code == 200
    except Exception:  # noqa: BLE001 - not being up is the answer, not an error
        return False


@pytest.fixture(scope="module")
def harness() -> dict:
    """Skip — loudly — unless the fixture, the collaborator and a browser are all up."""
    missing: list[str] = []
    if not _up(FIXTURE):
        missing.append("the fixture app (docker compose up -d fixture_app)")
    if not _up(COLLABORATOR):
        missing.append("the OOB collaborator (docker compose up -d oob_collaborator)")
    browser = BrowserEffect()
    if not browser.capabilities.available:
        missing.append(f"a browser: {browser.capabilities.reason}")
    if missing:
        pytest.skip("the Phase 1 harness is not up: " + "; ".join(missing))
    return {"collaborator": COLLABORATOR}


@pytest.fixture(scope="module")
def report(tmp_path_factory, harness) -> run_engine.RunReport:  # noqa: ARG001 - ordering
    output = tmp_path_factory.mktemp("phase1")
    return run_engine.run(run_engine.fixture_profile(), output_dir=output)


# --------------------------------------------------------------------------- #
# criterion 1 — two findings, each on its own evidence class
# --------------------------------------------------------------------------- #


def test_both_findings_are_produced(report: run_engine.RunReport) -> None:
    classes = {finding["vuln_class"]: finding["evidence_class"] for finding in report.findings}
    assert classes == {"xss": "execution", "ssrf": "oob"}


def test_every_finding_is_independently_verified(report: run_engine.RunReport) -> None:
    for finding in report.findings:
        assert finding["independent"] is True
        assert finding["evidence_class"] != finding["proposer_grade"]
        assert finding["evidence_class"] in ("execution", "oob")


def test_the_xss_finding_rests_on_a_browser_actually_running_the_payload(report: run_engine.RunReport) -> None:
    xss = next(finding for finding in report.findings if finding["vuln_class"] == "xss")
    assert xss["evidence"]["markers"], "a marker answer has to be recorded"
    assert any(xss["evidence"]["markers"].values())
    assert xss["evidence"]["context"] == "double_quoted_attribute"
    assert xss["evidence"]["dialogs"], "the dialog the payload opens is the corroboration"
    assert xss["evidence"]["driver"] in ("cdp", "playwright")


def test_the_ssrf_finding_rests_on_our_own_collaborator(report: run_engine.RunReport) -> None:
    ssrf = next(finding for finding in report.findings if finding["vuln_class"] == "ssrf")
    assert ssrf["evidence"]["source_ip"], "the interaction has to record where it came from"
    assert ssrf["evidence"]["interactions"] >= 1
    assert "/oob/" in str(ssrf["evidence"]["path"])


# --------------------------------------------------------------------------- #
# criterion 2 — the report line
# --------------------------------------------------------------------------- #


def test_report_lines_carry_the_class_and_a_reproducible_url(report: run_engine.RunReport) -> None:
    assert len(report.report_lines) == 2
    xss_line = next(line for line in report.report_lines if "XSS" in line)
    assert "Confirmed by browser execution" in xss_line
    assert "Evidence class: execution" in xss_line
    assert "http://127.0.0.1:8080/search?q=" in xss_line
    ssrf_line = next(line for line in report.report_lines if "SSRF" in line)
    assert "our own collaborator" in ssrf_line
    assert "Evidence class: oob" in ssrf_line


# --------------------------------------------------------------------------- #
# criterion 3 — replay, offline
# --------------------------------------------------------------------------- #


def test_the_run_replays_from_its_log_with_networking_disabled(report: run_engine.RunReport) -> None:
    def no_sockets(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("a replay must not touch the network")

    original_socket = socket.socket
    original_connect = socket.create_connection
    socket.socket = no_sockets  # type: ignore[assignment]
    socket.create_connection = no_sockets  # type: ignore[assignment]
    try:
        result = replay(WorldLog(report.log_path), seed=run_engine.fixture_profile().seed)
    finally:
        socket.socket = original_socket  # type: ignore[assignment]
        socket.create_connection = original_connect  # type: ignore[assignment]

    assert result.clean, result.mismatches
    assert result.candidates_logged == 2
    assert result.candidates_recomputed == 2
    assert len(result.findings) == 2


def test_the_log_is_append_only_jsonl_that_reads_back(report: run_engine.RunReport) -> None:
    rows = WorldLog.read(report.log_path)
    assert rows[0]["type"] == "run.begin"
    assert rows[-1]["type"] == "run.end"
    assert all("at" in row for row in rows)
    assert WorldLog(report.log_path).summary()["verdict"] == 2


# --------------------------------------------------------------------------- #
# criterion 4 — the gate audit
# --------------------------------------------------------------------------- #


def test_the_gate_audit_is_clean(report: run_engine.RunReport) -> None:
    assert report.gate["out_of_scope_requests"] == 0
    assert report.gate["uncleared_effects"] == 0
    # Phase 1's three effects (xss canary, verifier browser, oob fetch) plus
    # xss_dom's two (its canary and the placement browser run the fixture's
    # reflected context entitles it to; its interpreter then dedupes the
    # candidate away — the wire lens found it first).
    assert report.gate["by_verb"] == {"ALLOW": 5}
    # Two target requests and one browser confirmation, plus the collaborator's own
    # allocation and read, which are internal by design and logged as such.
    assert report.gate["internal_effects"] == 2


def test_every_decision_has_a_reason(report: run_engine.RunReport) -> None:
    log = WorldLog(report.log_path)
    assert all(row.get("reason") for row in log.events("gate.decision"))


# --------------------------------------------------------------------------- #
# criterion 5 — no model anywhere
# --------------------------------------------------------------------------- #


def test_the_run_needed_no_llm_key(report: run_engine.RunReport, monkeypatch) -> None:
    """The no-key claim, unchanged by Phase 3: no key means degraded advisory
    and an ordinary run — the engine's behaviour is identical, not merely
    unassisted. The empty-``llm/`` half of this test retired when Phase 3
    landed; the invariants now enforce the advisory boundary instead."""
    monkeypatch.delenv("VULN_ENGINE_LLM_API_KEY", raising=False)
    monkeypatch.delenv("VULN_ENGINE_LLM_API_URL", raising=False)
    capabilities = report.capabilities
    assert set(capabilities) == {"http1", "browser", "oob"}
    assert report.advisory in ({}, None)


# --------------------------------------------------------------------------- #
# criteria 6 and 7 — the report on disk, and idempotence
# --------------------------------------------------------------------------- #


def test_the_run_writes_its_report_beside_its_log(report: run_engine.RunReport, tmp_path: Path) -> None:
    output = Path(report.log_path).parent
    payload = json.loads((output / "report.json").read_text(encoding="utf-8"))
    assert payload["target"] == "127.0.0.1"
    assert len(payload["findings"]) == 2
    assert payload["gate"]["uncleared_effects"] == 0
    assert (output / "receipts.jsonl").is_file()


def test_a_second_run_does_not_pay_for_what_it_already_proved(harness, tmp_path: Path) -> None:  # noqa: ARG001
    output = tmp_path / "second"
    first = run_engine.run(run_engine.fixture_profile(), output_dir=output)
    second = run_engine.run(run_engine.fixture_profile(), output_dir=output)
    assert first.counts["findings"] == 2
    # Three settled arms: Phase 1's two, plus xss_dom's settled ``none``
    # (its dedupe rule leaves the wire-lens finding as the only claimant).
    assert second.counts["skipped_conclusive"] == 3
    assert second.counts["probes_run"] == 0
    assert second.findings == []
