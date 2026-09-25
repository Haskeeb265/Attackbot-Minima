"""The stored-XSS verifier: the two-step confirmation and its refusals.

The accept path proves the *sequence*: the inject went through the gate, then
the browser ran the read-back page, and the payload's execution signal answered.
The refusal tests keep the four facts apart (nothing offered / gate refused /
inject failed / browser ran and nothing executed) because a report that
collapsed them would be unreadable.

The independence test reuses the browser-verifier file's rule: a candidate
whose proposition already rested on execution must make the check raise, not
quietly produce a finding.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from service.vuln_engine.kernel.evidence import (
    EVIDENCE_EXECUTION,
    EVIDENCE_HYPOTHESIS,
    EVIDENCE_REFLECTION,
    EVIDENCE_SEMANTIC,
    Evidence,
)
from service.vuln_engine.kernel.exchange import RawBrowserRun, RawHttpExchange
from service.vuln_engine.kernel.technique import CONFIRM_STORED_EXECUTE
from service.vuln_engine.kernel.verdict import Candidate
from service.vuln_engine.verification.stored_xss_runner import StoredXssVerifier

READ_BACK = "http://127.0.0.1:8080/comments"
MARKERS = {"xss_stored.raw_html": "window.__ve_xss_raw_html === 1"}
INJECT = {
    "url": "http://127.0.0.1:8080/comment",
    "method": "POST",
    "content": "text=%3Cscript%3E__ve_xss_raw_html%3D1%3Bconfirm%28%27vuln-engine-xss%27%29%3C%2Fscript%3E&sign=1",
    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
}


def _candidate(**overrides) -> Candidate:
    fields = {
        "id": "xss_stored:127.0.0.1:/comment:text",
        "technique": "xss_stored",
        "vuln_class": "xss",
        "surface": {
            "url": "http://127.0.0.1:8080/comment",
            "param": "text",
            "where": "body",
            "host": "127.0.0.1",
            "read_back": READ_BACK,
        },
        "summary": "stored input in 'text' renders in a raw html context on the read-back page",
        "evidence": Evidence(kind="observation.reflection", grade=EVIDENCE_SEMANTIC, payload={}),
        "confirm": {
            "kind": CONFIRM_STORED_EXECUTE,
            "inject": dict(INJECT),
            "read_back": READ_BACK,
            "markers": dict(MARKERS),
            "context": "raw_html",
            "dialog": "vuln-engine-xss",
        },
        "repro_url": READ_BACK,
    }
    fields.update(overrides)
    return Candidate(**fields)  # type: ignore[arg-type]


@dataclass
class ScriptedHttp:
    """An HTTP fake whose answer is decided by the test, field by field."""

    ok: bool = True
    error: str = ""
    calls: list[dict] = field(default_factory=list)

    def perform(
        self,
        url: str,
        *,
        method: str = "GET",
        headers=None,
        content=None,
        params=None,
        at: float = 0.0,
    ) -> RawHttpExchange:
        self.calls.append({"url": url, "method": method, "content": content, "headers": headers})
        if not self.ok:
            # status=None: no response came back at all — the same shape the
            # real transport reports for a timeout or connection failure, and
            # the only one ``ok`` reads as false.
            return RawHttpExchange(
                url=url,
                method=method,
                status=None,
                body=b"",
                headers={},
                error=self.error or "connection refused",
            )
        return RawHttpExchange(
            url=url, method=method, status=200, body=b"stored", headers={"content-type": "text/html"}
        )

    @property
    def capabilities(self):
        class _Capabilities:
            def to_dict(self) -> dict:
                return {"name": "http1", "available": self.ok, "reason": self.error}

        return _Capabilities()


@dataclass
class ScriptedBrowser:
    """A browser whose answer is decided by the test, field by field."""

    markers: dict[str, bool] = field(default_factory=lambda: {key: True for key in MARKERS})
    dialogs: tuple[tuple[str, str], ...] = ()
    ok: bool = True
    error: str = ""
    driver: str = "scripted"
    runs: list[str] = field(default_factory=list)

    def run(self, url: str, *, markers: dict[str, str] | None = None, at: float = 0.0) -> RawBrowserRun:
        self.runs.append(url)
        if not self.ok:
            return RawBrowserRun(url=url, driver=self.driver, ok=False, error=self.error)
        return RawBrowserRun(
            url=url,
            driver=self.driver,
            ok=True,
            status=200,
            dialogs=self.dialogs,
            markers=dict(self.markers),
            mutations=1,
        )

    @property
    def capabilities(self):
        class _Capabilities:
            def to_dict(self) -> dict:
                return {"name": "browser", "available": self.ok, "reason": self.error}

        return _Capabilities()


def _gate(http: ScriptedHttp, browser: ScriptedBrowser):
    from service.recon_pipeline.platform import dispatch, escalation
    from service.recon_pipeline.platform.scope import ScopeEngine
    from service.vuln_engine.policy.gate import PolicyGate
    from service.vuln_engine.world.log import WorldLog

    scope = ScopeEngine(declared_addresses={"127.0.0.1"})
    dispatcher = dispatch.Dispatcher(
        scope,
        policy=dispatch.DispatchPolicy(min_score=40, host_budget=50, run_budget=0),
        escalation=escalation.EscalationPolicy(),
    )
    return PolicyGate(
        dispatcher,
        http=http,
        browser=browser,
        oob=None,
        log=WorldLog(),
        clock=lambda: 1000.0,
    )


def _verifier(http: ScriptedHttp, browser: ScriptedBrowser) -> StoredXssVerifier:
    return StoredXssVerifier(_gate(http, browser))


# --------------------------------------------------------------------------- #
# the accept: the sequence, in order
# --------------------------------------------------------------------------- #


def test_the_inject_goes_through_the_gate_then_the_browser_runs_the_read_back() -> None:
    http, browser = ScriptedHttp(), ScriptedBrowser()
    verdict = _verifier(http, browser).verify(_candidate())
    assert verdict.proven
    assert verdict.grade == EVIDENCE_EXECUTION
    # The sequence, in order: POST first, browser second.
    assert http.calls and http.calls[0]["method"] == "POST"
    assert browser.runs == [READ_BACK]
    assert verdict.evidence is not None
    assert verdict.evidence.payload["context"] == "raw_html"
    assert verdict.evidence.payload["reason"].startswith("stored payload re-injected")


def test_the_inject_body_travels_verbatim_from_the_confirmation_spec() -> None:
    http, browser = ScriptedHttp(), ScriptedBrowser()
    _verifier(http, browser).verify(_candidate())
    # The verifier is a courier for the spec's inject, not a re-builder of it:
    # the payload and its companions reach the wire exactly as the proposer
    # packed them.
    call = http.calls[0]
    assert call["url"] == INJECT["url"]
    # The body stays a str end to end: the confirm spec must survive the log as
    # JSON, and the transport encodes at the wire, not before.
    assert call["content"] == INJECT["content"]
    assert call["headers"] and call["headers"].get("Content-Type") == "application/x-www-form-urlencoded"


def test_a_dialog_of_ours_is_also_execution_evidence() -> None:
    browser = ScriptedBrowser(markers={key: False for key in MARKERS}, dialogs=(("confirm", "vuln-engine-xss"),))
    verdict = _verifier(ScriptedHttp(), browser).verify(_candidate())
    assert verdict.proven
    assert verdict.grade == EVIDENCE_EXECUTION
    assert verdict.evidence is not None
    assert verdict.evidence.payload["dialogs"][0]["message"] == "vuln-engine-xss"


# --------------------------------------------------------------------------- #
# the refusals
# --------------------------------------------------------------------------- #


def test_a_candidate_with_no_confirmation_spec_stays_a_lead() -> None:
    http, browser = ScriptedHttp(), ScriptedBrowser()
    verdict = _verifier(http, browser).verify(_candidate(confirm={}))
    assert not verdict.proven
    assert "no stored-execution confirmation" in verdict.reason
    assert http.calls == [] and browser.runs == []


def test_a_spec_with_no_read_back_or_marker_is_refused() -> None:
    verdict = _verifier(ScriptedHttp(), ScriptedBrowser()).verify(
        _candidate(confirm={"kind": CONFIRM_STORED_EXECUTE, "inject": dict(INJECT)})
    )
    assert not verdict.proven
    assert "no inject, no read-back page, or no marker" in verdict.reason


def test_an_inject_the_gate_refused_is_inconclusive_not_refuted() -> None:
    # No http transport wired: the gate refuses before anything is sent, and
    # the reason says so rather than pretending the target refused.
    gate = _gate(None, ScriptedBrowser())
    verdict = StoredXssVerifier(gate).verify(_candidate())
    assert not verdict.proven
    assert "not allowed" in verdict.reason
    assert gate.log.events("gate.decision")


def test_a_failed_inject_says_so_and_learns_nothing() -> None:
    http, browser = ScriptedHttp(ok=False, error="connection reset"), ScriptedBrowser()
    verdict = _verifier(http, browser).verify(_candidate())
    assert not verdict.proven
    assert "confirmation inject failed" in verdict.reason
    assert "connection reset" in verdict.reason
    # The browser never ran: with nothing stored, there is nothing to read back.
    assert browser.runs == []


def test_a_browser_that_ran_and_ran_nothing_refutes() -> None:
    http, browser = ScriptedHttp(), ScriptedBrowser(markers={key: False for key in MARKERS})
    verdict = _verifier(http, browser).verify(_candidate())
    assert not verdict.proven
    assert verdict.reason.startswith("the payload's script did not execute")


# --------------------------------------------------------------------------- #
# the independence check
# --------------------------------------------------------------------------- #


def test_a_candidate_already_resting_on_execution_makes_the_check_raise() -> None:
    broken = _candidate(
        evidence=Evidence(kind="observation.script_execution", grade=EVIDENCE_EXECUTION, payload={})
    )
    with pytest.raises(ValueError, match="reuses the proposer's evidence class"):
        _verifier(ScriptedHttp(), ScriptedBrowser()).verify(broken)


def test_a_reflection_grade_proposer_is_the_common_case() -> None:
    verdict = _verifier(ScriptedHttp(), ScriptedBrowser()).verify(
        _candidate(evidence=Evidence(kind="observation.reflection", grade=EVIDENCE_REFLECTION, payload={}))
    )
    assert verdict.proven
    assert verdict.proposer_grade == EVIDENCE_REFLECTION


def test_a_hypothesis_grade_proposer_still_produces_a_finding() -> None:
    verdict = _verifier(ScriptedHttp(), ScriptedBrowser()).verify(
        _candidate(evidence=Evidence(kind="observation.http", grade=EVIDENCE_HYPOTHESIS, payload={}))
    )
    assert verdict.proven
    assert verdict.grade == EVIDENCE_EXECUTION
