"""The browser verifier: what it accepts, and the four ways it refuses.

Each refusal is a different fact about the world, and the tests keep them apart
because a report that collapsed them would be unreadable:

* the proposer offered nothing to confirm with → a lead, by design;
* the confirmation was not allowed by the gate → nothing was learned about the
  target, so it is inconclusive;
* the browser could not run → also inconclusive;
* the browser ran and nothing executed → **refuted**, which is the strongest and
  most useful answer of the four.

The last test in the file is the one that keeps the verifier honest: a candidate
whose proposition already rested on the execution class must make the independence
check *raise*, not quietly produce a finding.

(Named ``test_browser_verifier`` rather than ``test_browser`` so pytest's default
import mode does not confuse it with the *transport* test of the same basename.)
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
from service.vuln_engine.kernel.exchange import RawBrowserRun
from service.vuln_engine.kernel.verdict import Candidate
from service.vuln_engine.verification.browser_runner import BrowserVerifier

URL = "http://127.0.0.1:8080/search?q=%22%3E%3Cscript%3E__ve_xss%3D1%3C%2Fscript%3E"
MARKERS = {"xss_reflected.double_quoted_attribute": "window.__ve_xss_double_quoted_attribute === 1"}


def _candidate(**overrides) -> Candidate:
    fields = {
        "id": "xss_reflected:127.0.0.1:/search:q",
        "technique": "xss_reflected",
        "vuln_class": "xss",
        "surface": {"url": "http://127.0.0.1:8080/search", "param": "q"},
        "summary": "parameter 'q' is reflected inside a double quoted attribute context",
        "evidence": Evidence(kind="observation.reflection", grade=EVIDENCE_SEMANTIC, payload={}),
        "confirm": {
            "kind": "browser.run",
            "url": URL,
            "markers": MARKERS,
            "context": "double_quoted_attribute",
            "dialog": "vuln-engine-xss",
        },
        "repro_url": URL,
    }
    fields.update(overrides)
    return Candidate(**fields)  # type: ignore[arg-type]


@dataclass
class ScriptedBrowser:
    """A browser whose answer is decided by the test, field by field."""

    markers: dict[str, bool] = field(default_factory=lambda: {"xss_reflected.double_quoted_attribute": True})
    dialogs: tuple[tuple[str, str], ...] = ()
    ok: bool = True
    error: str = ""
    driver: str = "scripted"
    runs: list[str] = field(default_factory=list)

    def run(self, url: str, *, markers: dict[str, str] | None = None, at: float = 0.0) -> RawBrowserRun:
        self.runs.append(url)
        if not self.ok:
            # A browser that did not run answers nothing — it does not answer yes.
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


def _verifier(build_gate, browser: ScriptedBrowser) -> BrowserVerifier:
    return BrowserVerifier(build_gate(browser=browser))


# --------------------------------------------------------------------------- #
# the accept
# --------------------------------------------------------------------------- #


def test_a_marker_that_answered_true_is_a_finding(build_gate) -> None:
    browser = ScriptedBrowser()
    verdict = _verifier(build_gate, browser).verify(_candidate())
    assert verdict.proven
    assert verdict.grade == EVIDENCE_EXECUTION
    assert verdict.proposer_grade == EVIDENCE_SEMANTIC
    assert browser.runs == [URL]
    assert verdict.evidence is not None
    assert verdict.evidence.payload["markers"] == {"xss_reflected.double_quoted_attribute": True}
    assert verdict.evidence.payload["context"] == "double_quoted_attribute"


def test_a_dialog_of_ours_is_also_execution_evidence(build_gate) -> None:
    # Two independent execution signals: a marker can fail to be reported and a
    # dialog cannot open unless the script ran.
    browser = ScriptedBrowser(markers={"xss_reflected.double_quoted_attribute": False}, dialogs=(("confirm", "vuln-engine-xss"),))
    verdict = _verifier(build_gate, browser).verify(_candidate())
    assert verdict.proven
    assert verdict.grade == EVIDENCE_EXECUTION
    assert verdict.evidence is not None
    assert verdict.evidence.payload["dialogs"][0]["message"] == "vuln-engine-xss"


def test_a_dialog_that_is_not_ours_is_not_proof(build_gate) -> None:
    browser = ScriptedBrowser(
        markers={"xss_reflected.double_quoted_attribute": False},
        dialogs=(("confirm", "Are you sure?"),),
    )
    verdict = _verifier(build_gate, browser).verify(_candidate())
    assert not verdict.proven
    assert "did not execute" in verdict.reason


def test_the_browser_run_goes_through_the_gate(build_gate) -> None:
    gate = build_gate(browser=ScriptedBrowser())
    BrowserVerifier(gate).verify(_candidate())
    # A verifier that could skip the gate would be the one component able to touch
    # a target without a clearance.
    assert [row["verb"] for row in gate.log.events("gate.decision")] == ["ALLOW"]
    assert gate.log.events("effect.result")


# --------------------------------------------------------------------------- #
# the four refusals
# --------------------------------------------------------------------------- #


def test_a_candidate_with_no_confirmation_spec_stays_a_lead(build_gate) -> None:
    browser = ScriptedBrowser()
    verdict = _verifier(build_gate, browser).verify(_candidate(confirm={}))
    assert not verdict.proven
    assert "no browser confirmation" in verdict.reason
    assert browser.runs == []


def test_a_confirmation_spec_with_no_markers_is_refused(build_gate) -> None:
    verdict = _verifier(build_gate, ScriptedBrowser()).verify(_candidate(confirm={"kind": "browser.run", "url": URL}))
    assert not verdict.proven
    assert "no marker" in verdict.reason


def test_a_confirmation_the_gate_refused_is_inconclusive(build_gate) -> None:
    # No browser transport wired: the gate refuses before anything is sent, and the
    # reason says so rather than pretending the target refused.
    gate = build_gate(browser=None)
    verdict = BrowserVerifier(gate).verify(_candidate())
    assert not verdict.proven
    assert "not allowed (DENY" in verdict.reason


def test_a_browser_that_could_not_run_says_why(build_gate) -> None:
    browser = ScriptedBrowser(ok=False, error="chrome did not expose a DevTools target in time")
    gate = build_gate(browser=browser)
    verdict = BrowserVerifier(gate).verify(_candidate())
    assert not verdict.proven
    assert verdict.grade == ""
    assert "the browser run failed" in verdict.reason
    assert "DevTools" in verdict.reason
    # And the failed run is still recorded: an inconclusive attempt is evidence
    # about the engine, even when it is not evidence about the target.
    assert any(row["reason"] for row in gate.log.events("gate.decision"))


def test_a_browser_that_ran_and_ran_nothing_refutes(build_gate) -> None:
    browser = ScriptedBrowser(markers={"xss_reflected.double_quoted_attribute": False})
    verdict = _verifier(build_gate, browser).verify(_candidate())
    assert not verdict.proven
    assert verdict.reason.startswith("the payload's script did not execute")


# --------------------------------------------------------------------------- #
# the independence check
# --------------------------------------------------------------------------- #


def test_a_candidate_already_resting_on_execution_makes_the_check_raise(build_gate) -> None:
    # A broken technique would produce this, and the correct answer is an exception
    # rather than a finding: silently downgrading it to a lead would hide the bug.
    broken = _candidate(
        evidence=Evidence(kind="observation.script_execution", grade=EVIDENCE_EXECUTION, payload={})
    )
    with pytest.raises(ValueError, match="reuses the proposer's evidence class"):
        _verifier(build_gate, ScriptedBrowser()).verify(broken)


def test_a_hypothesis_grade_proposer_still_produces_a_finding(build_gate) -> None:
    # The weakest possible proposer class is still a different class.
    verdict = _verifier(build_gate, ScriptedBrowser()).verify(
        _candidate(evidence=Evidence(kind="observation.http", grade=EVIDENCE_HYPOTHESIS, payload={}))
    )
    assert verdict.proven
    assert verdict.grade == EVIDENCE_EXECUTION


def test_a_reflection_grade_proposer_is_the_common_case(build_gate) -> None:
    verdict = _verifier(build_gate, ScriptedBrowser()).verify(
        _candidate(evidence=Evidence(kind="observation.reflection", grade=EVIDENCE_REFLECTION, payload={}))
    )
    assert verdict.proven
    assert verdict.proposer_grade == EVIDENCE_REFLECTION
