"""The independence check, which is the single most important assertion in the engine.

``check_independence`` is eight lines, and it is the check that stops the closed
false-positive loop every automated scanner has. So the tests are written as the
two ways it must refuse, and the one way it must pass — plus the shape of a
refusal, because "not proven" has to be a first-class answer rather than an
exception.
"""

from __future__ import annotations

import pytest

from service.vuln_engine.kernel.evidence import (
    EVIDENCE_EXECUTION,
    EVIDENCE_HYPOTHESIS,
    EVIDENCE_OOB,
    EVIDENCE_REFLECTION,
    EVIDENCE_SEMANTIC,
    Evidence,
)
from service.vuln_engine.kernel.verdict import Candidate, Verdict, refuse


def _evidence(grade: str) -> Evidence:
    return Evidence(kind="observation.script_execution", grade=grade, payload={"marker": "m"})


def test_a_verdict_that_reuses_the_proposer_class_raises() -> None:
    with pytest.raises(ValueError, match="reuses the proposer's evidence class"):
        Verdict.check_independence(EVIDENCE_REFLECTION, _evidence(EVIDENCE_REFLECTION))


def test_a_verdict_on_a_non_finding_grade_raises() -> None:
    # A different class is not enough: it also has to be strong enough.
    with pytest.raises(ValueError, match="cannot support a finding"):
        Verdict.check_independence(EVIDENCE_HYPOTHESIS, _evidence(EVIDENCE_SEMANTIC))


def test_a_different_finding_class_passes() -> None:
    Verdict.check_independence(EVIDENCE_SEMANTIC, _evidence(EVIDENCE_EXECUTION))
    Verdict.check_independence(EVIDENCE_REFLECTION, _evidence(EVIDENCE_OOB))


def test_candidate_carries_the_proposer_grade_and_nothing_stronger() -> None:
    candidate = Candidate(
        id="xss_reflected:host:/search:q",
        technique="xss_reflected",
        vuln_class="xss",
        evidence=_evidence(EVIDENCE_SEMANTIC),
    )
    assert candidate.proposer_grade == EVIDENCE_SEMANTIC
    assert candidate.to_dict()["proposer_grade"] == EVIDENCE_SEMANTIC


def test_a_candidate_without_evidence_is_only_a_hypothesis() -> None:
    candidate = Candidate(id="c", technique="t", vuln_class="xss")
    assert candidate.proposer_grade == EVIDENCE_HYPOTHESIS


def test_a_refusal_has_no_grade_and_says_why() -> None:
    candidate = Candidate(id="c", technique="t", vuln_class="xss", evidence=_evidence(EVIDENCE_REFLECTION))
    verdict = refuse(candidate, "the payload's script did not execute")
    assert not verdict.proven
    assert verdict.grade == ""
    assert verdict.reason == "the payload's script did not execute"
    assert verdict.to_dict() == {
        "candidate": "c",
        "proven": False,
        "proposer_grade": EVIDENCE_REFLECTION,
        "reason": "the payload's script did not execute",
    }


def test_a_proven_verdict_reports_the_grade_it_rests_on() -> None:
    candidate = Candidate(id="c", technique="t", vuln_class="xss", evidence=_evidence(EVIDENCE_REFLECTION))
    Verdict.check_independence(candidate.proposer_grade, _evidence(EVIDENCE_EXECUTION))
    verdict = Verdict(
        candidate_id="c",
        proven=True,
        evidence=_evidence(EVIDENCE_EXECUTION),
        proposer_grade=candidate.proposer_grade,
    )
    assert verdict.grade == EVIDENCE_EXECUTION
    assert verdict.to_dict()["grade"] == EVIDENCE_EXECUTION
