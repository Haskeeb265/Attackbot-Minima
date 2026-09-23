"""The evidence contract, and the rejections that matter more than the accepts.

A test suite for a dataclass tends to test that it holds values. The tests that
matter here are the ones that assert it *refuses*: an unknown grade, a text blob
where typed fields belong, a hypothesis pretending to be a finding. They matter
because every one of them is a path by which a lead could become a finding — the
failure this whole engine is built to prevent.
"""

from __future__ import annotations

import pytest

from service.vuln_engine.kernel.evidence import (
    EVIDENCE_EXECUTION,
    EVIDENCE_HYPOTHESIS,
    EVIDENCE_OOB,
    EVIDENCE_ORDER,
    EVIDENCE_REFLECTION,
    Evidence,
    FINDING_GRADES,
    is_evidence_class,
    weaker_than,
)


def test_a_finding_rests_only_on_the_three_strong_classes() -> None:
    assert FINDING_GRADES == {EVIDENCE_EXECUTION, EVIDENCE_OOB, "differential"}
    assert EVIDENCE_HYPOTHESIS not in FINDING_GRADES
    assert EVIDENCE_REFLECTION not in FINDING_GRADES


def test_sufficient_for_finding_is_a_property_of_the_class_not_the_payload() -> None:
    reflection = Evidence(kind="observation.reflection", grade=EVIDENCE_REFLECTION)
    execution = Evidence(kind="observation.script_execution", grade=EVIDENCE_EXECUTION)
    assert not reflection.sufficient_for_finding
    assert execution.sufficient_for_finding


def test_an_unknown_grade_is_rejected_at_construction() -> None:
    with pytest.raises(ValueError, match="unknown evidence grade"):
        Evidence(kind="observation.reflection", grade="probably-fine")


def test_a_text_blob_payload_is_rejected() -> None:
    # The invariant, at the smallest possible scale: a string payload cannot be
    # reasoned over, remembered, or verified.
    with pytest.raises(TypeError, match="dict of typed fields"):
        Evidence(kind="observation.http", grade=EVIDENCE_REFLECTION, payload="200 OK")  # type: ignore[arg-type]


def test_payload_is_copied_not_aliased_in_to_dict() -> None:
    payload = {"context": "raw_html"}
    evidence = Evidence(kind="observation.reflection", grade=EVIDENCE_REFLECTION, payload=payload)
    payload["context"] = "tampered"
    assert evidence.to_dict()["payload"] == {"context": "raw_html"}


def test_order_is_weakest_to_strongest_and_unknown_sorts_weakest() -> None:
    assert EVIDENCE_ORDER[0] == EVIDENCE_HYPOTHESIS
    assert weaker_than(EVIDENCE_REFLECTION, EVIDENCE_EXECUTION)
    assert not weaker_than(EVIDENCE_OOB, EVIDENCE_EXECUTION)
    # An unrecognised class must never outrank a known one in a comparison.
    assert weaker_than("something-new", EVIDENCE_HYPOTHESIS)


def test_class_membership() -> None:
    assert is_evidence_class(EVIDENCE_OOB)
    assert not is_evidence_class("")
    assert not is_evidence_class("OOB")


def test_to_dict_round_trips_the_fields_the_log_needs() -> None:
    evidence = Evidence(
        kind="observation.reflection",
        grade=EVIDENCE_REFLECTION,
        payload={"context": "double_quoted_attribute"},
        at=1760000000.1234,
        probe="xss_reflected:canary",
    )
    row = evidence.to_dict()
    assert row == {
        "kind": "observation.reflection",
        "grade": "reflection",
        "payload": {"context": "double_quoted_attribute"},
        "at": 1760000000.123,
        "probe": "xss_reflected:canary",
    }
