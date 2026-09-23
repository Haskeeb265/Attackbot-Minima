"""The OOB verifier: an interaction either arrived or it did not.

There is no threshold anywhere in this file, and that is the point. A blind class
verified by timing would need one, and a threshold is a place for a false positive
to hide. Here the answers are: the record is there (finding), it is not there
(refuted), or our own listener could not be read (inconclusive) — and the third one
must never be reported as the second.
"""

from __future__ import annotations

import pytest

from service.vuln_engine.kernel.evidence import (
    EVIDENCE_OOB,
    EVIDENCE_REFLECTION,
    EVIDENCE_SEMANTIC,
    Evidence,
)
from service.vuln_engine.kernel.verdict import Candidate
from service.vuln_engine.verification.oob_verifier import OobVerifier

PROBE = "oob_fetch:127.0.0.1:url"


def _candidate(**overrides) -> Candidate:
    fields = {
        "id": "oob_fetch:127.0.0.1:/fetch:url",
        "technique": "oob_fetch",
        "vuln_class": "ssrf",
        "surface": {"url": "http://127.0.0.1:8080/fetch", "param": "url"},
        "summary": "the response contained our collaborator's answer",
        "evidence": Evidence(kind="observation.reflection", grade=EVIDENCE_REFLECTION, payload={}),
        "confirm": {
            "kind": "oob.read",
            "probe": PROBE,
            "path": f"/oob/{PROBE}",
            "token": f"vuln-engine-collaborator:{PROBE}",
        },
    }
    fields.update(overrides)
    return Candidate(**fields)  # type: ignore[arg-type]


def test_an_interaction_on_the_expected_path_is_a_finding(build_gate, fake_collaborator) -> None:
    verdict = OobVerifier(build_gate()).verify(_candidate())
    assert verdict.proven
    assert verdict.grade == EVIDENCE_OOB
    assert verdict.proposer_grade == EVIDENCE_REFLECTION
    assert verdict.evidence is not None
    assert verdict.evidence.payload["path"] == f"/oob/{PROBE}"
    assert verdict.evidence.payload["interactions"] == 1
    assert fake_collaborator.reads == [PROBE]


def test_no_interaction_is_a_refutation_with_the_claim_named(build_gate, fake_collaborator) -> None:
    fake_collaborator.arrives = False
    verdict = OobVerifier(build_gate()).verify(_candidate())
    assert not verdict.proven
    assert verdict.grade == ""
    assert "no interaction arrived" in verdict.reason
    assert "our own listener" in verdict.reason


def test_an_unreadable_collaborator_is_inconclusive_rather_than_refuted(build_gate) -> None:
    # If our own listener cannot be read, nothing at all is known about the target.
    weak = _candidate()
    gate = build_gate(oob=None)
    verdict = OobVerifier(gate).verify(weak)
    assert not verdict.proven
    assert "no OOB collaborator is wired" in verdict.reason


def test_a_candidate_with_no_oob_confirmation_spec_stays_a_lead(build_gate, fake_collaborator) -> None:
    verdict = OobVerifier(build_gate()).verify(_candidate(confirm={}))
    assert not verdict.proven
    assert "out-of-band confirmation" in verdict.reason
    assert fake_collaborator.reads == []


def test_the_verifier_does_not_ask_the_target_again(build_gate, fake_http) -> None:
    # Confirming a blind fetch must not mean re-fetching: the evidence is our own
    # listener's record, and asking the target twice would be a second loud action.
    OobVerifier(build_gate()).verify(_candidate())
    assert fake_http.calls == []


def test_the_lookup_is_recorded_as_an_internal_effect(build_gate) -> None:
    gate = build_gate()
    OobVerifier(gate).verify(_candidate())
    rows = [row for row in gate.log.events("effect.internal") if row["kind"] == "oob.read"]
    assert rows and rows[0]["probe"] == PROBE
    assert rows[0]["interactions"] == 1


def test_a_proposer_already_on_the_oob_class_makes_the_check_raise(build_gate) -> None:
    broken = _candidate(evidence=Evidence(kind="observation.oob", grade=EVIDENCE_OOB, payload={}))
    with pytest.raises(ValueError, match="reuses the proposer's evidence class"):
        OobVerifier(build_gate()).verify(broken)


def test_a_semantic_proposer_is_confirmed_by_the_interaction(build_gate) -> None:
    verdict = OobVerifier(build_gate()).verify(
        _candidate(evidence=Evidence(kind="observation.reflection", grade=EVIDENCE_SEMANTIC, payload={}))
    )
    assert verdict.proven
    assert verdict.proposer_grade == EVIDENCE_SEMANTIC
