"""The state-change verifier: the claim \"the change at T reaches V\", proven fresh.

A flipped two-session read observes V and never executes T — proving \"B can
read V\" would score the weaker, often-legitimate claim at the strongest grade
(the scar NOVELTY.md §7.2 exists to prevent). This verifier answers the claim
*as stated*: two unchanged victim reads, the change executed fresh as session
A, one victim read after. Pinned here, over a scripted transport:

* the proven path — a change that moves the victim's read across stable
  before-reads, with the hashes on the evidence;
* the honesty refusals — drifting background state (inconclusive), a change
  that moves nothing (not proven), a transport that never answered
  (inconclusive), each with its named reason and nothing dispatched twice;
* the routing guards — a candidate without this verifier's confirm kind, or
  with a different claim shape, is refused with the reason that says which
  verifier does prove it.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from service.vuln_engine.kernel.claim import CLAIM_OBJECT_READ, CLAIM_STATE_CHANGE
from service.vuln_engine.kernel.evidence import EVIDENCE_DIFFERENTIAL, EVIDENCE_REFLECTION, Evidence
from service.vuln_engine.kernel.exchange import RawHttpExchange
from service.vuln_engine.kernel.observation import OBS_HTTP_RESPONSE
from service.vuln_engine.kernel.verdict import Candidate
from service.vuln_engine.verification import VerificationLayer
from service.vuln_engine.verification.state_change_verifier import (
    CONFIRM_KIND,
    StateChangeVerifier,
)
from service.vuln_engine.world.log import WorldLog
from tests.vuln_engine.conftest import FakeHttpEffect

ACTOR_URL = "http://127.0.0.1:8080/api/promote"
VICTIM_URL = "http://127.0.0.1:8080/api/role"


def _confirm() -> dict:
    return {
        "kind": CONFIRM_KIND,
        "claim_shape": CLAIM_STATE_CHANGE,
        "actor": {"url": ACTOR_URL, "method": "POST"},
        "victim_url": VICTIM_URL,
        "probe": "state-change-spec",
    }


def _candidate(confirm: dict | None = None) -> Candidate:
    return Candidate(
        id="generic_differential:127.0.0.1:/api/role:role",
        technique="generic_differential",
        vuln_class="object-access",
        surface={
            "url": VICTIM_URL,
            "host": "127.0.0.1",
            "param": "role",
            "where": "query",
        },
        summary="the change at T reaches V",
        evidence=Evidence(
            kind=OBS_HTTP_RESPONSE,
            grade=EVIDENCE_REFLECTION,
            probe="p",
            at=1.0,
            payload={},
        ),
        confirm=_confirm() if confirm is None else confirm,
    )


#: The victim identity the claim reads under — what ``--session-b-cookie``
#: wires on a real run. The measurement tests pass it to ``build_gate``; the
#: refusal test omits it to pin the up-front refusal.
SESSION_B = {"Cookie": "sid=victim-b"}


def _app(state: dict, *, victim_reads: list[bytes] | None = None):
    """A scripted target with one toggleable fact.

    ``GET /api/role`` answers with the current fact; ``POST /api/promote`` flips
    it (or not, when ``state["moves"]`` is False). ``victim_reads`` overrides the
    reads with a scripted sequence — the drift control's test needs two
    unchanged reads to disagree.
    """
    reads = list(victim_reads or [])

    def respond(url: str) -> RawHttpExchange:
        if url == ACTOR_URL:
            if state["moves"]:
                state["promoted"] = True
            return RawHttpExchange(url=url, status=200, body=b"ok", headers={})
        if url == VICTIM_URL:
            if reads:
                body = reads.pop(0)
            else:
                body = b"role=admin" if state["promoted"] else b"role=guest"
            return RawHttpExchange(url=url, status=200, body=body, headers={})
        return RawHttpExchange(url=url, status=404, body=b"nope", headers={})

    return respond


# --------------------------------------------------------------------------- #
# the proven path
# --------------------------------------------------------------------------- #


def test_a_change_that_reaches_the_victim_is_proven_fresh(build_gate, clock) -> None:
    state = {"moves": True, "promoted": False}
    http = FakeHttpEffect(respond=_app(state))
    gate = build_gate(http=http, log=WorldLog(), session_b_headers=SESSION_B)
    verifier = StateChangeVerifier(gate)

    verdict = verifier.verify(_candidate())

    assert verdict.proven
    assert verdict.evidence is not None
    assert verdict.evidence.grade == EVIDENCE_DIFFERENTIAL
    payload = verdict.evidence.payload
    assert payload["oracle"] == "state_change_reaches_victim"
    # The order is the verifier's own: two unchanged before-reads, the change
    # executed fresh, one read after — and all of it went through the gate.
    assert payload["pre_stable"] is True
    assert payload["changed"] is True
    assert payload["actor_status"] == 200
    assert payload["pre_body_hash"] != payload["post_body_hash"]
    assert payload["pre_body_hash"] == payload["pre_repeat_body_hash"]
    paths = {urlsplit(u).path for u in http.calls}
    assert "/api/promote" in paths and "/api/role" in paths
    assert "the change at T reaches V" in verdict.reason


def test_the_verifier_measures_through_the_gate_and_nothing_else(build_gate, clock) -> None:
    state = {"moves": True, "promoted": False}
    log = WorldLog()
    gate = build_gate(http=FakeHttpEffect(respond=_app(state)), log=log, session_b_headers=SESSION_B)
    assert StateChangeVerifier(gate).verify(_candidate()).proven
    rows = [row for row in log.events("gate.decision") if row.get("verb") == "ALLOW"]
    assert rows, "every measurement rides the ordinary policy gate"
    assert all(row["technique"] == "state_change_verifier" for row in rows)
    assert {row["probe"].split(":")[-1] for row in rows} == {"pre", "pre_repeat", "change", "post"}


# --------------------------------------------------------------------------- #
# the honesty refusals
# --------------------------------------------------------------------------- #


def test_drifting_background_state_is_inconclusive_not_refuted(build_gate, clock) -> None:
    state = {"moves": True, "promoted": False}
    gate = build_gate(
        http=FakeHttpEffect(
            respond=_app(state, victim_reads=[b"role=guest v1", b"role=guest v2"])
        ),
        session_b_headers=SESSION_B,
    )
    verdict = StateChangeVerifier(gate).verify(_candidate())

    assert not verdict.proven
    assert "moved between two unchanged reads" in verdict.reason


def test_a_change_that_moves_nothing_is_not_proven(build_gate, clock) -> None:
    state = {"moves": False, "promoted": False}
    gate = build_gate(http=FakeHttpEffect(respond=_app(state)), session_b_headers=SESSION_B)
    verdict = StateChangeVerifier(gate).verify(_candidate())

    assert not verdict.proven
    assert "did not move the victim's read" in verdict.reason
    assert "could not be reproduced fresh" in verdict.reason


def test_a_victim_that_never_answers_is_inconclusive(build_gate, clock) -> None:
    state = {"moves": True, "promoted": False}

    def dead_victim(url: str) -> RawHttpExchange:
        if url == VICTIM_URL:
            return RawHttpExchange(url=url, error="ConnectError: refused", transport="http1")
        return _app(state)(url)

    gate = build_gate(http=FakeHttpEffect(respond=dead_victim), session_b_headers=SESSION_B)
    verdict = StateChangeVerifier(gate).verify(_candidate())

    assert not verdict.proven
    assert "before-measurement failed" in verdict.reason


# --------------------------------------------------------------------------- #
# the routing guards
# --------------------------------------------------------------------------- #


def test_a_candidate_without_this_verifiers_kind_is_refused(build_gate, clock) -> None:
    gate = build_gate()
    misrouted = dict(_confirm(), kind="authorization.differential")
    verdict = StateChangeVerifier(gate).verify(_candidate(misrouted))

    assert not verdict.proven
    assert "no state-change confirmation" in verdict.reason


def test_a_different_claim_shape_is_refused_by_name(build_gate, clock) -> None:
    gate = build_gate()
    wrong_shape = dict(_confirm(), claim_shape=CLAIM_OBJECT_READ)
    verdict = StateChangeVerifier(gate).verify(_candidate(wrong_shape))

    assert not verdict.proven
    assert CLAIM_OBJECT_READ in verdict.reason
    assert "re-executes changes" in verdict.reason


def test_a_run_without_a_second_session_is_refused_before_any_request(
    build_gate, clock, fake_http
) -> None:
    """The victim's view is session B by the claim's own semantics. With no
    second session wired, the gate would deny every read — so the verifier
    refuses up front, names the operator's fix, and spends nothing."""
    gate = build_gate()  # no session_b_headers: what a default run looks like
    verdict = StateChangeVerifier(gate).verify(_candidate())

    assert not verdict.proven
    assert "no second session" in verdict.reason
    assert "--session-b-cookie" in verdict.reason
    assert fake_http.calls == []


def test_a_spec_missing_its_actor_or_victim_is_refused(build_gate, clock) -> None:
    gate = build_gate()
    victim_only = {k: v for k, v in _confirm().items() if k != "actor"}
    assert "no actor change" in StateChangeVerifier(gate).verify(_candidate(victim_only)).reason

    actor_only = {k: v for k, v in _confirm().items() if k != "victim_url"}
    assert "no victim URL" in StateChangeVerifier(gate).verify(_candidate(actor_only)).reason


# --------------------------------------------------------------------------- #
# the layer: the planner gate runs before any measurement
# --------------------------------------------------------------------------- #


def test_the_layer_refuses_a_foreign_spec_before_the_verifier_runs(
    build_gate, clock, fake_http
) -> None:
    log = WorldLog()
    gate = build_gate(log=log)
    foreign = dict(_confirm(), victim_url="http://other.test/api/role")

    verdict = VerificationLayer(gate).verify(_candidate(foreign))

    assert not verdict.proven
    assert "other.test" in verdict.reason
    assert fake_http.calls == [], "a refused spec must cost no measurement"


def test_the_layer_dispatches_a_state_change_spec_to_this_verifier(
    build_gate, clock
) -> None:
    state = {"moves": True, "promoted": False}
    gate = build_gate(http=FakeHttpEffect(respond=_app(state)), log=WorldLog(), session_b_headers=SESSION_B)
    verdict = VerificationLayer(gate).verify(_candidate())
    assert verdict.proven
    assert verdict.evidence.grade == EVIDENCE_DIFFERENTIAL
