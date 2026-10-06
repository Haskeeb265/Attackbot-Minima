"""Claim shapes: the plan declares what kind of claim it makes, the verifier
refuses to prove at differential what its measurement cannot prove.

The spike's scar, pinned as invariants (NOVELTY.md §7.2, kernel/claim.py):

* an ``object_read`` claim is exactly what a flipped two-session re-measure
  proves — it passes;
* a ``state_change`` claim ("the change at T reaches V") is provable by the
  setup-re-executing confirm kind (``authorization.state_change``) — and is
  refused *here* with the misroute reason, because a flipped two-session
  re-measure proves only the read, never the change;
* a shape nobody speaks is refused, not squinted at;
* legacy specs with no shape (the hand-written techniques, which predate
  shapes and prove exactly what the verifier measures) are grandfathered.
"""

from __future__ import annotations

import pytest

from service.vuln_engine.kernel import claim
from service.vuln_engine.kernel.claim import STATE_CHANGE_MISROUTE_REASON
from service.vuln_engine.kernel.evidence import EVIDENCE_HYPOTHESIS, Evidence
from service.vuln_engine.kernel.observation import OBS_HTTP_RESPONSE
from service.vuln_engine.kernel.verdict import Candidate
from service.vuln_engine.policy.gate import PolicyGate
from service.vuln_engine.techniques.generic_differential.plan import (
    BehaviorPlan,
    DifferentialPlan,
    validate_plan,
)
from service.vuln_engine.verification.authorization_verifier import (
    AuthorizationVerifier,
)
from service.vuln_engine.world.log import WorldLog

from tests.vuln_engine.test_generic_differential import _broken_authz_responder


def _candidate(claim_shape: str) -> Candidate:
    """A candidate whose confirm spec names *claim_shape* — everything else
    is the exact shape the generic plans emit (a valid URL, the right oracle)."""
    return Candidate(
        id="gd:test",
        technique="generic_differential",
        vuln_class="object-access",
        surface={"url": "http://127.0.0.1:8080/api/invoices/4821"},
        summary="the object reads across the boundary",
        evidence=Evidence(
            kind=OBS_HTTP_RESPONSE,
            grade=EVIDENCE_HYPOTHESIS,
            probe="gd:test",
            payload={"actor_status": 200, "target_status": 200},
        ),
        confirm={
            "kind": "authorization.differential",
            "url": "http://127.0.0.1:8080/api/invoices/4821",
            "param": "4821",
            "oracle": "two_sessions_one_object",
            "probe": "gd:test",
            "claim_shape": claim_shape,
        },
    )


@pytest.fixture
def gate(
    made_dispatcher, fake_http, fake_browser, fake_collaborator, clock
) -> PolicyGate:
    """A gate whose target answers 200 to both sessions: the routing rule is
    the only thing standing between this verifier's verdict and a proven
    finding for a shape its measurement cannot prove."""
    fake_http.respond = _broken_authz_responder
    return PolicyGate(
        made_dispatcher(),
        http=fake_http,
        browser=fake_browser,
        oob=fake_collaborator,
        log=WorldLog(),
        clock=clock,
        session_b_headers={"Cookie": "session=9f8e7d6c5b4a"},
    )


def test_an_object_read_claim_is_provable_at_differential(gate) -> None:
    """The shape the verifier's measurement actually proves: confirmed."""
    verdict = AuthorizationVerifier(gate).verify(_candidate(claim.CLAIM_OBJECT_READ))
    assert verdict.proven
    assert verdict.grade == "differential"


def test_a_state_change_claim_is_refused_with_the_misroute_reason(gate) -> None:
    """Routing, not a cap: the shape is provable today — by the
    setup-re-executing verifier — but *this* verifier re-measures the read and
    never the change, so a state_change spec routed here is refused, and the
    refusal names the verifier that does prove it."""
    verdict = AuthorizationVerifier(gate).verify(_candidate(claim.CLAIM_STATE_CHANGE))
    assert not verdict.proven
    assert verdict.evidence is None, "a refusal carries no verifier evidence"
    assert STATE_CHANGE_MISROUTE_REASON in verdict.reason


def test_an_unspeakable_claim_shape_is_refused_not_squinted_at(gate) -> None:
    verdict = AuthorizationVerifier(gate).verify(_candidate("privilege_thing"))
    assert not verdict.proven
    assert "claim_shape" in verdict.reason


def test_a_legacy_spec_without_a_shape_is_grandfathered(gate) -> None:
    """The hand-written techniques predate shapes; their specs carry none and
    prove exactly what this verifier measures. They keep verifying."""
    candidate = _candidate(claim.CLAIM_OBJECT_READ)
    confirm = dict(candidate.confirm)
    confirm.pop("claim_shape")
    legacy = Candidate(
        id=candidate.id,
        technique=candidate.technique,
        vuln_class=candidate.vuln_class,
        surface=candidate.surface,
        summary=candidate.summary,
        evidence=candidate.evidence,
        confirm=confirm,
    )
    verdict = AuthorizationVerifier(gate).verify(legacy)
    assert verdict.proven


def test_state_change_is_provable_now_the_setup_reexecuting_kind_exists() -> None:
    """The cap lifted by *landing a verifier*, not by editing callers: the
    setup-re-executing confirm kind (``authorization.state_change``) proves the
    shape, so it joins DIFFERENTIAL_PROVABLE — one place, no technique edits,
    exactly as the PRD's Phase 0 deliverable promised."""
    assert claim.DIFFERENTIAL_PROVABLE == frozenset(
        {claim.CLAIM_OBJECT_READ, claim.CLAIM_STATE_CHANGE}
    )
    assert claim.is_differential_provable(claim.CLAIM_STATE_CHANGE)
    assert claim.CLAIM_STATE_CHANGE in claim.CLAIM_SHAPES


# --------------------------------------------------------------------------- #
# the plan table refuses shapeless rows
# --------------------------------------------------------------------------- #


def test_a_plan_without_a_claim_shape_is_refused() -> None:
    actor = BehaviorPlan(name="a", url="http://h/x")
    target = BehaviorPlan(name="b", url="http://h/x", requires_session_b=True)
    plan = DifferentialPlan(
        plan_id="p", vuln_class="c", summary="s", actor=actor, target=target
    )
    problems = validate_plan(plan)
    assert any("claim_shape" in problem for problem in problems)


def test_a_plan_with_an_unknown_claim_shape_is_refused() -> None:
    actor = BehaviorPlan(name="a", url="http://h/x")
    target = BehaviorPlan(name="b", url="http://h/x", requires_session_b=True)
    plan = DifferentialPlan(
        plan_id="p",
        vuln_class="c",
        summary="s",
        actor=actor,
        target=target,
        claim_shape="privilege_thing",
    )
    problems = validate_plan(plan)
    assert any("not one the engine speaks" in problem for problem in problems)


def test_both_table_sources_declare_their_shape() -> None:
    """The table's rows carry shapes, so the validator's rule has nothing to
    refuse in what actually ships."""
    class _Surface:
        url = "http://h/x"
        key = "x"
        param = "x"

    from service.vuln_engine.techniques.generic_differential.plan import (
        object_read_plans,
        session_role_plans,
    )

    for plan in object_read_plans([_Surface()]):
        assert validate_plan(plan) == []
        assert plan.claim_shape == claim.CLAIM_OBJECT_READ
    for plan in session_role_plans([_Surface()], [_Surface()]):
        assert validate_plan(plan) == []
        assert plan.claim_shape == claim.CLAIM_STATE_CHANGE
