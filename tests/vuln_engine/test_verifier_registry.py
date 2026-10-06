"""Phase 6: the verifier vocabulary registry is the single expressibility lever.

PRD §6.10 + A4: confirm kinds are first-class records with the claim shapes they
prove, the registry cannot drift from the dispatcher, and the abductive
validator's vocabulary comes from it — so adding a confirm kind is a code change
in one place.
"""

from __future__ import annotations

from service.vuln_engine.abduction.proposal import EXPRESSIBLE_NOW, Proposal
from service.vuln_engine.abduction.validator import Validator, verifier_vocabulary
from service.vuln_engine.kernel.claim import DIFFERENTIAL_PROVABLE
from service.vuln_engine.verification import CONFIRM_VERIFIERS
from service.vuln_engine.verification.registry import (
    VERIFIER_KINDS,
    by_name,
    check_alignment,
    provable_claim_shapes,
    registry,
)


def test_the_registry_covers_every_dispatched_kind() -> None:
    assert check_alignment(CONFIRM_VERIFIERS) == []
    assert set(registry()) == set(CONFIRM_VERIFIERS)


def test_the_registry_names_which_verifier_proves_which_shape() -> None:
    # The flipped two-session read: re-measures, never re-executes, so it
    # proves exactly the object_read shape.
    authorization = registry()["authorization.differential"]
    assert authorization.claim_shapes == frozenset({"object_read"})
    assert authorization.re_executes_setup is False
    # The setup-re-executing verifier that lifted the state_change cap: it
    # runs the change fresh between two unchanged victim reads.
    state_change = registry()["authorization.state_change"]
    assert state_change.claim_shapes == frozenset({"state_change"})
    assert state_change.re_executes_setup is True
    assert by_name()["browser"].re_executes_setup is True


def test_the_validator_vocabulary_comes_from_the_registry() -> None:
    assert Validator().provable == provable_claim_shapes()
    assert verifier_vocabulary() == frozenset(DIFFERENTIAL_PROVABLE)


def test_a_new_confirm_kind_is_the_only_lever_that_frees_a_claim() -> None:
    # The state_change claim *was* the held case; landing the
    # setup-re-executing verifier freed it through the registry, with nothing
    # else in the abducer moving.
    proposal = Proposal(
        id="p1",
        technique="generic_differential",
        vuln_class="method-confusion",
        claim_shape="state_change",
        summary="the change at T reaches V",
        rule="role_composition_victim_read_unexplained",
        witness="w",
        needs_verifier="authorization.state_change",
    )
    assert Validator().validate(proposal).verdict == EXPRESSIBLE_NOW
    # A shape no landed verifier proves is still held: the next claim class
    # waits for exactly the same one-place change this one got.
    unlanded = Proposal(
        id="p2",
        technique="generic_differential",
        vuln_class="method-confusion",
        claim_shape="lateral_move",
        summary="the change at T moves state sideways",
        rule="role_composition_victim_read_unexplained",
        witness="w",
        needs_verifier="lateral_move.replay",
    )
    assert Validator().validate(unlanded).verdict != EXPRESSIBLE_NOW


def test_every_registry_entry_is_well_formed() -> None:
    for kind in VERIFIER_KINDS:
        assert kind.name and kind.confirm_kind and kind.measurement
        assert kind.independent
