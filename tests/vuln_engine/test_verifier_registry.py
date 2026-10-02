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


def test_the_registry_names_the_cap_that_stops_state_change() -> None:
    authorization = registry()["authorization.differential"]
    assert authorization.claim_shapes == frozenset(DIFFERENTIAL_PROVABLE)
    # The cap's premise, as data: it re-measures, it does not re-execute.
    assert authorization.re_executes_setup is False
    assert by_name()["browser"].re_executes_setup is True


def test_the_validator_vocabulary_comes_from_the_registry() -> None:
    assert Validator().provable == provable_claim_shapes()
    assert verifier_vocabulary() == frozenset(DIFFERENTIAL_PROVABLE)


def test_a_new_confirm_kind_is_the_only_lever_that_frees_a_claim() -> None:
    proposal = Proposal(
        id="p1",
        technique="generic_differential",
        vuln_class="method-confusion",
        claim_shape="state_change",
        summary="the change at T reaches V",
        rule="role_composition_victim_read_unexplained",
        witness="w",
        needs_verifier="state_change.replay",
    )
    assert Validator().validate(proposal).verdict != EXPRESSIBLE_NOW
    # Landing a verifier that re-executes the setup is exactly this change: the
    # registry gains the shape. Nothing else in the abducer needs to move.
    freed = Validator(provable=frozenset(DIFFERENTIAL_PROVABLE | {"state_change"}))
    assert freed.validate(proposal).verdict == EXPRESSIBLE_NOW


def test_every_registry_entry_is_well_formed() -> None:
    for kind in VERIFIER_KINDS:
        assert kind.name and kind.confirm_kind and kind.measurement
        assert kind.independent
