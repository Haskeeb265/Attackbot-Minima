"""The deterministic abducer: composition rules over known predicates.

PRD §6.5, implementation 1. No model. A retained anomaly is a *typed deviation*
— a predicate that was expected to hold and did not — and the abducer answers it
with a composition of predicates the plan table already speaks. The rules are a
small closed table; each reads the deviation's expected predicate and, when it
recognises the cell, emits the plan row that would *test* the explanation.

Two honest consequences, both intended:

* **it can only produce expressible claims.** Every proposal is a row of the
  plan table, so nothing here can invent a claim the engine cannot speak. The
  interesting no-verifier case is the state-change composition, whose row is
  speakable but not yet provable — that is what the holding pen is for.
* **it plateaus at L2.** Compositions of known primitives are, by NOVELTY.md
  §3, novelty level 2. This is the control arm the LLM channel (Phase 7) is
  measured against, not the primary novelty source.

The abducer is pure: same anomaly and surfaces in, same proposals out. It reads
no clock and does no I/O, so replaying a run re-derives the same explanations.
"""

from __future__ import annotations

from collections.abc import Sequence

from ..kernel.anomaly import Anomaly
from ..kernel.claim import CLAIM_OBJECT_READ, CLAIM_STATE_CHANGE
from ..kernel.technique import Surface
from .proposal import Proposal

#: The technique whose plan table these rules compose over. A single name today;
#: a richer capability ontology would make this a lookup, not a constant.
GENERIC_DIFFERENTIAL = "generic_differential"

#: The confirm kind the object-read row already has.
CONFIRM_AUTHORIZATION_DIFFERENTIAL = "authorization.differential"
#: The confirm kind a state-change claim needs — the verifier that re-executes
#: the setup rather than merely re-measuring the read. It used to name an
#: aspirational spelling (``state_change.replay``) because no such verifier
#: existed and the claim rode to the holding pen; the kind landed as
#: ``authorization.state_change``, so the proposal names a verifier that runs.
CONFIRM_STATE_CHANGE_REPLAY = "authorization.state_change"

#: Rule names, so a reviewer can see why a proposal exists.
RULE_OBJECT_READ = "object_read_boundary_unexplained"
RULE_ROLE_COMPOSITION = "role_composition_victim_read_unexplained"
#: The rule stamped on a proposal the LLM abduction/property channel produced.
RULE_LLM_ABDUCTION = "llm_abduction"

#: The predicate suffixes each rule answers.
OBJECT_READ_SUFFIX = ":other_read"
VICTIM_READ_SUFFIX = ":victim_read_session_b"


def _surface_for_arm(arm: str, surfaces: Sequence[Surface]) -> Surface | None:
    """Recover the surface an arm names (``technique@surface.key``)."""
    _, _, key = arm.partition("@")
    for surface in surfaces:
        if surface.key == key:
            return surface
    return None


def _proposal(plan, *, rule: str, needs_verifier: str, witness: str) -> Proposal:
    return Proposal(
        id=f"abduced:{rule}:{plan.plan_id}",
        technique=GENERIC_DIFFERENTIAL,
        vuln_class=plan.vuln_class,
        claim_shape=plan.claim_shape,
        summary=plan.summary,
        rule=rule,
        witness=witness,
        needs_verifier=needs_verifier,
        plan=plan.to_dict(),
    )


def proposal_for(
    *,
    surface: Surface,
    surfaces: Sequence[Surface],
    claim_shape: str,
    witness: str,
    vuln_class: str = "",
    summary: str = "",
    rule: str = RULE_LLM_ABDUCTION,
) -> Proposal | None:
    """Turn a validated (surface, claim shape) into a Proposal with a real plan.

    The LLM channel chooses *where* to look; this function supplies the
    experiment from the same plan table the deterministic abducer composes, so a
    model-proposed claim is still an ordinary plan row — nothing the engine
    cannot speak, and nothing the verifier has not seen before.
    """
    from ..techniques.generic_differential.plan import (
        ROLE_TARGET,
        ROLE_VICTIM,
        object_read_plans,
        session_role_plans,
    )

    plan = None
    if claim_shape == CLAIM_OBJECT_READ:
        plans = object_read_plans([surface])
        plan = plans[0] if plans else None
        needs_verifier = CONFIRM_AUTHORIZATION_DIFFERENTIAL
    elif claim_shape == CLAIM_STATE_CHANGE:
        targets = [s for s in surfaces if ROLE_TARGET in s.label and s.param]
        victims = [s for s in surfaces if ROLE_VICTIM in s.label and s.param]
        for candidate in session_role_plans(targets, victims):
            if candidate.actor.url == surface.url or candidate.target.url == surface.url:
                plan = candidate
                break
        needs_verifier = CONFIRM_STATE_CHANGE_REPLAY
    else:
        return None
    if plan is None:
        return None
    if vuln_class and vuln_class != plan.vuln_class:
        # A model that names the class it believes it found must have that name
        # reach the finding: the plan otherwise stamps its own canonical class
        # (``object-access``), and a novel class (L4) would be silently renamed
        # away. The *experiment* is still the plan table's; only the class label
        # is the model's. The verifier proves the measurement regardless.
        from dataclasses import replace

        plan = replace(plan, vuln_class=vuln_class)
    return Proposal(
        id=f"abduced:{rule}:{plan.plan_id}",
        technique=GENERIC_DIFFERENTIAL,
        vuln_class=plan.vuln_class,
        claim_shape=claim_shape,
        summary=summary or plan.summary,
        rule=rule,
        witness=witness,
        needs_verifier=needs_verifier,
        plan=plan.to_dict(),
    )


def abduce(anomaly: Anomaly, surfaces: Sequence[Surface]) -> list[Proposal]:
    """Explain a retained anomaly with rows of the plan table.

    Returns proposals in a deterministic order (the plan builders' order), each
    naming the rule that produced it and the anomaly that witnessed it.

    Deliberately memory-free (H1): the cross-engagement anomaly distillate
    (``memory/anomaly.py``) is advisory input to the *loop*, not to this
    function — every proposal one anomaly yields shares the anomaly's predicate
    family, so a per-call corroboration rank would be uniform and could reorder
    nothing. The distillate's measurable influence on what gets proposed lives
    where proposals from different anomalies compete: the hypothesis pool's
    ranking (``scheduler/pool.py``), which the driver feeds via the memory
    module's ``corroborated`` helper, and the LLM junction's prompt, which gets
    the cells via the ``memory`` parameter that was already plumbed and is now
    wired (H1).
    """
    from ..techniques.generic_differential.plan import (
        ROLE_TARGET,
        ROLE_VICTIM,
        object_read_plans,
        session_role_plans,
    )

    if anomaly.technique != GENERIC_DIFFERENTIAL:
        return []
    expected = anomaly.deviation.get("expected") or {}
    suffix = str(expected.get("probe_suffix", ""))
    proposals: list[Proposal] = []

    if suffix == OBJECT_READ_SUFFIX:
        surface = _surface_for_arm(anomaly.arm, surfaces)
        if surface is not None:
            for plan in object_read_plans([surface]):
                proposals.append(
                    _proposal(
                        plan,
                        rule=RULE_OBJECT_READ,
                        needs_verifier=CONFIRM_AUTHORIZATION_DIFFERENTIAL,
                        witness=anomaly.key,
                    )
                )
    elif suffix == VICTIM_READ_SUFFIX:
        targets = [s for s in surfaces if ROLE_TARGET in s.label and s.param]
        victims = [s for s in surfaces if ROLE_VICTIM in s.label and s.param]
        for plan in session_role_plans(targets, victims):
            proposals.append(
                _proposal(
                    plan,
                    rule=RULE_ROLE_COMPOSITION,
                    needs_verifier=CONFIRM_STATE_CHANGE_REPLAY,
                    witness=anomaly.key,
                )
            )
    return proposals


__all__ = [
    "CONFIRM_AUTHORIZATION_DIFFERENTIAL",
    "CONFIRM_STATE_CHANGE_REPLAY",
    "GENERIC_DIFFERENTIAL",
    "OBJECT_READ_SUFFIX",
    "RULE_LLM_ABDUCTION",
    "RULE_OBJECT_READ",
    "RULE_ROLE_COMPOSITION",
    "VICTIM_READ_SUFFIX",
    "abduce",
    "proposal_for",
]
