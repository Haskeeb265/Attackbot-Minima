"""The interpretation: the one piece of fixed code, and the honesty rules.

The plan spells the predicates; this module runs them. It is deliberately the
same shape for every plan row — that is the spike's claim: the vuln-class
knowledge lives in the row, and the comparison is class-independent code.

The honesty rules, in the order the code applies them:

* a missing measurement proposes nothing — an incomplete experiment is not a
  comparison;
* the actor must have *succeeded* (its ``expected_status``) — an actor that
  was denied leaves no privilege to violate, the same rule the IDOR
  interpreter applies to session A;
* the target must have *succeeded* too — the plan's claim is that the
  boundary the predicates declare is absent, and only a success on the
  denied side shows that;
* anything ambiguous (a 5xx, a transport zero) proposes nothing — a
  measurement problem is not an authorization fact.

The candidate's confirmation spec depends on the plan's own claim shape. An
``object_read`` plan asks for ``authorization.differential`` — the existing
verifier, unchanged: the flipped two-session re-measure of the target URL is
exactly the claim. A ``state_change`` plan asks for
``authorization.state_change`` — the setup-re-executing verifier: the claim is
"the change at T reaches V", so the spec carries the change itself (the actor
URL and method) for the verifier to execute fresh, between two unchanged
victim reads under session B. The proposer's own actor run is *its* experiment;
what travels on the spec is what to execute, never a conclusion.
"""

from __future__ import annotations

from ...kernel import claim
from ...kernel.evidence import EVIDENCE_HYPOTHESIS, Evidence
from ...kernel.observation import OBS_HTTP_RESPONSE, Observation
from ...kernel.technique import Hypothesis
from ...kernel.verdict import Candidate
from . import probes as probe_mod
from .manifest import NAME


def _status_for(observations: list[Observation], probe_suffix: str) -> int | None:
    """The status the named request observed, or ``None``."""
    for item in observations:
        if item.kind != OBS_HTTP_RESPONSE:
            continue
        if str(item.probe or "").endswith(probe_suffix):
            status = item.payload.get("status")
            try:
                return int(status)  # type: ignore[arg-type]
            except (TypeError, ValueError):
                return None
    return None


def candidates(hypothesis: Hypothesis, observations: list[Observation]) -> list[Candidate]:
    plan = probe_mod.plan_of(hypothesis)
    if plan is None:
        return []
    # The plan declares what kind of claim its pair makes; the confirm spec
    # carries it so the verifier knows what it is being asked to prove. A
    # plan-row default keeps hand-built rows working while the validator
    # refuses shapeless rows going forward.
    claim_shape = plan.claim_shape or claim.CLAIM_OBJECT_READ
    actor_status = _status_for(observations, f":{plan.actor.name}")
    target_status = _status_for(observations, f":{plan.target.name}")
    if actor_status is None or target_status is None:
        return []  # a missing measurement is not a comparison

    if actor_status not in plan.actor.expected_status:
        # The actor was denied (or answered outside the plan's expectation):
        # no privilege demonstrated, nothing to violate. Silence — the honest
        # zero, the same answer the expected claim's success gets.
        return []
    if target_status not in plan.actor.expected_status:
        # The target did not answer like the actor: the boundary held. This is
        # the *expected* answer for every well-configured target — silence.
        return []

    evidence = Evidence(
        kind=OBS_HTTP_RESPONSE,
        grade=EVIDENCE_HYPOTHESIS,
        probe=hypothesis.id,
        payload={
            "plan_id": plan.plan_id,
            "vuln_class": plan.vuln_class,
            "actor_status": actor_status,
            "target_status": target_status,
            "actor_url": plan.actor.url,
            "target_url": plan.target.url,
            "claim": plan.summary,
            "reason": (
                "both requests in the plan's pair answered success; the plan's "
                "predicates declare the second must have been denied"
            ),
        },
    )
    return [
        Candidate(
            id=f"{NAME}:{plan.plan_id}",
            technique=NAME,
            vuln_class=plan.vuln_class,
            surface={
                "url": plan.target.url,
                "param": hypothesis.surface.param,
                "where": hypothesis.surface.where,
                "host": hypothesis.surface.host,
            },
            summary=(
                f"{plan.summary} (actor {plan.actor.name} answered {actor_status}, "
                f"target {plan.target.name} answered {target_status})"
            ),
            evidence=evidence,
            confirm=(
                {
                    "kind": "authorization.state_change",
                    "probe": hypothesis.id,
                    "claim_shape": claim_shape,
                    # The change travels as *what to execute*: the actor's URL
                    # and method, for the verifier to run fresh as session A
                    # between its own unchanged victim reads. The victim URL is
                    # what the before/after reads measure.
                    "actor": {
                        "url": plan.actor.url,
                        "method": plan.actor.method,
                    },
                    "victim_url": plan.target.url,
                }
                if claim_shape == claim.CLAIM_STATE_CHANGE
                else {
                    "kind": "authorization.differential",
                    "url": plan.target.url,
                    "param": hypothesis.surface.param,
                    "oracle": "two_sessions_one_object",
                    "probe": hypothesis.id,
                    # The claim's shape travels on the spec (NOVELTY.md §7.2):
                    # the verifier refuses to prove a shape its measurement
                    # does not license, instead of scoring the weaker proof.
                    "claim_shape": claim_shape,
                }
            ),
            payload="",
            repro_url=plan.target.url,
        )
    ]


#: The name the driver and the tests use for this function. Same alias as the
#: sibling techniques', for the same reason.
interpret = candidates


__all__ = ["candidates", "interpret"]
