"""The plan table: a hypothesis as data, not code.

This module is the spike's point. A **plan** is one pair of requests and the
predicate pair that makes the pair mean something:

* ``actor`` — the request the *client* controls, with the behavior the plan
  expects of it (``expected_status``: which statuses count as "did the thing");
* ``target`` — the request the plan compares against, with ``denies_status``:
  the statuses that would mean "the boundary held".

The comparison is fixed code in ``interpret`` — statuses in, boolean out,
honesty rules applied — because the comparison is not where the vuln-class
knowledge lives. The knowledge is the *predicates*, and the predicates are
rows here. This is the minimal answer to "what would a kernel ``plan.py``
look like": a frozen dataclass, a validator that refuses unspeakable plans,
and a table whose entries are the classes.

The session-role composition (`method_role`) is the spike's one step beyond
per-class claims: two surfaces compose into one hypothesis purely because
their *declared roles* differ — no shared class string, no shared param, no
shared claim. That is the mechanism the capability-ontology work would build
on; one row pair demonstrates it end to end through the ordinary driver.
"""

from __future__ import annotations

from dataclasses import dataclass

from ...kernel import claim
from ...kernel.prediction import Expectation, ExpectedObservation

#: Role markers a surface's ``label`` may carry for session-role composition.
#: Declared by the operator (they are part of the surface's protocol), never
#: inferred from paths or parameters.
ROLE_TARGET = "method_role=target"
ROLE_VICTIM = "method_role=victim"

#: Status buckets, the same spellings the IDOR technique and its verifier use.
ALLOWED = frozenset(range(200, 300))
DENIED = frozenset({301, 302, 303, 307, 308, 401, 403, 404})


@dataclass(frozen=True)
class BehaviorPlan:
    """One request of a differential pair, as data.

    ``requires_session_b`` marks the request that must run under the gate's
    session-B shim; the verifier's flipped re-measure does the same for its
    own requests, which is what makes the confirmation independent.
    """

    name: str
    #: The exact URL to request — the operator's surface, verbatim. A plan
    #: that mutates the URL is testing a different engagement.
    url: str
    #: ``GET`` for this spike's rows; a field, not a constant, so the table
    #: stays a table.
    method: str = "GET"
    #: Statuses that mean "this request did the thing" (for the actor) or
    #: "the boundary held" (for the target).
    expected_status: frozenset[int] = ALLOWED
    #: Statuses that mean the opposite, honestly.
    denies_status: frozenset[int] = DENIED
    #: Run under the second declared session.
    requires_session_b: bool = False

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "url": self.url,
            "method": self.method,
            "expected_status": sorted(self.expected_status),
            "denies_status": sorted(self.denies_status),
            "requires_session_b": self.requires_session_b,
        }


@dataclass(frozen=True)
class DifferentialPlan:
    """A vuln class as a row pair: actor behavior vs target behavior.

    ``vuln_class`` is free here — deliberately. The registry's six classes
    exist because someone wrote a folder; a plan's class exists because
    someone wrote a row. ``summary`` is the claim, spelled by the plan author
    (operator or, later, a validated junction answer), not by interpret().

    ``claim_shape`` is what *kind* of claim the pair makes — the spike's own
    scar, answered in data (kernel/claim.py, NOVELTY.md §7.2): an
    ``object_read`` plan's claim is exactly what a flipped two-session
    re-measure proves, while a ``state_change`` plan's claim ("the change at
    T reaches V") is weaker than what the verifier can prove today, so the
    verifier refuses it instead of scoring the weaker proof at
    ``differential``. The row declares its shape; nothing infers it.
    """

    plan_id: str
    vuln_class: str
    summary: str
    actor: BehaviorPlan
    target: BehaviorPlan
    claim_shape: str = ""
    #: The declared surface's parameter and location, carried so a finding's
    #: ``surface`` is the operator's own declaration (a real param), not the
    #: plan's id. A candidate keyed by plan id cannot be joined against ground
    #: truth or a scheduler arm; empty falls back to the plan id.
    param: str = ""
    where: str = "query"
    #: What "nothing is broken" looks like, as falsifiable predicates over the
    #: plan's own probes (kernel/prediction.py). When the measurements come
    #: back clean but violate this, the driver retains the deviation as an
    #: anomaly — the material the abductive loop consumes. Optional: a row
    #: without one can only settle, never come back unexplained.
    expectation: Expectation | None = None

    def to_dict(self) -> dict:
        data: dict = {
            "plan_id": self.plan_id,
            "vuln_class": self.vuln_class,
            "summary": self.summary,
            "claim_shape": self.claim_shape,
            "param": self.param,
            "where": self.where,
            "actor": self.actor.to_dict(),
            "target": self.target.to_dict(),
        }
        if self.expectation is not None:
            data["expectation"] = self.expectation.to_dict()
        return data


def validate_plan(plan: DifferentialPlan) -> list[str]:
    """The plan's unspeakable answers, before anything is sent.

    A plan whose predicates allow everything, or whose actor IS its target,
    is not a differential — it is noise with a name. Refused here, loudly,
    the way a manifest missing postconditions is refused at discovery.
    """
    problems: list[str] = []
    if not plan.plan_id or not plan.vuln_class:
        problems.append("plan lacks an id or a vuln_class")
    if not plan.claim_shape:
        problems.append(
            "plan declares no claim_shape: the verifier must know what kind of "
            "claim it is being asked to prove (kernel/claim.py)"
        )
    elif plan.claim_shape not in claim.CLAIM_SHAPES:
        problems.append(
            f"plan's claim_shape {plan.claim_shape!r} is not one the engine "
            f"speaks: {', '.join(claim.CLAIM_SHAPES)}"
        )
    if plan.actor.expected_status & plan.actor.denies_status:
        problems.append("actor's expected and denied statuses overlap")
    if not plan.actor.expected_status:
        problems.append("actor's expected_status is empty")
    if plan.target.expected_status and plan.target.expected_status & plan.target.denies_status:
        problems.append("target's expected and denied statuses overlap")
    if plan.actor.url == plan.target.url and (
        plan.actor.requires_session_b == plan.target.requires_session_b
        and plan.actor.method == plan.target.method
    ):
        problems.append(
            "actor and target are the same request: nothing differs, so the "
            "comparison would prove nothing"
        )
    return problems


def behavior_from_dict(data: dict) -> "BehaviorPlan":
    """Rebuild one behavior from its serialized row (``to_dict``'s inverse)."""
    expected = data.get("expected_status")
    denies = data.get("denies_status")
    return BehaviorPlan(
        name=str(data.get("name", "")),
        url=str(data.get("url", "")),
        method=str(data.get("method", "GET")),
        expected_status=frozenset(expected) if expected else ALLOWED,
        denies_status=frozenset(denies) if denies else DENIED,
        requires_session_b=bool(data.get("requires_session_b", False)),
    )


def expectation_from_dict(data: dict) -> "Expectation | None":
    """Rebuild an expectation from its serialized row, or ``None`` when empty."""
    expected: list[ExpectedObservation] = []
    for item in data.get("expected") or []:
        try:
            expected.append(
                ExpectedObservation(
                    probe_suffix=str(item.get("probe_suffix", "")),
                    field=str(item.get("field", "")),
                    within=frozenset(item.get("within") or ()),
                    kind=str(item.get("kind", "observation.http")),
                )
            )
        except (AttributeError, TypeError, ValueError):
            continue
    if not expected:
        return None
    return Expectation(description=str(data.get("description", "")), expected=tuple(expected))


def plan_from_dict(data: dict) -> "DifferentialPlan | None":
    """Rebuild a plan from its serialized row, or ``None`` when unusable.

    The inverse of :meth:`DifferentialPlan.to_dict`, and the door the abduced
    round comes through: an abducer emits a *plan row as data*, the log holds it,
    and this is where it becomes a plan again. A row missing a half is refused
    rather than half-built — the same loudness ``validate_plan`` applies.
    """
    try:
        actor = behavior_from_dict(data["actor"])
        target = behavior_from_dict(data["target"])
    except (KeyError, TypeError, AttributeError):
        return None
    expectation = None
    raw_expectation = data.get("expectation")
    if isinstance(raw_expectation, dict):
        expectation = expectation_from_dict(raw_expectation)
    return DifferentialPlan(
        plan_id=str(data.get("plan_id", "")),
        vuln_class=str(data.get("vuln_class", "")),
        summary=str(data.get("summary", "")),
        actor=actor,
        target=target,
        claim_shape=str(data.get("claim_shape", "")),
        param=str(data.get("param", "")),
        where=str(data.get("where", "query") or "query"),
        expectation=expectation,
    )


def session_role_plans(
    targets: list, victims: list
) -> list[DifferentialPlan]:
    """Compose role-declared surfaces into state-change differential plans.

    A target surface (``method_role=target``) is the request that *does*
    something; a victim surface (``method_role=victim``) names the resource
    the doing should not touch. The hypothesis is the *relationship*: if the
    state change reaches the victim's resource, session B will answer the
    victim URL differently after the actor ran than the boundary intends.

    The probe order encodes the experiment: baseline the victim, run the
    actor's state change under session B, re-read the victim. The verifier's
    flipped re-measure of the victim under both sessions is what separates a
    finding from a one-off pair — the existing verifier, unchanged.

    ``targets`` and ``victims`` are ``Surface`` objects; typed loosely here to
    keep this module importable from the plan table alone.
    """
    plans: list[DifferentialPlan] = []
    for target in targets:
        for victim in victims:
            plans.append(
                DifferentialPlan(
                    plan_id=f"method_confusion:{target.key}->{victim.key}",
                    vuln_class="method-confusion",
                    summary=(
                        f"the state change at {target.url} may reach the resource "
                        f"at {victim.url}: after the change, session B's read of "
                        "the victim differs from the boundary the roles declare"
                    ),
                    claim_shape=claim.CLAIM_STATE_CHANGE,
                    param=getattr(target, "param", ""),
                    where=getattr(target, "where", "query") or "query",
                    expectation=Expectation(
                        description=(
                            "the boundary holds: session B's read of the victim "
                            "resource stays denied, whatever the state change did"
                        ),
                        expected=(
                            ExpectedObservation(
                                probe_suffix=":victim_read_session_b",
                                field="status",
                                within=DENIED,
                            ),
                        ),
                    ),
                    actor=BehaviorPlan(
                        name="actor_state_change",
                        url=target.url,
                        method="GET",
                    ),
                    target=BehaviorPlan(
                        name="victim_read_session_b",
                        url=victim.url,
                        method="GET",
                        requires_session_b=True,
                    ),
                )
            )
    return plans


def object_read_plans(surfaces: list) -> list[DifferentialPlan]:
    """The classic two-session object read, as a plan row instead of a module.

    One surface, the operator's declared object URL. Actor: session A reads
    it and must succeed (otherwise there is no boundary here to violate).
    Target: session B reads it and must be denied. This is
    ``idor_differential``'s experiment expressed as data — the spike's
    apples-to-apples comparison against a hand-written technique, firing on
    the same surface declaration IDOR does.
    """
    plans: list[DifferentialPlan] = []
    for surface in surfaces:
        plans.append(
            DifferentialPlan(
                plan_id=f"object_read:{surface.key}",
                vuln_class="object-access",
                summary=(
                    f"the object at {surface.url} is readable under the "
                    "low-privilege session, which must not be able to read it"
                ),
                claim_shape=claim.CLAIM_OBJECT_READ,
                param=getattr(surface, "param", ""),
                where=getattr(surface, "where", "query") or "query",
                expectation=Expectation(
                    description=(
                        "the boundary holds: the low-privilege session is denied "
                        "the object the owner reads"
                    ),
                    expected=(
                        ExpectedObservation(
                            probe_suffix=":other_read",
                            field="status",
                            within=DENIED,
                        ),
                    ),
                ),
                actor=BehaviorPlan(name="owner_read", url=surface.url, method="GET"),
                target=BehaviorPlan(
                    name="other_read",
                    url=surface.url,
                    method="GET",
                    requires_session_b=True,
                ),
            )
        )
    return plans


__all__ = [
    "ALLOWED",
    "DENIED",
    "ROLE_TARGET",
    "ROLE_VICTIM",
    "BehaviorPlan",
    "DifferentialPlan",
    "object_read_plans",
    "plan_from_dict",
    "session_role_plans",
    "validate_plan",
]
