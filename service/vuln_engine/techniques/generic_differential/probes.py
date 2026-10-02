"""The probes: one spec per plan request, carrying the plan as data.

A probe's ``detail`` is exactly what the gate forwards to the transport, so a
plan request becomes a probe by *being* the detail: the URL, the method, and —
for the session-B half — the ``_session: "b"`` marker the gate's shim already
speaks. No request-construction logic exists here beyond the copy.

Two structural details the driver's contract forces, both worth knowing:

* the driver sorts specs by id (determinism), so the experiment's order —
  actor's state change lands, *then* the target's read — is baked into the
  id as a step number, not left to list order;
* the plan does **not** ride the probe detail: the gate forwards detail keys
  straight to the transport (``perform(**detail)``), so anything but a
  transport kwarg there is a TypeError on the wire. The plan rides the
  *hypothesis* (``PLAN_ATTR``), where interpret reads it — the data-not-code
  move survives, and the log's whitelist stays untouched.
"""

from __future__ import annotations

from ...kernel.technique import KIND_HTTP, PURPOSE_PROPOSE, Hypothesis, ProbeSpec
from .plan import DifferentialPlan

#: Where the plan lives on a hypothesis. ``Hypothesis`` is a frozen dataclass,
#: so the adapter attaches it with ``object.__setattr__`` under this name.
PLAN_ATTR = "_plan"

_NOISE = {
    "requests_per_surface": 2,
    "burstiness": 0.6,
    "fingerprint_distance": 0.6,
    "requires_browser": False,
}


def plan_of(hypothesis: Hypothesis) -> DifferentialPlan | None:
    """The plan a hypothesis carries, or ``None`` when it carries none."""
    return getattr(hypothesis, PLAN_ATTR, None)


def probes(hypothesis: Hypothesis) -> list[ProbeSpec]:
    """The plan's two requests, in experiment order: actor (step 1), target (step 2)."""
    plan = plan_of(hypothesis)
    if plan is None:
        return []
    return [
        _spec(hypothesis, plan, plan.actor, step=1),
        _spec(hypothesis, plan, plan.target, step=2),
    ]


def _spec(
    hypothesis: Hypothesis, plan: DifferentialPlan, behavior, *, step: int
) -> ProbeSpec:
    _ = plan  # the predicates travel on the hypothesis, not the wire
    detail: dict = {"url": behavior.url, "method": behavior.method}
    if behavior.requires_session_b:
        detail["_session"] = "b"
    return ProbeSpec(
        id=f"{hypothesis.id}:{step}:{behavior.name}",
        kind=KIND_HTTP,
        host=hypothesis.surface.host,
        detail=detail,
        oracle="status_differential",
        noise=dict(_NOISE),
        produces="response",
        purpose=PURPOSE_PROPOSE,
        payload="",
    )


__all__ = ["PLAN_ATTR", "plan_of", "probes"]
