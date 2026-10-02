"""The hypotheses: one per plan row, spelled by the row.

The hand-written techniques each spell one claim in code; this module spells
none. It maps plan rows to ``Hypothesis`` objects — the claim text, the class,
and the identity of the experiment all come from the row — and attaches the
plan to the hypothesis (``probes.PLAN_ATTR``), which is how the row's
predicates reach probes and interpret without a second copy.

Two plan sources, both data:

* the object-read row — the classic two-session read, fires per eligible
  surface;
* the session-role composition — fires when two surfaces declare opposite
  ``method_role=`` labels: one changes state, one reads it. One surface is
  not enough by design: a relationship with one side is not a hypothesis.
"""

from __future__ import annotations

from ...kernel.technique import (
    CAP_ACCESS_DIFFERS_BY_SESSION,
    CAP_PUBLIC_PARAM,
    EngagementSeed,
    Hypothesis,
    Surface,
)
from . import probes as probe_mod
from .eligibility import plan_table_capabilities
from .plan import ROLE_TARGET, ROLE_VICTIM, object_read_plans, session_role_plans, validate_plan
from .manifest import NAME


def _host_of(url: str) -> str:
    from urllib.parse import urlsplit

    return (urlsplit(url).hostname or "").lower()


def _hypothesis_for(plan) -> Hypothesis:
    """One plan row -> one hypothesis, plan attached.

    The hypothesis hangs on the plan's *actor* URL (the request the client
    controls); the target's URL travels inside the plan data on the probes,
    so nothing is lost — the id carries both halves.
    """
    hyp = Hypothesis(
        id=f"{NAME}:{plan.plan_id}",
        technique=NAME,
        surface=Surface(
            url=plan.actor.url,
            host=_host_of(plan.actor.url),
            # The operator's own param where the plan carries one (so a finding's
            # surface joins against ground truth and scheduler arms); the plan id
            # is a last resort, never the ordinary case.
            param=plan.param or plan.plan_id,
            where=plan.where or "query",
            capability=CAP_PUBLIC_PARAM,
            label=f"plan:{plan.plan_id}",
        ),
        claim=plan.summary,
        rests_on=plan.vuln_class,
        preconditions=(CAP_PUBLIC_PARAM, "two declared sessions"),
        # The row's prediction travels with the hypothesis: the driver runs it
        # after the probes, and a clean measurement that violates it is the
        # third outcome — an anomaly retained (kernel/prediction.py).
        expectation=plan.expectation,
        # The plan itself is serialized onto the hypothesis (PRD §6.11), so the
        # world log explains the experiment rather than only replaying it.
        plan=plan.to_dict(),
    )
    object.__setattr__(hyp, probe_mod.PLAN_ATTR, plan)
    return hyp


def hypothesis_for_plan(plan) -> Hypothesis:
    """One plan row -> one runnable hypothesis.

    The abduced round's entry: the driver materializes an expressible proposal
    through the technique's own hook, and the technique builds the hypothesis
    from the row the plan table would have built anyway. Same construction, same
    experiment — provenance is the only difference (the proposal that asked for
    it, recorded by the driver).
    """
    return _hypothesis_for(plan)


#: The seed shape this module needs — the kernel's own seed, imported
#: directly: the technique modules import the kernel, never the reverse, so
#: there is no cycle, and typing it honestly keeps mypy honest too.
EngagementSeedLike = EngagementSeed


def hypotheses_for_seed(seed: EngagementSeedLike) -> list[Hypothesis]:
    """Every plan the seed admits, as hypotheses — the technique's real entry.

    Invalid plans are dropped loudly (a log line through ``validate``), the
    same discipline the registry applies to a bad manifest folder.
    """
    import logging

    log = logging.getLogger("vuln_engine.techniques.generic_differential")
    surfaces = list(seed.surfaces)
    # The eligibility filter is derived (``eligibility.py``), not hand-written
    # beside the table: the same set the adapter's door reads.
    eligible = plan_table_capabilities()
    # The session precondition, read honestly: every plan here asks for a
    # second identity, so the plans fire only when the engagement *declared*
    # sessions — the ``access_differs_by_session`` claim, spelled where the
    # operator declares what the world has. The separation from
    # ``idor_differential`` is the spike's point: that technique reads the
    # claim as its class identity; these plans read it as a *precondition*
    # only — one declared fact of the world, many classes downstream of it.
    # Without this gate the technique would probe session B on every
    # parameterised surface of every run, and the gate's refusals would be
    # honest but unearned spend.
    sessions_declared = any(
        surface.capability == CAP_ACCESS_DIFFERS_BY_SESSION for surface in surfaces
    )
    if not sessions_declared:
        return []
    # The object-read row is for surfaces that declare no role: a surface that
    # already announces itself as one side of a state-change pair gets its
    # hypothesis from the composition, not from a second, redundant read test.
    # It fires on the same surface declarations IDOR does — plus plain
    # ``public_param`` objects, since the sessions are already a declared fact.
    plans = object_read_plans(
        [
            s
            for s in surfaces
            if s.param
            and s.capability in eligible
            and ROLE_TARGET not in s.label
            and ROLE_VICTIM not in s.label
        ]
    )
    plans += session_role_plans(
        [s for s in surfaces if ROLE_TARGET in s.label and s.param],
        [s for s in surfaces if ROLE_VICTIM in s.label and s.param],
    )
    out: list[Hypothesis] = []
    seen: set[str] = set()
    for plan in plans:
        if plan.plan_id in seen:
            continue  # the same URL declared twice (e.g. once per role) is one plan
        seen.add(plan.plan_id)
        problems = validate_plan(plan)
        if problems:
            log.error("plan %s refused: %s", plan.plan_id, "; ".join(problems))
            continue
        out.append(_hypothesis_for(plan))
    return out

__all__ = ["hypotheses_for_seed", "hypothesis_for_plan"]
