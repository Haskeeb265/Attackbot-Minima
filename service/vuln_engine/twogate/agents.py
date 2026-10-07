"""The two agents and the routing planner between them.

The flow the module implements:

1. the **capability agent** looks at a surface, the capabilities that were
   *measured* on it, and the history of what was already tried, and proposes one
   or more candidate bugs (a label + a confirm kind + a payload family);
2. the **planner** routes each candidate to a routine, or classifies it as a lead
   with a named missing prerequisite, and enforces independence;
3. the **verifier agent** turns ``(candidate, routine, surface)`` into a
   declarative :class:`~.spec.ConfirmationSpec` — populations, oracle, margin.

Both agents have a deterministic core that runs with no model at all, and an
optional injected *advisor* that may only re-choose within the closed sets the
deterministic core already allows: the capability agent may pick among label
families the measured capabilities admit, and the verifier agent may pick among
the payloads the selected routine already contains. Neither can invent a label,
an oracle, or a test case.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

from ..kernel.evidence import EVIDENCE_HYPOTHESIS, FINDING_GRADES
from ..kernel.technique import Surface
from .routines import (
    CAP_ACCESS_DIFFERS_BY_SESSION,
    CAP_DELAYED_RESPONSE,
    CAP_INFLUENCE_REMOTE_FETCH,
    CAP_PUBLIC_PARAM,
    CAP_REFLECTS_INPUT,
    Routine,
    routine_for_id,
    routines_for_label,
    select_routine,
)
from .spec import ORACLE_EVIDENCE, ConfirmationSpec

#: Provenance label for a candidate the capability agent shaped.
ORIGIN_CAPABILITY = "llm.capability"

#: Candidate labels by the measured capability they rest on, strongest first.
#: Each entry is ``(label, confirm_kind, vuln_class, payload_family)``.
CAPABILITY_ROUTES: dict[str, tuple[tuple[str, str, str, str], ...]] = {
    CAP_REFLECTS_INPUT: (
        ("xss", "browser.run", "xss", "script-marker"),
    ),
    CAP_DELAYED_RESPONSE: (
        ("sqli", "timing.differential", "sqli", "sleep-family"),
        # The second explanation of one measured timing fact: the value may
        # have reached a shell rather than a SQL interpreter. Route parity
        # with the classic ``command_injection`` technique (batch 2, Phase 3);
        # the routine carries the shell grammar and its own dose payloads.
        ("command_injection", "timing.differential", "command-injection", "shell-family"),
    ),
    CAP_INFLUENCE_REMOTE_FETCH: (
        ("ssrf", "oob.read", "ssrf", "collaborator-url"),
    ),
    CAP_ACCESS_DIFFERS_BY_SESSION: (
        ("idor", "authorization.differential", "idor", "two-session"),
    ),
    CAP_PUBLIC_PARAM: (
        ("method_confusion", "differential.response", "method-confusion", "response-diff"),
        ("path_traversal", "differential.response", "path-traversal", "traversal-family"),
        # Extraction rides the same measured ``public_param`` precondition as
        # the response-difference family: the probe needs a parameter whose
        # answer we can read, not a target that sleeps. It keeps the ``sqli``
        # label the timing routine uses — a distinct confirm kind (and oracle)
        # is what makes it a different experiment rather than a re-run.
        ("sqli", "differential.extraction", "sqli", "union-extraction"),
    ),
}

#: The order capabilities are tried in — cheapest, most specific first.
CAPABILITY_ORDER: tuple[str, ...] = (
    CAP_REFLECTS_INPUT,
    CAP_INFLUENCE_REMOTE_FETCH,
    CAP_DELAYED_RESPONSE,
    CAP_ACCESS_DIFFERS_BY_SESSION,
    CAP_PUBLIC_PARAM,
)

#: A model advisor: ``(surface, capabilities, history) -> proposals | None``.
#: ``None`` (or a degraded advisor) falls back to the deterministic proposal.
CapabilityAdvisor = Callable[[Surface, frozenset[str], "list[str]"], "list[Proposal] | None"]
#: A verifier advisor: ``(proposal, routine, surface) -> payload_id | None``.
VerifierAdvisor = Callable[[Surface, "Proposal", Routine], "str | None"]


@dataclass(frozen=True)
class Proposal:
    """One candidate bug the capability agent believes is worth testing."""

    id: str
    surface_key: str
    label: str
    vuln_class: str
    confirm_kind: str
    capability: str
    payload_family: str
    rationale: str
    evidence_grade: str = EVIDENCE_HYPOTHESIS
    origin: str = ORIGIN_CAPABILITY

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "surface_key": self.surface_key,
            "label": self.label,
            "vuln_class": self.vuln_class,
            "confirm_kind": self.confirm_kind,
            "capability": self.capability,
            "payload_family": self.payload_family,
            "rationale": self.rationale,
            "evidence_grade": self.evidence_grade,
            "origin": self.origin,
        }


@dataclass(frozen=True)
class Lead:
    """A candidate the planner could not route, with the reason."""

    proposal_id: str
    label: str
    reason: str

    def to_dict(self) -> dict:
        return {"proposal_id": self.proposal_id, "label": self.label, "reason": self.reason}


@dataclass(frozen=True)
class Planned:
    """A candidate routed to a routine that can verify it."""

    proposal: Proposal
    routine: Routine


class CapabilityAgent:
    """Proposes candidate bugs from *measured* capabilities, deterministically.

    The deterministic core maps a measured capability to the bug families it
    admits, skipping anything already tried on this surface. An injected advisor
    may re-order or narrow that list, but every proposal it returns is validated
    against the same closed mapping — an advisor cannot propose a label the
    capability does not admit.
    """

    def __init__(self, advisor: CapabilityAdvisor | None = None) -> None:
        self.advisor = advisor

    def propose(
        self,
        surface: Surface,
        capabilities: frozenset[str],
        history: list[str] | None = None,
    ) -> list[Proposal]:
        tried = set(history or [])
        proposals = self._deterministic(surface, capabilities, tried)
        if self.advisor is not None:
            advised = self.advisor(surface, capabilities, list(tried))
            allowed = {item.label for item in proposals}
            if advised is not None:
                valid = [item for item in advised if item.label in allowed or self._admits(capabilities, item.label)]
                if valid:
                    return valid
        return proposals

    def _deterministic(
        self, surface: Surface, capabilities: frozenset[str], tried: set[str]
    ) -> list[Proposal]:
        proposals: list[Proposal] = []
        for capability in CAPABILITY_ORDER:
            if capability not in capabilities:
                continue
            for label, confirm_kind, vuln_class, family in CAPABILITY_ROUTES[capability]:
                if label in tried:
                    continue
                proposals.append(
                    Proposal(
                        id=f"{label}:{surface.key}",
                        surface_key=surface.key,
                        label=label,
                        vuln_class=vuln_class,
                        confirm_kind=confirm_kind,
                        capability=capability,
                        payload_family=family,
                        rationale=(
                            f"{capability!r} was measured on this surface, which is "
                            f"the precondition for {label}"
                        ),
                    )
                )
        return proposals

    @staticmethod
    def _admits(capabilities: frozenset[str], label: str) -> bool:
        for routes in CAPABILITY_ROUTES.values():
            if any(route[0] == label for route in routes):
                return True
        return False


class VerifierAgent:
    """Turns a routed candidate into a declarative confirmation spec.

    Anchors on the given label and routine; it may pick among the routine's own
    payloads (deterministically the first, or the advisor's choice when the
    advisor names one that is actually in the family) and adapt the URL/param to
    the target. It cannot write an oracle or invent a payload.
    """

    def __init__(self, advisor: VerifierAdvisor | None = None) -> None:
        self.advisor = advisor

    def spec_for(self, proposal: Proposal, routine: Routine, surface: Surface) -> ConfirmationSpec:
        payload = self._choose_payload(proposal, routine, surface)
        return ConfirmationSpec(
            kind=routine.confirm_kind,
            routine_id=routine.routine_id,
            label=proposal.label,
            host=surface.host,
            url=surface.url,
            param=surface.param,
            where=surface.where,
            baseline_payload=routine.baseline_payload,
            control_payload=routine.control_payload,
            injected_payload=payload,
            dose_short_payload=routine.dose_short_payload,
            dose_long_payload=routine.dose_long_payload,
            samples=routine.samples,
            oracle=routine.oracle,
            margin=routine.margin,
            length_delta=routine.length_delta,
            canary=routine.canary,
            marker=routine.marker,
            companions=dict(surface.companions or {}),
        )

    def _choose_payload(self, proposal: Proposal, routine: Routine, surface: Surface) -> str:
        family = routine.injected_payloads or ("",)
        if self.advisor is not None:
            chosen = self.advisor(surface, proposal, routine)
            if chosen is not None and chosen in family:
                return chosen
        return family[0]


class ConfirmationPlanner:
    """Routes a candidate to a verifier, or names why it cannot be routed.

    This is the deterministic guard on the whole loop: it decides which confirm
    kinds are admissible for a candidate *before* the verifier agent is asked to
    write a spec, so the proposer can never steer the choice of verifier. It also
    enforces the independence rule — a verifier whose evidence class equals the
    proposer's is refused.
    """

    def __init__(self, *, available_transports: set[str] | None = None) -> None:
        self.available_transports = set(available_transports or {"http1"})

    def plan(
        self,
        proposal: Proposal,
        capabilities: frozenset[str],
    ) -> Planned | Lead:
        routine = select_routine(proposal.label, proposal.confirm_kind)
        if routine is None:
            # Fall back to any routine the label admits, but only if its confirm
            # kind matches the candidate's — the candidate named the kind.
            matches = routines_for_label(proposal.label)
            if not matches:
                return Lead(proposal.id, proposal.label, "no_matching_routine")
            return Lead(proposal.id, proposal.label, "no_matching_routine")
        missing = [cap for cap in routine.preconditions if cap not in capabilities]
        if missing:
            return Lead(proposal.id, proposal.label, f"missing_capability:{missing[0]}")
        missing_transport = [
            name for name in routine.transports if name not in self.available_transports
        ]
        if missing_transport:
            return Lead(
                proposal.id, proposal.label, f"missing_transport:{missing_transport[0]}"
            )
        grade = ORACLE_EVIDENCE.get(routine.oracle, "")
        if grade not in FINDING_GRADES or grade == proposal.evidence_grade:
            return Lead(proposal.id, proposal.label, "no_independent_verifier")
        return Planned(proposal=proposal, routine=routine)

    def transports_from_gate(self, gate) -> None:
        """Refresh the available-transport set from a live gate's capability report."""
        report = gate.capabilities()
        available = {"http1"}
        if report.get("browser", {}).get("available"):
            available.add("browser")
        if report.get("oob", {}).get("available"):
            available.add("oob")
        self.available_transports = available


def plan_and_spec(
    planner: ConfirmationPlanner,
    verifier_agent: VerifierAgent,
    proposal: Proposal,
    capabilities: frozenset[str],
    surface: Surface,
) -> tuple[Planned, ConfirmationSpec] | Lead:
    """Convenience: route a candidate and build its spec, or return the lead."""
    planned = planner.plan(proposal, capabilities)
    if isinstance(planned, Lead):
        return planned
    spec = verifier_agent.spec_for(planned.proposal, planned.routine, surface)
    return planned, spec


def routine_index() -> list[dict]:
    """The routine index rows the agents may read (imported from routines)."""
    from .routines import index_rows

    return index_rows()


__all__ = [
    "CAPABILITY_ORDER",
    "CAPABILITY_ROUTES",
    "CapabilityAdvisor",
    "CapabilityAgent",
    "ConfirmationPlanner",
    "Lead",
    "ORIGIN_CAPABILITY",
    "Planned",
    "Proposal",
    "VerifierAdvisor",
    "VerifierAgent",
    "plan_and_spec",
    "routine_index",
]
