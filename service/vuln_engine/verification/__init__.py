"""Verification: independent confirmation, by a class the proposer did not use.

Six verifiers, one per confirmation shape a finding may rest on:

``browser_runner``           execution — a script ran in a browser
``oob_verifier``             oob — our own collaborator saw the interaction
``timing_verifier``          differential — two populations re-measured fresh
``stored_xss_runner``        execution — a stored payload re-injected, then a
                             browser proved the script ran on the read-back page
``authorization_verifier``   differential — both sessions re-asked, flipped order
``state_change_verifier``    differential — the change re-executed fresh,
                             between two unchanged victim reads

:class:`VerificationLayer` picks between them from the candidate's *confirmation
spec*, which is the only thing a verifier is allowed to read from a candidate. It
does not read the proposer's summary, class or confidence, because reading them is
how a verification step quietly becomes a second opinion from the same source.

Before the dispatch, the spec itself is validated
(:mod:`.validator`, the classic path's planner gate): the URLs it names must
belong to the surface the candidate declares, and the fields the answering
verifier reads must be present. A spec that fails is refused with the reason —
no measurement spent, nothing dispatched. The two-gate flow has its planner for
exactly this; the classic path now has the same defense in depth, sized down.

A candidate with no confirmation spec is refused, with that as the reason. Those
refusals are the engine's **leads**: recorded, visible in the report, and never
promoted. A verifier that could not refuse would make every proposal a finding,
which is precisely the scanner behaviour this design exists to avoid.

Phase 3: a candidate the synthesize junction proposed carries ``origin`` set.
Verification treats it exactly like any other candidate — the independence rule
is about *evidence class*, not about who shaped the proposal, and the AWE
evidence (``RnD_2026-09.md`` §C2) is that constraint-aware model synthesis is
valuable precisely because the browser verifier still proves it independently.
The provenance is kept so an operator can see which findings rest on
model-shaped proposals.
"""

from __future__ import annotations

from ..kernel.technique import CONFIRM_STORED_EXECUTE
from ..kernel.verdict import Candidate, Verdict, refuse
from ..policy.gate import KIND_BROWSER_RUN, KIND_OOB_READ, PolicyGate
from .authorization_verifier import CONFIRM_KIND as AUTHORIZATION_CONFIRM_KIND
from .authorization_verifier import AuthorizationVerifier
from .browser_runner import BrowserVerifier
from .oob_verifier import CONFIRM_KIND as OOB_CONFIRM_KIND
from .oob_verifier import OobVerifier
from .state_change_verifier import CONFIRM_KIND as STATE_CHANGE_CONFIRM_KIND
from .state_change_verifier import StateChangeVerifier
from .stored_xss_runner import StoredXssVerifier
from .timing_verifier import CONFIRM_KIND as TIMING_CONFIRM_KIND
from .timing_verifier import TimingVerifier
from .validator import validate_confirm_spec

#: Confirmation spec kind -> the verifier that answers it.
CONFIRM_VERIFIERS: dict[str, str] = {
    KIND_BROWSER_RUN: "browser",
    OOB_CONFIRM_KIND: "oob",
    TIMING_CONFIRM_KIND: "timing",
    CONFIRM_STORED_EXECUTE: "stored",
    AUTHORIZATION_CONFIRM_KIND: "authorization",
    STATE_CHANGE_CONFIRM_KIND: "state_change",
}


class VerificationLayer:
    """Dispatches a candidate to the verifier its confirmation spec asks for."""

    def __init__(self, gate: PolicyGate, *, oob_wait: bool = True) -> None:
        self.gate = gate
        self.verifiers: dict[
            str,
            (
                AuthorizationVerifier
                | BrowserVerifier
                | OobVerifier
                | StateChangeVerifier
                | TimingVerifier
                | StoredXssVerifier
            ),
        ] = {
            "browser": BrowserVerifier(gate),
            "oob": OobVerifier(gate, wait=oob_wait),
            "timing": TimingVerifier(gate),
            "stored": StoredXssVerifier(gate),
            "authorization": AuthorizationVerifier(gate),
            "state_change": StateChangeVerifier(gate),
        }

    def verify(self, candidate: Candidate) -> Verdict:
        """Confirm or refuse *candidate*, always with a reason.

        The planner gate (``validator.validate_confirm_spec``) runs first: a
        spec whose URLs do not belong to the candidate's declared surface, or
        whose required fields are missing, is refused here — no measurement
        spent, the reason in the log. The synthesize junction's candidates
        (``origin`` set) verify through the ordinary path: independence is an
        *evidence-class* property, and the browser's confirmation is in a class
        the proposer — model or grammar — did not use either way.
        """
        problem = validate_confirm_spec(candidate.confirm or {}, candidate.surface)
        if problem:
            return refuse(candidate, problem)
        kind = str((candidate.confirm or {}).get("kind", ""))
        name = CONFIRM_VERIFIERS.get(kind)
        if name is None:
            return refuse(
                candidate,
                (
                    "no verifier answers this candidate's confirmation spec "
                    f"({kind or 'none offered'}): it stays a lead"
                ),
            )
        verifier = self.verifiers[name]
        return verifier.verify(candidate)


__all__ = [
    "CONFIRM_VERIFIERS",
    "AuthorizationVerifier",
    "BrowserVerifier",
    "OobVerifier",
    "StateChangeVerifier",
    "StoredXssVerifier",
    "TimingVerifier",
    "VerificationLayer",
    "validate_confirm_spec",
]
