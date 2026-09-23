"""The browser verifier: the thing that answers "did the script actually run?".

This is where a lead becomes a finding, and the module is deliberately narrow. It
reads a candidate's **confirmation spec** — a request to make, and the markers that
would have to answer true — and nothing else. Not the proposer's summary, not its
confidence, not its reasoning: those are the proposer's, and a verifier that read
them would be the second auditor signing the first auditor's book.

Two independent ways to satisfy it, both of which are *execution* facts:

* a marker the payload sets answered true, which is only possible if the payload's
  JavaScript ran;
* a dialog opened whose message is ours, which is only possible for the same
  reason.

Either one is enough, and the other is recorded as corroboration. Neither can be
produced by a response that merely contains our bytes — which is the whole reason
this class exists.

The run goes through the policy gate like everything else, so a browser is loud and
therefore *visible in the audit*: a verifier that could skip the gate would be the
one component able to touch a target without a clearance.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from ..kernel.evidence import EVIDENCE_EXECUTION, Evidence
from ..kernel.observation import (
    OBS_BROWSER,
    OBS_DIALOG,
    OBS_SCRIPT_EXECUTION,
    Observation,
)
from ..kernel.verdict import Candidate, Verdict, refuse
from ..policy.gate import KIND_BROWSER_RUN, EffectRequest, PolicyGate
from ..world.observe import browser_observations


@dataclass
class BrowserVerifier:
    """Confirms a candidate by making a browser prove the effect happened."""

    gate: PolicyGate

    def verify(self, candidate: Candidate) -> Verdict:
        """Confirm or refuse *candidate*.  Never raises for an ordinary failure."""
        confirm = dict(candidate.confirm or {})
        if confirm.get("kind") != KIND_BROWSER_RUN:
            return refuse(
                candidate,
                "the proposer offered no browser confirmation for this candidate, and "
                "an execution finding cannot be established any other way in Phase 1",
            )
        url = str(confirm.get("url") or "")
        markers = dict(confirm.get("markers") or {})
        if not url or not markers:
            return refuse(candidate, "the confirmation spec names no url or no marker")

        request = EffectRequest(
            kind=KIND_BROWSER_RUN,
            host=(urlsplit(url).hostname or "").lower(),
            detail={"url": url, "markers": markers},
            technique=candidate.technique,
            probe=candidate.id,
        )
        outcome = self.gate.run(request)
        if not outcome.executed:
            return refuse(
                candidate,
                f"the confirmation run was not allowed ({outcome.verb}: {outcome.reason})",
            )

        at = self.gate.now()
        observations = browser_observations(outcome.effect, probe=candidate.id, at=at)
        if not bool(getattr(outcome.effect, "ok", False)):
            # A run that failed proves nothing, whatever its other fields say. This
            # is checked before the proof search so a half-populated result from a
            # crashed driver can never be read as an execution.
            return refuse(candidate, _why_not(outcome.effect, observations))
        proof = _execution_proof(observations, expect_dialog=str(confirm.get("dialog") or ""))
        if proof is None:
            return refuse(candidate, _why_not(outcome.effect, observations))

        run = next((item for item in observations if item.kind == OBS_BROWSER), None)
        evidence = Evidence(
            kind=proof.kind,
            grade=EVIDENCE_EXECUTION,
            probe=candidate.id,
            at=at,
            payload={
                "driver": str(run.payload.get("driver", "")) if run else "",
                "url": url,
                "context": str(confirm.get("context") or ""),
                "markers": proof_marker(proof, observations),
                "dialogs": [
                    {
                        "dialog": item.payload.get("dialog", ""),
                        "message": item.payload.get("message", ""),
                    }
                    for item in observations
                    if item.kind == OBS_DIALOG
                ],
                "mutations": int((run.payload.get("mutations") if run else 0) or 0),
                "reason": "script execution observed in a browser",
            },
        )
        # The check that makes this a finding rather than a closed loop. It raises
        # on a reused class, which is a programming error, not a target's answer.
        Verdict.check_independence(candidate.proposer_grade, evidence)
        return Verdict(
            candidate_id=candidate.id,
            proven=True,
            evidence=evidence,
            reason=(
                f"the payload's script ran in the browser "
                f"({proof.kind.split('.')[-1]} observed)"
            ),
            proposer_grade=candidate.proposer_grade,
        )


def _execution_proof(
    observations: list[Observation], *, expect_dialog: str
) -> Observation | None:
    """The first observation that proves the payload executed, or ``None``."""
    for item in observations:
        if item.kind == OBS_SCRIPT_EXECUTION and item.payload.get("executed"):
            return item
    for item in observations:
        if item.kind != OBS_DIALOG:
            continue
        message = str(item.payload.get("message") or "")
        if expect_dialog and message.startswith(expect_dialog):
            return item
    return None


def proof_marker(proof: Observation, observations: list[Observation]) -> dict[str, bool]:
    """Every marker the browser answered, for the record — true and false alike."""
    answers: dict[str, bool] = {}
    for item in observations:
        if item.kind == OBS_SCRIPT_EXECUTION:
            answers[str(item.payload.get("marker", ""))] = bool(item.payload.get("executed"))
    if not answers and proof.kind == OBS_DIALOG:
        answers["dialog"] = True
    return answers


def _why_not(effect: object, observations: list[Observation]) -> str:
    """A refusal reason that says what the browser actually saw.

    "Not proven" on its own is indistinguishable from "the verifier was broken",
    and the difference decides whether a lead is worth another look.
    """
    run = next((item for item in observations if item.kind == OBS_BROWSER), None)
    error = str(getattr(effect, "error", "") or (run.payload.get("error") if run else "") or "")
    if error:
        return f"the browser run failed: {error}"
    dialogs = [item for item in observations if item.kind == OBS_DIALOG]
    markers = [item for item in observations if item.kind == OBS_SCRIPT_EXECUTION]
    if not markers:
        return "the browser run recorded no marker answer: nothing executed"
    return (
        "the payload's script did not execute "
        f"({len(markers)} marker(s) answered false, {len(dialogs)} dialog(s) seen)"
    )


__all__ = ["BrowserVerifier", "proof_marker"]
