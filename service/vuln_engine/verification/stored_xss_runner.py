"""The stored-XSS verifier: the two-step answer to "did the stored script run?".

A stored candidate cannot be confirmed the way a reflected one is. A reflected
confirmation is one URL: put the payload in the query, run the page. A stored
payload lives *behind a POST* — no URL carries it — so the confirmation is a
**sequence**:

1. **re-inject** the payload through the gate (an HTTP POST carrying the
   payload and the surface's companion fields — the same protocol the
   proposal's inject spoke);
2. **read back in a browser** and require the payload's own execution signal:
   a marker answering true, or a dialog whose message is ours.

Either signal is an *execution* fact, and neither can be produced by a response
that merely contains our bytes — the stored page renders whatever is in the
store, so "the bytes came back" was already known; what the finding needs is
the script running. Step 1 happens through the gate like every other effect, so
the loud half of this confirmation stays visible in the audit.

The verifier reads the candidate's confirmation spec and nothing else — not the
proposer's summary, not its reasoning. Independence is structural: the proposal
rested on a reflection (HTTP GET); the proof rests on execution (browser run).
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
from ..kernel.technique import CONFIRM_STORED_EXECUTE
from ..kernel.verdict import Candidate, Verdict, refuse
from ..policy.gate import KIND_BROWSER_RUN, KIND_HTTP_REQUEST, EffectRequest, PolicyGate
from ..world.observe import browser_observations, http_observations


@dataclass
class StoredXssVerifier:
    """Confirms a stored candidate by re-injecting, then proving execution."""

    gate: PolicyGate

    def verify(self, candidate: Candidate) -> Verdict:
        """Confirm or refuse *candidate*.  Never raises for an ordinary failure."""
        confirm = dict(candidate.confirm or {})
        if confirm.get("kind") != CONFIRM_STORED_EXECUTE:
            return refuse(
                candidate,
                "the proposer offered no stored-execution confirmation for this "
                "candidate, and a stored finding cannot be established any other "
                "way in this phase",
            )
        inject = dict(confirm.get("inject") or {})
        read_back = str(confirm.get("read_back") or "")
        markers = dict(confirm.get("markers") or {})
        if not read_back or not markers or not inject.get("url"):
            return refuse(
                candidate,
                "the confirmation spec names no inject, no read-back page, or no marker",
            )

        # Step 1 — the inject, through the gate like any other request. A refused
        # inject is an inconclusive confirmation, not a refuted candidate: nothing
        # was learned about the target.
        outcome = self.gate.run(
            EffectRequest(
                kind=KIND_HTTP_REQUEST,
                host=(urlsplit(str(inject["url"])).hostname or "").lower(),
                detail=dict(inject),
                technique=candidate.technique,
                probe=f"{candidate.id}:confirm-inject",
            )
        )
        if not outcome.executed:
            return refuse(
                candidate,
                f"the confirmation inject was not allowed ({outcome.verb}: {outcome.reason})",
            )
        if not bool(getattr(outcome.effect, "ok", False)):
            at = self.gate.now()
            http_observations(
                outcome.effect,
                probe=f"{candidate.id}:confirm-inject",
                at=at,
            )
            return refuse(
                candidate,
                f"the confirmation inject failed ({getattr(outcome.effect, 'error', '') or 'non-ok response'}); "
                "nothing was learned about the target",
            )

        # Step 2 — the browser reads the page where the payload now sits.
        run = self.gate.run(
            EffectRequest(
                kind=KIND_BROWSER_RUN,
                host=(urlsplit(read_back).hostname or "").lower(),
                detail={"url": read_back, "markers": markers},
                technique=candidate.technique,
                probe=candidate.id,
            )
        )
        if not run.executed:
            return refuse(
                candidate,
                f"the confirmation run was not allowed ({run.verb}: {run.reason})",
            )

        at = self.gate.now()
        observations = browser_observations(run.effect, probe=candidate.id, at=at)
        if not bool(getattr(run.effect, "ok", False)):
            return refuse(candidate, _why_not(run.effect, observations))
        proof = _execution_proof(observations, expect_dialog=str(confirm.get("dialog") or ""))
        if proof is None:
            return refuse(candidate, _why_not(run.effect, observations))

        browser_row = next((item for item in observations if item.kind == OBS_BROWSER), None)
        evidence = Evidence(
            kind=proof.kind,
            grade=EVIDENCE_EXECUTION,
            probe=candidate.id,
            at=at,
            payload={
                "driver": str(browser_row.payload.get("driver", "")) if browser_row else "",
                "url": read_back,
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
                "mutations": int((browser_row.payload.get("mutations") if browser_row else 0) or 0),
                "reason": "stored payload re-injected, then script execution observed in a browser",
            },
        )
        Verdict.check_independence(candidate.proposer_grade, evidence)
        return Verdict(
            candidate_id=candidate.id,
            proven=True,
            evidence=evidence,
            reason=(
                "the re-injected payload's script ran on the read-back page "
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
    """A refusal reason that says what the browser actually saw."""
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


__all__ = ["StoredXssVerifier", "proof_marker"]
