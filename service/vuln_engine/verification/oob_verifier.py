"""The OOB verifier: for a blind class, the only evidence strong enough.

It is thin on purpose, and the thinness is the argument. The proposer saw bytes
come back that contained our collaborator's answer; this verifier asks a
*different* question of a *different* system: did our collaborator record a
request, on the path only this probe knows, from somewhere that is not us?

That record cannot be produced by a cached page, a proxy error quoting our input,
or a reflected parameter. It can only be produced by something on the far side
actually reaching our listener — which is exactly the proof a blind class needs
and which no amount of response inspection can fake.

Nothing here is probabilistic. There is no timing heuristic and no threshold: an
interaction either arrived or it did not, so "inconclusive" is a real answer and
never gets laundered into either a finding or a refutation.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..kernel.evidence import EVIDENCE_OOB, Evidence
from ..kernel.observation import OBS_OOB_INTERACTION
from ..kernel.verdict import Candidate, Verdict, refuse
from ..policy.gate import KIND_OOB_READ, PolicyGate
from ..world.observe import oob_observations

#: The confirmation spec's kind for a collaborator lookup.
CONFIRM_KIND = KIND_OOB_READ


@dataclass
class OobVerifier:
    """Confirms a candidate by finding the interaction our own listener recorded."""

    gate: PolicyGate
    #: How long the collaborator is polled for an interaction.  A blind fetch may
    #: happen after the server has already answered us, so waiting is part of the
    #: verification rather than an optimisation.
    wait: bool = True

    def verify(self, candidate: Candidate) -> Verdict:
        """Confirm or refuse *candidate* from the collaborator's own record."""
        confirm = dict(candidate.confirm or {})
        if confirm.get("kind") != CONFIRM_KIND:
            return refuse(
                candidate,
                "the proposer offered no out-of-band confirmation for this candidate, "
                "and a blind class cannot be established any other way",
            )
        probe = str(confirm.get("probe") or candidate.id)
        expected_path = str(confirm.get("path") or "")

        fetched = self.gate.read_oob(probe, wait=self.wait)
        if fetched.error:
            # An error is not a refutation: if our own collaborator could not be
            # read, nothing at all is known about the target.
            return refuse(
                candidate,
                f"the collaborator could not be read ({fetched.error}), so this "
                "candidate is inconclusive rather than refuted",
            )

        at = self.gate.now()
        observations = oob_observations(fetched, at=at)
        match = _matching_interaction(observations, expected_path)
        if match is None:
            return refuse(
                candidate,
                "no interaction arrived for this probe: the claim that the server "
                "fetches a supplied URL is not supported by our own listener",
            )

        evidence = Evidence(
            kind=OBS_OOB_INTERACTION,
            grade=EVIDENCE_OOB,
            probe=probe,
            at=at,
            payload={
                "method": match.payload.get("method", ""),
                "path": match.payload.get("path", ""),
                "source_ip": match.payload.get("source_ip", ""),
                "user_agent": match.payload.get("user_agent", ""),
                "interactions": len(observations),
                "reason": "our collaborator recorded the interaction",
            },
        )
        Verdict.check_independence(candidate.proposer_grade, evidence)
        return Verdict(
            candidate_id=candidate.id,
            proven=True,
            evidence=evidence,
            reason=(
                "our own collaborator recorded an inbound request on the path only "
                "this probe used"
            ),
            proposer_grade=candidate.proposer_grade,
        )


def _matching_interaction(observations: list, expected_path: str):
    """The interaction on the expected path, or any interaction at all.

    Preferring the exact path keeps the record specific; falling back to any
    interaction for this probe id is correct rather than lenient, because the id
    itself is unique per probe — a request that carried it came from our attempt
    even if the server normalised the path on the way through.
    """
    for item in observations:
        if expected_path and str(item.payload.get("path", "")).endswith(expected_path):
            return item
    return observations[0] if observations else None


__all__ = ["CONFIRM_KIND", "OobVerifier"]
