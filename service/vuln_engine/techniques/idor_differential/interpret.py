"""The IDOR interpretation: one comparison, honestly weak, honestly labeled.

The proposer's question: did session B receive what session A received? The
answer is drawn from the two responses' status codes — the one field that is
comparable across identities without reading either body. Reading bodies to
"confirm similarity" here would be the proposer grading its own claim with
target-controlled bytes; the verifier does that work properly, by flipping
the identities and re-measuring.

The outcomes, in the order the code checks them:

* a session's measurement is missing — no comparison, no candidate;
* session A denied — there is no privilege boundary here to violate (or the
  session shim expired, which a re-run answers), no candidate;
* session B denied — the *expected* answer: A sees it, B does not. The claim
  holds; the honest outcome is silence, and the receipt files ``none``;
* session B allowed — B read the object the operator declared B must not
  read. The candidate. Grade ``hypothesis`` — a lead until the differential
  verifier re-asks both identities fresh, in flipped order.
* anything else (a 5xx, a transport zero) — a measurement problem, not an
  authorization fact, no candidate.
"""

from __future__ import annotations

from ...kernel.evidence import EVIDENCE_HYPOTHESIS, Evidence
from ...kernel.observation import OBS_HTTP_RESPONSE
from ...kernel.technique import Hypothesis, Observation
from ...kernel.verdict import Candidate
from .manifest import NAME, ORACLE

#: Status buckets. ``allowed`` is the 2xx family; ``denied`` is the honest set
#: of "the server said no" — 401/403 are the ordinary spellings, 404 counts
#: because many targets hide rather than admit, and redirects to a login page
#: are denial shapes the transport records as 30x.
_ALLOWED = range(200, 300)
_DENIED = {301, 302, 303, 307, 308, 401, 403, 404}


def _status(observations: list[Observation], probe_suffix: str) -> int | None:
    """The status the session-* probe observed, or ``None``."""
    for item in observations:
        if item.kind != OBS_HTTP_RESPONSE:
            continue
        probe_id = str(item.probe or "")
        if probe_id.endswith(probe_suffix):
            status = item.payload.get("status")
            try:
                return int(status)  # type: ignore[arg-type]
            except (TypeError, ValueError):
                return None
    return None


def candidates(hypothesis: Hypothesis, observations: list[Observation]) -> list[Candidate]:
    surface = hypothesis.surface
    status_a = _status(observations, ":session-a")
    status_b = _status(observations, ":session-b")
    if status_a is None or status_b is None:
        return []  # a missing measurement is not a comparison
    if status_a not in _ALLOWED:
        return []
    if status_b in _DENIED:
        # The expected answer: the claim holds. Silence, and a ``none`` receipt.
        return []
    if status_b in _ALLOWED:
        evidence = Evidence(
            kind=OBS_HTTP_RESPONSE,
            grade=EVIDENCE_HYPOTHESIS,
            probe=f"idor:{surface.key}",
            payload={
                "session_a_status": status_a,
                "session_b_status": status_b,
                "claim": hypothesis.claim,
                "reason": (
                    "both sessions received a success status for the same object; "
                    "the declared claim says session B must not"
                ),
            },
        )
        confirm = {
            "kind": "authorization.differential",
            "url": surface.url,
            "param": surface.param,
            "oracle": ORACLE,
            "probe": f"idor:{surface.key}",
        }
        return [
            Candidate(
                id=f"idor:{surface.host}:{surface.url}:{surface.param or 'object'}",
                technique=NAME,
                vuln_class="idor",
                surface={"url": surface.url, "param": surface.param, "where": surface.where},
                summary=(
                    f"the object at {surface.url} answered {status_b} to the "
                    f"low-privilege session (session A: {status_a}); the declared "
                    "claim is that this session must not read it"
                ),
                evidence=evidence,
                confirm=confirm,
                payload="",
                repro_url=surface.url,
            )
        ]
    # A 5xx or a transport zero: a measurement problem, not an authorization fact.
    return []


__all__ = ["candidates"]
