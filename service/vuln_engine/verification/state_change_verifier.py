"""The state-change verifier: re-execute the change, between two unchanged reads.

A ``state_change`` claim ("the change at T reaches V") cannot be proven by a
flipped two-session read — that measurement observes V and never executes T, so
proving "B can read V" would score the weaker, often-legitimate claim at the
strongest grade. This verifier answers the claim *as stated*, by running the
whole experiment itself, fresh, through the policy gate:

1. **V under session B** — the state as this verifier finds it;
2. **V under session B again** — the drift control. Two unchanged reads bracket
   the experiment: if the target's own background state moves between them, no
   later difference can be attributed to the change, and the claim is
   *inconclusive* rather than refuted (the same honesty rule every verifier
   here applies to a failed measurement);
3. **the change, executed fresh as session A** — the setup re-execution. What
   the verifier was handed about the change is *what to execute* (the spec's
   actor URL and method), never a conclusion; the measurements are all its own;
4. **V under session B** — the post read.

The oracle: pre-reads agree, the post read differs (status or body hash). That
is "the change at T is visible at V across the boundary" — the claim the plan
row declared, measured fresh and in the verifier's own order.

Independence holds in kind, not just in class: the proposer's actor run was
*its* experiment; this verifier executes the change itself, after its own
before-pair, so a cached response, a one-off pair, or an ordering artifact that
produced the proposal will not reproduce here.

An honest limitation, stated rather than hidden: if the proposer's pass already
changed the state *irreversibly*, this verifier's before-pair reads the changed
state, the fresh change moves nothing, and the verdict is a refusal naming the
numbers — the experiment could not be reproduced fresh, so it is not proven.
A repeatable change (the general case for the mutations this claim class names:
role changes, invitations, counters) reproduces cleanly. The evidence always
carries both pre-read hashes and the post hash, so a reader can see which case
they are looking at.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from urllib.parse import urlsplit

from ..kernel.claim import CLAIM_STATE_CHANGE
from ..kernel.evidence import EVIDENCE_DIFFERENTIAL, Evidence
from ..kernel.exchange import RawHttpExchange
from ..kernel.observation import OBS_HTTP_RESPONSE
from ..kernel.verdict import Candidate, Verdict, refuse
from ..policy.gate import EffectRequest, PolicyGate

#: Confirmation-spec kind this verifier answers.  Must equal the technique's
#: ``confirm["kind"]``; pinned by a test so the two cannot drift.
CONFIRM_KIND = "authorization.state_change"


@dataclass
class StateChangeVerifier:
    """Confirms a state-change claim by re-executing the change itself."""

    gate: PolicyGate

    def verify(self, candidate: Candidate) -> Verdict:
        """Confirm or refuse *candidate*.  Never raises for an ordinary failure."""
        confirm = dict(candidate.confirm or {})
        if confirm.get("kind") != CONFIRM_KIND:
            return refuse(
                candidate,
                "the proposer offered no state-change confirmation for this "
                "candidate, and a state_change claim cannot be established by a "
                "flipped read alone",
            )
        claim_shape = str(confirm.get("claim_shape") or CLAIM_STATE_CHANGE)
        if claim_shape != CLAIM_STATE_CHANGE:
            return refuse(
                candidate,
                f"the confirmation spec's claim_shape is {claim_shape!r}, not "
                f"{CLAIM_STATE_CHANGE!r}: this verifier re-executes changes, so "
                "it is not the proof a different shape needs",
            )
        actor = dict(confirm.get("actor") or {})
        actor_url = str(actor.get("url") or "")
        actor_method = str(actor.get("method") or "GET")
        victim_url = str(confirm.get("victim_url") or "")
        if not actor_url or not victim_url:
            return refuse(
                candidate,
                "the confirmation spec names no actor change or no victim URL to "
                "re-measure",
            )
        # The claim reads the victim's view, and the victim's view is session
        # B — the same identity the plan rows that emitted this claim marked
        # ``requires_session_b``. Without a declared second session the
        # experiment cannot be run as the claim states it, so refuse here, with
        # the operator's fix in the reason, rather than send reads the gate
        # would deny anyway (or worse, quietly re-measure under the wrong
        # identity and prove a claim nobody made).
        if not self.gate.session_b_wired:
            return refuse(
                candidate,
                "the state-change claim reads the victim under session B, but the "
                "run declared no second session (wire it with --session-b-cookie): "
                "the experiment is refused rather than re-measured under the "
                "wrong identity",
            )

        # ---- the fresh experiment, in the verifier's own order ----
        pre_one = self._measure(victim_url, session="b", probe=candidate.id, step="pre")
        pre_two = self._measure(
            victim_url, session="b", probe=candidate.id, step="pre_repeat"
        )
        if pre_one is None or pre_two is None:
            return refuse(
                candidate,
                "a before-measurement failed before the change ran, so the claim "
                "is inconclusive rather than refuted",
            )
        actor_exchange = self._execute_change(
            actor_url, actor_method, probe=candidate.id
        )
        if actor_exchange is None:
            return refuse(
                candidate,
                "the fresh execution of the change failed (the gate refused it or "
                "the transport errored), so the claim is inconclusive rather than "
                "refuted",
            )
        post = self._measure(victim_url, session="b", probe=candidate.id, step="post")
        if post is None:
            return refuse(
                candidate,
                "the after-measurement failed, so the claim is inconclusive rather "
                "than refuted",
            )

        at = self.gate.now()
        pre_hash = hashlib.sha256(pre_one.body).hexdigest()
        pre_repeat_hash = hashlib.sha256(pre_two.body).hexdigest()
        post_hash = hashlib.sha256(post.body).hexdigest()
        pre_stable = (
            pre_one.status == pre_two.status and pre_hash == pre_repeat_hash
        )
        changed = (
            post.status != pre_one.status or post_hash != pre_hash
        )
        evidence = Evidence(
            kind=OBS_HTTP_RESPONSE,
            grade=EVIDENCE_DIFFERENTIAL,
            probe=str(confirm.get("probe") or candidate.id),
            at=at,
            payload={
                "oracle": "state_change_reaches_victim",
                "victim_url": victim_url,
                "actor_url": actor_url,
                "actor_method": actor_method,
                "actor_status": actor_exchange.status,
                "pre_status": pre_one.status,
                "pre_repeat_status": pre_two.status,
                "post_status": post.status,
                "pre_body_hash": pre_hash,
                "pre_repeat_body_hash": pre_repeat_hash,
                "post_body_hash": post_hash,
                "pre_body_length": len(pre_one.body),
                "post_body_length": len(post.body),
                "pre_stable": pre_stable,
                "changed": changed,
                "reason": (
                    "fresh setup-re-executing measurement through the policy gate: "
                    "two unchanged victim reads, the change executed as session A, "
                    "one victim read after"
                ),
            },
        )
        if not pre_stable:
            return refuse(
                candidate,
                (
                    f"the victim's state moved between two unchanged reads "
                    f"(status {pre_one.status} -> {pre_two.status}): a target whose "
                    "background state drifts mid-experiment cannot attribute the "
                    "post-read difference to the change — inconclusive"
                ),
            )
        if not changed:
            return refuse(
                candidate,
                (
                    f"the freshly executed change did not move the victim's read "
                    f"under session B (status {pre_one.status} -> {post.status}, "
                    f"{len(post.body)} vs {len(pre_one.body)} bytes): either the "
                    "change does not reach the victim, or the proposer's pass "
                    "already applied it irreversibly — the experiment could not be "
                    "reproduced fresh, so the claim is not proven"
                ),
            )
        Verdict.check_independence(candidate.proposer_grade, evidence)
        return Verdict(
            candidate_id=candidate.id,
            proven=True,
            evidence=evidence,
            reason=(
                f"fresh setup re-execution: the victim read under session B moved "
                f"(status {pre_one.status} -> {post.status}) across two unchanged "
                "before-reads, with the change executed as session A — the change "
                "at T reaches V"
            ),
            proposer_grade=candidate.proposer_grade,
        )

    # ------------------------------------------------------------------ #
    # measurement
    # ------------------------------------------------------------------ #

    def _measure(
        self, url: str, *, session: str, probe: str, step: str
    ) -> RawHttpExchange | None:
        """One victim read under one identity; the exchange, or ``None``.

        The bodies live exactly as long as hashing takes and are then dropped —
        the evidence carries statuses, hashes and lengths only.
        """
        detail: dict = {"url": url, "method": "GET", "_session": session}
        outcome = self.gate.run(
            EffectRequest(
                kind="http.request",
                host=(urlsplit(url).hostname or "").lower(),
                detail=detail,
                technique="state_change_verifier",
                probe=f"{probe}:{step}",
            )
        )
        if not outcome.executed:
            return None
        exchange: RawHttpExchange = outcome.effect
        if not exchange.ok:
            return None
        return exchange

    def _execute_change(
        self, url: str, method: str, *, probe: str
    ) -> RawHttpExchange | None:
        """The change itself, executed fresh as session A (the actor identity)."""
        outcome = self.gate.run(
            EffectRequest(
                kind="http.request",
                host=(urlsplit(url).hostname or "").lower(),
                detail={"url": url, "method": method or "GET"},
                technique="state_change_verifier",
                probe=f"{probe}:change",
            )
        )
        if not outcome.executed:
            return None
        exchange: RawHttpExchange = outcome.effect
        if not exchange.ok:
            return None
        return exchange


__all__ = ["CONFIRM_KIND", "StateChangeVerifier"]
