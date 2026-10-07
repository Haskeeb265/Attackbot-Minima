"""Derived views: everything a consumer wants to see, recomputed from the log.

The bank-ledger rule again — balance is derived, the ledger wins. Nothing here
holds state, nothing here writes, and every function takes a :class:`WorldLog`
and returns plain data. That is what makes the report reproducible: a report is a
*view* of the log, so two views of the same log cannot disagree, and a replay that
recomputes them offline either matches or has found a bug.

The four views Phase 1 needs:

``gate_audit``
    Every decision with its reason, plus the one number the whole chokepoint
    exists to produce: how many effects ran without a clearance. That number is
    zero by construction — the gate is the only caller — and it is computed here
    rather than asserted, so a future refactor that broke the property would show
    up as a number instead of as silence.
``receipts_by_arm``
    Attempts grouped by ``(technique, surface)``, which is the arm the scheduler
    ranks over and the punch card that stops a conclusive attempt being paid for
    twice. Inconclusive attempts are visible here on purpose: a failed probe must
    be readable as "not done", not merely absent.
``findings``
    Proven candidates, carrying the *class* of the confirmation and the class of
    the proposal, plus a reproducible URL.
``report_lines``
    The reporting rule of ``engine_explained.md`` §10: what was proven, how, with
    what reproducibility, and which evidence class it rests on.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol

from ..kernel.evidence import EVIDENCE_HYPOTHESIS
from .holding_pen import PEN_HELD
from .log import (
    EVENT_CANDIDATE,
    EVENT_EFFECT_RESULT,
    EVENT_GATE_DECISION,
    EVENT_HOLDING_PEN_ENTRY,
    EVENT_RECEIPT,
    EVENT_VERDICT,
)


if TYPE_CHECKING:  # pragma: no cover - typing only
    from .holding_pen import HoldingPen


class LogView(Protocol):
    """What a derived view needs from a log: read-only access to its rows.

    A protocol rather than the concrete :class:`WorldLog` so a view can be taken
    over a *window* of the ledger — one run's rows — as well as over the whole
    file. Both satisfy this structurally; neither has to know about the other.
    """

    def events(self, *types: str) -> list[dict]:
        """Rows of the given types, in the order they were written."""
        ...

    def __len__(self) -> int:
        ...

    def summary(self) -> dict[str, int]:
        """``{row type: count}``."""
        ...

#: The substring that marks a gate refusal caused *only* by a missing second
#: session. A marker rather than the whole message so the operator-facing
#: wording can change without breaking the count; a test pins it to
#: :data:`policy.gate.SESSION_B_REFUSAL`. ``views`` cannot import ``policy``
#: (the import graph is one-way: ``policy`` → ``world``), hence the marker.
SESSION_B_REFUSAL_MARKER = "no second session is wired"

#: Technique names whose session-B refusal is a *capability check* — a
#: measurement of a precondition — rather than a candidate's own experiment.
#: These are the two-gate prober and the six elicitors; everything else (a
#: technique's own probes and the verifiers) counts as a candidate. Pinned to
#: the live elicitor registry by a test, so a new elicitor cannot silently
#: change the split.
CAPABILITY_CHECK_TECHNIQUES: frozenset[str] = frozenset(
    {
        "capability_prober",
        "public_param",
        "reflection",
        "remote_fetch",
        "sessions",
        "storage",
        "timing",
    }
)

#: How a finding's evidence class reads in a report line.  Kept as a table so the
#: prose cannot drift away from the class it claims to describe.
GRADE_PROSE: dict[str, str] = {
    "execution": "browser execution",
    "oob": "an out-of-band interaction with our own collaborator",
    "differential": "a difference between two authenticated states",
}


def arm_key(technique: str, surface: dict | str) -> str:
    """The ``(technique, surface)`` arm name the receipts and the budget use."""
    if isinstance(surface, str):
        return f"{technique}@{surface}"
    url = str(surface.get("url", ""))
    param = str(surface.get("param", ""))
    return f"{technique}@{url}#{param}" if param else f"{technique}@{url}"


def gate_audit(log: LogView) -> dict:
    """Every gate decision, counted by verb, with the uncleared-effect number."""
    decisions = log.events(EVENT_GATE_DECISION)
    by_verb: dict[str, int] = {}
    refusals: list[dict] = []
    for row in decisions:
        verb = str(row.get("verb", ""))
        by_verb[verb] = by_verb.get(verb, 0) + 1
        if verb != "ALLOW":
            refusals.append(
                {
                    "host": row.get("host", ""),
                    "kind": row.get("kind", ""),
                    "verb": verb,
                    "reason": row.get("reason", ""),
                    "at": row.get("at", 0.0),
                }
            )
    internal = log.events("effect.internal")
    allowed = by_verb.get("ALLOW", 0)
    executed = len(log.events(EVENT_EFFECT_RESULT))
    out_of_scope = [
        row for row in refusals if str(row.get("reason", "")).startswith("scope:")
    ]
    return {
        "decisions": len(decisions),
        "by_verb": dict(sorted(by_verb.items())),
        "allowed": allowed,
        "executed": executed,
        # The invariant, as a number: effects that ran without a clearance.  The
        # gate cannot produce a non-zero value here; computing it is how we find
        # out if that ever stops being true.
        "uncleared_effects": max(0, executed - allowed),
        "out_of_scope_requests": len(out_of_scope),
        "internal_effects": len(internal),
        "refusals": refusals,
    }


def session_b_refusals(log: LogView) -> list[dict]:
    """Every gate refusal whose only cause is a missing second session.

    These are the refusals an operator can *unlock* by wiring
    ``--session-b-cookie``; counted apart from the general refusal tally so the
    report can say so instead of burying them among unrelated denials.
    """
    return [
        row
        for row in log.events(EVENT_GATE_DECISION)
        if SESSION_B_REFUSAL_MARKER in str(row.get("reason", ""))
    ]


def blocked_on_session_b(log: LogView) -> int:
    """How many gate refusals the missing ``--session-b-cookie`` alone caused."""
    return len(session_b_refusals(log))


def blocked_on_session_b_split(log: LogView) -> dict[str, int]:
    """The same count split into capability checks vs candidate verifications."""
    checks = 0
    candidates_count = 0
    for row in session_b_refusals(log):
        if str(row.get("technique", "")) in CAPABILITY_CHECK_TECHNIQUES:
            checks += 1
        else:
            candidates_count += 1
    return {
        "capability_checks": checks,
        "candidates": candidates_count,
        "total": checks + candidates_count,
    }


def candidates(log: LogView) -> list[dict]:
    """Every candidate that was proposed, in the order it was proposed."""
    return log.events(EVENT_CANDIDATE)


def verdicts(log: LogView) -> list[dict]:
    """Every verdict the verification layer returned."""
    return log.events(EVENT_VERDICT)


@dataclass
class Finding:
    """One proven candidate, as the report needs it."""

    candidate_id: str
    technique: str
    vuln_class: str
    summary: str
    #: The class the confirmation rests on — the only one a reader should trust.
    grade: str
    #: The class the proposal rested on, kept visible so a reader can see the gap.
    proposer_grade: str
    repro_url: str = ""
    payload: str = ""
    #: The arm that proved this finding. The ordinary pass keys it by the
    #: surface, the abduced round by the plan id, so novelty can tell a
    #: plan-table finding from a model-proven one even when both share a
    #: plan id (``object_read:{key}``).
    arm: str = ""
    surface: dict = field(default_factory=dict)
    #: Verifier evidence payload, e.g. the dialogs and markers that proved it.
    evidence: dict = field(default_factory=dict)
    reason: str = ""

    @property
    def independent(self) -> bool:
        """True when the confirmation came from a different class than the proposal."""
        return bool(self.grade) and self.grade != self.proposer_grade

    def to_dict(self) -> dict:
        return {
            "candidate_id": self.candidate_id,
            "technique": self.technique,
            "vuln_class": self.vuln_class,
            "summary": self.summary,
            "evidence_class": self.grade,
            "proposer_grade": self.proposer_grade,
            "independent": self.independent,
            "repro_url": self.repro_url,
            "payload": self.payload,
            "arm": self.arm,
            "surface": dict(self.surface),
            "evidence": dict(self.evidence),
            "reason": self.reason,
        }


def findings(log: LogView) -> list[Finding]:
    """Proven candidates, joined to the candidate rows that proposed them."""
    proposed = {str(row.get("id", "")): row for row in candidates(log)}
    found: list[Finding] = []
    for row in verdicts(log):
        if not row.get("proven"):
            continue
        candidate_id = str(row.get("candidate", ""))
        source = proposed.get(candidate_id, {})
        evidence = row.get("evidence") or {}
        found.append(
            Finding(
                candidate_id=candidate_id,
                technique=str(source.get("technique", "")),
                vuln_class=str(source.get("vuln_class", "")),
                summary=str(source.get("summary", "")),
                grade=str(row.get("grade", "")),
                proposer_grade=str(
                    row.get("proposer_grade")
                    or source.get("proposer_grade")
                    or EVIDENCE_HYPOTHESIS
                ),
                repro_url=str(source.get("repro_url", "")),
                payload=str(source.get("payload", "")),
                arm=str(row.get("arm", "")),
                surface=dict(source.get("surface") or {}),
                evidence=dict(evidence.get("payload") or {}),
                reason=str(row.get("reason", "")),
            )
        )
    return found


def leads(log: LogView) -> list[dict]:
    """Candidates that were proposed and not proven — leads, kept as leads.

    A lead is not a failure and must not be reported as one: it is the honest
    answer for "something suggested this and nothing confirmed it".
    """
    proven = {str(row.get("candidate", "")) for row in verdicts(log) if row.get("proven")}
    return [
        row for row in candidates(log) if str(row.get("id", "")) not in proven
    ]


def holding_pen_summary(log: LogView, *, pen: "HoldingPen | None" = None) -> dict:
    """Held hypotheses, counted by ``(needs_verifier, vuln_class | claim_shape)``.

    The pen's backlog — hypotheses the verifier vocabulary cannot confirm yet —
    grouped so an operator can see which single confirm kind would unlock the
    most. Groups are sorted **descending by count** (ties broken by the group's
    own names, so the order is stable), because the question the view answers is
    "what should a new verifier unlock first".

    The group key prefers ``vuln_class`` (what the run believes) and falls back
    to ``claim_shape`` (what kind of claim it is) when no class was named.

    **What counts as still held.** A ``holding_pen.entry`` row records that a
    hypothesis was held; it does not record that it later left. Promotion and
    demotion are transitions in the pen's *own* ledger
    (``world/holding_pen.py``), the one place a code change or a decline is
    written, so when the caller has the pen it is passed in and every entry
    whose key has since left the pen is excluded. Without a pen the view can
    only describe the entries themselves (``held == lifetime``) — stated rather
    than guessed, because a promotion is not derivable from the world log.
    """
    rows = log.events(EVENT_HOLDING_PEN_ENTRY)
    lifetime = len(rows)
    left: frozenset[str] = frozenset()
    if pen is not None:
        left = frozenset(
            str(entry.get("key", ""))
            for entry in pen.entries()
            if entry.get("status") != PEN_HELD
        )
    counts: dict[tuple[str, str], int] = {}
    held = 0
    for row in rows:
        if left and str(row.get("proposal_id", "")) in left:
            continue
        needs_verifier = str(row.get("needs_verifier", "")) or "(unnamed)"
        key = (
            str(row.get("vuln_class", ""))
            or str(row.get("claim_shape", ""))
            or "(unknown)"
        )
        counts[(needs_verifier, key)] = counts.get((needs_verifier, key), 0) + 1
        held += 1
    # Descending by count; the group's names are the tiebreak so two runs over
    # the same log cannot disagree on the order.
    ranked: list[tuple[str, str, int]] = [
        (needs, key, count) for (needs, key), count in counts.items()
    ]
    ranked.sort(key=lambda item: (-item[2], item[0], item[1]))
    return {
        "held": held,
        "lifetime": lifetime,
        "groups": [
            {"needs_verifier": needs, "key": key, "count": count}
            for needs, key, count in ranked
        ],
    }


def receipts_by_arm(log: LogView) -> dict[str, dict[str, int]]:
    """``{arm: {outcome: count}}`` — the receipts ledger's view of the log.

    The punch-card subtlety survives into the view: ``failed`` is present and
    distinct, so "we tried and it errored" cannot be read as "we looked and there
    was nothing".
    """
    summary: dict[str, dict[str, int]] = {}
    for row in log.events(EVENT_RECEIPT):
        arm = str(row.get("arm") or arm_key(str(row.get("technique", "")), row.get("surface") or {}))
        outcome = str(row.get("outcome") or "unknown")
        bucket = summary.setdefault(arm, {})
        bucket[outcome] = bucket.get(outcome, 0) + 1
    return {arm: dict(sorted(counts.items())) for arm, counts in sorted(summary.items())}


def report_lines(log: LogView) -> list[str]:
    """The report, as lines: what was proven, how, reproducibly, with what class."""
    lines: list[str] = []
    for finding in findings(log):
        how = GRADE_PROSE.get(finding.grade, finding.grade or "no evidence class")
        detail = ""
        if finding.grade == "execution" and finding.evidence:
            markers = [key for key, value in finding.evidence.get("markers", {}).items() if value]
            dialogs = finding.evidence.get("dialogs", [])
            notes = []
            if markers:
                notes.append("script ran")
            if dialogs:
                kinds = ", ".join(sorted({str(item.get("dialog", "")) for item in dialogs if item}))
                notes.append(f"{kinds} dialog triggered" if kinds else "a dialog triggered")
            context = finding.evidence.get("context", "")
            if context:
                notes.append(f"reflected in a {context.replace('_', ' ')} context")
            detail = f" ({'; '.join(notes)})" if notes else ""
        elif finding.grade == "oob" and finding.evidence:
            method = finding.evidence.get("method", "GET")
            path = finding.evidence.get("path", "")
            source = finding.evidence.get("source_ip", "")
            detail = f" ({method} {path} arrived from {source})" if path else ""
        where = finding.surface.get("param", "")
        title = f"**{finding.vuln_class.upper()} in `{where}`**" if where else f"**{finding.vuln_class}**"
        lines.append(
            f"{title} — {finding.summary}. Confirmed by {how}{detail}. "
            f"Reproducible: {finding.repro_url or '(no URL recorded)'}. "
            f"Evidence class: {finding.grade} "
            f"(proposed on {finding.proposer_grade})."
        )
    return lines


def summary(log: LogView) -> dict:
    """The machine summary a run report embeds."""
    audit = gate_audit(log)
    found = findings(log)
    return {
        "rows": len(log),
        "by_type": log.summary(),
        "gate": {
            "decisions": audit["decisions"],
            "by_verb": audit["by_verb"],
            "uncleared_effects": audit["uncleared_effects"],
            "out_of_scope_requests": audit["out_of_scope_requests"],
            "internal_effects": audit["internal_effects"],
        },
        "candidates": len(candidates(log)),
        "findings": [finding.to_dict() for finding in found],
        "leads": len(leads(log)),
        "receipts": receipts_by_arm(log),
        "blocked_on_session_b": blocked_on_session_b(log),
        "holding_pen": holding_pen_summary(log),
    }


__all__ = [
    "CAPABILITY_CHECK_TECHNIQUES",
    "Finding",
    "GRADE_PROSE",
    "SESSION_B_REFUSAL_MARKER",
    "arm_key",
    "blocked_on_session_b",
    "blocked_on_session_b_split",
    "candidates",
    "findings",
    "gate_audit",
    "holding_pen_summary",
    "leads",
    "receipts_by_arm",
    "report_lines",
    "session_b_refusals",
    "summary",
    "verdicts",
]
