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

Three views gap-closure batch 2 adds:

``coverage``
    Per-surface coverage from the receipts ledger: the last attempt's outcome
    per ``(surface, technique)``, conclusive or not.
``findings_deduplicated``
    ``findings`` collapsed to the strongest per ``(surface, vuln_class)``,
    with the losers' ids carried alongside rather than erased.
``abduction_summary``
    The abductive junction's ledger: proposals and validator verdicts, counted
    by verdict so a run explains why an explanation was (or was not) pursued.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol

from ..kernel.claim import DIFFERENTIAL_PROVABLE
from ..kernel.evidence import EVIDENCE_HYPOTHESIS, EVIDENCE_ORDER
from .holding_pen import PEN_HELD
from .log import (
    EVENT_ABDUCTION_PROPOSED,
    EVENT_ABDUCTION_VALIDATED,
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

#: The row type ``llm/client.py`` writes for every junction call (item 4.2).
#: ``views`` cannot import ``llm`` (the import graph is one-way:
#: ``llm`` → ``world``), hence the literal — pinned by test to
#: :data:`llm.client.EVENT_LLM_JUNCTION`.
LLM_JUNCTION_EVENT = "llm.junction"

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


#: How much one proven finding of a class is worth in the holding pen's value
#: weighting — the risk rank an operator's triage order would use, not a CVSS
#: model. Static, in one place, and pinned by a test: editing a weight edits an
#: operator's reading of the backlog, so the edit must be deliberate.
SEVERITY_WEIGHTS: dict[str, float] = {
    "command-injection": 5.0,
    "sqli": 4.0,
    "ssrf": 3.0,
    "idor": 3.0,
    "xss": 2.0,
    "method-confusion": 2.0,
    "path-traversal": 2.0,
}
#: The weight a class with no entry carries — deliberately below every named
#: class, so an unknown can never outrank a known one in the sort.
SEVERITY_WEIGHT_UNKNOWN = 1.0

#: How provable a claim shape already is, as a multiplier: a shape a
#: differential-class verifier can prove today (``kernel.claim.DIFFERENTIAL_PROVABLE``)
#: is worth double a shape still waiting on one.
PROVABILITY_WEIGHT_PROVABLE = 1.0
PROVABILITY_WEIGHT_HELD = 0.5


def severity_weight(vuln_class: str) -> float:
    """The triage weight of one vuln class (unknown classes rank lowest)."""
    return SEVERITY_WEIGHTS.get(vuln_class, SEVERITY_WEIGHT_UNKNOWN)


def provability_weight(claim_shape: str) -> float:
    """How much a claim shape's provability multiplies its pen value."""
    return (
        PROVABILITY_WEIGHT_PROVABLE
        if claim_shape in DIFFERENTIAL_PROVABLE
        else PROVABILITY_WEIGHT_HELD
    )


def coverage(log: LogView) -> dict[str, dict[str, dict]]:
    """Per-surface coverage, from the receipts ledger — what was *tried*.

    One row per ``(surface, technique)`` with the last attempt's outcome, its
    conclusiveness and its ``at``. The receipt's ``technique`` field is the
    driver's operation string (``technique:hypothesis id``), so the technique
    column here is the arm's technique — the first ``@``-segment of ``arm`` —
    not the operation that happened to run last.

    Receipt rows carry no ``stage`` (the driver's ``_file_receipt`` writes
    ``arm``/``technique``/``outcome``/``conclusive`` only), so hypothesis-only
    visits — a technique that read a surface and proposed nothing — are *not*
    in this view; they stay in the ``note stage=hypothesis`` rows. Stated
    rather than implied: coverage here means "an attempt was filed", nothing
    more.
    """
    out: dict[str, dict[str, dict]] = {}
    for row in log.events(EVENT_RECEIPT):
        technique, _, surface_key = str(row.get("arm", "")).partition("@")
        out.setdefault(surface_key, {})[technique] = {
            "outcome": str(row.get("outcome", "")),
            "conclusive": bool(row.get("conclusive")),
            "at": row.get("at", 0.0),
        }
    return out


def _surface_key_of(surface: dict) -> str:
    """A finding's surface key — the ``url#param`` spelling ``Surface.key`` uses."""
    url = str(surface.get("url", ""))
    param = str(surface.get("param", ""))
    return f"{url}#{param}" if param else url


def findings_deduplicated(log: LogView) -> list[dict]:
    """The strongest finding per ``(surface, vuln_class)``, losers kept visible.

    The raw ``findings`` list is untouched — this view has its own key and its
    rows carry ``duplicate_ids``, because a collapse is an editorial claim the
    report must show, not a silent rewrite of the ledger's findings.

    The strongest is the highest evidence class (``kernel.evidence.EVIDENCE_ORDER``,
    unknown grades weakest); ties break on reproducibility (a finding with a
    reproducible URL outranks one without), then on log order, so two runs over
    the same log cannot disagree.
    """
    rank = {grade: index for index, grade in enumerate(EVIDENCE_ORDER)}
    groups: dict[tuple[str, str], list[tuple[int, Finding]]] = {}
    for position, finding in enumerate(findings(log)):
        groups.setdefault((_surface_key_of(finding.surface), finding.vuln_class), []).append(
            (position, finding)
        )
    out: list[dict] = []
    for (surface_key, vuln_class), members in groups.items():
        ordered = sorted(
            members,
            key=lambda item: (
                -rank.get(item[1].grade, -1),
                not bool(item[1].repro_url),
                item[0],
            ),
        )
        _, winner = ordered[0]
        out.append(
            {
                "vuln_class": vuln_class,
                **winner.to_dict(),
                # After the spread: the winner's own ``surface`` dict travels
                # too, and the *key* the group collapsed on is named apart.
                "surface_key": surface_key,
                "duplicate_ids": [
                    member.candidate_id
                    for _, member in ordered[1:]
                    if member.candidate_id != winner.candidate_id
                ],
            }
        )
    return out


def abduction_summary(log: LogView) -> dict:
    """The abductive junction's ledger, counted by verdict — the pen's mirror.

    ``abduction.proposed`` rows are the explanations; ``abduction.validated``
    rows are the three-valued validator's answers (``expressible_now``,
    ``not_yet_expressible``, ``invalid`` — ``abduction/proposal.py``). Top-level
    counts name what happened to every explanation; ``groups`` descends on
    ``needs_verifier`` — the very field the holding-pen backlog groups on — so
    both backlogs read the same way.
    """
    proposed = log.events(EVENT_ABDUCTION_PROPOSED)
    validated = log.events(EVENT_ABDUCTION_VALIDATED)
    by_proposal: dict[str, dict] = {}
    for row in validated:
        by_proposal[str(row.get("proposal_id", ""))] = {
            "verdict": str(row.get("verdict", "")),
            "reason": str(row.get("reason", "")),
        }
    by_verdict: dict[str, int] = {}
    for entry in by_proposal.values():
        verdict = entry["verdict"] or "(unvalidated)"
        by_verdict[verdict] = by_verdict.get(verdict, 0) + 1
    proposals: list[dict] = []
    for row in proposed:
        proposal = dict(row.get("proposal") or {})
        entry = by_proposal.get(
            str(row.get("proposal_id") or proposal.get("id", "")),
            {},
        )
        proposals.append(
            {
                "id": str(proposal.get("id", "")),
                "vuln_class": str(proposal.get("vuln_class", "")),
                "claim_shape": str(proposal.get("claim_shape", "")),
                "needs_verifier": str(proposal.get("needs_verifier", "")),
                "source": str(row.get("source", "")),
                "verdict": entry.get("verdict") or "(unvalidated)",
                "reason": entry.get("reason", ""),
                "at": row.get("at", 0.0),
            }
        )
    needs: dict[str, dict[str, int]] = {}
    for row in proposals:
        bucket = needs.setdefault(row["needs_verifier"] or "(unnamed)", {})
        bucket[row["verdict"]] = bucket.get(row["verdict"], 0) + 1
    ranked = sorted(
        needs.items(),
        key=lambda item: (-sum(item[1].values()), sorted(item[1]), item[0]),
    )
    return {
        "proposed": len(proposed),
        "validated": len(validated),
        "by_verdict": dict(sorted(by_verdict.items())),
        "proposals": proposals,
        "groups": [
            {
                "needs_verifier": needs_verifier,
                "by_verdict": dict(sorted(counts.items())),
                "count": sum(counts.values()),
            }
            for needs_verifier, counts in ranked
        ],
    }


def holding_pen_summary(log: LogView, *, pen: "HoldingPen | None" = None) -> dict:
    """Held hypotheses, counted by ``(needs_verifier, vuln_class | claim_shape)``.

    The pen's backlog — hypotheses the verifier vocabulary cannot confirm yet —
    grouped so an operator can see which single confirm kind would unlock the
    most. Groups are sorted **descending by value** (ties broken by the group's
    own names, so the order is stable), because the question the view answers is
    "what is this backlog worth, most valuable first".

    **Value weighting.** Each held row is worth
    ``severity_weight(vuln_class) × provability_weight(claim_shape)`` — the
    triage risk of the class (``SEVERITY_WEIGHTS``) times how provable the
    claim already is (differential-provable shapes double, everything else
    half). A group's value is the sum of its rows'; ``count`` travels alongside
    so "five cheap" stays distinguishable from "one expensive". Rows without a
    class or shape still weigh in — unknown classes carry the floor weight — so
    nothing in the backlog can disappear from the arithmetic.

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
    groups: dict[tuple[str, str], dict] = {}
    held = 0
    value = 0.0
    for row in rows:
        if left and str(row.get("proposal_id", "")) in left:
            continue
        needs_verifier = str(row.get("needs_verifier", "")) or "(unnamed)"
        vuln_class = str(row.get("vuln_class", ""))
        claim_shape = str(row.get("claim_shape", ""))
        key = vuln_class or claim_shape or "(unknown)"
        group = groups.setdefault((needs_verifier, key), {"count": 0, "value": 0.0})
        weight = severity_weight(vuln_class) * provability_weight(claim_shape)
        group["count"] += 1
        group["value"] += weight
        value += weight
        held += 1
    # Descending by value; the group's names are the tiebreak so two runs over
    # the same log cannot disagree on the order.
    ranked = sorted(
        groups.items(),
        key=lambda item: (-item[1]["value"], item[0][0], item[0][1]),
    )
    return {
        "held": held,
        "lifetime": lifetime,
        "value": value,
        "groups": [
            {
                "needs_verifier": needs,
                "key": key,
                "count": group["count"],
                "value": group["value"],
            }
            for (needs, key), group in ranked
        ],
    }


def llm_cost_summary(log: LogView) -> dict:
    """What the model channel cost this window (item 4.2).

    A pure derivation over the ``llm.junction`` rows: call counts, token
    totals, the worst single-call latency, and the summed cost. The cost on
    each row is a fact the client stamped at call time (from the static
    ``MODEL_PRICES`` table); this view only adds — it prices nothing itself.
    A keyless run has no such rows, so the summary is all zeros: the model's
    cost of a deterministic engine is exactly nothing, and the report says so.
    """
    rows = log.events(LLM_JUNCTION_EVENT)
    return {
        "calls": len(rows),
        "degraded": sum(1 for row in rows if row.get("degraded")),
        "prompt_tokens": sum(int(row.get("prompt_tokens") or 0) for row in rows),
        "completion_tokens": sum(
            int(row.get("completion_tokens") or 0) for row in rows
        ),
        "worst_latency": max(
            (float(row.get("latency") or 0.0) for row in rows), default=0.0
        ),
        "cost_usd": round(
            sum(float(row.get("cost_usd") or 0.0) for row in rows), 6
        ),
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
        "coverage": coverage(log),
        "abduction": abduction_summary(log),
        "findings_deduplicated": findings_deduplicated(log),
        "llm_cost": llm_cost_summary(log),
    }


__all__ = [
    "CAPABILITY_CHECK_TECHNIQUES",
    "Finding",
    "GRADE_PROSE",
    "LLM_JUNCTION_EVENT",
    "PROVABILITY_WEIGHT_HELD",
    "PROVABILITY_WEIGHT_PROVABLE",
    "SEVERITY_WEIGHTS",
    "SEVERITY_WEIGHT_UNKNOWN",
    "SESSION_B_REFUSAL_MARKER",
    "abduction_summary",
    "arm_key",
    "blocked_on_session_b",
    "blocked_on_session_b_split",
    "candidates",
    "llm_cost_summary",
    "coverage",
    "findings",
    "findings_deduplicated",
    "gate_audit",
    "holding_pen_summary",
    "leads",
    "provability_weight",
    "receipts_by_arm",
    "report_lines",
    "session_b_refusals",
    "severity_weight",
    "summary",
    "verdicts",
]
