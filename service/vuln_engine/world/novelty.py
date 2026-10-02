"""Novelty levels: L0–L4 computed, not asserted (PRD §6.12, NOVELTY.md §3).

The engine's north star is a *measured* novelty level, never a claimed one. This
module computes it from facts the log already holds, with an ordered decision
tree whose every branch is a state NOVELTY.md names:

===========  ==========================================================
``L0``       duplicate — the same experiment is already in the registry or
             the log (a hand-written technique firing its own class, or a
             signature already seen this run)
``L1``       probe novelty — a known structural hypothesis with a new probe
             (a registry technique naming a class its manifest does not)
``L2``       composition novelty — known primitives combined into a
             previously absent experiment (a plan-table row: the data-row
             mechanism itself)
``L3``       structural novelty — a previously unseen relationship proposed
             through a model channel (abduction / property proposal)
``L4``       new security property — the same, naming a class with no
             representation in the hypothesis library
===========  ==========================================================

The classifier reads provenance, not prose: whether the hypothesis came from a
hand-written registry technique, from a plan row, or through the LLM channel
(``abduction.proposed`` / ``property.proposed``), and whether its class is
canonical. It is deterministic and clock-free, so a replay recomputes the same
levels from the same log — the property that makes the level a fact rather than
a boast.
"""

from __future__ import annotations

from dataclasses import dataclass, field as _field
from urllib.parse import urlsplit

from ..kernel.vuln_class import vuln_class_status

#: Claim shapes the *registry* can already generate: ``object_read`` is the
#: two-session read ``idor_differential`` performs. A model channel that proposes
#: one of these is proposing a known invariant — a novel *name* for it is L3
#: (structural novelty in the channel), never L4 (a new security property), per
#: NOVELTY.md §3's "a paraphrase of IDOR is L0 no matter who proposed it".
REGISTRY_EXPERIMENTS: frozenset[str] = frozenset({"object_read"})

#: Levels, ascending. A name per level so a report never carries a bare number.
LEVEL_DUPLICATE = 0
LEVEL_PROBE = 1
LEVEL_COMPOSITION = 2
LEVEL_STRUCTURAL = 3
LEVEL_PROPERTY = 4

LEVEL_LABELS: dict[int, str] = {
    LEVEL_DUPLICATE: "duplicate",
    LEVEL_PROBE: "probe novelty",
    LEVEL_COMPOSITION: "composition novelty",
    LEVEL_STRUCTURAL: "structural novelty",
    LEVEL_PROPERTY: "new security property",
}
LEVEL_NAMES: dict[int, str] = {level: f"L{level}" for level in LEVEL_LABELS}

#: Rules the model channels stamp on a proposal; anything else is deterministic.
LLM_RULES: tuple[str, ...] = ("llm_abduction",)


@dataclass(frozen=True)
class NoveltyFacts:
    """The provenance one finding's hypothesis carries, as the classifier reads it."""

    vuln_class: str
    technique: str
    #: The hypothesis was built from a plan row (the data-row mechanism) — L2.
    from_plan: bool = False
    #: The hypothesis came through a model channel (abduction/property) — L3/L4.
    from_llm: bool = False
    #: The kind of claim the experiment makes (``object_read`` / ``state_change``
    #: / ``""``), so the classifier can tell a novel *name* from a novel
    #: *experiment* (see ``REGISTRY_EXPERIMENTS``).
    claim_shape: str = ""
    #: A signature identifying the experiment, for the duplicate check.
    signature: str = ""
    #: Why the classifier read these facts — carried into the report verbatim.
    note: str = ""


def level_for(
    facts: NoveltyFacts,
    *,
    seen: frozenset[str] | set[str] = frozenset(),
    duplicated_surface: bool = False,
) -> dict:
    """The novelty level for one finding, with a recordable reason.

    Ordered, as the table above: a duplicate is a duplicate however clever the
    mechanism; a model proposal over a novel class is the top rung; a plan row
    is a composition; a hand-written technique is probe novelty at best.
    """
    status = vuln_class_status(facts.vuln_class)
    canonical = status == "canonical"

    if facts.signature and facts.signature in seen:
        return _result(LEVEL_DUPLICATE, "the same experiment signature already occurred in this run")
    if facts.from_llm:
        if duplicated_surface and facts.claim_shape in REGISTRY_EXPERIMENTS:
            return _result(
                LEVEL_DUPLICATE,
                "a model channel re-proposed an experiment a registry technique already "
                "proved on this surface — a paraphrase of a known finding, L0",
            )
        if facts.claim_shape in REGISTRY_EXPERIMENTS:
            return _result(
                LEVEL_STRUCTURAL,
                f"a model channel proposed {facts.claim_shape!r}, an experiment the "
                "registry already generates — structural novelty, not a new property",
            )
        if not canonical:
            return _result(
                LEVEL_PROPERTY,
                f"a model channel named class {facts.vuln_class!r}, which no registry entry represents",
            )
        return _result(LEVEL_STRUCTURAL, "a model channel proposed an experiment no registry entry generates")
    if facts.from_plan:
        return _result(LEVEL_COMPOSITION, "known predicates composed into a plan-row experiment")
    if canonical:
        return _result(LEVEL_DUPLICATE, "a hand-written technique proving its own canonical class")
    return _result(LEVEL_PROBE, "a known structural hypothesis carrying a class its manifest does not")


def _result(level: int, reason: str) -> dict:
    return {
        "level": level,
        "name": LEVEL_NAMES[level],
        "label": LEVEL_LABELS[level],
        "reason": reason,
    }


def facts_for_finding(
    finding: dict,
    *,
    hypotheses: list[dict],
    rules_by_plan: dict[str, str] | None = None,
) -> NoveltyFacts:
    """Derive a finding's provenance from the log's own rows.

    ``hypotheses`` are the ``note`` rows' ``hypothesis`` dicts; a finding whose
    candidate id ends with a hypothesis's ``plan.plan_id`` came from that plan
    row. ``rules_by_plan`` maps a ``plan_id`` to the rule an abducer stamped on
    it (``abduction.proposed`` rows), so a model-proposed experiment classifies
    as L3/L4 rather than L2.
    """
    technique = str(finding.get("technique", ""))
    candidate_id = str(finding.get("candidate_id", ""))
    vuln_class = str(finding.get("vuln_class", ""))
    rules = rules_by_plan or {}
    match: dict | None = None
    for hypothesis in hypotheses:
        if str(hypothesis.get("technique", "")) != technique:
            continue
        plan = hypothesis.get("plan") or {}
        plan_id = str(plan.get("plan_id", ""))
        if plan_id and candidate_id.endswith(plan_id):
            match = hypothesis
            break
    plan = (match or {}).get("plan") or {}
    plan_id = str(plan.get("plan_id", ""))
    rule = rules.get(plan_id, "")
    # A model proposal and the plan table's own row share a plan id (both build
    # ``object_read:{key}``), so the plan id alone cannot say which channel
    # proved the finding: a deterministic finding would inherit the model's
    # rule and inflate from L2 to L3. The **arm** disambiguates — the ordinary
    # pass keys it by the surface, the abduced round by the plan id — so only a
    # finding that ran through the abduced arm is model-proven. An empty arm
    # (no arm recorded) falls back to the rule, as before.
    arm = str(finding.get("arm", ""))
    abduced_arm = f"{technique}@{plan_id}" if plan_id else ""
    from_llm = rule in LLM_RULES and (not arm or arm == abduced_arm)
    signature = "|".join(
        [technique, vuln_class, report_plan_digest(match) or str(finding.get("summary", ""))]
    )
    return NoveltyFacts(
        vuln_class=vuln_class,
        technique=technique,
        from_plan=bool(plan),
        from_llm=from_llm,
        claim_shape=str(plan.get("claim_shape", "")),
        signature=signature,
    )


def report_plan_digest(hypothesis: dict | None) -> str:
    """The plan digest a hypothesis note carried, or ``\"\"``."""
    if not hypothesis:
        return ""
    return str(hypothesis.get("plan_digest", ""))


def rules_by_plan(log) -> dict[str, str]:
    """``{plan_id: rule}`` from the log's ``abduction.proposed`` rows."""
    mapping: dict[str, str] = {}
    for row in log.events("abduction.proposed"):
        proposal = row.get("proposal") or {}
        plan = proposal.get("plan") or {}
        plan_id = str(plan.get("plan_id", ""))
        rule = str(proposal.get("rule", ""))
        if plan_id and rule:
            mapping.setdefault(plan_id, rule)
    return mapping


def levels_for_log(log) -> dict[str, dict]:
    """``{candidate_id: level}`` for every proven finding on *log*.

    Deterministic: the same log always yields the same levels and reasons, so a
    replay can recompute them and a report can carry them without hand-labeling.
    """
    from . import views

    # Both the ordinary pass (``hypothesis``) and the abduced round
    # (``hypothesis.abduced``) log their hypothesis dicts; a finding from either
    # must be matched to its plan, or an abduced L2/L3/L4 finding would classify
    # as a bare duplicate (L0) for want of provenance.
    hypotheses = [
        row.get("hypothesis") or {}
        for row in log.events("note")
        if row.get("stage") in ("hypothesis", "hypothesis.abduced")
    ]
    rules = rules_by_plan(log)
    seen: set[str] = set()
    out: dict[str, dict] = {}
    findings = views.findings(log)
    facts_by_finding = [
        (
            finding,
            facts_for_finding(
                finding.to_dict(), hypotheses=hypotheses, rules_by_plan=rules
            ),
        )
        for finding in findings
    ]
    # Surfaces a *non-model* finding already proved: a model finding on one of
    # them re-proposed a known experiment, so it is a duplicate however novel its
    # class name (NOVELTY.md §3).
    registry_surfaces = {
        _surface_key(finding.surface)
        for finding, facts in facts_by_finding
        if not facts.from_llm
    }
    for finding, facts in facts_by_finding:
        result = level_for(
            facts,
            seen=seen,
            duplicated_surface=_surface_key(finding.surface) in registry_surfaces,
        )
        if facts.signature:
            seen.add(facts.signature)
        # First occurrence wins: a forced campaign re-runs an arm and re-proves
        # the same finding, and those later rows are duplicates (L0). The
        # finding's novelty is established when it is first proven, so a
        # duplicate row must not overwrite the genuine level for the same id.
        out.setdefault(
            finding.candidate_id,
            {**result, "vuln_class": finding.vuln_class, "technique": finding.technique},
        )
    return out


def _surface_key(surface: dict) -> tuple[str, str]:
    """The ``(host, path)`` an experiment targets — the duplicate key.

    Coarser than an experiment signature, and only consulted for a claim shape
    the registry already generates (``REGISTRY_EXPERIMENTS``): a plan-row
    candidate carries its *plan id* as ``param``, so the param cannot be part of
    the match. Two techniques reading the same endpoint through different names
    must still collide — the doctrine is that a paraphrase of a known finding is
    not novelty.
    """
    url = str(surface.get("url", ""))
    host = str(surface.get("host", "") or (urlsplit(url).hostname or "")).lower()
    return (host, urlsplit(url).path)


def summarize(levels: dict[str, dict]) -> dict:
    """Counts by level, for the per-run instrumentation metric."""
    counts = {LEVEL_NAMES[level]: 0 for level in LEVEL_LABELS}
    for entry in levels.values():
        counts[entry["name"]] = counts.get(entry["name"], 0) + 1
    return {
        "findings": len(levels),
        "by_level": counts,
        "max_level": max((entry["level"] for entry in levels.values()), default=LEVEL_DUPLICATE),
    }


__all__ = [
    "LEVEL_COMPOSITION",
    "LEVEL_DUPLICATE",
    "LEVEL_LABELS",
    "LEVEL_NAMES",
    "LEVEL_PROBE",
    "LEVEL_PROPERTY",
    "LEVEL_STRUCTURAL",
    "LLM_RULES",
    "NoveltyFacts",
    "facts_for_finding",
    "level_for",
    "levels_for_log",
    "report_plan_digest",
    "rules_by_plan",
    "summarize",
]
