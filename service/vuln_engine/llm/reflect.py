"""Junction 5 — reflect: what did the response teach us, and what next?

The upstream complement of synthesize. The synthesize junction asks the model
for a *payload shape*; this junction asks it for a *decision*: after a
hypothesis's own probes ran and its interpretation came back empty, is there
a probe from the technique's **own already-run grammar** worth re-asking once
— a jitter check on an anomalous timing pair, a fresh sample after a flaky
5xx — or should the arm settle?

This is the "investigation" the one-pass engine lacks (the RnD addendum's
M1): the honest zero currently comes from one population per probe, and a
single outlier or one failed request among a family is indistinguishable
from a settled answer. The reflect junction's input is exactly the typed
observation summary the driver already holds — statuses, elapsed times,
contexts seen, which probes ran — and **never a response body** (the
quarantined-LLM rule; the whitelist here is the same discipline
``write.finding_input`` applies to findings).

The honesty rule that gives the model no room to act: its only non-stop
action is ``recheck`` naming a probe id **the technique already ran this
pass**. It cannot invent probes, cannot reorder the grammar, cannot raise
the budget — the driver bounds the loop at two reflected rounds per
hypothesis and refuses any id outside the pass's own specs. An answer that
drifts from that is a degraded opinion and the loop ends, which is exactly
the one-pass behavior the engine had before this junction existed.
"""

from __future__ import annotations

from collections.abc import Callable

#: The driver's bound on reflected rounds per hypothesis. Two is the budget the
#: RnD addendum declared: enough to re-ask one anomalous reading and survive
#: one flaky sample, small enough that a confused model cannot turn one arm
#: into a burst.
MAX_REFLECT_ROUNDS = 2

#: The observation payload fields the junction may see. Typed structural
#: fields only — a response body never enters the prompt, and neither does
#: anything the target's content could influence beyond these measured facts.
OBSERVATION_FIELDS = ("status", "elapsed", "timing_class", "context", "ok", "error")

#: The actions the answer may take. Deliberately two: anything richer
#: (payload synthesis, surface switching) belongs to other junctions.
ACTION_STOP = "stop"
ACTION_RECHECK = "recheck"


def _clean_str(value: object) -> str:
    return str(value).strip() if value is not None else ""


def build_input(
    hypothesis: dict,
    probe_rows: list[dict],
    observations_summary: list[dict],
) -> dict:
    """The junction's input, as plain typed data — the digest's content.

    ``probe_rows``: ``{id, purpose, oracle}`` for every spec the technique's
    own grammar declared this pass. ``observations_summary``: one row per
    executed probe — whitelisted payload fields only, plus the probe id.
    Aggregation is deterministic; the same pass always yields the same
    digest, so a replay finds the cached opinion.
    """
    return {
        "hypothesis": {
            "id": _clean_str(hypothesis.get("id")),
            "claim": _clean_str(hypothesis.get("claim")),
            "oracle": _clean_str(hypothesis.get("oracle", "")),
        },
        "probes": [
            {
                "id": _clean_str(row.get("id")),
                "purpose": _clean_str(row.get("purpose")),
                "oracle": _clean_str(row.get("oracle")),
            }
            for row in sorted(probe_rows, key=lambda row: str(row.get("id", "")))
        ],
        "observations": [
            {key: row.get(key) for key in OBSERVATION_FIELDS if key in row}
            | {"probe": _clean_str(row.get("probe"))}
            for row in observations_summary
        ],
    }


def build_prompt(input: dict) -> tuple[str, str]:
    """The (prompt, system) pair: a pass summary in, one decision out."""
    lines = [
        "A vulnerability-testing technique just finished probing one hypothesis",
        "and its deterministic interpretation found nothing. You decide whether",
        "one already-run probe is worth re-asking once (a flaky sample, an",
        "anomalous timing pair) or whether the arm should settle.",
        "",
        f"Hypothesis: {input['hypothesis']['claim']}",
        "",
        "The probes this technique ran, with what each measured:",
    ]
    seen_by_probe: dict[str, list[dict]] = {}
    for row in input["observations"]:
        seen_by_probe.setdefault(row.get("probe", ""), []).append(row)
    for probe in input["probes"]:
        lines.append(f"- {probe['id']} (purpose: {probe['purpose']})")
        for row in seen_by_probe.get(probe["id"], []):
            facts = ", ".join(
                f"{key}={row[key]}" for key in OBSERVATION_FIELDS if key in row
            )
            lines.append(f"    observed: {facts or 'nothing usable'}")
    lines.append("")
    lines.append(
        'Answer with JSON only: {"action": "stop"} to settle, or'
        ' {"action": "recheck", "probe_id": "<one of the probe ids above>",'
        ' "reason": "<one short factual phrase>"} to re-ask one already-run'
        " probe once. Recheck only when the recorded readings look anomalous"
        " or incomplete for what that probe was measuring — never to fish for"
        " a different answer."
    )
    system = (
        "You are an advisory reflection module inside an authorized vulnerability-scanning"
        " engine. You read typed measurement summaries of the operator's own probes and"
        " decide between settling an arm and re-asking one probe the technique already"
        " ran. You never invent probes, never write payloads, never see response bodies,"
        " and your output is one JSON object."
    )
    return "\n".join(lines), system


def validate_answer(known_probe_ids: set[str]) -> Callable[[dict], str]:
    """Build the validator over the pass's own probe ids.

    A ``recheck`` naming an id the pass did not run is the one failure this
    junction must never let through: it would be the model directing the
    engine's spend, not reflecting on it. The refusal degrades the opinion
    whole and the driver's loop ends — the one-pass behavior, unchanged.
    """

    def _validate(answer: dict) -> str:
        action = _clean_str(answer.get("action"))
        if action == ACTION_STOP:
            return "validated (stop)"
        if action != ACTION_RECHECK:
            raise ValueError(f"action {action!r} is neither stop nor recheck")
        probe_id = _clean_str(answer.get("probe_id"))
        if probe_id not in known_probe_ids:
            raise ValueError(
                f"recheck names probe {probe_id!r}, which this pass did not run"
            )
        reason = _clean_str(answer.get("reason"))
        if len(reason) > 200:
            raise ValueError("reason over 200 chars")
        return f"validated (recheck {probe_id})"

    return _validate


def extract(answer: dict, known_probe_ids: set[str]) -> tuple[str, str, str]:
    """``(action, probe_id, reason)`` from a validated answer, deterministically.

    Re-applies the validation rules so a replay recomputing from the logged
    answer gets exactly what the original run used. An unusable answer
    extracts to ``("stop", "", "")`` — settle, never guess.
    """
    try:
        validate_answer(known_probe_ids)(answer)
    except ValueError:
        return ACTION_STOP, "", ""
    action = _clean_str(answer.get("action"))
    if action == ACTION_STOP:
        return ACTION_STOP, "", ""
    return ACTION_RECHECK, _clean_str(answer.get("probe_id")), _clean_str(answer.get("reason"))


__all__ = [
    "ACTION_RECHECK",
    "ACTION_STOP",
    "MAX_REFLECT_ROUNDS",
    "OBSERVATION_FIELDS",
    "build_input",
    "build_prompt",
    "extract",
    "validate_answer",
]
