"""Junction 7 — abduce: explain a surprise, or propose a property unasked.

The LLM half of the abductive loop (PRD §6.5 implementations 2 and 3; A3). Two
channels share one discipline:

* **abduction** — given a retained anomaly (typed deviation: technique, arm,
  predicate cell, observed value), the declared surfaces, the claim ontology,
  and the anomaly memory, propose explanations. An explanation is a *place to
  look*: a declared surface plus a claim shape the ontology names. The model
  chooses where; the plan table still supplies the experiment.
* **property proposal** — from static context alone (surface rows: url, param,
  capability, label), with no anomaly as trigger, propose semantic properties
  that deserve testing (e.g. "invoice ids are sequential ⇒ object-read across
  accounts"). This is A3's channel: the external evidence is that L3-class
  hypotheses arise from models reading semantic context, not only from observed
  surprises.

The honesty rule both channels obey: **every proposal names a claim shape the
engine can speak and a surface the operator already declared**. The model cannot
invent a target, a claim vocabulary, or a conclusion. It returns a bounded list
of ``{surface_key, claim_shape, vuln_class, why}`` rows; anything else — an
unknown surface, an unknown shape, an over-cap list — degrades the opinion
whole. The input is typed structural fields only (the quarantined-LLM rule):
no response bodies, ever.

The returned rows are *not* hypotheses yet. ``abduction.proposal.proposal_for``
turns a validated row into a Proposal whose plan is a real row of the plan
table, and the three-valued validator decides whether any verifier can prove
it. That is the junction's whole influence: it directs attention; the engine
still decides expressibility and still earns findings through the verifier.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from ..kernel.claim import CLAIM_SHAPES

#: How many explanations one abduction answer may carry.
MAX_ABDUCED = 6
#: How many properties one property answer may carry (A3: a smaller budget).
MAX_PROPERTIES = 8
#: How many surfaces the prompt may carry, deterministically ordered.
MAX_SURFACES = 60
#: How many memory cells the prompt may carry.
MAX_MEMORY_CELLS = 30

#: The vuln-class token shape a proposal may name (a canonical class or a novel
#: hyphenated token); the vocabulary itself lives in ``kernel.vuln_class``.
VULN_CLASS_RE = re.compile(r"^[a-z][a-z0-9-]{1,40}$")


def _clean_str(value: object) -> str:
    return str(value).strip() if value is not None else ""


def needs_verifier_for(claim_shape: str) -> str:
    """The confirm kind a claim shape would need, for the pen to name."""
    if claim_shape == "state_change":
        return "state_change.replay"
    return "authorization.differential"


def ontology_rows() -> list[dict]:
    """The claim vocabulary the prompt may offer, with what each needs.

    Built from the one authority (``kernel.claim.CLAIM_SHAPES``), so the prompt
    cannot offer a shape the engine does not speak.
    """
    help_text = {
        "object_read": (
            "the low-privilege session can read an object the owner reads; "
            "provable at differential today"
        ),
        "state_change": (
            "a state change on one endpoint reaches a resource another session "
            "reads; speakable, but no re-executing verifier yet"
        ),
    }
    return [
        {
            "claim_shape": shape,
            "needs_verifier": needs_verifier_for(shape),
            "note": help_text.get(shape, ""),
        }
        for shape in CLAIM_SHAPES
    ]


def surface_rows(surfaces) -> list[dict]:
    """Whitelisted, bounded, deterministically-ordered surface rows for a prompt."""
    rows = [
        {
            "key": surface.key,
            "url": surface.url,
            "param": surface.param,
            "capability": surface.capability,
            "label": (surface.label or "")[:120],
        }
        for surface in surfaces
    ]
    rows.sort(key=lambda row: row["key"])
    return rows[:MAX_SURFACES]


def memory_cells(memory: dict | None) -> list[dict]:
    """Whitelisted, bounded anomaly-memory cells for a prompt."""
    if not isinstance(memory, dict):
        return []
    cells = []
    for cell in (memory.get("cells") or [])[:MAX_MEMORY_CELLS]:
        if not isinstance(cell, dict):
            continue
        cells.append(
            {
                "technique": _clean_str(cell.get("technique")),
                "kind": _clean_str(cell.get("kind")),
                "probe_suffix": _clean_str(cell.get("probe_suffix")),
                "field": _clean_str(cell.get("field")),
                "count": int(cell.get("count") or 0),
            }
        )
    return cells


def build_abduce_input(
    anomaly: dict,
    surfaces,
    *,
    memory: dict | None = None,
) -> dict:
    """The abduction junction's input, as typed data (the digest's content)."""
    expected = anomaly.get("expected") or {}
    observed = anomaly.get("observed") or {}
    return {
        "anomaly": {
            "technique": _clean_str(anomaly.get("technique")),
            "arm": _clean_str(anomaly.get("arm")),
            "kind": _clean_str(anomaly.get("kind")),
            "probe_suffix": _clean_str(expected.get("probe_suffix")),
            "field": _clean_str(expected.get("field")),
            "within": list(expected.get("within") or []),
            "observed_value": observed.get("value"),
        },
        "surfaces": surface_rows(surfaces),
        "ontology": ontology_rows(),
        **({"memory": memory_cells(memory)} if memory_cells(memory) else {}),
    }


def build_abduce_prompt(input: dict) -> tuple[str, str]:
    """The (prompt, system) pair: a surprise in, places-to-look out."""
    anomaly = input["anomaly"]
    lines = [
        "A vulnerability-testing technique measured the target and got a",
        "surprise: a predicate it expected to hold did not.",
        "",
        "The surprise:",
        f"- technique {anomaly['technique']} on arm {anomaly['arm']}",
        f"- predicate: probe ending {anomaly['probe_suffix']!r}, field"
        f" {anomaly['field']!r}, expected one of {anomaly['within']}",
        f"- observed value: {anomaly['observed_value']!r}",
        "",
        "The declared surfaces you may point at (copy the key exactly):",
    ]
    for row in input.get("surfaces", []):
        lines.append(
            f"- {row['key']}  url={row['url']}  param={row['param']}"
            f"  capability={row['capability']}"
        )
    lines.append("")
    lines.append("The claim shapes the engine can speak, and what each needs:")
    for row in input.get("ontology", []):
        lines.append(
            f"- {row['claim_shape']}: {row['note']} (needs {row['needs_verifier']})"
        )
    memory = input.get("memory") or []
    if memory:
        lines.append("")
        lines.append(
            "Predicate cells previous engagements retained (do not re-propose a"
            " cell already explained unless the evidence changed):"
        )
        for cell in memory:
            lines.append(
                f"- {cell['technique']} {cell['kind']} {cell['probe_suffix']}"
                f" {cell['field']} x{cell['count']}"
            )
    lines.append("")
    lines.append(
        f"Answer with JSON only: {{\"hypotheses\": [{{\"surface_key\": \"<\u2026>\","
        f" \"claim_shape\": \"<one of the shapes above>\", \"vuln_class\":"
        f" \"<a short lowercase-hyphen class>\", \"summary\": \"<one sentence>\","
        f" \"why\": \"<one short factual phrase>\"}}]}}."
        f" At most {MAX_ABDUCED}; an empty list is valid when the surprise looks"
        f" like a measurement problem, not a vulnerability."
    )
    system = (
        "You are an advisory abduction module inside an authorized vulnerability-scanning"
        " engine. You read typed measurements of the operator's own probes and propose"
        " places the engine should look. You never invent surfaces or claim shapes, never"
        " write payloads, never see response bodies, and never conclude anything — your"
        " output is one JSON object."
    )
    return "\n".join(lines), system


def build_property_input(surfaces) -> dict:
    """The property channel's input: static context only, no anomaly."""
    return {
        "surfaces": surface_rows(surfaces),
        "ontology": ontology_rows(),
    }


def build_property_prompt(input: dict) -> tuple[str, str]:
    """The (prompt, system) pair: static context in, properties out."""
    lines = [
        "Below are surfaces an operator declared on an authorized target. With no",
        "measurement to go on, propose semantic properties worth testing — what",
        "the names, parameters and declared capabilities suggest could be broken.",
        "",
        "Declared surfaces (copy the key exactly):",
    ]
    for row in input.get("surfaces", []):
        label = f"  label={row['label']}" if row["label"] else ""
        lines.append(
            f"- {row['key']}  url={row['url']}  param={row['param']}"
            f"  capability={row['capability']}{label}"
        )
    lines.append("")
    lines.append("The claim shapes the engine can speak, and what each needs:")
    for row in input.get("ontology", []):
        lines.append(
            f"- {row['claim_shape']}: {row['note']} (needs {row['needs_verifier']})"
        )
    lines.append("")
    lines.append(
        f"Answer with JSON only: {{\"properties\": [{{\"surface_key\": \"<\u2026>\","
        f" \"claim_shape\": \"<one of the shapes above>\", \"vuln_class\":"
        f" \"<a short lowercase-hyphen class>\", \"why\": \"<one short factual"
        f" phrase>\"}}]}}. At most {MAX_PROPERTIES}; an empty list is valid when"
        f" nothing in the names suggests a testable property."
    )
    system = (
        "You are an advisory property-proposal module inside an authorized"
        " vulnerability-scanning engine. From static surface context alone you assert"
        " only falsifiable properties about where the engine should look. You never"
        " invent surfaces or claim shapes and your output is one JSON object."
    )
    return "\n".join(lines), system


def _validate_rows(
    rows: object,
    *,
    list_name: str,
    cap: int,
    known_surface_keys: set[str],
) -> str:
    if not isinstance(rows, list):
        raise ValueError(f"'{list_name}' is not a list")
    if len(rows) > cap:
        raise ValueError(f"proposes {len(rows)} {list_name}, over the {cap} cap")
    seen: set[tuple[str, str]] = set()
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError(f"{list_name}[{index}] is not an object")
        surface_key = _clean_str(row.get("surface_key"))
        if surface_key not in known_surface_keys:
            raise ValueError(
                f"{list_name}[{index}] names surface {surface_key!r}, which the"
                " operator did not declare"
            )
        shape = _clean_str(row.get("claim_shape"))
        if shape not in CLAIM_SHAPES:
            raise ValueError(
                f"{list_name}[{index}] claim_shape {shape!r} is not one the engine speaks"
            )
        vuln_class = _clean_str(row.get("vuln_class"))
        if not VULN_CLASS_RE.match(vuln_class):
            raise ValueError(
                f"{list_name}[{index}] has an unusable vuln_class {vuln_class!r}"
            )
        if len(_clean_str(row.get("why"))) > 200:
            raise ValueError(f"{list_name}[{index}] why over 200 chars")
        if len(_clean_str(row.get("summary"))) > 300:
            raise ValueError(f"{list_name}[{index}] summary over 300 chars")
        key = (surface_key, shape)
        if key in seen:
            continue
        seen.add(key)
    return f"validated ({len(seen)} distinct {list_name} over {len(known_surface_keys)} surface(s))"


def validate_answer(
    list_name: str, cap: int, known_surface_keys: set[str]
) -> Callable[[dict], str]:
    """The validator for one channel's answer, over the declared surface set."""

    def _validate(answer: dict) -> str:
        return _validate_rows(
            answer.get(list_name),
            list_name=list_name,
            cap=cap,
            known_surface_keys=known_surface_keys,
        )

    return _validate


def _extract_rows(
    rows: object,
    *,
    list_name: str,
    known_surface_keys: set[str],
) -> list[dict]:
    if not isinstance(rows, list):
        return []
    extracted: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        surface_key = _clean_str(row.get("surface_key"))
        shape = _clean_str(row.get("claim_shape"))
        if surface_key not in known_surface_keys or shape not in CLAIM_SHAPES:
            continue
        key = (surface_key, shape)
        if key in seen:
            continue
        seen.add(key)
        extracted.append(
            {
                "surface_key": surface_key,
                "claim_shape": shape,
                "vuln_class": _clean_str(row.get("vuln_class")) or "novel",
                "summary": _clean_str(row.get("summary")),
                "why": _clean_str(row.get("why")),
            }
        )
    return extracted


def extract(answer: dict, *, list_name: str, cap: int, known_surface_keys: set[str]) -> list[dict]:
    """The usable rows from a validated answer, deterministically."""
    try:
        validate_answer(list_name, cap, known_surface_keys)(answer)
    except ValueError:
        return []
    return _extract_rows(answer.get(list_name), list_name=list_name, known_surface_keys=known_surface_keys)


__all__ = [
    "MAX_ABDUCED",
    "MAX_MEMORY_CELLS",
    "MAX_PROPERTIES",
    "MAX_SURFACES",
    "VULN_CLASS_RE",
    "build_abduce_input",
    "build_abduce_prompt",
    "build_property_input",
    "build_property_prompt",
    "extract",
    "memory_cells",
    "needs_verifier_for",
    "ontology_rows",
    "surface_rows",
    "validate_answer",
]
