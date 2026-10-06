"""The step-by-step trace: how the engine did the work, for either flow.

The UI's other engine panels answer "what happened" one row at a time. This
module answers the operator's actual question — *show me exactly how it did
the work* — by reading one run's append-only ledger and normalizing every row
into an ordered **step**:

* a **phase** (input → measure → propose → reason → plan → execute → judge →
  verdict → output), so the flow's stages are visible, not implied;
* a short **title** describing what the step is;
* and the **raw row**, so no detail is lost.

It serves **both** engines, because both write the same kind of ledger:

* the classic engine writes ``world.jsonl`` + ``report.json``;
* the two-gate engine writes ``twogate.jsonl`` + ``twogate_report.json``.

The two-gate flow is the one that needs this view most: its rows carry the
capability measurements, the LLM junction prompts/answers (the agents'
reasoning), the confirmation specs, and the oracle results — all invisible in
the classic panels.

Read-only, tolerant, and paged by the same append-only **cursor** the world
log uses (a row index, not a timestamp), so a live run can be followed without
gaps or double-counting.
"""

from __future__ import annotations

import json
from pathlib import Path

from service.ui.artifacts import ArtifactError, ROOT, read_json, read_jsonl, safe_resolve

#: Where every engine run lives. Both flows write under here; the two-gate CLI's
#: default output root is ``output/vuln_engine/<target>`` too, which is why a run
#: directory is classified by *which ledger file* it holds, not by its location.
OUTPUT_ROOT = ROOT / "output"
ENGINE_ROOT = OUTPUT_ROOT / "vuln_engine"

#: Ledger filenames per flow, and the report each flow writes.
TWOGATE_LOG = "twogate.jsonl"
TWOGATE_REPORT = "twogate_report.json"
CLASSIC_LOG = "world.jsonl"
CLASSIC_REPORT = "report.json"

FLOW_CLASSIC = "classic"
FLOW_TWOGATE = "twogate"

#: A bounded scan for the LLM marker when labelling a run: large campaign logs
#: should not make the run selector slow.
_LLM_SCAN_BYTES = 4_000_000

MAX_ROWS = 2000
DEFAULT_ROWS = 500


# --------------------------------------------------------------------------- #
# discovery
# --------------------------------------------------------------------------- #


def flow_of(directory: Path) -> str:
    """Which engine wrote in *directory* — decided by the ledger it holds."""
    if (directory / TWOGATE_LOG).is_file():
        return FLOW_TWOGATE
    if (directory / CLASSIC_LOG).is_file():
        return FLOW_CLASSIC
    return ""


def log_path(directory: Path, flow: str) -> Path:
    return directory / (TWOGATE_LOG if flow == FLOW_TWOGATE else CLASSIC_LOG)


def report_path(directory: Path, flow: str) -> Path:
    return directory / (TWOGATE_REPORT if flow == FLOW_TWOGATE else CLASSIC_REPORT)


def resolve(key: str) -> Path:
    """A run key (a path relative to ``output/``) as a checked directory.

    Both a bare name (``twogate_dvwa``) and a nested one
    (``vuln_engine/example.test``) are valid keys, so the check cannot be a
    single-segment allowlist — it is ``safe_resolve`` under ``output/``, which
    refuses anything that escapes after ``..`` resolves away.
    """
    parts = [part for part in str(key).split("/") if part not in ("", ".")]
    if not parts or any(part == ".." for part in parts):
        raise ArtifactError(f"invalid run key: {key!r}")
    return safe_resolve(OUTPUT_ROOT, *parts)


def _used_llm(directory: Path, flow: str) -> bool:
    """Whether the run's ledger holds at least one LLM junction row."""
    path = log_path(directory, flow)
    try:
        with path.open("rb") as handle:
            data = handle.read(_LLM_SCAN_BYTES)
    except OSError:
        return False
    return b"llm.junction" in data


def discover() -> list[dict]:
    """Every traceable run, newest activity first.

    Scans the immediate children of ``output/`` and of
    ``output/vuln_engine/`` off one shared root, so both a two-gate run that
    used the CLI default and one written to a bare ``output/<name>`` directory
    are found. A run key is its path relative to ``output/``.
    """
    runs: list[dict] = []
    seen: set[str] = set()
    for parent in (OUTPUT_ROOT, ENGINE_ROOT):
        if not parent.is_dir():
            continue
        for child in sorted(parent.iterdir()):
            if not child.is_dir():
                continue
            flow = flow_of(child)
            if not flow:
                continue
            try:
                key = child.relative_to(OUTPUT_ROOT).as_posix()
            except ValueError:  # pragma: no cover - defensive
                continue
            if key in seen:
                continue
            seen.add(key)
            log = log_path(child, flow)
            report = report_path(child, flow)
            try:
                mtime = max(
                    (p.stat().st_mtime for p in (log, report, child) if p.exists()),
                    default=child.stat().st_mtime,
                )
            except OSError:
                continue
            runs.append(
                {
                    "key": key,
                    "flow": flow,
                    "label": f"{flow} · {key}" + (" · llm" if _used_llm(child, flow) else ""),
                    "log_exists": log.is_file(),
                    "report_exists": report.is_file(),
                    "used_llm": _used_llm(child, flow),
                    "mtime": mtime,
                }
            )
    runs.sort(key=lambda item: -item["mtime"])
    return runs


# --------------------------------------------------------------------------- #
# row → step normalization
# --------------------------------------------------------------------------- #

#: Row type → phase, for the two-gate ledger. A phase is what makes the flow's
#: stages legible; an unmapped type is ``other`` rather than dropped.
_TWOGATE_PHASE: dict[str, str] = {
    "run.begin": "input",
    "capability.measured": "measure",
    "loop.round": "propose",
    "llm.junction": "reason",
    "confirmation.planned": "plan",
    "confirmation.spec": "spec",
    "effect.request": "request",
    "gate.decision": "gate",
    "effect.result": "result",
    "effect.internal": "internal",
    "confirmation.executed": "judge",
    "confirmation.refused": "judge",
    "candidate": "candidate",
    "verdict": "verdict",
    "lead.classified": "lead",
    "loop.stopped": "stop",
    "run.end": "output",
}

#: Row type → phase, for the classic ledger.
_CLASSIC_PHASE: dict[str, str] = {
    "run.begin": "input",
    "scheduler.pick": "plan",
    "note": "note",
    "effect.request": "request",
    "gate.decision": "gate",
    "effect.result": "result",
    "observation": "observe",
    "candidate": "candidate",
    "candidate.junction": "candidate",
    "verdict": "verdict",
    "receipt": "receipt",
    "llm.junction": "reason",
    "run.end": "output",
}

#: The order phases are shown in when a reader wants the flow, not the clock.
PHASE_ORDER: tuple[str, ...] = (
    "input", "measure", "propose", "reason", "plan", "spec", "request", "gate",
    "result", "internal", "observe", "judge", "candidate", "verdict", "lead",
    "receipt", "note", "stop", "output", "other",
)


def phase_of(row: dict, flow: str) -> str:
    table = _TWOGATE_PHASE if flow == FLOW_TWOGATE else _CLASSIC_PHASE
    return table.get(str(row.get("type", "")), "other")


def title_of(row: dict, flow: str) -> str:
    """A one-line, human title for the step."""
    t = str(row.get("type", ""))
    if t == "run.begin":
        target = row.get("target", "")
        if flow == FLOW_TWOGATE:
            return f"Run begins — target {target}; criteria {row.get('criteria', {})}"
        return (
            f"Run begins — target {target}; "
            f"{len(row.get('techniques') or [])} technique(s) loaded"
        )
    if t == "capability.measured":
        state = "measured" if row.get("measured") else "not measured"
        return f"Capability {state}: {row.get('capability', '')} on {row.get('surface_key', '')}"
    if t == "loop.round":
        return (
            f"Round {row.get('round', '')} on {row.get('surface_key', '')} — "
            f"{row.get('proposed', 0)} proposed, {row.get('fresh', 0)} fresh"
        )
    if t == "llm.junction":
        mode = "degraded" if row.get("degraded") else "live"
        return f"Agent reasoning ({row.get('junction', '')}, {mode}) — model {row.get('model', '—')}"
    if t == "confirmation.planned":
        return f"Planned {row.get('label', '')} via routine {row.get('routine_id', '')} (oracle {row.get('oracle', '')})"
    if t == "confirmation.spec":
        return f"Confirmation spec written for {row.get('surface_key', '')}"
    if t == "confirmation.executed":
        verdict = "held" if row.get("oracle_true") else "did not hold"
        return f"Oracle {verdict}: {row.get('routine_id', '')} on {row.get('surface_key', '')}"
    if t == "confirmation.refused":
        return f"Confirmation refused: {row.get('routine_id', '')} — {row.get('reason', '')}"
    if t == "candidate":
        return f"Candidate proposed: {row.get('vuln_class', '')} — {row.get('summary', '')}"
    if t == "verdict":
        return f"Verdict {'PROVEN' if row.get('proven') else 'REFUSED'} ({row.get('grade', '') or row.get('proposer_grade', '')})"
    if t == "lead.classified":
        return f"Lead classified: {row.get('label', '')} — {row.get('reason', '')}"
    if t == "loop.stopped":
        return f"Stopped on {row.get('surface_key', '')}: {row.get('reason', '')} — {row.get('detail', '')}"
    if t == "gate.decision":
        return f"Gate {row.get('verb', '')} {row.get('host', '')} ({row.get('technique', '')})"
    if t == "effect.request":
        url = (row.get("detail") or {}).get("url") or row.get("operation", "")
        return f"Request → {row.get('kind', '')} {url}"
    if t == "effect.result":
        return (
            f"Response ← status {row.get('status', '—')} "
            f"{row.get('bytes', '')}B {row.get('elapsed', '')}s"
        )
    if t == "effect.internal":
        return f"Internal effect: {row.get('kind', '')} {row.get('url', '')} {row.get('verb', '')}"
    if t == "observation":
        return f"Observation: {row.get('kind', '')}"
    if t == "receipt":
        return f"Receipt: {row.get('arm', '')} → {row.get('outcome', '')}"
    if t == "scheduler.pick":
        return f"Scheduler picked {row.get('technique', '')} on {row.get('surface', '')} — {row.get('reason', '')}"
    if t == "note":
        return f"Note [{row.get('stage', '')}]"
    if t == "run.end":
        return f"Run ends — {json.dumps(row.get('counts', {}), sort_keys=True)}"
    return t or "row"


def step_for(index: int, row: dict, flow: str) -> dict:
    """One ledger row as an ordered step: index, time, phase, title, raw row."""
    return {
        "index": index,
        "at": row.get("at"),
        "type": str(row.get("type", "")),
        "phase": phase_of(row, flow),
        "title": title_of(row, flow),
        "raw": row,
    }


# --------------------------------------------------------------------------- #
# views
# --------------------------------------------------------------------------- #


def _summarize(key: str, flow: str, rows: list[dict]) -> dict:
    by_type: dict[str, int] = {}
    by_phase: dict[str, int] = {}
    gate = {"ALLOW": 0, "DENY": 0, "DEFER": 0}
    findings = 0
    capabilities: dict[str, list[str]] = {}
    surfaces: list[str] = []
    target = ""
    criteria: dict = {}
    for row in rows:
        t = str(row.get("type", ""))
        by_type[t] = by_type.get(t, 0) + 1
        phase = phase_of(row, flow)
        by_phase[phase] = by_phase.get(phase, 0) + 1
        if t == "run.begin":
            target = str(row.get("target", "") or target)
            criteria = row.get("criteria") or criteria
            for surface in row.get("surfaces") or []:
                skey = str(surface.get("url", ""))
                if skey and skey not in surfaces:
                    surfaces.append(skey)
        elif t == "verdict" and row.get("proven"):
            findings += 1
        elif t == "gate.decision":
            verb = str(row.get("verb", ""))
            if verb in gate:
                gate[verb] += 1
        elif t == "capability.measured" and row.get("measured"):
            capabilities.setdefault(str(row.get("surface_key", "")), []).append(
                str(row.get("capability", ""))
            )
    return {
        "key": key,
        "flow": flow,
        "rows": len(rows),
        "by_type": dict(sorted(by_type.items())),
        "by_phase": {phase: by_phase[phase] for phase in PHASE_ORDER if phase in by_phase},
        "findings": findings,
        "gate": gate,
        "target": target,
        "criteria": criteria,
        "surfaces": surfaces,
        "capabilities": {k: sorted(set(v)) for k, v in sorted(capabilities.items())},
    }


def trace_view(
    key: str, *, cursor: int = 0, limit: int = DEFAULT_ROWS
) -> dict:
    """The run's steps from *cursor*, oldest first, plus a whole-ledger summary.

    The cursor is a row index over an append-only file (the same contract the
    world-log view uses): row N is row N forever, so a live run can be followed
    step by step with no gap and no overlap.
    """
    directory = resolve(key)
    flow = flow_of(directory)
    if not flow:
        return {
            "key": key,
            "available": False,
            "reason": "no engine ledger in this directory",
            "steps": [],
            "cursor": 0,
            "next_index": 0,
        }
    rows = read_jsonl(log_path(directory, flow))
    summary = _summarize(key, flow, rows)

    cursor = max(0, min(cursor, len(rows)))
    page = rows[cursor:]
    if limit and limit > 0:
        page = page[: min(limit, MAX_ROWS)]
    steps = [step_for(cursor + offset, row, flow) for offset, row in enumerate(page)]
    next_index = cursor + len(page)
    newest = max((float(row.get("at", 0.0)) for row in rows), default=0.0)
    return {
        "key": key,
        "available": True,
        "flow": flow,
        "summary": summary,
        "steps": steps,
        "count": len(steps),
        "cursor": next_index,
        "next_index": next_index,
        "total_rows": len(rows),
        "newest_at": newest,
    }


def output_view(key: str) -> dict:
    """The run's output — the report it wrote, or a derivation from the ledger.

    The two-gate CLI writes ``twogate_report.json``; the classic single-pass
    runner writes ``report.json``; a classic campaign run writes neither (its
    findings live in the ledger). All three are answered here, so the panel
    ends on the flow's actual output rather than an empty box.
    """
    directory = resolve(key)
    flow = flow_of(directory)
    if not flow:
        return {"key": key, "available": False, "reason": "no engine ledger in this directory"}

    path = report_path(directory, flow)
    report = read_json(path)
    if report:
        return {
            "key": key,
            "flow": flow,
            "available": True,
            "source": path.name,
            "report": report,
        }

    if flow == FLOW_TWOGATE:
        return {
            "key": key,
            "flow": flow,
            "available": False,
            "reason": "the run wrote no twogate_report.json",
        }

    rows = read_jsonl(log_path(directory, flow))
    if not rows:
        return {
            "key": key,
            "flow": flow,
            "available": False,
            "reason": "no report.json and no world log yet",
        }
    return {
        "key": key,
        "flow": flow,
        "available": True,
        "source": "world_log",
        "report": _derive_classic_report(rows),
    }


def _derive_classic_report(rows: list[dict]) -> dict:
    """Findings from a classic ledger when no report.json was written."""
    candidates = {
        str(row.get("id")): row
        for row in rows
        if row.get("type") in ("candidate", "candidate.junction")
    }
    findings: list[dict] = []
    gate = {"ALLOW": 0, "DENY": 0, "DEFER": 0}
    for row in rows:
        if row.get("type") == "verdict" and row.get("proven"):
            candidate = candidates.get(str(row.get("candidate"))) or {}
            findings.append(
                {
                    "vuln_class": candidate.get("vuln_class", ""),
                    "grade": row.get("grade", ""),
                    "summary": candidate.get("summary", ""),
                    "payload": candidate.get("payload", ""),
                    "repro_url": candidate.get("repro_url", ""),
                    "reason": row.get("reason", ""),
                    "proven_at": row.get("at"),
                }
            )
        elif row.get("type") == "gate.decision":
            verb = str(row.get("verb", ""))
            if verb in gate:
                gate[verb] += 1
    return {
        "findings": findings,
        "gate": {"by_verb": gate, "uncleared_effects": None},
        "report_lines": [f"{f['vuln_class']} — {f['grade']} — {f['summary']}" for f in findings],
    }


__all__ = [
    "CLASSIC_LOG",
    "CLASSIC_REPORT",
    "DEFAULT_ROWS",
    "ENGINE_ROOT",
    "FLOW_CLASSIC",
    "FLOW_TWOGATE",
    "MAX_ROWS",
    "OUTPUT_ROOT",
    "PHASE_ORDER",
    "TWOGATE_LOG",
    "TWOGATE_REPORT",
    "discover",
    "flow_of",
    "log_path",
    "output_view",
    "phase_of",
    "report_path",
    "resolve",
    "step_for",
    "title_of",
    "trace_view",
]
