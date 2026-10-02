"""The vuln-engine half of the UI: the world log and its report, as views.

``world.jsonl`` is the engine's append-only ledger — every scheduler pick,
hypothesis, gated request, observation, candidate, verdict, receipt and LLM
junction lands there as one JSON row. The UI's job is to show *that*, in
order, as it grows: not a second engine, not a summary that could disagree
with the ledger. "Every step/thinking should be logged and shown in realtime"
is satisfied by tailing the file the engine already writes, because the
engine's own discipline (every decision is a row, no clock reads, the report
is derived from the log) is what makes the tail a faithful view.

``inputs`` assembles what entered the engine on a run: the seed's surfaces
(declared + graph-derived, with provenance), the gate's decision counters,
and the per-technique manifest the run loaded.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from service.ui.artifacts import ROOT, read_json, safe_resolve

#: Where engine runs live: one directory per target (run_engine.py's default).
ENGINE_ROOT = ROOT / "output" / "vuln_engine"

#: Row types the world log uses (service/vuln_engine/world/log.py's constants,
#: spelled here so the view cannot drift from the log's own names).
EVENT_BEGIN = "run.begin"
EVENT_EFFECT_REQUEST = "effect.request"
EVENT_EFFECT_RESULT = "effect.result"
EVENT_GATE_DECISION = "gate.decision"
EVENT_CANDIDATE = "candidate"
EVENT_CANDIDATE_JUNCTION = "candidate.junction"
EVENT_VERDICT = "verdict"
EVENT_RECEIPT = "receipt"
EVENT_NOTE = "note"
EVENT_END = "run.end"
EVENT_OBSERVATION = "observation"
#: LLM junction rows and scheduler picks also land in the log; the UI renders
#: them like any other row rather than special-casing them.
EVENT_LLM_JUNCTION = "llm.junction"
EVENT_SCHEDULER_PICK = "scheduler.pick"
EVENT_REFLECT_RECHECK = "reflect.recheck"

#: Max rows one /api/engine/log response carries. A campaign log can hold
#: tens of thousands of rows; the client polls with ``after`` and pages.
MAX_ROWS = 2000
DEFAULT_ROWS = 500


def list_run_dirs() -> list[dict]:
    """Every engine run directory (one per target), newest activity first."""
    runs: list[dict] = []
    if not ENGINE_ROOT.is_dir():
        return runs
    for child in ENGINE_ROOT.iterdir():
        if not child.is_dir():
            continue
        log = child / "world.jsonl"
        report = child / "report.json"
        try:
            mtime = max(
                (p.stat().st_mtime for p in (log, report, child) if p.exists()),
                default=child.stat().st_mtime,
            )
        except OSError:
            continue
        runs.append(
            {
                "run": child.name,
                "log_exists": log.is_file(),
                "report_exists": report.is_file(),
                "mtime": mtime,
            }
        )
    runs.sort(key=lambda item: -item["mtime"])
    return runs


def resolve_run(name: str) -> Path:
    """A run directory under output/vuln_engine, path-checked against the root."""
    return safe_resolve(ROOT, ENGINE_ROOT.relative_to(ROOT).as_posix(), name)


def log_overview(run: str) -> dict:
    """One run's shape: row counts by type, targets, findings count.

    Derived the way the engine's own views derive: read the ledger, count,
    never invent. A missing log is an empty overview with ``rows: 0`` — the
    UI still renders the panel, honestly empty.
    """
    run_dir = resolve_run(run)
    log_path = run_dir / "world.jsonl"
    rows = _read_rows(log_path)
    by_type: dict[str, int] = {}
    targets: list[str] = []
    verdicts_proven = 0
    verdicts_refused = 0
    candidates = 0
    gate_allow = 0
    gate_deny = 0
    gate_defer = 0
    for row in rows:
        row_type = str(row.get("type", ""))
        by_type[row_type] = by_type.get(row_type, 0) + 1
        if row_type == EVENT_BEGIN:
            target = str(row.get("target", ""))
            if target and target not in targets:
                targets.append(target)
        elif row_type == EVENT_VERDICT:
            if row.get("proven"):
                verdicts_proven += 1
            elif row.get("proven") is False:
                verdicts_refused += 1
        elif row_type in (EVENT_CANDIDATE, EVENT_CANDIDATE_JUNCTION):
            candidates += 1
        elif row_type == EVENT_GATE_DECISION:
            verb = str(row.get("verb", ""))
            if verb == "ALLOW":
                gate_allow += 1
            elif verb == "DENY":
                gate_deny += 1
            elif verb == "DEFER":
                gate_defer += 1
    return {
        "run": run,
        "path": str(log_path),
        "rows": len(rows),
        "by_type": dict(sorted(by_type.items())),
        "targets": targets,
        "findings": verdicts_proven,
        "refused": verdicts_refused,
        "candidates": candidates,
        "gate": {"ALLOW": gate_allow, "DENY": gate_deny, "DEFER": gate_defer},
    }


def log_rows(
    run: str, *, cursor: int = 0, limit: int = DEFAULT_ROWS, after: float = 0.0
) -> dict:
    """Rows from *cursor* (a 0-based index into the ledger), oldest first.

    The realtime contract is a **cursor, not a timestamp**: rows share
    timestamps (a burst of decisions lands within the same millisecond), so
    resuming at ``at > t`` silently drops every same-``at`` row that followed
    the batch boundary — a gap a reader cannot see. The ledger is
    append-only, which is exactly what makes a row index stable: row N is
    row N forever. The client sends back ``next_index`` verbatim and walks
    the ledger in order, poll by poll, never skipping, never re-reading.

    ``after`` (a timestamp floor) is still honoured for a one-shot "show me
    the run from here" query; a cursor greater than 0 wins over it.
    """
    run_dir = resolve_run(run)
    log_path = run_dir / "world.jsonl"
    rows = _read_rows(log_path)

    # How many leading rows are already consumed: exactly the cursor, or —
    # for the one-shot timestamp query — every row at or before *after*.
    if cursor > 0:
        skipped = min(cursor, len(rows))
    elif after > 0:
        skipped = sum(1 for row in rows if float(row.get("at", 0.0)) <= after)
    else:
        skipped = 0
    rows = rows[skipped:]

    if limit and limit > 0:
        rows = rows[: min(limit, MAX_ROWS)]
    next_index = skipped + len(rows)
    newest = max((float(row.get("at", 0.0)) for row in rows), default=0.0)
    return {
        "run": run,
        "count": len(rows),
        "cursor": next_index,
        "next_index": next_index,
        "newest_at": newest,
        "rows": rows,
    }


def inputs_view(run: str) -> dict:
    """What entered the engine on this run's most recent window.

    The seed (declared surfaces, in order, with capability and provenance
    hints), the run's techniques, transport capabilities, and the gate's
    policy counters — read from the newest ``run.begin`` plus the following
    rows, exactly what the engine logged when it accepted the engagement.
    """
    run_dir = resolve_run(run)
    rows = _read_rows(run_dir / "world.jsonl")
    last_begin = None
    last_end_at = -1.0
    for index, row in enumerate(rows):
        if row.get("type") == EVENT_BEGIN:
            last_begin = index
        elif row.get("type") == EVENT_END:
            last_end_at = float(row.get("at", 0.0))
    if last_begin is None:
        return {"run": run, "available": False, "reason": "no run.begin row in the log"}

    begin = rows[last_begin]
    window = [
        row for row in rows[last_begin:]
        if float(row.get("at", 0.0)) >= float(begin.get("at", 0.0)) - 0.0005
    ]
    hypotheses = [
        row.get("hypothesis")
        for row in window
        if row.get("type") == EVENT_NOTE and row.get("stage") == "hypothesis"
    ]
    picks = [row for row in window if row.get("type") == EVENT_SCHEDULER_PICK]
    junction_candidates = [
        row for row in window if row.get("type") == EVENT_CANDIDATE_JUNCTION
    ]
    return {
        "run": run,
        "available": True,
        "at": begin.get("at"),
        "target": begin.get("target"),
        "techniques": begin.get("techniques") or [],
        "surfaces": begin.get("surfaces") or [],
        "capabilities": begin.get("capabilities") or {},
        "hypotheses": hypotheses,
        "scheduler_picks": [
            {
                "technique": pick.get("technique"),
                "surface": pick.get("surface"),
                "reason": pick.get("reason"),
            }
            for pick in picks
        ],
        "junction_candidates": len(junction_candidates),
    }


def report_view(run: str) -> dict:
    """The run's report — report.json when it exists, the ledger otherwise.

    A campaign run (``--campaign``) writes world.jsonl and receipts.jsonl but
    never report.json — that file is the single-pass runner's artifact. The
    findings are still in the ledger (every proven verdict is a row, joined
    here to its candidate's summary/payload/repro), and deriving a view from
    the ledger is exactly what the engine's own report views do. The response
    names its ``source`` so a reader knows which artifact produced it.
    """
    run_dir = resolve_run(run)
    report = read_json(run_dir / "report.json")
    if report:
        return {"run": run, "available": True, "source": "report.json", "report": report}

    rows = _read_rows(run_dir / "world.jsonl")
    if not rows:
        return {"run": run, "available": False, "reason": "no report.json and no world log yet"}
    candidates = {
        str(row.get("id")): row
        for row in rows
        if row.get("type") in (EVENT_CANDIDATE, EVENT_CANDIDATE_JUNCTION)
    }
    findings: list[dict] = []
    gate = {"ALLOW": 0, "DENY": 0, "DEFER": 0}
    for row in rows:
        if row.get("type") == EVENT_VERDICT and row.get("proven"):
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
        elif row.get("type") == EVENT_GATE_DECISION:
            verb = str(row.get("verb", ""))
            if verb in gate:
                gate[verb] += 1
    by_type: dict[str, int] = {}
    for row in rows:
        row_type = str(row.get("type", ""))
        by_type[row_type] = by_type.get(row_type, 0) + 1
    return {
        "run": run,
        "available": True,
        "source": "world_log",
        "report": {
            "findings": findings,
            "gate": {"by_verb": gate, "uncleared_effects": None},
            "counts": dict(sorted(by_type.items())),
            "report_lines": [
                f"{f['vuln_class']} — {f['grade']} — {f['summary']}" for f in findings
            ],
        },
    }


def runs_with_activity() -> dict[str, float]:
    """Run-name → newest activity, for the server's auto-refresh hints."""
    return {item["run"]: item["mtime"] for item in list_run_dirs()}


def _read_rows(log_path: Path) -> list[dict]:
    """Read the ledger tolerantly, in order."""
    if not log_path.is_file():
        return []
    rows: list[dict] = []
    for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict) and "type" in row:
            rows.append(row)
    return rows


__all__ = [
    "DEFAULT_ROWS",
    "ENGINE_ROOT",
    "MAX_ROWS",
    "inputs_view",
    "list_run_dirs",
    "log_overview",
    "log_rows",
    "report_view",
    "resolve_run",
    "runs_with_activity",
]
