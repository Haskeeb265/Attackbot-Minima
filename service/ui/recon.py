"""The recon half of the UI: per-pipeline logs, run records, the graph state.

Every function is read-only and artifact-shaped: the same files the recon
pipelines already write (``recon_<target>_*.log`` per stage,
``output/runs/`` summaries, ``graph_state.json``) are what this module reads
back — the UI adds no second pipeline, no second place truth lives.

The log convention is ``run_recon.py``'s: one ``recon_<apex>_<stage>_<stamp>.log``
per pipeline per engagement at the repo root. ``latest_run_log`` picks the
newest log matching a stage glob; ``run_logs`` returns every log whose mtime
falls inside a run's window (or the newest per stage when no window is
known), which is how a UI shows "the logs of the recon module" for the run
that produced the artifacts on screen.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from service.ui.artifacts import ROOT, read_json

#: Per-stage log globs, in run order (the same order run_recon.py's jobs run).
STAGE_GLOBS: tuple[tuple[str, str], ...] = (
    ("subdomain", "recon_{target}_subdomain_*.log"),
    ("ports", "recon_{target}_ports_*.log"),
    ("url", "recon_{target}_url_*.log"),
    ("asn", "recon_{target}_asn_*.log"),
    ("cloud", "recon_{target}_cloud_*.log"),
    ("names", "recon_{target}_names_*.log"),
)

_LOG_STEM = re.compile(
    r"^recon_(?P<target>.+)_(?P<stage>subdomain|ports|url|asn|cloud|names)_(?P<stamp>\d{8}_\d{6})(?:_r(?P<round>\d+))?\.log$"
)

#: Per-stage caps. A passive source log can hold thousands of lines; the UI
#: asks for a tail, not the whole file, and the cap keeps one careless
#: ``?limit=0`` from serialising a hundred megabytes into one response.
MAX_TAIL_LINES = 5000
DEFAULT_TAIL_LINES = 400


def _logs_dir() -> Path:
    """Where engagement logs live (the repo root, run_recon.py's convention)."""
    return ROOT


def tail_text(path: Path, limit: int) -> list[str]:
    """The last *limit* lines of a text file, oldest-first.

    Line-oriented reads keep a huge log cheap: the whole file is never held in
    memory, only the tail. A missing file is an empty list — a stage that
    never ran has no log, which is information, not an error.
    """
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            lines = handle.readlines()
    except FileNotFoundError:
        return []
    except OSError:
        return []
    if limit > 0 and len(lines) > limit:
        return [line.rstrip("\r\n") for line in lines[-limit:]]
    return [line.rstrip("\r\n") for line in lines]


def _stage_logs(target: str, stage: str, glob: str) -> list[Path]:
    """Every log for one stage, newest first (stamp sorts lexically)."""
    pattern = glob.format(target=target)
    return sorted(_logs_dir().glob(pattern), key=lambda p: p.name, reverse=True)


def latest_run_log(target: str, stage: str) -> Path | None:
    """The newest log for one stage of one target, or None."""
    for _name, glob in STAGE_GLOBS:
        if _name == stage:
            logs = _stage_logs(target, stage, glob)
            return logs[0] if logs else None
    return None


def run_logs(target: str, *, after: float = 0.0, before: float = 0.0) -> list[dict]:
    """The recon logs of one engagement, per stage.

    With a time window (a run record's started_at/finished_at), the logs whose
    mtime falls inside it — the logs that engagement actually wrote. Without
    one, the newest log per stage: what an operator means by "the recon logs"
    when they have not picked a run yet.
    """
    picked: list[dict] = []
    for stage, glob in STAGE_GLOBS:
        candidates = _stage_logs(target, stage, glob)
        if not candidates:
            continue
        if after or before:
            chosen = [
                p
                for p in candidates
                if (not after or p.stat().st_mtime >= after - 1.0)
                and (not before or p.stat().st_mtime <= before + 1.0)
            ]
            if not chosen:
                continue
        else:
            chosen = [candidates[0]]
        for path in chosen:
            try:
                mtime = path.stat().st_mtime
            except OSError:
                continue
            # The full path travels (not just the name): the consumer
            # re-checks it with safe_resolve against this module's ROOT, so
            # the boundary travels with the value rather than being assumed.
            picked.append(
                {
                    "stage": stage,
                    "path": str(path),
                    "mtime": mtime,
                }
            )
    return picked


def list_known_targets() -> list[str]:
    """Every target a recon run or engine run has ever produced artifacts for."""
    targets: set[str] = set()
    for path in ROOT.glob("recon_*_subdomain_*.log"):
        match = _LOG_STEM.match(path.name)
        if match:
            targets.add(match.group("target"))
    runs_root = ROOT / "output" / "runs"
    if runs_root.is_dir():
        targets.update(
            child.name for child in runs_root.iterdir() if child.is_dir()
        )
    engine_root = ROOT / "output" / "vuln_engine"
    if engine_root.is_dir():
        targets.update(
            child.name for child in engine_root.iterdir() if child.is_dir()
        )
    return sorted(targets)


# --------------------------------------------------------------------------- #
# runs
# --------------------------------------------------------------------------- #


def read_runs(limit: int = 40) -> list[dict]:
    """The shared run timeline, newest first (the platform appends one row per run)."""
    rows: list[dict] = []
    path = ROOT / "output" / "runs" / "runs.jsonl"
    if path.is_file():
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if isinstance(row, dict):
                rows.append(row)
    return rows[-limit:] if limit > 0 else rows


# --------------------------------------------------------------------------- #
# the graph
# --------------------------------------------------------------------------- #

#: Node caps for the API response. graph_state.json can hold thousands of
#: nodes; the UI asks for the top-scored slice and the counts, and the
#: client-side graph draws what it is given.
DEFAULT_NODE_CAP = 120
MAX_NODE_CAP = 500


def graph_state_path(target: str | None = None) -> Path:
    """The graph_state.json for *target*, or the default handoff location."""
    if target:
        candidate = ROOT / "output" / "runs" / target
        if candidate.is_dir():
            stamps = sorted((child for child in candidate.iterdir() if child.is_dir()))
            for stamp in reversed(stamps):
                candidate_file = stamp / "graph_state.json"
                if candidate_file.is_file():
                    return candidate_file
    return (
        ROOT
        / "service"
        / "recon_pipeline"
        / "pipelines"
        / "graph_normalize"
        / "output"
        / "graph_state.json"
    )


def graph_overview(
    target: str | None = None,
    *,
    cap: int = DEFAULT_NODE_CAP,
    kind: str = "",
    query: str = "",
) -> dict:
    """The widened attack surface as one document: counts + a drawable slice.

    Nodes are sorted by score (highest attention first), optionally filtered
    by kind prefix and a substring of identity, and capped. Edges are limited
    to those whose endpoints both survived the cap, so what the client draws
    is always a consistent subgraph of the real one — never a graph with
    dangling ends.
    """
    path = graph_state_path(target)
    if not path.is_file():
        return {"available": False, "reason": f"no graph_state.json at {path}"}
    doc = read_json(path)
    if not doc:
        return {"available": False, "reason": f"graph_state.json at {path} is unreadable"}

    nodes = doc.get("nodes") or []
    edges = doc.get("edges") or []

    wanted = [n for n in nodes if isinstance(n, dict)]
    if kind:
        wanted = [n for n in wanted if str(n.get("kind", "")).startswith(kind)]
    if query:
        needle = query.lower()
        wanted = [
            n
            for n in wanted
            if needle in str(n.get("identity", "")).lower()
            or needle in str(n.get("id", "")).lower()
        ]

    def _score(node: dict) -> float:
        score = node.get("score")
        if score is None:
            return -1.0
        try:
            return float(score)
        except (TypeError, ValueError):
            return -1.0

    wanted.sort(key=_score, reverse=True)
    kept = wanted[: max(1, min(cap, MAX_NODE_CAP))]
    kept_ids = {n.get("id") for n in kept}
    kept_edges = [
        e
        for e in edges
        if isinstance(e, dict) and e.get("source") in kept_ids and e.get("target") in kept_ids
    ]

    by_kind: dict[str, int] = {}
    by_trust: dict[str, int] = {}
    by_scope: dict[str, int] = {}
    for node in nodes:
        if not isinstance(node, dict):
            continue
        node_kind = str(node.get("kind", "unknown"))
        by_kind[node_kind] = by_kind.get(node_kind, 0) + 1
        trust = str(node.get("trust", "unknown"))
        by_trust[trust] = by_trust.get(trust, 0) + 1
        scope_state = str((node.get("props") or {}).get("scope_state", ""))
        if scope_state:
            by_scope[scope_state] = by_scope.get(scope_state, 0) + 1

    return {
        "available": True,
        "path": str(path),
        "target": doc.get("target"),
        "generated_at": doc.get("generated_at"),
        "integrity": doc.get("integrity") or {},
        "counts": {
            "nodes": len(nodes),
            "edges": len(edges),
            "shown_nodes": len(kept),
            "shown_edges": len(kept_edges),
        },
        "by_kind": dict(sorted(by_kind.items(), key=lambda kv: -kv[1])),
        "by_trust": by_trust,
        "by_scope": by_scope,
        "nodes": [
            {
                "id": n.get("id"),
                "kind": n.get("kind"),
                "identity": n.get("identity"),
                "score": n.get("score"),
                "band": n.get("band"),
                "trust": n.get("trust"),
                "evidence_state": n.get("evidence_state"),
                "scope_state": (n.get("props") or {}).get("scope_state", ""),
                "scope_reason": (n.get("props") or {}).get("scope_reason", ""),
            }
            for n in kept
        ],
        "edges": [
            {
                "source": e.get("source"),
                "target": e.get("target"),
                "type": e.get("type"),
                "relationship": e.get("relationship"),
            }
            for e in kept_edges
        ],
    }


__all__ = [
    "DEFAULT_NODE_CAP",
    "DEFAULT_TAIL_LINES",
    "MAX_NODE_CAP",
    "MAX_TAIL_LINES",
    "STAGE_GLOBS",
    "graph_overview",
    "graph_state_path",
    "latest_run_log",
    "list_known_targets",
    "read_runs",
    "run_logs",
    "tail_text",
]
