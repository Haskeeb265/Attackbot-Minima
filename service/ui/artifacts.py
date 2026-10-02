"""Shared artifact helpers for the UI: path safety, JSON reading, repo root.

The UI reads only paths the server itself resolves from the repo layout or
from repo artifacts. A client-supplied *name* (a target, a log file name, a
world-log name) is never used to build a path without first being resolved
and checked to still be inside the repo — the same guard a public file
server applies, applied here because a UI that reads files on behalf of a
request is a file server.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class ArtifactError(ValueError):
    """A requested artifact path escaped the repo or was otherwise refused."""


def safe_resolve(root: Path, *parts: str) -> Path:
    """Resolve *parts* under *root* and refuse anything that escapes.

    The check is ``relative_to`` on the resolved path, not a string prefix:
    ``..`` segments resolve away before the comparison, so a symlink or a
    ``?log=../../.env`` request cannot walk out of the tree. The root is an
    explicit argument, not a module constant, because each view module owns
    its artifact root (and a test owns a temp tree) — the caller names the
    boundary, this function enforces it. A path inside is returned resolved;
    anything else raises :class:`ArtifactError`.
    """
    base = Path(root).resolve()
    candidate = base.joinpath(*[p for p in parts if p])
    resolved = candidate.resolve()
    try:
        resolved.relative_to(base)
    except ValueError as exc:
        raise ArtifactError(
            f"refusing path outside {base}: {candidate}"
        ) from exc
    return resolved


def read_json(path: Path) -> dict:
    """A JSON file as a dict; unreadable or non-dict content is an empty dict."""
    try:
        doc = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return {}
    return doc if isinstance(doc, dict) else {}


def read_jsonl(path: Path, limit: int = 0) -> list[dict]:
    """Every readable JSON object from a JSONL file, oldest first.

    ``limit`` keeps the last *limit* rows (a tail). A corrupt line costs one
    row, never the file — the same tolerance the world log and the run
    registry apply to their own writes.
    """
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    rows: list[dict] = []
    for line in lines:
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


def file_tail(path: Path, limit: int) -> list[str]:
    """The last *limit* lines of a text file, oldest-first, as plain strings."""
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            lines = handle.readlines()
    except OSError:
        return []
    if limit > 0 and len(lines) > limit:
        return [line.rstrip("\r\n") for line in lines[-limit:]]
    return [line.rstrip("\r\n") for line in lines]
