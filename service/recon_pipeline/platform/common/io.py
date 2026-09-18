"""Deterministic, atomic IO helpers — the one convention for every artifact.

Extracted from the port pipeline's ``normalize.py`` (the most complete copy)
so no pipeline re-implements file writing and the conventions cannot drift:

* **Atomic replace** (temp sibling + rename) — a reader, or a crashed run,
  never observes a half-written artifact.
* **Sorted + deduplicated** where the helper's contract says so.
* **Missing input is a state, not an exception** — several inputs are optional
  (an operator's scope file, a sibling's resolver pool) and their absence must
  degrade, not raise.
* **One corrupt JSONL line costs one record**, never the file.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from pathlib import Path


def read_text(path: Path | str) -> str:
    """Read a text file, returning ``""`` when it is missing or unreadable."""
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def read_lines(path: Path | str) -> list[str]:
    """Read non-blank lines (comments with ``#`` stripped, whitespace trimmed)."""
    lines: list[str] = []
    for line in read_text(path).splitlines():
        token = line.split("#", 1)[0].strip()
        if token:
            lines.append(token)
    return lines


def read_jsonl(path: Path | str) -> list[dict]:
    """Read JSON-lines into dicts, skipping blank and malformed lines."""
    records: list[dict] = []
    for line in read_text(path).splitlines():
        stripped = line.strip()
        if not stripped.startswith("{"):
            continue
        try:
            payload = json.loads(stripped)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(payload, dict):
            records.append(payload)
    return records


def write_lines(path: Path | str, lines: Iterable[str]) -> Path:
    """Write newline-terminated lines atomically."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    body = "".join(f"{line}\n" for line in lines if line)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(body, encoding="utf-8", newline="\n")
    tmp.replace(path)
    return path


def write_jsonl(path: Path | str, records: Iterable[Mapping[str, object]]) -> Path:
    """Write one JSON object per line, atomically."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    body = "".join(
        json.dumps(dict(record), sort_keys=False) + "\n" for record in records
    )
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(body, encoding="utf-8", newline="\n")
    tmp.replace(path)
    return path


def write_json(path: Path | str, payload: object) -> Path:
    """Write a JSON document, atomically."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(
        json.dumps(payload, indent=2, sort_keys=False), encoding="utf-8", newline="\n"
    )
    tmp.replace(path)
    return path
