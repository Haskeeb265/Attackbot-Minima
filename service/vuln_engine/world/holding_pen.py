"""The holding pen: hypotheses the verifier vocabulary cannot confirm yet.

PRD §6.7, amendment A1 (a JSONL ledger, not a table) and A4 (promotion is a
code change, not an out-of-band flag). A hypothesis that is *expressible* but
whose claim needs a confirm kind the engine does not have goes here, with the
verifier it would need named on the entry. It is the backlog of the verifier
vocabulary, made explicit instead of lost.

Three row types, append-only like every ledger in this engine:

``holding_pen.entry``    a hypothesis was held
``holding_pen.promoted`` it left because a new confirm kind landed (a PR — A4)
``holding_pen.demoted``  it left because the process declined to pursue it

The rule this module enforces: a held hypothesis leaves the pen exactly once,
by one of those two doors, and never by a grade change. Transitioning an entry
that never existed, or that already left, is refused.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..kernel.claim import CLAIM_SHAPES

#: Waiting for a confirm kind.
PEN_HELD = "held"
#: A new confirm kind landed; a PR moved the claim shape into the registry.
PEN_PROMOTED = "promoted"
#: Declined: duplicate, stale, or judged not worth a verifier.
PEN_DEMOTED = "demoted"

PEN_STATUSES: tuple[str, ...] = (PEN_HELD, PEN_PROMOTED, PEN_DEMOTED)

ROW_ENTRY = "holding_pen.entry"
ROW_PROMOTED = "holding_pen.promoted"
ROW_DEMOTED = "holding_pen.demoted"

DEFAULT_NAME = "world/holding_pen.jsonl"


class HoldingPen:
    """Append-only JSONL ledger of held hypotheses and their transitions."""

    def __init__(self, path: Path | str | None = None) -> None:
        self._path = Path(path) if path else None
        self._rows: list[dict] = []
        if self._path is not None and self._path.is_file():
            from .log import read_rows

            self._rows = read_rows(self._path)

    @property
    def path(self) -> Path | None:
        return self._path

    def _append(self, row_type: str, *, at: float, **fields: Any) -> dict:
        row: dict = {"type": row_type, "at": round(float(at), 3)}
        row.update(fields)
        try:
            line = json.dumps(row, sort_keys=False, allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise TypeError(
                f"holding-pen row {row_type!r} is not serialisable ({exc})"
            ) from exc
        if self._path is not None:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(line + "\n")
        self._rows.append(row)
        return row

    # ------------------------------------------------------------------ #
    # writing
    # ------------------------------------------------------------------ #

    def hold(
        self,
        *,
        key: str,
        hypothesis: dict,
        claim_shape: str,
        needs_verifier: str,
        at: float,
    ) -> dict:
        """Hold one hypothesis that needs *needs_verifier* to be confirmable."""
        if not key:
            raise ValueError("a held hypothesis needs a key")
        if claim_shape not in CLAIM_SHAPES:
            raise ValueError(
                f"unknown claim shape {claim_shape!r}; known: "
                f"{', '.join(CLAIM_SHAPES)}"
            )
        if not needs_verifier:
            raise ValueError(
                "a held hypothesis must name the verifier it needs; an unnamed "
                "need is a graveyard entry"
            )
        existing = self.get(key)
        if existing is not None and existing["status"] == PEN_HELD:
            return existing  # already held: idempotent, no duplicate row
        if existing is not None:
            raise ValueError(
                f"hypothesis {key!r} already left the pen as "
                f"{existing['status']!r}; it cannot be re-held with the same key"
            )
        return self._append(
            ROW_ENTRY,
            at=at,
            key=key,
            hypothesis=dict(hypothesis),
            claim_shape=claim_shape,
            needs_verifier=needs_verifier,
            status=PEN_HELD,
        )

    def promote(self, key: str, *, at: float, note: str = "") -> dict:
        """Promote a held entry — the code change that landed its confirm kind.

        A4: there is no schedule or metric path here; the caller is the PR.
        """
        return self._transition(key, PEN_PROMOTED, at=at, note=note)

    def demote(self, key: str, *, at: float, note: str = "") -> dict:
        """Demote a held entry — declined, duplicate, or stale."""
        return self._transition(key, PEN_DEMOTED, at=at, note=note)

    def _transition(self, key: str, status: str, *, at: float, note: str) -> dict:
        existing = self.get(key)
        if existing is None:
            raise KeyError(f"no held hypothesis with key {key!r}")
        if existing["status"] != PEN_HELD:
            raise ValueError(
                f"hypothesis {key!r} already left the pen as "
                f"{existing['status']!r}; it cannot leave again"
            )
        row_type = ROW_PROMOTED if status == PEN_PROMOTED else ROW_DEMOTED
        return self._append(row_type, at=at, key=key, status=status, note=note)

    # ------------------------------------------------------------------ #
    # reading (derived)
    # ------------------------------------------------------------------ #

    def entries(self) -> list[dict]:
        """Every held hypothesis with its current status, sorted by key."""
        current: dict[str, dict] = {}
        for row in self._rows:
            if row.get("type") == ROW_ENTRY:
                entry = dict(row)
                entry["status"] = row.get("status", PEN_HELD)
                current[str(row.get("key", ""))] = entry
        for row in self._rows:
            if row.get("type") not in (ROW_PROMOTED, ROW_DEMOTED):
                continue
            key = str(row.get("key", ""))
            if key in current:
                current[key]["status"] = row.get("status", PEN_HELD)
                current[key]["note"] = row.get("note", "")
                current[key]["left_at"] = row.get("at", 0.0)
        return [current[key] for key in sorted(current)]

    def get(self, key: str) -> dict | None:
        for entry in self.entries():
            if entry.get("key") == key:
                return entry
        return None

    def held(self) -> list[dict]:
        """The pen's live contents — the verifier-vocabulary backlog."""
        return [entry for entry in self.entries() if entry["status"] == PEN_HELD]


__all__ = [
    "DEFAULT_NAME",
    "PEN_DEMOTED",
    "PEN_HELD",
    "PEN_PROMOTED",
    "PEN_STATUSES",
    "ROW_DEMOTED",
    "ROW_ENTRY",
    "ROW_PROMOTED",
    "HoldingPen",
]
