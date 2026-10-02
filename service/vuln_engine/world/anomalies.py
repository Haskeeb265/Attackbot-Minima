"""The anomaly ledger: retained surprises, append-only, status derived.

PRD §6.4, amendment A1: the store is a JSONL ledger under the same discipline
as ``world.jsonl`` — one typed dict per atomic fact, derived views, no rewrite,
clock-free. The engine has no database dependency and this module adds none.

Two row types only:

``anomaly.retained``
    A surprise was retained (mirrors the world log's own ``anomaly.retained``
    row; :meth:`AnomalyLedger.ingest` copies them, idempotently, so the ledger
    is a *derived* store rather than a second thing the driver must remember to
    write).

``anomaly.status``
    The anomaly moved through its lifecycle (``open → abduced → resolved`` or
    ``→ demoted``). Status is never stored on the retained row and never edited
    in place: the current status is the last status row for a key, recomputed by
    :meth:`AnomalyLedger.entries`.

The bank-ledger rule again: the current status is derived, the ledger wins.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..kernel.anomaly import (
    ANOMALY_OPEN,
    ANOMALY_STATUSES,
    Anomaly,
    anomaly_key,
)
from .log import EVENT_ANOMALY_RETAINED, read_rows
from .views import LogView

#: Row type for a status transition. The retained row reuses the world log's
#: constant so the two stores cannot disagree on spelling.
ROW_RETAINED = EVENT_ANOMALY_RETAINED
ROW_STATUS = "anomaly.status"

#: Where a per-engagement ledger lives, relative to the engagement directory.
DEFAULT_NAME = "world/anomalies.jsonl"


class AnomalyLedger:
    """Append-only JSONL ledger of retained anomalies and their status."""

    def __init__(self, path: Path | str | None = None) -> None:
        self._path = Path(path) if path else None
        self._rows: list[dict] = []
        if self._path is not None and self._path.is_file():
            self._rows = read_rows(self._path)

    @property
    def path(self) -> Path | None:
        return self._path

    def __len__(self) -> int:
        return len(self.retained_rows())

    # ------------------------------------------------------------------ #
    # writing
    # ------------------------------------------------------------------ #

    def _append(self, row_type: str, *, at: float, **fields: Any) -> dict:
        row: dict = {"type": row_type, "at": round(float(at), 3)}
        row.update(fields)
        try:
            line = json.dumps(row, sort_keys=False, allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise TypeError(
                f"anomaly-ledger row {row_type!r} is not serialisable ({exc}); a "
                "row that cannot be read back would be silently lost on replay"
            ) from exc
        if self._path is not None:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(line + "\n")
        self._rows.append(row)
        return row

    def retain(self, *, technique: str, arm: str, deviation: dict, at: float) -> Anomaly:
        """Retain one typed deviation, keyed by its predicate cell."""
        key = anomaly_key(technique, arm, deviation)
        self._append(
            ROW_RETAINED,
            at=at,
            key=key,
            technique=technique,
            arm=arm,
            deviation=dict(deviation),
        )
        return Anomaly(key=key, technique=technique, arm=arm, deviation=dict(deviation), at=at)

    def ingest(self, log: LogView) -> int:
        """Mirror a world log's retained anomalies into this ledger, once.

        Idempotent by key: a ledger that already holds a cell is not written
        again, so replaying an engagement into an existing ledger is a no-op
        rather than a duplicate. Returns the number of new cells retained.
        """
        known = {entry.key for entry in self.entries()}
        added = 0
        for row in log.events(EVENT_ANOMALY_RETAINED):
            technique = str(row.get("technique", ""))
            arm = str(row.get("arm", ""))
            for deviation in row.get("deviations") or []:
                key = anomaly_key(technique, arm, deviation)
                if key in known:
                    continue
                known.add(key)
                self._append(
                    ROW_RETAINED,
                    at=float(row.get("at") or 0.0),
                    key=key,
                    technique=technique,
                    arm=arm,
                    deviation=dict(deviation),
                )
                added += 1
        return added

    def set_status(self, key: str, status: str, *, at: float, note: str = "") -> dict:
        """Append a status transition for *key*.

        The ledger is append-only, so this never edits the retained row; the
        current status is recomputed from the transitions. An unknown status is
        refused here rather than surviving to confuse a view.
        """
        if status not in ANOMALY_STATUSES:
            raise ValueError(
                f"unknown anomaly status {status!r}; known: "
                f"{', '.join(ANOMALY_STATUSES)}"
            )
        if self.get(key) is None:
            raise KeyError(f"no retained anomaly with key {key!r}")
        return self._append(ROW_STATUS, at=at, key=key, status=status, note=note)

    # ------------------------------------------------------------------ #
    # reading (derived)
    # ------------------------------------------------------------------ #

    def retained_rows(self) -> list[dict]:
        return [dict(row) for row in self._rows if row.get("type") == ROW_RETAINED]

    def status_rows(self) -> list[dict]:
        return [dict(row) for row in self._rows if row.get("type") == ROW_STATUS]

    def entries(self) -> list[Anomaly]:
        """Every retained anomaly with its current (last) status, sorted by key."""
        current: dict[str, dict] = {}
        for row in self.retained_rows():
            current[str(row.get("key", ""))] = row
        for row in self.status_rows():
            key = str(row.get("key", ""))
            if key in current:
                current[key]["status"] = row.get("status", ANOMALY_OPEN)
                current[key]["note"] = row.get("note", "")
        entries = [
            Anomaly(
                key=str(row.get("key", "")),
                technique=str(row.get("technique", "")),
                arm=str(row.get("arm", "")),
                deviation=dict(row.get("deviation") or {}),
                status=str(row.get("status", ANOMALY_OPEN) or ANOMALY_OPEN),
                at=float(row.get("at") or 0.0),
                note=str(row.get("note", "")),
            )
            for row in current.values()
        ]
        return sorted(entries, key=lambda entry: entry.key)

    def get(self, key: str) -> Anomaly | None:
        for entry in self.entries():
            if entry.key == key:
                return entry
        return None

    def open_entries(self) -> list[Anomaly]:
        """The abducer's inbox: retained and not yet explained."""
        return [entry for entry in self.entries() if entry.status == ANOMALY_OPEN]


__all__ = [
    "DEFAULT_NAME",
    "ROW_RETAINED",
    "ROW_STATUS",
    "AnomalyLedger",
]
