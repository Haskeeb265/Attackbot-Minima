"""The world model's event log: append-only JSONL, and the only place truth lives.

One line per atomic fact, and every line carries the ``at`` the *caller* passed
in. Nothing in this module reads a clock, and that is not fastidiousness: a module
that reads the clock cannot be replayed, and replay is how this engine is tested
offline against its own recorded engagements.

The bank-ledger rule, which is the whole design of this module:

    Balance is derived; the ledger wins. Nothing else holds state.

So there is no ``set``, no ``update``, no rewrite, and no in-memory model that
must be kept in sync. :class:`WorldLog` appends; :mod:`..world.views` derives
whatever a consumer wants to see from the rows. Two consequences worth stating
because they are the reason for the shape:

* **an engagement can pause for a week and resume coherently** — a run is a log,
  not a session;
* **a refusal is an observation, not an error** — a ``gate.decision`` row with
  ``verb=DENY`` and a reason is data, and it replays like any other fact.

Rows are ``{"type": …, "at": float, …typed fields}``. A row that will not
serialise raises rather than being escaped into a string: a log line that cannot
be read back is worse than no line, because replay would silently lose it.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

from ..kernel.observation import Observation

#: Row types.  Named constants rather than loose strings so the replay path and
#: the views cannot disagree on spelling.
EVENT_BEGIN = "run.begin"
EVENT_EFFECT_REQUEST = "effect.request"
EVENT_EFFECT_RESULT = "effect.result"
EVENT_INTERNAL = "effect.internal"
EVENT_GATE_DECISION = "gate.decision"
EVENT_CANDIDATE = "candidate"
#: A candidate the Phase 3 synthesize junction proposed from a model's
#: (validated, grammar-bounded) answer. A separate row type on purpose: the pure
#: replay recomputes the techniques' own candidates and must not count these
#: against itself — the model's answer is recorded fact, like an effect's
#: result, not a derivation. The verification layer refuses these on sight:
#: the model that shaped a payload must never also be its proof.
EVENT_CANDIDATE_JUNCTION = "candidate.junction"
EVENT_VERDICT = "verdict"
EVENT_RECEIPT = "receipt"
EVENT_NOTE = "note"
EVENT_END = "run.end"


class WorldLog:
    """Append-only JSONL event log.

    ``path=None`` builds an in-memory log: the tests use it, and so does a
    dry-run, because the alternative is a test that has to be *given* a temp
    directory to assert on a decision.

    The file is a **ledger that may span many runs** — that is what makes an
    engagement resumable — and a view of it may need to describe *one* run.
    :meth:`since` hands out a window over this log's rows without copying or
    re-reading anything; the driver builds each run's report through it, so a
    second run into the same directory cannot resell the first run's findings.
    """

    def __init__(self, path: Path | str | None = None) -> None:
        self._path = Path(path) if path else None
        self._rows: list[dict] = []
        if self._path is not None and self._path.is_file():
            self._rows = self.read(self._path)

    def since(self, at: float) -> "WorldLogWindow":
        """A read-only view of the rows appended at or after *at*.

        A cheap wrapper, not a copy: it holds a reference to this log's live row
        list and an index, so rows this run appends after the call are part of the
        window too. Reporting through the window is what keeps a run's report
        about its own work when the file already holds earlier runs.
        """
        return WorldLogWindow(self, at)

    # ------------------------------------------------------------------ #
    # writing
    # ------------------------------------------------------------------ #

    def append(self, event_type: str, *, at: float, **fields: Any) -> dict:
        """Append one row.  *at* is required and supplied by the caller.

        Passing the timestamp in is what makes a run reproducible: two replays of
        the same log produce the same decisions, and a test can assert on a fake
        clock instead of sleeping.
        """
        row: dict = {"type": event_type, "at": round(float(at), 3)}
        row.update(fields)
        try:
            line = json.dumps(row, sort_keys=False, allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise TypeError(
                f"world-log row {event_type!r} is not serialisable ({exc}); a row that "
                "cannot be read back would be silently lost on replay"
            ) from exc
        if self._path is not None:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(line + "\n")
        self._rows.append(row)
        return row

    def observation(self, observation: Observation) -> dict:
        """Append a typed observation row."""
        row: dict = {"kind": observation.kind, "payload": dict(observation.payload)}
        if observation.probe:
            row["probe"] = observation.probe
        return self.append(_OBSERVATION, at=observation.at, **row)

    # ------------------------------------------------------------------ #
    # reading
    # ------------------------------------------------------------------ #

    @staticmethod
    def read(path: Path | str) -> list[dict]:
        """Every readable row at *path*; a missing file is an empty log.

        A corrupt line costs one record rather than the file — the same
        tolerance the receipts ledger takes, and for the same reason: a run's
        record must survive a partial write.
        """
        file = Path(path)
        if not file.is_file():
            return []
        rows: list[dict] = []
        for line in file.read_text(encoding="utf-8", errors="replace").splitlines():
            stripped = line.strip()
            if not stripped.startswith("{"):
                continue
            try:
                row = json.loads(stripped)
            except (json.JSONDecodeError, ValueError):
                continue
            if isinstance(row, dict) and "type" in row:
                rows.append(row)
        return rows

    @property
    def path(self) -> Path | None:
        return self._path

    def __len__(self) -> int:
        return len(self._rows)

    def __iter__(self) -> Iterator[dict]:
        return iter(self._rows)

    @property
    def rows(self) -> list[dict]:
        """A copy of every row, in the order they were written."""
        return [dict(row) for row in self._rows]

    def events(self, *types: str) -> list[dict]:
        """Rows of the given types, in order; no arguments means every row."""
        wanted = set(types)
        return [
            dict(row)
            for row in self._rows
            if not wanted or str(row.get("type", "")) in wanted
        ]
    def observations(self) -> list[Observation]:
        """Rebuild typed observations from the log — the replay path's entry point.

        This is the one function that makes "the log *is* the environment for
        testing" true rather than a slogan: everything the pure half of the engine
        needs is recoverable from here, so a replay needs no network at all.
        """
        seen: list[Observation] = []
        for row in self._rows:
            if str(row.get("type", "")) != _OBSERVATION:
                continue
            seen.append(
                Observation.from_dict(
                    {
                        "kind": row.get("kind", ""),
                        "payload": row.get("payload") or {},
                        "probe": row.get("probe", ""),
                        "at": row.get("at", 0.0),
                    }
                )
            )
        return seen

    def observations_by_probe(self) -> dict[str, list[Observation]]:
        """Observations grouped by the probe that produced them."""
        grouped: dict[str, list[Observation]] = {}
        for observation in self.observations():
            grouped.setdefault(observation.probe, []).append(observation)
        return grouped

    def summary(self) -> dict[str, int]:
        """``{row type: count}`` — the report-shaped summary of the log itself."""
        counts: dict[str, int] = {}
        for row in self._rows:
            token = str(row.get("type", ""))
            counts[token] = counts.get(token, 0) + 1
        return dict(sorted(counts.items()))


#: The one row type that is not an "event": an observation.  Kept as a private
#: constant so ``observations()`` and ``observation()`` cannot drift apart.
_OBSERVATION = "observation"


class WorldLogWindow:
    """A read-only slice of a :class:`WorldLog` — one run's view of the ledger.

    Exists for one reason: a report must describe the run that produced it, and
    the file a run appends to may already hold earlier runs. The window forwards
    the log's read API over the rows appended since it was taken, and exposes no
    way to write — appending goes through the log, so the ledger stays append-only
    and whole.
    """

    #: Rows are stored with ``at`` rounded to 3 decimals, so membership is tested
    #: with half a rounding unit of slack: a row appended exactly at the window's
    #: start (the run's own ``begin`` row) must never round out of its own window.
    _EPSILON = 0.0005

    def __init__(self, log: WorldLog, at: float) -> None:
        self._log = log
        self._at = at

    def _mine(self, row: dict) -> bool:
        return float(row.get("at", 0.0)) >= self._at - self._EPSILON

    @property
    def path(self) -> Path | None:
        return self._log.path

    def __len__(self) -> int:
        return sum(1 for row in self._log if self._mine(row))

    def __iter__(self) -> Iterator[dict]:
        return iter(self.rows)

    @property
    def rows(self) -> list[dict]:
        """Copies of this run's rows, in the order they were written."""
        return [dict(row) for row in self._log if self._mine(row)]

    def events(self, *types: str) -> list[dict]:
        wanted = set(types)
        return [
            dict(row)
            for row in self._log
            if self._mine(row)
            and (not wanted or str(row.get("type", "")) in wanted)
        ]

    def observations(self) -> list[Observation]:
        """Typed observations rebuilt from this run's rows only."""
        seen: list[Observation] = []
        for row in self.events(_OBSERVATION):
            seen.append(
                Observation.from_dict(
                    {
                        "kind": row.get("kind", ""),
                        "payload": row.get("payload") or {},
                        "probe": row.get("probe", ""),
                        "at": row.get("at", 0.0),
                    }
                )
            )
        return seen

    def summary(self) -> dict[str, int]:
        """``{row type: count}`` over this run's rows only."""
        counts: dict[str, int] = {}
        for row in self.rows:
            token = str(row.get("type", ""))
            counts[token] = counts.get(token, 0) + 1
        return dict(sorted(counts.items()))


def read_rows(path: Path | str) -> list[dict]:
    """Module-level convenience for a consumer that only has a path."""
    return WorldLog.read(path)


def write_summary(log: WorldLog, keys: Iterable[str] = ()) -> dict[str, Any]:
    """A small derived block for a report: counts by row type, plus *keys*."""
    summary: dict[str, Any] = {"rows": len(log), "by_type": log.summary()}
    for key in keys:
        summary[key] = [row for row in log.rows if row.get(key)]
    return summary


__all__ = [
    "EVENT_BEGIN",
    "EVENT_CANDIDATE",
    "EVENT_CANDIDATE_JUNCTION",
    "EVENT_END",
    "EVENT_EFFECT_REQUEST",
    "EVENT_EFFECT_RESULT",
    "EVENT_GATE_DECISION",
    "EVENT_INTERNAL",
    "EVENT_NOTE",
    "EVENT_RECEIPT",
    "EVENT_VERDICT",
    "WorldLog",
    "WorldLogWindow",
    "read_rows",
    "write_summary",
]
