"""The graph storage seam — and what the pre-run schema taught us.

**Why there is no schema here.** The original Neo4j schema (20+ labels,
relationship types, constraints, seed ingestion from the scraper's PostgreSQL
tables) was written *before* the first recon run existed. Designing it from the
plan rather than from observations meant every label was a guess about shapes
the collectors had never produced. It was removed on 2026-09-19, after the first
converged run produced `graph_state.json` — 6 476 assets of *observed* reality —
so the next schema can be designed from data instead of imagination. The
discussion it deserves now starts from that document, not from a guess.

Two mechanics survived because the runs *proved* them, and they are facts about
durability, not guesses about shapes:

1. **A run must never fail because storage is down.** The sink degrades to a
   journal: writes are appended to local JSONL, health reports
   ``available=False`` with the reason, and the run's summary shows the
   degradation. That contract was live-verified (Neo4j absent in every run so
   far) and is kept verbatim.
2. **Identity, not insertion.** Whatever schema we settle on, a re-run must
   merge by a canonical identity rather than append a duplicate. The old
   schema's MERGE on ``(asset_type, canonical_value)`` was the right instinct;
   it is recorded here so the new design inherits the requirement, not the code.

What is deliberately **not** kept: the guessed labels, the guessed
relationships, the seed ingestion, and the typed writers — all of it was
committed before a single recon artifact existed to justify it. The journal
below is written schema-agnostically (``asset_type`` + ``canonical_value`` +
``payload``), so whatever we decide in the schema discussion can replay the
records this code preserved in the meantime.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from ..common.io import read_jsonl

log = logging.getLogger("platform.graph.ingest")

JOURNAL_FILE = "graph_journal.jsonl"


@dataclass
class GraphHealth:
    available: bool
    reason: str = ""
    journaled: int = 0

    def to_dict(self) -> dict:
        return {
            "available": self.available,
            "reason": self.reason,
            "journaled": self.journaled,
        }


class GraphSink:
    """The only graph object a pipeline may see, until the schema exists.

    With no schema to write against, ``write()`` records what was *offered* to
    the graph — canonical identity plus payload — into the engagement journal,
    and health reports exactly why nothing was stored. Nothing is invented:
    no labels, no relationships, no fallback shapes.
    """

    def __init__(self, journal_path: Path | None = None) -> None:
        self._journal_path = journal_path
        self.health = GraphHealth(
            available=False,
            reason="no graph database is wired — writes are journaled against the settled schema for the future writer",
        )

    @property
    def journaled(self) -> int:
        return self.health.journaled

    @property
    def available(self) -> bool:
        return self.health.available

    @property
    def journal_path(self) -> Path | None:
        return self._journal_path

    def write(
        self,
        asset_type: str,
        canonical_value: str,
        payload: dict | None = None,
        *,
        source: str = "",
    ) -> bool:
        """Journal one offered write; returns False because nothing was stored.

        The record is the *identity pair* the future schema must merge on, plus
        the payload that justified it — enough for a replay once the schema
        discussion settles. A journal that cannot be written is logged, not
        raised: losing an observation note must not fail an engagement.
        """
        entry = {
            "asset_type": asset_type,
            "canonical_value": canonical_value,
            "source": source,
            "payload": payload or {},
            "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        if self._journal_path is None:
            return False
        try:
            self._journal_path.parent.mkdir(parents=True, exist_ok=True)
            with self._journal_path.open("a", encoding="utf-8", newline="\n") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
            self.health.journaled += 1
        except OSError as exc:
            log.warning("graph journal unwritable (%s); write not recorded", exc)
        return False

    def replay_journal(self) -> int:
        """There is nowhere to replay *to* — say so, and leave the journal alone.

        Returns the count that would be replayed once a schema exists, so the
        operator sees the debt, not a silent success.
        """
        if self._journal_path is None:
            return 0
        try:
            rows = read_jsonl(self._journal_path)
        except OSError:
            return 0
        log.warning(
            "graph journal holds %d write(s) but no schema is defined; nothing was replayed",
            len(rows),
        )
        return 0


def connect_repository():
    """Absent by design: there is no schema to connect a repository against.

    The old implementation returned a live ``Neo4jRepository`` wired to root
    ``config.py`` settings. The new one will be written when the schema
    discussion decides what a node *is* — connection details are the easy part
    and are still in ``config.py`` (``NEO4J_*``).
    """
    raise NotImplementedError(
        "graph repository removed with the pre-run schema; "
        "it returns when the schema is designed from observed data"
    )
