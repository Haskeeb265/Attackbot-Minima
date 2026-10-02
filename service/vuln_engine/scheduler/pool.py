"""The hypothesis pool, and the novelty term read off the ledger (PRD §6.8).

Two small things Phase 5 adds to the scheduler:

* :class:`HypothesisPool` — templates, generated compositions and abduced
  candidates in **one** in-memory ranking, per §7.2's "hypothesis pool
  (in-memory per run)". A pool entry is an abduced proposal plus the arm that
  produced it and the validator's verdict; expressible entries are candidates
  for the next round, held ones already live in the pen.

* :func:`novelty_cells_from_log` — the A2 novelty term, derived from the
  ledger's own ``anomaly.retained`` rows rather than from a counter the
  scheduler would have to keep in sync. Each retained deviation names a
  *cell* (``kernel.anomaly.anomaly_key``: surface-scoped, predicate-family
  shaped); the term pays for the first entry and decays on re-entry, capped
  below ``REWARD_FOUND``. Deriving it here keeps the selector pure and the
  replay exact: the same log yields the same novelty, always.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field as _field

from ..kernel.anomaly import anomaly_key
from .ucb import novelty_reward


@dataclass(frozen=True)
class PoolEntry:
    """One abduced hypothesis, with the arm and verdict that brought it in."""

    cell: str
    arm: str
    technique: str
    claim_shape: str
    verdict: str
    #: Which channel asked: ``abduction`` (an anomaly-driven explanation) or
    #: ``property`` (A3's static-context proposal). The abduced round uses it to
    #: skip a *property* that merely re-proposes an experiment the ordinary pass
    #: already ran — a surprise is worth re-measuring, a plain duplicate is not.
    source: str = "abduction"
    proposal: dict = _field(default_factory=dict)

    @property
    def expressible(self) -> bool:
        from ..abduction.proposal import EXPRESSIBLE_NOW

        return self.verdict == EXPRESSIBLE_NOW

    def to_dict(self) -> dict:
        return {
            "cell": self.cell,
            "arm": self.arm,
            "technique": self.technique,
            "claim_shape": self.claim_shape,
            "verdict": self.verdict,
            "source": self.source,
            "expressible": self.expressible,
            "proposal": dict(self.proposal),
        }


class HypothesisPool:
    """A per-run, in-memory set of abduced hypotheses, keyed by cell."""

    def __init__(self) -> None:
        self._entries: dict[str, PoolEntry] = {}

    def add(self, proposal, *, arm: str, verdict: str, source: str = "abduction") -> PoolEntry:
        """Add one proposal; a repeated cell is idempotent (first verdict wins)."""
        entry = PoolEntry(
            cell=proposal.witness or proposal.id,
            arm=arm,
            technique=proposal.technique,
            claim_shape=proposal.claim_shape,
            verdict=verdict,
            source=source,
            proposal=proposal.to_dict(),
        )
        self._entries.setdefault(entry.cell, entry)
        return self._entries[entry.cell]

    def entries(self) -> list[PoolEntry]:
        return [self._entries[key] for key in sorted(self._entries)]

    def expressible(self) -> list[PoolEntry]:
        return [entry for entry in self.entries() if entry.expressible]

    def __len__(self) -> int:
        return len(self._entries)


def novelty_cells_from_log(log, *, technique: str | None = None) -> dict[str, float]:
    """``{arm: novelty payout}`` derived from a log's retained anomalies.

    Only ``anomaly.retained`` rows contribute: the term rewards *entered*
    territory, and a retention is the ledger's own record that an arm entered
    a cell. The count of prior entries decays each cell's payout, so an arm
    that keeps re-entering the same cell stops being paid for it.
    """
    counts: dict[str, dict[str, int]] = {}
    for row in log.events("anomaly.retained"):
        if technique is not None and str(row.get("technique", "")) != technique:
            continue
        arm = str(row.get("arm", ""))
        family = str(row.get("technique", ""))
        for deviation in row.get("deviations") or []:
            cell = anomaly_key(family, arm, deviation)
            bucket = counts.setdefault(arm, {})
            bucket[cell] = bucket.get(cell, 0) + 1
    return {arm: novelty_reward(cells) for arm, cells in counts.items()}


__all__ = ["HypothesisPool", "PoolEntry", "novelty_cells_from_log"]
