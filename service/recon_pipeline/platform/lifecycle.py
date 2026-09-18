"""S11 — the lifecycle loop: a model that changes when the world does.

Three jobs from the plan, all reading previous-run state and current evidence:

* **re-scoring** — an asset's score is re-computed when fresh evidence exists;
  evidence older than ``stale_after_days`` loses its weight (an HTTP banner
  from six months ago is a claim about six months ago).
* **pruning** — assets whose score decayed below the floor for
  ``prune_after_runs`` consecutive runs are archived (never silently deleted —
  the archive is a JSONL the operator can re-import).
* **differencing** — what appeared / disappeared / changed since the previous
  run's registry, which is the differential-monitoring primitive S14 reports on.

The module is pure over :class:`AssetRecord`s — the graph writers and the run
registry (S14) produce those; this module decides what happens to them.  No
clock: ``now`` is a parameter so tests run on a fixed timeline.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field, replace

DAY = 86_400.0
DEFAULT_STALE_DAYS = 30
DEFAULT_PRUNE_RUNS = 3


@dataclass
class AssetRecord:
    """One asset as the platform's lifecycle sees it."""

    asset_type: str
    canonical_value: str
    score: int = 0
    #: Monotonic run counter when last seen, and wall-clock when last evidenced.
    last_seen_run: int = 0
    last_evidence_at: float = 0.0
    archived: bool = False

    def key(self) -> tuple[str, str]:
        return (self.asset_type, self.canonical_value)


@dataclass
class LifecyclePolicy:
    stale_after_days: int = DEFAULT_STALE_DAYS
    prune_after_runs: int = DEFAULT_PRUNE_RUNS
    prune_below_score: int = 10


@dataclass
class LifecycleReport:
    rescoring: list[dict] = field(default_factory=list)
    pruned: list[dict] = field(default_factory=list)
    appeared: list[str] = field(default_factory=list)
    disappeared: list[str] = field(default_factory=list)
    changed: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "rescoring": self.rescoring,
            "pruned": self.pruned,
            "appeared": self.appeared,
            "disappeared": self.disappeared,
            "changed": self.changed,
        }


class Lifecycle:
    """Apply one run's evidence to the previous model."""

    def __init__(self, policy: LifecyclePolicy | None = None) -> None:
        self.policy = policy or LifecyclePolicy()
        self.run_counter = 0

    # ------------------------------------------------------------------ #
    # re-scoring
    # ------------------------------------------------------------------ #

    def rescore(
        self,
        previous: AssetRecord,
        *,
        fresh_score: int,
        now: float,
    ) -> tuple[AssetRecord, dict]:
        """Merge fresh evidence into a record; stale evidence decays.

        Fresh evidence wins outright.  Without it, a record whose last evidence
        is older than ``stale_after_days`` decays by 10 points per run — a
        slow fade, not a cliff, because "not seen recently" is weaker
        evidence than "seen and dead".
        """
        self.run_counter += 1
        new_record = replace(
            previous,
            last_seen_run=self.run_counter,
        )
        if fresh_score > 0:
            new_record.score = fresh_score
            new_record.last_evidence_at = now
            entry = {
                "asset": previous.canonical_value,
                "from": previous.score,
                "to": fresh_score,
                "reason": "fresh evidence",
            }
        else:
            age_days = max(0.0, (now - previous.last_evidence_at) / DAY)
            if age_days > self.policy.stale_after_days:
                decayed = max(0, previous.score - 10)
            else:
                decayed = previous.score
            new_record.score = decayed
            entry = {
                "asset": previous.canonical_value,
                "from": previous.score,
                "to": decayed,
                "reason": f"no fresh evidence ({age_days:.0f}d old)",
            }
        return new_record, entry

    # ------------------------------------------------------------------ #
    # pruning
    # ------------------------------------------------------------------ #

    def prune(self, record: AssetRecord) -> tuple[AssetRecord, bool]:
        """Archive a record that has faded below the floor for N runs.

        Archived, not deleted: the return value carries the updated record and
        whether this call archived it, and the caller persists the archive row.
        """
        if record.archived:
            return record, False
        faded = record.score < self.policy.prune_below_score
        unseen = self.run_counter - record.last_seen_run >= self.policy.prune_after_runs
        if faded and unseen:
            return replace(record, archived=True), True
        return record, False

    # ------------------------------------------------------------------ #
    # differencing
    # ------------------------------------------------------------------ #

    def diff(
        self,
        previous: dict[tuple[str, str], AssetRecord],
        current: dict[tuple[str, str], AssetRecord],
    ) -> LifecycleReport:
        """What appeared, disappeared or changed between two asset maps."""
        report = LifecycleReport()
        for key, record in current.items():
            if key not in previous:
                report.appeared.append(f"{key[0]}:{key[1]}")
                continue
            before = previous[key]
            if before.score != record.score or before.archived != record.archived:
                report.changed.append(
                    {
                        "asset": f"{key[0]}:{key[1]}",
                        "score": [before.score, record.score],
                        "archived": [before.archived, record.archived],
                    }
                )
        for key, record in previous.items():
            if key not in current and not record.archived:
                report.disappeared.append(f"{key[0]}:{key[1]}")
        return report

    # ------------------------------------------------------------------ #
    # the loop, assembled
    # ------------------------------------------------------------------ #

    def apply_run(
        self,
        previous: dict[tuple[str, str], AssetRecord],
        fresh: dict[tuple[str, str], int],
        *,
        now: float,
    ) -> tuple[dict[tuple[str, str], AssetRecord], LifecycleReport]:
        """One lifecycle pass: rescore everything, prune the faded, diff the world.

        ``fresh`` maps asset keys to this run's scores (0 = known but not
        re-evidenced).  Returns the new model and the report S14 embeds.
        """
        model: dict[tuple[str, str], AssetRecord] = {}
        report = LifecycleReport()

        all_keys = set(previous) | set(fresh)
        for key in sorted(all_keys):
            old = previous.get(key)
            score_now = fresh.get(key, 0)
            if old is None:
                record = AssetRecord(
                    asset_type=key[0],
                    canonical_value=key[1],
                    score=score_now,
                    last_seen_run=self.run_counter,
                    last_evidence_at=now,
                )
                model[key] = record
                report.appeared.append(f"{key[0]}:{key[1]}")
                continue

            record, entry = self.rescore(old, fresh_score=score_now, now=now)
            model[key] = record
            if entry["from"] != entry["to"]:
                report.rescoring.append(entry)

        for key in sorted(model):
            record, did_prune = self.prune(model[key])
            model[key] = record
            if did_prune:
                report.pruned.append(
                    {"asset": f"{key[0]}:{key[1]}", "score": record.score}
                )

        prev_live = {k: v for k, v in previous.items() if not v.archived}
        curr_live = {k: v for k, v in model.items() if not v.archived}
        report.disappeared = [
            f"{k[0]}:{k[1]}" for k in sorted(set(prev_live) - set(curr_live))
        ]
        return model, report


def monotonic_now() -> float:
    """Wall-clock helper so callers do not import time for one call."""
    return time.time()
