"""Emit the probe stage's artifacts, in the shapes the design promises.

Three curated sets, kept apart because they answer different questions:

* ``verdicts.jsonl`` — every probe, including refusals and unclassifiable
  answers: the audit trail.
* ``buckets.jsonl`` — **only names that exist** (open / auth_required /
  exists-elsewhere) with their evidence class: the curated artifact.
* ``dangling.jsonl`` — CNAME-claimed names the provider says are absent: the
  S25 takeover detector's raw material.

Emission is pure — it takes verdicts and writes text — so everything about
formatting is testable without a network.  Deterministic: both stages sort
every emitted set, so two runs over the same facts are byte-identical (tested).
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path

from .verify import EXISTING_STATES, STATE_DANGLING, STATE_NXDOMAIN_ABSENT, STATE_UNAVAILABLE, Verdict
from .verify import EVIDENCE_CNAME_CLAIMED


def write_jsonl(path: Path, records: Iterable[dict[str, object]]) -> Path:
    """Write JSON rows atomically, one per line, in the order given."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(
        "".join(json.dumps(dict(row), sort_keys=False) + "\n" for row in records),
        encoding="utf-8",
        newline="\n",
    )
    tmp.replace(path)
    return path


def write_json(path: Path, payload: object) -> Path:
    """Write a JSON document atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(
        json.dumps(payload, indent=2, sort_keys=False), encoding="utf-8", newline="\n"
    )
    tmp.replace(path)
    return path


def bucket_rows(verdicts: list[Verdict]) -> list[dict[str, object]]:
    """The curated set: only names that exist, sorted (name, provider)."""
    rows = [verdict.to_dict() for verdict in verdicts if verdict.state in EXISTING_STATES]
    return sorted(rows, key=lambda row: (str(row["name"]), str(row["provider"])))


def dangling_rows(verdicts: list[Verdict]) -> list[dict[str, object]]:
    """CNAME-claimed names the provider says are absent (S25 raw material).

    A derived candidate that comes back absent is a *negative* — noise, not a
    dangling reference.  Only a name the target's own DNS claimed counts, in
    either absence dialect: an HTTP-level absence (S3 ``NoSuchBucket``) or the
    Azure NXDOMAIN fact (no wildcard DNS — the account does not resolve).
    """
    rows = [
        verdict.to_dict()
        for verdict in verdicts
        if verdict.evidence_class == EVIDENCE_CNAME_CLAIMED
        and verdict.state in (STATE_DANGLING, STATE_NXDOMAIN_ABSENT)
    ]
    return sorted(rows, key=lambda row: (str(row["name"]), str(row["provider"])))


def probe_report(
    target: str,
    verdicts: list[Verdict],
    counts: dict[str, int],
    seconds: float,
) -> dict[str, object]:
    """The probe stage's machine report."""
    by_state: dict[str, int] = {}
    for verdict in verdicts:
        by_state[verdict.state] = by_state.get(verdict.state, 0) + 1
    by_evidence: dict[str, int] = {}
    for verdict in verdicts:
        by_evidence[verdict.evidence_class] = by_evidence.get(verdict.evidence_class, 0) + 1
    unavailable = sum(1 for verdict in verdicts if verdict.state == STATE_UNAVAILABLE)
    return {
        "target": target,
        "finished_at": _utc_now(),
        "seconds": round(seconds, 2),
        "ok": unavailable == 0,
        "counts": counts,
        "by_state": by_state,
        "by_evidence": by_evidence,
        "truncated": bool(counts.get("truncated")),
    }


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
