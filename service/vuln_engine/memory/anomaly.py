"""Anomaly memory: a deterministic, capped distillate of retained surprises.

PRD §6.9: two memories, not one. Findings memory (already exists) is distilled
from verified findings only. This is the other half — distilled from the
*anomaly* ledger, cross-engagement, advisory, never evidence. The abducer reads
it the way the hypothesize junction reads its memory: as an input file, so the
run stays replayable and a wrong entry sits in the repository where an operator
can read and correct it.

The distillate is a count over **predicate families**, deliberately
surface-free: a surprise that keeps recurring across engagements — the same
technique violating the same kind of predicate — is a generalisable fact, and
the particular host belongs in the ledger, not the memory. It is capped so a
long-lived ledger cannot grow the file without bound, and every field is a
primitive so two distillates of the same input are byte-identical.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path

from ..kernel.anomaly import ANOMALY_STATUSES, Anomaly

#: How many cells a distillate keeps. The cap is on cells (families), not rows:
#: a family seen a thousand times is one cell with a big count.
DEFAULT_CAP = 200


def _as_anomaly(item: Anomaly | dict) -> Anomaly:
    return item if isinstance(item, Anomaly) else Anomaly.from_dict(item)


def _family(anomaly: Anomaly) -> tuple[str, str, str, str]:
    expected = anomaly.deviation.get("expected") or {}
    return (
        anomaly.technique,
        str(anomaly.deviation.get("kind", "")),
        str(expected.get("probe_suffix", "")),
        str(expected.get("field", "")),
    )


def distill(anomalies: Iterable[Anomaly | dict], *, cap: int = DEFAULT_CAP) -> dict:
    """Distil anomalies into a capped, deterministic memory record."""
    cells: dict[tuple[str, str, str, str], dict] = {}
    total = 0
    for item in anomalies:
        anomaly = _as_anomaly(item)
        total += 1
        cell = cells.setdefault(
            _family(anomaly),
            {
                "technique": anomaly.technique,
                "kind": str(anomaly.deviation.get("kind", "")),
                "probe_suffix": str((anomaly.deviation.get("expected") or {}).get("probe_suffix", "")),
                "field": str((anomaly.deviation.get("expected") or {}).get("field", "")),
                "count": 0,
                "statuses": {status: 0 for status in ANOMALY_STATUSES},
            },
        )
        cell["count"] += 1
        cell["statuses"][anomaly.status] = cell["statuses"].get(anomaly.status, 0) + 1

    ordered = sorted(cells.values(), key=lambda cell: (cell["technique"], cell["kind"], cell["probe_suffix"], cell["field"]))
    kept = ordered[:cap]
    return {
        # Advisory, loudly: no consumer may mistake this for evidence.
        "advisory": True,
        "total": total,
        "cap": cap,
        "truncated": max(0, len(ordered) - cap),
        "cells": kept,
    }


def family_of(anomaly: Anomaly | dict) -> tuple[str, str, str, str]:
    """The predicate family one anomaly belongs to — the distillate's cell key.

    The same four fields a cell carries (``technique, kind, probe_suffix,
    field``), deliberately surface-free: the family is the generalisable fact,
    the particular host belongs in the ledger.
    """
    return _family(_as_anomaly(anomaly))


def corroborated(record: object, anomaly: Anomaly | dict) -> bool:
    """True when *anomaly*'s predicate family appears in a distillate.

    The one question a consumer is allowed to ask of anomaly memory, kept here
    so the family semantics cannot drift between consumers. Read-only and
    advisory by construction: a corroboration is a count over past surprises,
    never evidence, never a gate — it may order what gets proposed, it may not
    decide what gets believed.
    """
    if not isinstance(record, dict):
        return False
    family = family_of(anomaly)
    for cell in record.get("cells") or []:
        if not isinstance(cell, dict):
            continue
        if (
            str(cell.get("technique", "")),
            str(cell.get("kind", "")),
            str(cell.get("probe_suffix", "")),
            str(cell.get("field", "")),
        ) == family:
            return True
    return False


def write_memory(path: Path | str, record: dict) -> dict:
    """Write a distillate to *path*; returns the record unchanged."""
    file = Path(path)
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return record


def read_memory(path: Path | str) -> dict:
    """Read a distillate, or an empty one when the file is absent/corrupt."""
    file = Path(path)
    if not file.is_file():
        return {"advisory": True, "total": 0, "cap": DEFAULT_CAP, "truncated": 0, "cells": []}
    try:
        record = json.loads(file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, ValueError):
        return {"advisory": True, "total": 0, "cap": DEFAULT_CAP, "truncated": 0, "cells": []}
    if not isinstance(record, dict):
        return {"advisory": True, "total": 0, "cap": DEFAULT_CAP, "truncated": 0, "cells": []}
    return record


__all__ = ["DEFAULT_CAP", "corroborated", "distill", "family_of", "read_memory", "write_memory"]
