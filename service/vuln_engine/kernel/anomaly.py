"""Anomalies: a retained surprise, and its lifecycle.

Phase 2 produced the *surprise* — a typed :class:`~.prediction.Deviation`. Phase
3 gives it somewhere to live and a small closed vocabulary for what happens to
it. The two ideas this module fixes:

* **the key is the predicate, not the value.** A deviation names a probe and a
  field (the *cell*); the observed value is the surprise, not its identity. Two
  runs that violate the same predicate on the same surface are the same anomaly
  seen twice, so the abducer can generalise a cell instead of drowning in
  near-duplicate rows. The surface rides the arm (``technique@surface``), the
  same key the receipts and the budget already use.

* **status is a lifecycle, and only four states exist.** An anomaly is
  ``open`` until an abducer has explained it (``abduced``), a proof has settled
  it (``resolved``), or the process gave up on it (``demoted``). Nothing else —
  a wider vocabulary would let a consumer invent a state no one transitions.

Anomalies are advisory by construction: the type carries no grade, is never
evidence, and nothing here promotes one toward a finding.
"""

from __future__ import annotations

from dataclasses import dataclass, field as _field

#: Retained and unexplained: the abducer's inbox.
ANOMALY_OPEN = "open"
#: An abducer produced a hypothesis that explains it (expressible or held).
ANOMALY_ABDUCED = "abduced"
#: The explanation was proven — the surprise is understood, not merely shelved.
ANOMALY_RESOLVED = "resolved"
#: The process declined to pursue it (not worth a verifier, duplicate, stale).
ANOMALY_DEMOTED = "demoted"

ANOMALY_STATUSES: tuple[str, ...] = (
    ANOMALY_OPEN,
    ANOMALY_ABDUCED,
    ANOMALY_RESOLVED,
    ANOMALY_DEMOTED,
)


def anomaly_key(technique: str, arm: str, deviation: dict) -> str:
    """The stable cell key for a typed deviation.

    The predicate fields only (kind, observation kind, probe suffix, field) —
    deliberately **not** the observed value. The key is a *place* the world
    surprised us, which is what a generalising abducer wants; the value is in
    the row.
    """
    expected = deviation.get("expected") or {}
    parts = (
        technique,
        arm,
        str(deviation.get("kind", "")),
        str(expected.get("kind", "")),
        str(expected.get("probe_suffix", "")),
        str(expected.get("field", "")),
    )
    return "|".join(parts)


@dataclass(frozen=True)
class Anomaly:
    """One retained surprise, with its current status."""

    key: str
    technique: str
    arm: str
    #: The typed deviation that was retained (``Deviation.to_dict()``).
    deviation: dict = _field(default_factory=dict)
    status: str = ANOMALY_OPEN
    at: float = 0.0
    note: str = ""

    def __post_init__(self) -> None:
        if not self.key:
            raise ValueError("an anomaly needs a key")
        if self.status not in ANOMALY_STATUSES:
            raise ValueError(
                f"unknown anomaly status {self.status!r}; known: "
                f"{', '.join(ANOMALY_STATUSES)}"
            )

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "technique": self.technique,
            "arm": self.arm,
            "deviation": dict(self.deviation),
            "status": self.status,
            "at": round(float(self.at), 3),
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, row: dict) -> "Anomaly":
        return cls(
            key=str(row.get("key", "")),
            technique=str(row.get("technique", "")),
            arm=str(row.get("arm", "")),
            deviation=dict(row.get("deviation") or {}),
            status=str(row.get("status", ANOMALY_OPEN) or ANOMALY_OPEN),
            at=float(row.get("at") or 0.0),
            note=str(row.get("note", "")),
        )


__all__ = [
    "ANOMALY_ABDUCED",
    "ANOMALY_DEMOTED",
    "ANOMALY_OPEN",
    "ANOMALY_RESOLVED",
    "ANOMALY_STATUSES",
    "Anomaly",
    "anomaly_key",
]
