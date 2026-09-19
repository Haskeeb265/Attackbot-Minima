"""The attempt receipt: what this engagement already tried, per asset.

The convergence ledger records what a run has **seen**.  This records what it has
**attempted**, and the two are not the same question — which is exactly why a
repeated round used to pay twice: an address scanned with nothing open appears
nowhere in the discovery artifacts (no open ports, no service, no host row), so
from the outside it is indistinguishable from an address nobody ever looked at.
The escalation policy has always *asked* whether an operation had already been
paid for; until now every caller had to answer from memory.  This is the answer.

**Keyed by ``(asset, operation)``** with the operation vocabulary
:mod:`platform.escalation` already uses (``port_scan``, ``url_validation``, …),
because a receipt is only meaningful next to the question it answers: *this*
operation, on *this* asset.

**Only a conclusive attempt earns a skip.**  ``OUTCOME_NONE`` ("we looked,
nothing was there") and ``OUTCOME_FOUND`` are conclusive; ``OUTCOME_FAILED`` and a
blank outcome are not.  An address whose scan errored has *not* been examined, so
a later round must be free to try it again — recording a failure as an attempt
would be the receipt quietly inventing knowledge we do not have.

Store: append-only JSONL, the same conventions as the ledger — one row per
attempt, atomic-ish append, a corrupt line costs one record, and a write failure
is logged rather than raised (telemetry must not take a run down).
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from .common.io import read_text
from .common.normalize import canonicalize_host, canonicalize_ip, is_ip_literal

log = logging.getLogger("platform.receipt")

#: Outcomes.  The first two are conclusive — they mean the operation was carried
#: out and answered — and they are the only ones that earn a skip.
OUTCOME_NONE = "none"
OUTCOME_FOUND = "found"
OUTCOME_FAILED = "failed"

#: Attempts that must not be treated as "done" next round.
INCONCLUSIVE: frozenset[str] = frozenset({OUTCOME_FAILED, ""})


def asset_token(value: str, kind: str = "") -> str | None:
    """Canonical ``<kind>:<value>`` receipt key, or ``None`` when unparseable.

    Kind-prefixed for the same reason the frontier is: an address and a name are
    different assets even when they are the same string, and an operation on one
    says nothing about the other.
    """
    token = (value or "").strip()
    if not token:
        return None
    if kind == "ip" or (not kind and is_ip_literal(token)):
        address = canonicalize_ip(token)
        return f"ip:{address}" if address else None
    host = canonicalize_host(token)
    return f"host:{host}" if host else None


@dataclass(frozen=True)
class Attempt:
    """One recorded attempt.

    Carries no round number: the stage that does the work does not know which
    round it is in, and inventing one would be a field nobody could fill honestly.
    ``at`` (plus the run directory the receipt lives in) is the correlation.
    """

    asset: str
    operation: str
    outcome: str = OUTCOME_NONE
    at: float = 0.0

    @property
    def conclusive(self) -> bool:
        """True when this attempt may stop a later round repeating the work."""
        return self.outcome not in INCONCLUSIVE

    def to_dict(self) -> dict:
        return {
            "asset": self.asset,
            "operation": self.operation,
            "outcome": self.outcome,
            "at": round(self.at, 3),
        }


class Receipt:
    """Append-only record of what has been attempted, keyed by asset + operation.

    Loads on construction, so a stage re-run (or the next convergence round)
    starts from everything earlier passes paid for.
    """

    def __init__(self, path: Path | str | None = None) -> None:
        self._path = Path(path) if path else None
        self._attempts: dict[tuple[str, str], Attempt] = {}
        self._rows: int = 0
        if self._path is not None:
            self._load()

    # ------------------------------------------------------------------ #
    # persistence
    # ------------------------------------------------------------------ #

    def _load(self) -> None:
        assert self._path is not None
        for line in read_text(self._path).splitlines():
            stripped = line.strip()
            if not stripped.startswith("{"):
                continue
            try:
                row = json.loads(stripped)
            except (json.JSONDecodeError, ValueError):
                continue
            asset = str(row.get("asset") or "")
            operation = str(row.get("operation") or "")
            if not asset or not operation:
                continue
            self._rows += 1
            attempt = Attempt(
                asset=asset,
                operation=operation,
                outcome=str(row.get("outcome") or ""),
                at=float(row.get("at") or 0.0),
            )
            # A conclusive attempt wins over an inconclusive one for the same key,
            # whichever order they were written in: "we looked and there was
            # nothing" is a better answer than "the scan errored".
            previous = self._attempts.get((asset, operation))
            if previous is None or (attempt.conclusive and not previous.conclusive):
                self._attempts[(asset, operation)] = attempt

    @property
    def path(self) -> Path | None:
        return self._path

    def __len__(self) -> int:
        return len(self._attempts)

    # ------------------------------------------------------------------ #
    # writing
    # ------------------------------------------------------------------ #

    def record(
        self,
        asset: str | None,
        operation: str,
        *,
        outcome: str = "",
        at: float | None = None,
    ) -> bool:
        """Record one attempt; returns True when the store actually took it.

        *asset* may be a raw address/host or a token already prefixed with its
        kind (``ip:…``); anything unparseable is refused rather than stored under
        a spelling nothing will look up again.
        """
        token = asset if asset and ":" in asset else asset_token(str(asset or ""))
        if not token or not operation:
            return False
        now = time.time() if at is None else at
        attempt = Attempt(asset=token, operation=operation, outcome=outcome, at=now)
        previous = self._attempts.get((token, operation))
        if previous is None or (attempt.conclusive and not previous.conclusive):
            self._attempts[(token, operation)] = attempt
        self._append(attempt)
        return True

    def _append(self, attempt: Attempt) -> bool:
        if self._path is None:
            return False
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(json.dumps(attempt.to_dict(), sort_keys=False) + "\n")
            self._rows += 1
            return True
        except OSError as exc:
            log.warning("receipt append failed: %s", exc)
            return False

    # ------------------------------------------------------------------ #
    # reading
    # ------------------------------------------------------------------ #

    def attempt(self, asset: str, operation: str) -> Attempt | None:
        """The recorded attempt for this key, or ``None``."""
        token = asset if ":" in asset else (asset_token(asset) or asset)
        return self._attempts.get((token, operation))

    def attempted(self, asset: str, operation: str) -> bool:
        """True when this operation was carried out on this asset with an answer.

        Inconclusive attempts return False on purpose — a failed scan is not
        knowledge, and skipping on it would turn an outage into a permanent gap.
        """
        found = self.attempt(asset, operation)
        return bool(found and found.conclusive)

    def attempted_assets(self, operation: str) -> frozenset[str]:
        """Every asset conclusively attempted for *operation*, as tokens."""
        return frozenset(
            asset
            for (asset, recorded), attempt in self._attempts.items()
            if recorded == operation and attempt.conclusive
        )

    def pending(self, assets: Iterable[str], operation: str) -> list[str]:
        """The *assets* not yet conclusively attempted, in the order given.

        The one call a stage needs to spend its requests only on what is new.
        Values may be raw or token-prefixed; the output keeps the caller's own
        spelling so it can go straight back into a scan list.
        """
        done = self.attempted_assets(operation)
        remaining: list[str] = []
        for asset in assets:
            token = asset if ":" in asset else (asset_token(asset) or asset)
            if token not in done and asset not in remaining:
                remaining.append(asset)
        return remaining

    def by_operation(self) -> dict[str, dict[str, int]]:
        """``{operation: {outcome: count}}`` — the report-shaped summary."""
        summary: dict[str, dict[str, int]] = {}
        for (_asset, operation), attempt in self._attempts.items():
            bucket = summary.setdefault(operation, {})
            bucket[attempt.outcome or "unknown"] = bucket.get(attempt.outcome or "unknown", 0) + 1
        return {operation: dict(sorted(counts.items())) for operation, counts in sorted(summary.items())}

    def to_dict(self) -> dict:
        return {
            "path": self._path.as_posix() if self._path else "",
            "assets": len(self._attempts),
            "rows": self._rows,
            "by_operation": self.by_operation(),
        }
