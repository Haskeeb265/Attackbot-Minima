"""The confirmation substrate: features, named oracles, and a declarative spec.

This is the deterministic heart of the two-gate flow. Nothing here talks to the
network, reads a clock, or calls a model — it is the vocabulary the capability
agent proposes in, the verifier agent writes a spec in, and the runner decides in.

The rule the module exists to enforce: **a verdict is a deterministic oracle over
raw measurements, never an agent's opinion.** The capability agent may propose
what to look for; the verifier agent may choose *which* pre-written oracle and
parameters apply; but the boolean answer comes from here, from a pure predicate
over measured features.

Mirrors the shape the plan calls ``ConfirmationSpec`` + ``Features`` +
oracle library, kept in one module because the oracle signature and the feature
fields are one contract and splitting them is how they drift.
"""

from __future__ import annotations

import hashlib
import json
import statistics
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from ..kernel.confirm import ConfirmSpec
from ..kernel.evidence import (
    DIFFERENTIAL_SESSIONS,
    EVIDENCE_DIFFERENTIAL,
    EVIDENCE_EXECUTION,
    EVIDENCE_OOB,
)

# --------------------------------------------------------------------------- #
# Features — the typed measurements an oracle reads
# --------------------------------------------------------------------------- #

#: Feature field names, as a closed set. The runner fills exactly these; an
#: oracle that wants a new fact must add it here, so the vocabulary is one place.
FEATURE_FIELDS: tuple[str, ...] = (
    "status",
    "length",
    "body_hash",
    "headers_hash",
    "elapsed_ms",
    "oob_hit",
    "script_executed",
    "value_present",
    "error",
)


@dataclass(frozen=True)
class Features:
    """One measurement, reduced to the fields an oracle can ask about.

    A response body is never carried: ``body_hash`` and ``value_present`` are the
    two questions an oracle is allowed to ask about bytes. Everything else is a
    number, an id, or a boolean.
    """

    status: int | None = None
    length: int = 0
    body_hash: str = ""
    headers_hash: str = ""
    elapsed_ms: float = 0.0
    oob_hit: bool = False
    script_executed: bool = False
    value_present: bool = False
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "length": self.length,
            "body_hash": self.body_hash,
            "headers_hash": self.headers_hash,
            "elapsed_ms": self.elapsed_ms,
            "oob_hit": self.oob_hit,
            "script_executed": self.script_executed,
            "value_present": self.value_present,
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, row: Mapping[str, Any]) -> "Features":
        return cls(
            status=row.get("status"),  # type: ignore[arg-type]
            length=int(row.get("length", 0)),
            body_hash=str(row.get("body_hash", "")),
            headers_hash=str(row.get("headers_hash", "")),
            elapsed_ms=float(row.get("elapsed_ms", 0.0)),
            oob_hit=bool(row.get("oob_hit", False)),
            script_executed=bool(row.get("script_executed", False)),
            value_present=bool(row.get("value_present", False)),
            error=str(row.get("error", "")),
        )


def _digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()[:16]


def feature_from_exchange(exchange: Any, *, value: str = "") -> Features:
    """Reduce one ``RawHttpExchange`` to features. Pure; no bytes retained."""
    headers = {str(k).lower(): str(v) for k, v in (getattr(exchange, "headers", {}) or {}).items()}
    body = getattr(exchange, "body", b"") or b""
    text = body.decode("utf-8", errors="replace")
    return Features(
        status=getattr(exchange, "status", None),
        length=len(body),
        body_hash=_digest(body),
        headers_hash=_digest(
            json.dumps(sorted(headers.items()), separators=(",", ":")).encode("utf-8")
        ),
        elapsed_ms=round(float(getattr(exchange, "elapsed", 0.0)) * 1000.0, 3),
        value_present=bool(value) and value in text,
        error=str(getattr(exchange, "error", "") or ""),
    )


def feature_from_browser(run: Any) -> Features:
    """Reduce one ``RawBrowserRun`` to features.

    ``script_executed`` is true when any non-placement marker the caller asked for
    answered true — the same predicate the observation layer uses, one layer down.
    """
    markers = getattr(run, "markers", {}) or {}
    executed = any(
        bool(answer)
        for name, answer in markers.items()
        if not str(name).startswith("dom:")
    )
    return Features(
        status=getattr(run, "status", None),
        elapsed_ms=round(float(getattr(run, "elapsed", 0.0)) * 1000.0, 3),
        script_executed=executed,
        error=str(getattr(run, "error", "") or ""),
    )


# --------------------------------------------------------------------------- #
# The oracle context and the named predicates
# --------------------------------------------------------------------------- #

ORACLE_RESPONSE_DIFFERS = "response_differs"
ORACLE_TIMING_DIFFERENTIAL = "timing_differential"
ORACLE_OOB_HIT = "oob_hit"
ORACLE_SCRIPT_EXECUTED = "script_executed"
ORACLE_AUTHZ_DIFFERENTIAL = "authz_differential"
ORACLE_DATA_EXTRACTED = "data_extracted"

#: Which evidence class an oracle's true answer rests on. The planner refuses a
#: confirmation whose class equals the proposer's (always ``hypothesis`` here),
#: and the verdict carries this class.
ORACLE_EVIDENCE: dict[str, str] = {
    ORACLE_RESPONSE_DIFFERS: EVIDENCE_DIFFERENTIAL,
    ORACLE_TIMING_DIFFERENTIAL: EVIDENCE_DIFFERENTIAL,
    ORACLE_OOB_HIT: EVIDENCE_OOB,
    ORACLE_SCRIPT_EXECUTED: EVIDENCE_EXECUTION,
    ORACLE_AUTHZ_DIFFERENTIAL: EVIDENCE_DIFFERENTIAL,
    ORACLE_DATA_EXTRACTED: EVIDENCE_DIFFERENTIAL,
}


@dataclass(frozen=True)
class OracleContext:
    """Everything a named oracle may read. One typed shape, no free-form dict."""

    baseline: Features
    injected: tuple[Features, ...]
    control: Features | None = None
    session_a: Features | None = None
    session_b: Features | None = None
    oob_hit: bool = False
    margin: float = 0.0
    #: A body-length change beyond this many bytes counts as a response difference.
    length_delta: int = 0

    def to_dict(self) -> dict:
        return {
            "baseline": self.baseline.to_dict(),
            "injected": [item.to_dict() for item in self.injected],
            "control": self.control.to_dict() if self.control else None,
            "session_a": self.session_a.to_dict() if self.session_a else None,
            "session_b": self.session_b.to_dict() if self.session_b else None,
            "oob_hit": self.oob_hit,
            "margin": self.margin,
            "length_delta": self.length_delta,
        }


OracleFn = Callable[[OracleContext], bool]


def _differs(left: Features, right: Features, length_delta: int) -> bool:
    if left.status != right.status:
        return True
    if abs(left.length - right.length) > length_delta:
        return True
    return bool(left.body_hash) and left.body_hash != right.body_hash


def oracle_response_differs(ctx: OracleContext) -> bool:
    """The injected population differs from *both* baseline and control."""
    if not ctx.injected:
        return False
    differs = any(_differs(item, ctx.baseline, ctx.length_delta) for item in ctx.injected)
    if not differs:
        return False
    if ctx.control is None:
        return True
    return any(_differs(item, ctx.control, ctx.length_delta) for item in ctx.injected)


def oracle_timing_differential(ctx: OracleContext) -> bool:
    """The injected median elapsed time exceeds the baseline by the margin."""
    if not ctx.injected:
        return False
    injected = statistics.median(item.elapsed_ms for item in ctx.injected)
    baseline = ctx.baseline.elapsed_ms
    return (injected - baseline) >= ctx.margin


def oracle_oob_hit(ctx: OracleContext) -> bool:
    return bool(ctx.oob_hit)


def oracle_script_executed(ctx: OracleContext) -> bool:
    return any(item.script_executed for item in ctx.injected)


def oracle_authz_differential(ctx: OracleContext) -> bool:
    """The two sessions saw different content — an access boundary is present."""
    if ctx.session_a is None or ctx.session_b is None:
        return False
    return _differs(ctx.session_a, ctx.session_b, ctx.length_delta)


def oracle_data_extracted(ctx: OracleContext) -> bool:
    return any(item.value_present for item in ctx.injected)


ORACLES: dict[str, OracleFn] = {
    ORACLE_RESPONSE_DIFFERS: oracle_response_differs,
    ORACLE_TIMING_DIFFERENTIAL: oracle_timing_differential,
    ORACLE_OOB_HIT: oracle_oob_hit,
    ORACLE_SCRIPT_EXECUTED: oracle_script_executed,
    ORACLE_AUTHZ_DIFFERENTIAL: oracle_authz_differential,
    ORACLE_DATA_EXTRACTED: oracle_data_extracted,
}


def apply_oracle(name: str, ctx: OracleContext) -> bool:
    """Apply a named oracle. An unknown name is a false answer, never a crash.

    A spec that named an oracle this build does not have is not a proof of
    anything; returning false keeps it a lead instead of inventing a finding.
    """
    predicate = ORACLES.get(name)
    if predicate is None:
        return False
    return bool(predicate(ctx))


# --------------------------------------------------------------------------- #
# The confirmation spec
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ConfirmationSpec:
    """A pre-declared experiment: what to send and which oracle decides.

    Emitted by the verifier agent before any execution, logged, and then run by
    the deterministic :class:`~.runner.ConfirmationSpecRunner`. The spec carries
    no conclusion — only populations, an oracle *name*, a margin, and a routine
    id. The oracle body lives in this module, not on the spec, so the model can
    select an oracle but cannot write one.
    """

    kind: str
    routine_id: str
    label: str
    host: str
    url: str
    param: str = ""
    where: str = "query"
    baseline_payload: str = ""
    control_payload: str = ""
    injected_payload: str = ""
    #: The causal discriminator's two doses in the winning payload's own shape
    #: (gap-closure batch 2, Phase 3): a timing spec that names them is
    #: dose-discriminated on *this* injection, not on the verifier's SQL
    #: fallback spelling. Empty keeps the fallback behavior.
    dose_short_payload: str = ""
    dose_long_payload: str = ""
    samples: int = 3
    oracle: str = ORACLE_RESPONSE_DIFFERS
    margin: float = 0.0
    length_delta: int = 0
    canary: str = ""
    marker: str = ""
    #: The JavaScript expression a browser oracle evaluates for the marker.
    marker_expression: str = ""
    #: where a stored routine reads its store back (the proof page).
    read_back: str = ""
    companions: dict[str, str] = field(default_factory=dict)
    origin: str = "verifier.agent"

    def _content(self) -> dict:
        """The spec's fields, without the digest — the digest is computed over this."""
        return {
            "kind": self.kind,
            "routine_id": self.routine_id,
            "label": self.label,
            "host": self.host,
            "url": self.url,
            "param": self.param,
            "where": self.where,
            "baseline_payload": self.baseline_payload,
            "control_payload": self.control_payload,
            "injected_payload": self.injected_payload,
            "dose_short_payload": self.dose_short_payload,
            "dose_long_payload": self.dose_long_payload,
            "samples": self.samples,
            "oracle": self.oracle,
            "margin": self.margin,
            "length_delta": self.length_delta,
            "canary": self.canary,
            "marker": self.marker,
            "marker_expression": self.marker_expression,
            "read_back": self.read_back,
            "companions": dict(self.companions),
            "origin": self.origin,
        }

    def to_dict(self) -> dict:
        return {**self._content(), "spec_digest": self.digest}

    @property
    def digest(self) -> str:
        """A stable digest over the spec's *content* — the replay key."""
        canonical = json.dumps(
            self._content(), sort_keys=True, separators=(",", ":"), default=str
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def as_confirm_spec(self) -> ConfirmSpec:
        """This spec, as the kernel's shared :class:`~..kernel.confirm.ConfirmSpec`.

        The one projection the delegation rides: the runner hands the classic
        verifiers this shape, so a two-gate timing or authorization finding is
        measured by exactly the logic a classic candidate's is. Two conversions,
        both pinned by test:

        * **units** — this spec's ``margin`` is milliseconds (the runner's
          feature vocabulary); the shared spec's is seconds (the classic
          verifiers' spelling). The division happens here, once, and nowhere
          else.
        * **the authorization oracle** — this spec's oracle names a runner
          predicate (``authz_differential``); the shared spec carries the
          verifier-side contract (``DIFFERENTIAL_SESSIONS``), which the
          authorization verifier checks and the timing verifier ignores.
        """
        kind = self.kind
        oracle = self.oracle
        if kind == "authorization.differential":
            oracle = DIFFERENTIAL_SESSIONS
        return ConfirmSpec(
            kind=kind,
            url=self.url,
            host=self.host,
            param=self.param,
            where=self.where,
            companions=dict(self.companions),
            baseline_payload=self.baseline_payload,
            control_payload=self.control_payload,
            injected_payload=self.injected_payload,
            dose_short_payload=self.dose_short_payload,
            dose_long_payload=self.dose_long_payload,
            samples=self.samples,
            margin=self.margin / 1000.0,
            oracle=oracle,
            probe=f"confirm:{self.routine_id}",
        )


@dataclass(frozen=True)
class ConfirmationResult:
    """The runner's answer: the spec, the oracle's boolean, and the raw features."""

    spec: ConfirmationSpec
    proven: bool
    oracle_true: bool
    reason: str
    context: OracleContext | None = None
    #: The evidence class the oracle rests on, or ``""`` when nothing was proven.
    evidence_grade: str = ""

    def to_dict(self) -> dict:
        return {
            "routine_id": self.spec.routine_id,
            "spec_digest": self.spec.digest,
            "proven": self.proven,
            "oracle_true": self.oracle_true,
            "reason": self.reason,
            "evidence_grade": self.evidence_grade,
            "features": self.context.to_dict() if self.context else {},
        }


def median_elapsed(items: Sequence[Features]) -> float:
    """Median elapsed ms of a population — exposed for tests and reports."""
    if not items:
        return 0.0
    return round(statistics.median(item.elapsed_ms for item in items), 3)


__all__ = [
    "ConfirmationResult",
    "ConfirmationSpec",
    "FEATURE_FIELDS",
    "Features",
    "ORACLES",
    "ORACLE_AUTHZ_DIFFERENTIAL",
    "ORACLE_DATA_EXTRACTED",
    "ORACLE_EVIDENCE",
    "ORACLE_OOB_HIT",
    "ORACLE_RESPONSE_DIFFERS",
    "ORACLE_SCRIPT_EXECUTED",
    "ORACLE_TIMING_DIFFERENTIAL",
    "OracleContext",
    "apply_oracle",
    "feature_from_browser",
    "feature_from_exchange",
    "median_elapsed",
    "oracle_authz_differential",
    "oracle_data_extracted",
    "oracle_oob_hit",
    "oracle_response_differs",
    "oracle_script_executed",
    "oracle_timing_differential",
]
