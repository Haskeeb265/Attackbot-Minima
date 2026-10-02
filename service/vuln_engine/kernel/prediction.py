"""The prediction layer: what a hypothesis expected, and what deviated.

Phase 2's substrate (PRD §6.1–6.3). Before this module, ``interpret`` had two
answers — candidate or honest zero — and everything that did not match a
predicate was discarded. But a discarded surprise is exactly the material
abduction needs. So a hypothesis may now carry an **expectation**: typed,
falsifiable predicates over the observations, in the same spirit as the plan
table's status predicates. The driver runs one fixed comparator:

* every expected observation was measured and matched → **settled** (silence,
  the honest zero, unchanged);
* a candidate came out of ``interpret`` → the ordinary pipeline (the
  expectation is not even consulted);
* measurements exist, matched nothing, and violated an expectation →
  **unexplained** — a :class:`Deviation`, logged as a retained anomaly.

The rules the module enforces on itself:

* **pure** — no clock, no I/O; the same observations always yield the same
  deviations, which is what keeps replay clean;
* **a missing measurement is not a deviation** — an experiment that never ran
  says nothing about the world; inventing a surprise from absent data is the
  receipt's ``failed``-is-not-an-answer rule, again;
* **typed payloads, never text blobs** — a deviation names the probe, the
  field, the expected set and the observed value, so a consumer (the abducer,
  the memory layer) can generalise over *facts*.

Optional technique contract: a technique MAY define ``unexplained(hypothesis,
observations)`` to supply its own deviations. The driver reads it with
``getattr`` (the same courtesy ``synthesis_grammar()`` gets); absent it, the
driver evaluates the hypothesis's own expectation through
:func:`evaluate`. The Protocol is deliberately not extended — an optional
method on a ``runtime_checkable`` Protocol would make existing techniques fail
``isinstance`` checks.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field as _field

from .observation import Observation

#: Deviation kinds. A small closed set, like every vocabulary in the kernel:
#: consumers switch on these, not on prose.
#: An observation arrived, was measured fine, and its value fell outside what
#: the hypothesis expected.
DEVIATION_OUTSIDE_EXPECTED = "observation_outside_expected"

DEVIATION_KINDS: tuple[str, ...] = (DEVIATION_OUTSIDE_EXPECTED,)


@dataclass(frozen=True)
class ExpectedObservation:
    """One falsifiable predicate over one probe's answer.

    ``probe_suffix`` matches the *tail* of a probe id — the technique names
    its own probes (``<hypothesis>:<step>:<behavior>``), so a plan row spells
    the behavior name it cares about and the evaluator does the suffix match,
    exactly the way the spike's ``interpret`` finds its statuses.
    """

    #: The probe-id tail this predicate is about (e.g. ``":owner_read"``).
    probe_suffix: str
    #: The payload field the predicate reads (e.g. ``"status"``).
    field: str
    #: The values that mean "as expected". Empty would be unfalsifiable in
    #: the other direction, so the constructor refuses it.
    within: frozenset = _field(default_factory=frozenset)
    #: The observation kind this predicate reads. Transport responses are the
    #: only family today; the field exists so the library can grow without a
    #: second predicate type.
    kind: str = "observation.http"

    def __post_init__(self) -> None:
        if not self.probe_suffix:
            raise ValueError("an expected observation names a probe suffix")
        if not self.field:
            raise ValueError("an expected observation names a payload field")
        if not self.within:
            raise ValueError(
                "an expected observation's `within` set is empty: a predicate "
                "that accepts everything is not a prediction"
            )

    def to_dict(self) -> dict:
        return {
            "probe_suffix": self.probe_suffix,
            "field": self.field,
            "within": sorted(self.within, key=repr),
            "kind": self.kind,
        }


@dataclass(frozen=True)
class Expectation:
    """What the world should look like if the hypothesis is false.

    A hypothesis *claims* something is broken; its expectation spells what
    "nothing is broken" looks like. Violated expectations on a clean
    measurement are the retained surprises.
    """

    description: str
    expected: tuple[ExpectedObservation, ...] = ()

    def __post_init__(self) -> None:
        if not self.expected:
            raise ValueError(
                "an expectation with no predicates predicts nothing; omit it "
                "instead (the field is optional on the hypothesis)"
            )

    def to_dict(self) -> dict:
        return {
            "description": self.description,
            "expected": [item.to_dict() for item in self.expected],
        }


@dataclass(frozen=True)
class Deviation:
    """One typed mismatch between expectation and observation.

    Advisory material by definition — a deviation is never evidence, never a
    finding, never a lead grade. It is the *question* the abducer will later
    turn into a hypothesis.
    """

    kind: str
    #: What was expected, typed (the predicate's own dict).
    expected: dict = _field(default_factory=dict)
    #: What was observed, typed: probe, field, value.
    observed: dict = _field(default_factory=dict)
    #: The expectation's own sentence, for humans reading the log.
    description: str = ""

    def __post_init__(self) -> None:
        if self.kind not in DEVIATION_KINDS:
            raise ValueError(
                f"unknown deviation kind {self.kind!r}; known: "
                f"{', '.join(DEVIATION_KINDS)}"
            )

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "expected": dict(self.expected),
            "observed": dict(self.observed),
            "description": self.description,
        }


def evaluate(
    expectation: Expectation | None, observations: Sequence[Observation]
) -> list[Deviation]:
    """The fixed comparator: expectations vs observations, deviations out.

    One function, the way the spike's comparison is one function: the
    knowledge lives in the expectations (data), the comparison is fixed code.
    ``None`` in, empty list out — a hypothesis without an expectation can
    never be "unexplained", it is only settled.
    """
    if expectation is None:
        return []
    deviations: list[Deviation] = []
    for predicate in expectation.expected:
        match: Observation | None = None
        for item in observations:
            if item.kind != predicate.kind:
                continue
            if not str(item.probe or "").endswith(predicate.probe_suffix):
                continue
            match = item  # last wins: the final measurement of that probe
        if match is None:
            continue  # a missing measurement is not a deviation
        value = match.payload.get(predicate.field)
        if _contains(predicate.within, value):
            continue  # as expected: settled, silence
        deviations.append(
            Deviation(
                kind=DEVIATION_OUTSIDE_EXPECTED,
                expected=predicate.to_dict(),
                observed={
                    "probe": match.probe,
                    "field": predicate.field,
                    "value": value,
                },
                description=expectation.description,
            )
        )
    return deviations


def _contains(within: Iterable, value: object) -> bool:
    """Membership that survives unhashable/absent values honestly.

    A ``None`` status (the transport recorded no status) is *not* a match —
    but it also reaches here as a deviation only when the measurement itself
    exists, which is the distinction that keeps transport errors from being
    mistaken for surprises.
    """
    try:
        return value in within
    except TypeError:
        return False


__all__ = [
    "DEVIATION_KINDS",
    "DEVIATION_OUTSIDE_EXPECTED",
    "Deviation",
    "Expectation",
    "ExpectedObservation",
    "evaluate",
]
