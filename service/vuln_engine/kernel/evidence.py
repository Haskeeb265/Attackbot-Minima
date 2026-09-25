"""Evidence: how we came to believe something, and what may support a finding.

Ported from ``engine_explained.md`` §1 (the sketch the design doc called
"copy-paste plausible"), with one addition the code needed and the sketch did
not have: :func:`weaker_than`, so a verifier's evidence can be *compared* to the
proposer's rather than only tested for equality.

The whole rule this module exists to enforce, in one line:

    An LLM saying "that looks like XSS" is a lead. A browser recording that the
    script ran is a finding.

Both are useful. They are not the same category, and blurring them is the
failure mode of every automated scanner. So evidence carries a **grade** — the
class that produced it — and only three grades may support a finding. A
hypothesis can never be one, no matter how confident the hypothesis was.

Ordering note: ``EVIDENCE_*`` is ordered weakest to strongest *for this purpose*
("did the thing actually happen?"), which is not severity. A reflection is not
"worse" than an execution — it is weaker as proof, and the report says which one
a finding rests on.
"""

from __future__ import annotations

from dataclasses import dataclass, field

#: An LLM or a rule said so — a lead, never a finding.
EVIDENCE_HYPOTHESIS = "hypothesis"
#: Bytes came back and contained our input; context unknown.
EVIDENCE_REFLECTION = "reflection"
#: The reflection's context was parsed and mapped (attribute, JS string, …).
EVIDENCE_SEMANTIC = "semantic"
#: A browser ran the script.
EVIDENCE_EXECUTION = "execution"
#: Our own collaborator saw the interaction.
EVIDENCE_OOB = "oob"
#: Two authenticated states differed.
EVIDENCE_DIFFERENTIAL = "differential"

#: Every class, weakest to strongest for the "did it actually happen?" purpose.
EVIDENCE_ORDER: tuple[str, ...] = (
    EVIDENCE_HYPOTHESIS,
    EVIDENCE_REFLECTION,
    EVIDENCE_SEMANTIC,
    EVIDENCE_EXECUTION,
    EVIDENCE_OOB,
    EVIDENCE_DIFFERENTIAL,
)

#: The classes a *finding* may rest on.  A hypothesis can never be one.
FINDING_GRADES: frozenset[str] = frozenset(
    {EVIDENCE_EXECUTION, EVIDENCE_OOB, EVIDENCE_DIFFERENTIAL}
)

#: The differential class's declared oracle: two sessions, one object. The
#: authorization verifier and its technique share this spelling so a test can
#: pin them together, exactly like every CONFIRM_KIND pin.
DIFFERENTIAL_SESSIONS = "two_sessions_one_object"

EVIDENCE_CLASSES: frozenset[str] = frozenset(EVIDENCE_ORDER)


def is_evidence_class(grade: str) -> bool:
    """True when *grade* is one of the classes this engine recognises."""
    return grade in EVIDENCE_CLASSES


def weaker_than(left: str, right: str) -> bool:
    """True when *left* is a weaker evidence class than *right*.

    Unknown classes sort weakest on purpose: an unrecognised grade is not
    evidence of anything, so it must never be able to outrank a known one in a
    comparison the scheduler might rank by.
    """
    rank = {grade: index for index, grade in enumerate(EVIDENCE_ORDER)}

    def position(grade: str) -> int:
        return rank.get(grade, -1)

    return position(left) < position(right)


@dataclass(frozen=True)
class Evidence:
    """One observation, labeled with the class that produced it.

    ``payload`` is a ``dict`` of typed fields, never a string. "Never raw text
    blobs" (contract three) starts here, and the invariant test in
    ``tests/vuln_engine/test_invariants.py`` enforces it by reading this
    module's own annotation.

    ``at`` is a parameter, not a clock read: a module that reads the clock
    cannot be replayed, and replay is how this engine is tested offline.
    """

    #: An observation kind (see :mod:`..kernel.observation`).
    kind: str
    #: One of the ``EVIDENCE_*`` constants.
    grade: str
    #: Typed fields — never raw bytes, never a text blob.
    payload: dict = field(default_factory=dict)
    #: Set by the caller; modules stay clock-free.
    at: float = 0.0
    #: Which probe produced it, when it came from one (correlates an OOB
    #: interaction back to the request that caused it).
    probe: str = ""

    def __post_init__(self) -> None:
        if not is_evidence_class(self.grade):
            raise ValueError(
                f"unknown evidence grade {self.grade!r}; known: "
                f"{', '.join(EVIDENCE_ORDER)}"
            )
        if not isinstance(self.payload, dict):
            raise TypeError(
                "an Evidence payload must be a dict of typed fields; a text blob "
                "cannot be reasoned over, remembered or verified"
            )
        # Taken by value. A frozen dataclass that aliased a caller's dict would be
        # frozen in name only: the log is the record, and a payload that could be
        # edited after it was recorded is not evidence.
        object.__setattr__(self, "payload", dict(self.payload))

    @property
    def sufficient_for_finding(self) -> bool:
        """True when this evidence class may support a finding on its own."""
        return self.grade in FINDING_GRADES

    def to_dict(self) -> dict:
        payload: dict = {
            "kind": self.kind,
            "grade": self.grade,
            "payload": dict(self.payload),
            "at": round(self.at, 3),
        }
        if self.probe:
            payload["probe"] = self.probe
        return payload


__all__ = [
    "DIFFERENTIAL_SESSIONS",
    "EVIDENCE_CLASSES",
    "EVIDENCE_DIFFERENTIAL",
    "EVIDENCE_EXECUTION",
    "EVIDENCE_HYPOTHESIS",
    "EVIDENCE_OOB",
    "EVIDENCE_ORDER",
    "EVIDENCE_REFLECTION",
    "EVIDENCE_SEMANTIC",
    "Evidence",
    "FINDING_GRADES",
    "is_evidence_class",
    "weaker_than",
]
