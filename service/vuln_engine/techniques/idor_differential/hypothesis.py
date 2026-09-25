"""The IDOR hypothesis: one endpoint, one object, two identities.

Exactly one hypothesis per surface, deliberately. An authorization test is
not a payload-family sweep — the interesting fact is a single comparison
between two identities on one object reference. The surface itself carries
the object reference (the operator declares the URL already naming the
object: ``/api/invoices/4821``), because picking which object id to test is
an operator fact about the engagement, not something a probe grammar should
invent.
"""

from __future__ import annotations

from ...kernel.technique import CAP_ACCESS_DIFFERS_BY_SESSION, Hypothesis, Surface

CLAIM = (
    "the object this URL names is readable under the declared low-privilege "
    "session, which must not be able to read it"
)


def hypotheses(surface: Surface) -> list[Hypothesis]:
    if surface.capability != CAP_ACCESS_DIFFERS_BY_SESSION:
        return []
    return [
        Hypothesis(
            id=f"idor:{surface.key}",
            technique="idor_differential",
            surface=surface,
            claim=CLAIM,
            rests_on=CAP_ACCESS_DIFFERS_BY_SESSION,
            preconditions=(
                "two declared sessions with different access to this object",
            ),
        )
    ]


__all__ = ["CLAIM", "hypotheses"]
