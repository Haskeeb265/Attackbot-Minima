"""The hypothesis: what might be true about a surface, before anything is sent.

One hypothesis, and it is the weakest useful one: *this parameter's value comes
back in the response*. That is a lead generator, not a finding — reflecting a
string is what a search box does on purpose. Its whole value is that it is cheap
to test and that the *context* of the reflection is what decides whether the lead
is worth a browser.

The preconditions are named rather than implied, because the scheduler's Phase 1
job is to enumerate eligible ``(technique × surface)`` pairs from them, and Phase 2
will rank the same pairs. A precondition that lived only in prose could not be
checked.
"""

from __future__ import annotations

from ...kernel.technique import (
    CAP_PUBLIC_PARAM,
    CAP_RESPONSE_REFLECTS_INPUT,
    Hypothesis,
    Surface,
)

NAME = "xss_reflected"


def hypotheses(surface: Surface) -> list[Hypothesis]:
    """The claims worth testing on *surface*.  Empty when there is no parameter."""
    if not surface.param:
        return []
    return [
        Hypothesis(
            id=f"{NAME}:{surface.host}:{surface.param}:reflect",
            technique=NAME,
            surface=surface,
            claim=f"parameter {surface.param!r} is reflected into the response",
            rests_on=CAP_RESPONSE_REFLECTS_INPUT,
            preconditions=(CAP_PUBLIC_PARAM,),
        )
    ]


__all__ = ["NAME", "hypotheses"]
