"""The hypothesis: what might be true about a surface, before anything is sent.

One hypothesis, resting on the *claimed* capability the operator declared: the
surface's processing time depends on this parameter. Like every claimed
capability in this engine it produces a lead at best — only the differential
verifier could ever make it a finding, and only with a margin a slow target
cannot fake by being slow in general.

The precondition is ``public_param`` rather than ``delayed_response`` on purpose:
an operator who *knew* the parameter reached a shell would not need the engine.
The claim is what gets tested, not what gets assumed.
"""

from __future__ import annotations

from ...kernel.technique import (
    CAP_DELAYED_RESPONSE,
    CAP_PUBLIC_PARAM,
    Hypothesis,
    Surface,
)

NAME = "command_injection"


def hypotheses(surface: Surface) -> list[Hypothesis]:
    """The claim worth testing on *surface*. Empty when there is no parameter."""
    if not surface.param:
        return []
    return [
        Hypothesis(
            id=f"{NAME}:{surface.host}:{surface.param}:shell",
            technique=NAME,
            surface=surface,
            claim=(
                f"parameter {surface.param!r} reaches a shell, so a value carrying "
                "a metacharacter and a delay command makes the response slow"
            ),
            rests_on=CAP_DELAYED_RESPONSE,
            preconditions=(CAP_PUBLIC_PARAM,),
        )
    ]


__all__ = ["NAME", "hypotheses"]
