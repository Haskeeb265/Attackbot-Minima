"""The hypothesis: the surface's parameter can make the server fetch a URL.

It fires only on a **claimed** capability
(:data:`CAP_INFLUENCE_REMOTE_FETCH`). That restriction is the honest half of
Phase 1: the engine has no cheap way to establish that a server fetches URLs, so
it does not pretend to. The operator claims it, the hypothesis is tested, and the
collaborator decides whether the claim was true.

A hypothesis that fired on every parameter would be a technique that asks every
server on the engagement to fetch our collaborator — noisy, and wrong for the one
objective this design optimises (progress per unit of visibility).
"""

from __future__ import annotations

from ...kernel.technique import (
    CAP_INFLUENCE_REMOTE_FETCH,
    Hypothesis,
    Surface,
)

NAME = "oob_fetch"


def hypotheses(surface: Surface) -> list[Hypothesis]:
    """The claims worth testing on *surface*.  Empty unless it claims the capability."""
    if not surface.param or surface.capability != CAP_INFLUENCE_REMOTE_FETCH:
        return []
    return [
        Hypothesis(
            id=f"{NAME}:{surface.host}:{surface.param}:fetch",
            technique=NAME,
            surface=surface,
            claim=(
                f"parameter {surface.param!r} makes the server fetch a URL we supply "
                "(claimed capability, not yet measured)"
            ),
            rests_on=CAP_INFLUENCE_REMOTE_FETCH,
            preconditions=(CAP_INFLUENCE_REMOTE_FETCH,),
        )
    ]


__all__ = ["NAME", "hypotheses"]
