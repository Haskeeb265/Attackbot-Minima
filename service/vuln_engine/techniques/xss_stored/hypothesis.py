"""The hypothesis: what might be true about a surface, before anything is sent.

One hypothesis, and it is the stored sibling of the reflected one: *input
submitted to this parameter is stored and served back on the read-back page*.
The claim is bigger than a reflection — it is persistence — which is exactly why
it rests on a capability claim (``server_stores_input``) the operator declares
and the read-back reflection then measures. A surface that accepts a POST and
renders nothing back anywhere is not this hypothesis, and the read-back's honest
``reflected: false`` says so.

The precondition is the capability itself: without an operator's persistence
claim there is nothing to test — a body parameter on an ordinary form is the
``xss_reflected`` technique's territory, and two techniques probing one surface
because their filters overlap would double the noise for half the information.
"""

from __future__ import annotations

from ...kernel.technique import (
    CAP_PERSISTENT_STORAGE,
    Hypothesis,
    Surface,
)

NAME = "xss_stored"


def hypotheses(surface: Surface) -> list[Hypothesis]:
    """The claims worth testing on *surface*.  Empty without a body parameter."""
    if not surface.param or surface.where != "body":
        return []
    return [
        Hypothesis(
            id=f"{NAME}:{surface.host}:{surface.param}:stored",
            technique=NAME,
            surface=surface,
            claim=(
                f"input submitted as {surface.param!r} is stored and served back on "
                f"the read-back page"
            ),
            rests_on=CAP_PERSISTENT_STORAGE,
            preconditions=(CAP_PERSISTENT_STORAGE,),
        )
    ]


__all__ = ["NAME", "hypotheses"]
