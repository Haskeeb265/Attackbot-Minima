"""Hypotheses for ``xss_dom``: what might be true about a surface, browser-lens edition.

The claim is deliberately narrower than it looks: not "this parameter is
vulnerable" but "**the page's own JavaScript reads this parameter and writes
what it parsed somewhere in the DOM**". That is the only claim a placement
probe can test, and it is the honest precondition for every payload family —
a value the page never renders cannot execute, whatever the server's bytes did.
"""

from __future__ import annotations

from ...kernel.technique import CAP_PUBLIC_PARAM, Hypothesis, Surface

NAME = "xss_dom"


def hypotheses(surface: Surface) -> list[Hypothesis]:
    """One hypothesis per parameterised surface: the page renders this param."""
    if not surface.param or surface.where not in ("query", "body", "path"):
        return []
    return [
        Hypothesis(
            id=f"{NAME}:{surface.host}:{surface.url.split('//')[-1]}:{surface.param}",
            technique=NAME,
            surface=surface,
            claim=(
                f"the page's client-side code renders parameter {surface.param!r} "
                "into the DOM after load"
            ),
            rests_on=CAP_PUBLIC_PARAM,
        )
    ]


__all__ = ["NAME", "hypotheses"]
