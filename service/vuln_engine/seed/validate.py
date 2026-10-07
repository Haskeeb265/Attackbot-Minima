"""Seed validation: the operator's declarations, held to the registry's grammar.

Batch 2, Phase 4. ``Surface.where`` speaks five positions — ``query``/``body``/
``path``/``header``/``url`` — but no registered technique's probing grammar
accepts ``header`` or ``url`` yet: the classic probing techniques and the
two-gate flow both probe query/body/path parameters, and the LLM junctions
already refuse anything outside ``query``/``body``/``path``. A surface declared
at a position nobody can probe used to be **silently skipped** — filtered out by
``EngagementSeed.with_param`` or gated off technique by technique — which is
exactly the "the scanner said nothing, so there was nothing" failure the
engine's design exists to prevent.

The gate here is the same shape as the capability gate: the accepted set is
*derived from the registry* (``TechniqueRegistry.accept_where`` — a manifest's
``gate_where`` when it declares one, the classic core default when it does
not), so a technique that starts accepting ``header`` widens the accepted set
by declaring it, and the gate moves with the registry. Nothing else edits a
second copy of the vocabulary.

:func:`validate_seed` returns one problem string per refused surface, with the
surface's label and the *named* reason — the report and the CLI print it, the
operator fixes the declaration or drops the surface. The failure is loud at
assembly, before any scheduling work, never a quiet skip at probe time.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..kernel.technique import EngagementSeed, Surface
from ..registry import TechniqueRegistry

#: The reason spelled on every where-refusal — one sentence, shared, so a
#: report's reasons and a test's assertions read the same words.
HEADER_URL_NOTE = (
    "no registered technique's probing grammar accepts it yet — header/url "
    "support is a named open follow-up (batch 2 deliberately left it open)"
)


@dataclass(frozen=True)
class SurfaceProblem:
    """One refused surface, with the reason it cannot run."""

    surface: Surface
    reason: str

    def to_dict(self) -> dict:
        return {
            "surface": self.surface.key,
            "param": self.surface.param,
            "where": self.surface.where,
            "label": self.surface.label,
            "reason": self.reason,
        }


def validate_seed(
    seed: EngagementSeed, registry: TechniqueRegistry | None
) -> list[SurfaceProblem]:
    """Every declared surface no registered technique accepts, with the reason.

    ``registry=None`` (no techniques discovered at all) is *not* this gate's
    problem: an engine with no techniques has bigger problems, and refusing
    every surface on its behalf would misreport the cause. The gate fires only
    when there is a registry to derive the accepted set from.
    """
    if registry is None:
        return []
    accepted = registry.accept_where()
    problems: list[SurfaceProblem] = []
    for surface in seed.surfaces:
        if surface.where in accepted:
            continue
        problems.append(
            SurfaceProblem(
                surface=surface,
                reason=(
                    f"where={surface.where!r} is not accepted by any registered "
                    f"technique's grammar (accepted: {', '.join(sorted(accepted))}); "
                    f"{HEADER_URL_NOTE}"
                ),
            )
        )
    return problems


__all__ = ["HEADER_URL_NOTE", "SurfaceProblem", "validate_seed"]
