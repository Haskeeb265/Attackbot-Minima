"""The elicitor registration shape — the registry's contract for ``elicit/`` folders.

An elicitor is the techniques' contract with the candidate removed: three pure
functions (``applies``, ``probes``, ``interpret``) and the manifest. The
``Elicitor`` wrapper is what a folder exposes as ``ELICITOR`` and what the
elicitor registry hands the driver — one frozen record, no behavior of its own.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from ..kernel.manifest import TechniqueManifest
from ..kernel.observation import Observation
from ..kernel.technique import Surface
from .common import Elicitation


@dataclass(frozen=True)
class Elicitor:
    """One discovered elicitor: the capability it can establish and its functions."""

    name: str
    manifest: TechniqueManifest
    #: The capability string a positive answer establishes.
    capability: str
    applies: Callable[[Surface], bool]
    probes: Callable[[Surface], list[dict]]
    interpret: Callable[..., Elicitation]

    def measure(
        self, surface: Surface, observations: list[Observation], *, at: float = 0.0
    ) -> Elicitation:
        """This elicitor's answer for *surface*, from this pass's observations."""
        return self.interpret(surface, observations, at=at)


__all__ = ["Elicitor"]
