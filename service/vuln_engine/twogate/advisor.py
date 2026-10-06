"""Model advisors for the two agents — advisory only, and closed-set.

The capability and verifier agents each accept an advisor. This module builds
them over the existing :class:`~..llm.client.LLMClient`: one door to the model,
every call logged as an ``llm.junction`` row keyed by content digest, and a
degraded (no-key / invalid / refused) answer returns ``None`` so the deterministic
core runs unchanged.

What a model may do here is deliberately tiny:

* the **capability advisor** may re-order the candidate labels the *measured*
  capabilities already admit (it cannot admit a new label);
* the **verifier advisor** may pick one payload from the routine's own family
  (it cannot add a payload or change the oracle).

Neither answer can name an oracle, a margin, or a label outside the closed set
the deterministic core handed it — so the model can shape emphasis, never
evidence. This is the same contract as every other junction in the engine, one
layer down.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ..llm.client import LLMClient
from ..kernel.technique import Surface


class ModelAdvisor:
    """Two junction-backed advisors over one LLM client."""

    def __init__(
        self,
        client: LLMClient,
        *,
        world: Any = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.client = client
        self._world = world
        self._clock = clock

    @property
    def available(self) -> bool:
        return self.client.available

    # ------------------------------------------------------------------ #
    # capability advisor
    # ------------------------------------------------------------------ #

    def capability_advisor(
        self, surface: Surface, capabilities: frozenset[str], history: list[str]
    ) -> Any:
        """Re-order the admitted labels, or ``None`` when degraded.

        The *options* are computed here from the same closed mapping the
        deterministic core uses, so the model can only choose among them. It
        cannot introduce a label, and an answer that names one is rejected by
        ``validate`` and becomes a degraded opinion.
        """
        from .agents import CAPABILITY_ROUTES, CAPABILITY_ORDER, Proposal

        admitted: list[Proposal] = []
        for capability in CAPABILITY_ORDER:
            if capability not in capabilities:
                continue
            for label, confirm_kind, vuln_class, family in CAPABILITY_ROUTES[capability]:
                if label in history:
                    continue
                admitted.append(
                    Proposal(
                        id=f"{label}:{surface.key}",
                        surface_key=surface.key,
                        label=label,
                        vuln_class=vuln_class,
                        confirm_kind=confirm_kind,
                        capability=capability,
                        payload_family=family,
                        rationale=f"model-selected from the admitted set for {capability}",
                    )
                )
        if not admitted:
            return None
        allowed = [item.label for item in admitted]
        input_payload = {
            "surface": {"url": surface.url, "param": surface.param, "where": surface.where},
            "capabilities": sorted(capabilities),
            "history": list(history),
            "options": allowed,
        }
        prompt = (
            "You are choosing which vulnerability class to test next on one input "
            "surface. You may only pick from the options given. Reply with JSON "
            '{"label": "<one of the options>"} and nothing else.\n'
            f"options: {allowed}\n"
            f"surface: {input_payload['surface']}\n"
            f"measured capabilities: {sorted(capabilities)}\n"
            f"already tried: {list(history)}"
        )
        system = "You output a single JSON object and nothing else."

        def validate(answer: Any) -> str:
            label = str((answer or {}).get("label", ""))
            if label not in allowed:
                raise ValueError(f"label {label!r} is not one of {allowed}")
            return "label-in-admitted-set"

        opinion = self.client.ask(
            junction="twogate.capability",
            input=input_payload,
            prompt=prompt,
            system=system,
            validate=validate,
            world=self._world,
            now=self._now(),
        )
        if not opinion.validated:
            return None
        chosen = str(opinion.answer.get("label", ""))
        # Return the full admitted list, model's choice first: the loop takes the
        # head, so the model's preference is honoured while the rest remain the
        # deterministic fallback ordering.
        return [item for item in admitted if item.label == chosen] + [
            item for item in admitted if item.label != chosen
        ]

    # ------------------------------------------------------------------ #
    # verifier advisor
    # ------------------------------------------------------------------ #

    def verifier_advisor(
        self, surface: Surface, proposal: Any, routine: Any
    ) -> str | None:
        """Pick one payload from the routine's family, or ``None`` when degraded."""
        family = list(routine.injected_payloads)
        if len(family) <= 1:
            return None
        input_payload = {
            "routine_id": routine.routine_id,
            "label": proposal.label,
            "payloads": family,
            "surface": {"url": surface.url, "param": surface.param, "where": surface.where},
        }
        prompt = (
            "Choose which payload from this verification routine's family to inject. "
            "You may only pick from the given list. Reply with JSON "
            '{"payload_index": <integer index into payloads>} and nothing else.\n'
            f"payloads: {family}"
        )
        system = "You output a single JSON object and nothing else."

        def validate(answer: Any) -> str:
            try:
                index = int(str((answer or {}).get("payload_index")))
            except (TypeError, ValueError):
                raise ValueError("payload_index is not an integer") from None
            if not 0 <= index < len(family):
                raise ValueError(f"payload_index {index} is out of range")
            return "index-in-family"

        opinion = self.client.ask(
            junction="twogate.verifier",
            input=input_payload,
            prompt=prompt,
            system=system,
            validate=validate,
            world=self._world,
            now=self._now(),
        )
        if not opinion.validated:
            return None
        return family[int(str(opinion.answer.get("payload_index", "0")))]

    def _now(self) -> float:
        return self._clock() if self._clock is not None else 0.0


def build_advisor(*, log: Any = None, clock: Callable[[], float] | None = None) -> ModelAdvisor | None:
    """Build an advisor from the environment, or ``None`` when no key is set."""
    client = LLMClient()
    if not client.available:
        return None
    return ModelAdvisor(client, world=log, clock=clock)


__all__ = ["ModelAdvisor", "build_advisor"]
