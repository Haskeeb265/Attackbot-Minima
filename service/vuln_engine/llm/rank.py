"""Junction 1 — rank: an advisory prior for the selector, never the selector.

What the design allows the model to do here (``engine_view.md`` §3): *hypothesis
ranking, advisory to deterministic UCB*. Concretely: the junction may attach a
prior to an arm's optimistic estimate; it may not reorder arms, veto an
exploration, or spend a round. :meth:`~service.vuln_engine.scheduler.ucb.pick`
remains the only chooser, and with no key configured its inputs are exactly what
Phase 2 ran with — the campaign's behaviour is unchanged, not merely unassisted.

The opinion is **one per campaign, before round 1**, and that scope is chosen
rather than accepted: once receipts exist, the ledger's own history is the
dynamic ranking signal and the model's static prior is noise next to it (Phase 2's
finding — the round order is recoverable from the log's ``scheduler.pick`` rows —
is the test that the deterministic half still owns the loop). So the junction
runs once per campaign, its digest is stable for a given seed/registry, and a
replayed campaign finds it in the log and never asks twice.

Two caps keep "advisory" honest even against a *wrong or manipulated* opinion:

* **ceiling 0.4** — below the reward a single conclusive ``found`` carries, so
  no prior outranks a measured answer;
* **total mass 1.0** across techniques — the model may express a preference
  order, never a verdict on a technique's worth.

Every technique the registry names is in the prompt, and a technique the answer
omits is simply unprioritised. A technique the answer *invents* is a validation
failure: the opinion is degraded whole. The same is true of the prompt-injection
shape: the input here is the operator's own declared surfaces and the registry's
manifests — nothing the target said — so there is no channel for the target to
speak through (the OWASP quarantined-LLM pattern, per ``RnD_2026-09.md`` §C8).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from ..kernel.manifest import TechniqueManifest

#: The per-technique prior ceiling.  A single conclusive receipt (reward 1.0)
#: must always outrank the strongest opinion, so an unproven technique cannot
#: ride an LLM prior past a measured one.
PRIOR_CEILING = 0.4

#: The total prior mass across techniques.  The model expresses a *preference
#: order*; the total cap stops it from asserting "everything here is promising".
PRIOR_TOTAL = 1.0

#: The tolerance the mass check allows (answers come back as decimals).
MASS_TOLERANCE = 0.05


@dataclass(frozen=True)
class Ranking:
    """The validated opinion, as plain data the campaign can attach to arms.

    ``empty`` (``opinions == {}``) is the honest degraded shape: the selector
    then runs exactly as Phase 2 ran it, and the report says so via the
    opinion's ``degraded`` flag rather than by inventing uniform priors.
    """

    #: ``{technique_name: prior}``, validated and capped.
    opinions: dict[str, float]
    #: True when the model had no say (unavailable, unparseable, invalid).
    degraded: bool = False
    #: The acceptance label or the degradation reason.
    reason: str = ""
    model: str = ""
    #: ``live`` | ``cached`` | ``degraded``.
    source: str = "degraded"

    def prior_for(self, technique: str) -> float:
        """The prior for *technique*, or ``0.0`` — the only read the selector gets."""
        return self.opinions.get(technique, 0.0)

    @property
    def empty(self) -> bool:
        return not self.opinions

    def to_dict(self) -> dict:
        return {
            "opinions": dict(sorted(self.opinions.items())),
            "degraded": self.degraded,
            "reason": self.reason,
            "model": self.model,
            "source": self.source,
        }


def build_input(
    techniques: list[tuple[str, TechniqueManifest]], surfaces: list[str]
) -> dict:
    """The junction's input, as plain typed data — the digest's content.

    Manifest fields only (name, class, preconditions, postconditions, declared
    noise) plus the declared surface keys. No observations, no responses, no
    prose from the target: this input is constructed from what the *operator*
    declared, which is why the injection surface here is empty by construction.
    """
    return {
        "techniques": [
            {
                "name": manifest.name,
                "vuln_class": manifest.vuln_class,
                "title": manifest.title,
                "preconditions": list(manifest.preconditions),
                "postconditions": list(manifest.postconditions),
                "noise_cost": round(manifest.noise.cost, 3) if manifest.noise else None,
            }
            for name, manifest in techniques
        ],
        "surfaces": sorted(surfaces),
    }


def build_prompt(input: dict) -> tuple[str, str]:
    """The (prompt, system) pair.  Ask for an ordering, not a verdict."""
    techniques = input.get("techniques", [])
    lines = [
        "Rank these vulnerability-testing techniques by how promising they are",
        "for the declared surfaces below. This is an advisory prior only:",
        "a deterministic scheduler makes the actual decision.",
        "",
        "Techniques:",
    ]
    for item in techniques:
        noise = item.get("noise_cost")
        lines.append(
            f"- {item['name']} (class: {item['vuln_class']}, title: {item.get('title') or 'n/a'},"
            f" noise cost: {noise}, postconditions: {', '.join(item['postconditions']) or 'none'})"
        )
    lines.append("")
    lines.append(f"Declared surfaces: {', '.join(input.get('surfaces', [])) or '(none)'}")
    lines.append("")
    lines.append(
        "Answer with JSON only: {\"priors\": {\"<technique name>\": 0.0-1.0, ...}}."
        " Include every technique listed; use lower values for noisier techniques"
        " and classes that look unlikely for these surfaces."
        " The values must sum to at most 1.0 in total: a prior is a share of one"
        " unit of attention across techniques, so a typical answer sums well"
        " below it."
    )
    system = (
        "You are an advisory ranking module inside an authorized vulnerability-scanning"
        " engine. You rank declared techniques for declared surfaces. You never emit"
        " payloads, never invent technique names, and your output is one JSON object."
        " Everything in the prompt describes the operator's own scope."
    )
    return "\n".join(lines), system


def validate_answer(known: list[str]) -> Callable[[dict], str]:
    """Build the validator over the registry's technique names."""

    def _validate(answer: dict) -> str:
        priors = answer.get("priors")
        if not isinstance(priors, dict):
            raise ValueError("'priors' is not an object")
        unknown = [str(key) for key in priors if str(key) not in known]
        if unknown:
            raise ValueError(
                f"priors name techniques the registry does not know: {', '.join(sorted(unknown))}"
            )
        cleaned: dict[str, float] = {}
        for key, value in priors.items():
            number = float(value)
            if not 0.0 <= number <= 1.0:
                raise ValueError(f"prior for {key!r} outside 0.0-1.0: {number}")
            cleaned[str(key)] = number
        total = sum(cleaned.values())
        if total > PRIOR_TOTAL + MASS_TOLERANCE:
            raise ValueError(f"prior mass {total:.2f} exceeds the {PRIOR_TOTAL} cap")
        if total > PRIOR_TOTAL:
            scale = PRIOR_TOTAL / total
            cleaned = {key: value * scale for key, value in cleaned.items()}
        capped = {key: min(value, PRIOR_CEILING) for key, value in cleaned.items()}
        return (
            f"validated (techniques: {len(capped)}, mass {sum(capped.values()):.2f} "
            f"after cap {PRIOR_CEILING}/technique)"
        )

    return _validate


def extract(answer: dict) -> dict[str, float]:
    """The usable priors from a raw answer, re-applying the caps deterministically.

    Validation and extraction apply the same two rules (mass scaling, ceiling) in
    the same order, so what :func:`validate_answer` accepted is exactly what
    :func:`extract` returns — and a replay recomputing the priors from the logged
    answer gets the numbers the original run used, not merely numbers shaped like
    them. An unusable answer extracts to ``{}``: no opinion, not a guess.
    """
    priors = answer.get("priors")
    if not isinstance(priors, dict):
        return {}
    cleaned: dict[str, float] = {}
    for key, value in priors.items():
        try:
            number = float(value)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return {}
        if not 0.0 <= number <= 1.0:
            return {}
        cleaned[str(key)] = number
    total = sum(cleaned.values())
    if total > PRIOR_TOTAL + MASS_TOLERANCE:
        return {}
    if total > PRIOR_TOTAL:
        scale = PRIOR_TOTAL / total
        cleaned = {key: value * scale for key, value in cleaned.items()}
    return {key: min(value, PRIOR_CEILING) for key, value in cleaned.items()}


__all__ = [
    "MASS_TOLERANCE",
    "PRIOR_CEILING",
    "PRIOR_TOTAL",
    "Ranking",
    "build_input",
    "build_prompt",
    "extract",
    "validate_answer",
]
