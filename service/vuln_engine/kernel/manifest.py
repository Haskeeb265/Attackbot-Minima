"""What a technique must declare to be discoverable, schedulable and chainable.

Mirrors the recon platform's ``platform/contract.py`` ``Manifest``: declarative,
lives in the technique's own folder, validated at discovery time. Two things it
buys, both structural rather than aspirational:

* **removability** — the registry discovers a folder and reads its manifest, so a
  technique can be deleted without editing anything outside itself;
* **chaining as data** — ``preconditions``/``postconditions`` are what make "can
  A's output feed B's input?" a computed query over the world model instead of an
  LLM's imaginative mood.

``NoiseProfile``'s units are **frozen as of Phase 2** (the checklist's open
question §6.3): visibility is measured in *expected analyst/WAF-visible requests,
normalized per surface, under the house timing envelope*. :attr:`NoiseProfile.cost`
is that scalar — deliberately simple, deliberately multiplicative (a technique
that is both bursty *and* distinctive is worse than either alone) — and it is now
normative: the scheduler divides UCB's optimistic reward by it, so a technique's
declared footprint directly sets how good its expected news has to be before it
is worth the noise. The Phase 1 rule stands unchanged: the profile is *declared*
by the technique, never measured post-hoc.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .evidence import EVIDENCE_CLASSES, is_evidence_class


@dataclass(frozen=True)
class NoiseProfile:
    """What a technique costs in visibility. Declared, never measured post-hoc.

    The analogy the design uses is the alert meter in a stealth game: the mission
    is not "finish fast", it is "finish without filling the bar". Every action
    raises it; some raise it a lot (a browser is the loudest thing this engine
    owns).
    """

    #: Raw request volume per surface.
    requests_per_surface: int = 1
    #: 0.0 steady … 1.0 machine-gun.
    burstiness: float = 0.0
    #: 0.0 = the house identity … 1.0 = distinctive.
    fingerprint_distance: float = 0.0
    #: Browsers are the loudest thing we own.
    requires_browser: bool = False

    def __post_init__(self) -> None:
        for name in ("burstiness", "fingerprint_distance"):
            value = getattr(self, name)
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"{name} must be within 0.0 … 1.0, got {value!r}")

    @property
    def cost(self) -> float:
        """The frozen visibility scalar: units per ``manifest.py``'s module docstring.

        Multiplicative on purpose — components compound, they do not average — and
        monotone in each, which is the property the Phase 2 property test pins:
        more of anything never costs less.
        """
        return (
            self.requests_per_surface
            * (1.0 + self.burstiness)
            * (1.0 + self.fingerprint_distance)
            * (3.0 if self.requires_browser else 1.0)
        )

    def to_dict(self) -> dict:
        return {
            "requests_per_surface": self.requests_per_surface,
            "burstiness": self.burstiness,
            "fingerprint_distance": self.fingerprint_distance,
            "requires_browser": self.requires_browser,
            "cost": round(self.cost, 3),
        }


@dataclass(frozen=True)
class TechniqueManifest:
    """The declarative half of the technique contract."""

    #: Must equal the folder name — validated at discovery, like the recon side's.
    name: str
    vuln_class: str
    #: What the world must look like for this to be worth trying.
    preconditions: tuple[str, ...] = ()
    #: What it establishes when it succeeds — the chain edges.
    postconditions: tuple[str, ...] = ()
    #: Evidence classes this technique can *produce*.
    produces: tuple[str, ...] = ()
    #: The class a verifier must use to confirm it (invariant #8).
    verification_needs: str = ""
    #: What it costs in visibility.
    noise: NoiseProfile | None = None
    #: Capability requirements — transport names this technique needs.
    transports: tuple[str, ...] = ("http1",)
    title: str = ""
    description: str = ""

    def validate(self) -> list[str]:
        """Return the reasons this manifest is unusable; ``[]`` when it is fine.

        Loud on purpose: a manifest missing ``postconditions`` is a technique
        that can never be chained, and discovering it at run time as "the chain
        query returned nothing" would be a silent wrong answer rather than a
        loud missing one.
        """
        problems: list[str] = []
        if not self.name:
            problems.append("no name")
        if not self.vuln_class:
            problems.append("no vuln_class")
        if not self.postconditions:
            problems.append(
                "no postconditions: without them this technique cannot be chained, "
                "and 'the chain query returned nothing' would be a silent wrong answer"
            )
        if not self.produces:
            problems.append("no evidence classes declared in `produces`")
        unknown = [grade for grade in self.produces if not is_evidence_class(grade)]
        if unknown:
            problems.append(
                f"unknown evidence class(es) in produces: {', '.join(sorted(unknown))} "
                f"(known: {', '.join(sorted(EVIDENCE_CLASSES))})"
            )
        if not self.verification_needs:
            problems.append(
                "no verification_needs: the contract requires every technique to say "
                "which independent class confirms it"
            )
        elif not is_evidence_class(self.verification_needs):
            problems.append(
                f"verification_needs {self.verification_needs!r} is not an evidence class"
            )
        elif self.verification_needs in self.produces:
            problems.append(
                f"verification_needs {self.verification_needs!r} is also in produces: a "
                "verifier must use a class the proposer did not"
            )
        if not self.transports:
            problems.append("declares no transports")
        return problems

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "vuln_class": self.vuln_class,
            "title": self.title,
            "preconditions": list(self.preconditions),
            "postconditions": list(self.postconditions),
            "produces": list(self.produces),
            "verification_needs": self.verification_needs,
            "transports": list(self.transports),
            "noise": self.noise.to_dict() if self.noise else None,
        }


__all__ = ["NoiseProfile", "TechniqueManifest"]
