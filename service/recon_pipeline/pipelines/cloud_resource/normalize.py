"""Canonicalization and name-shape rules for bucket candidates.

This module is the pipeline's identity layer, and it is pure: no network, no
clock, no filesystem.  Everything the passive stage harvests flows through here
before it is counted, because the pipeline's hard problem is the same one every
sibling solved for its own facts: **two spellings of one name must collapse to
one row, and an impossible name must be refused with a reason, not probed.**

The name rules are the providers' own (DESIGN.md §4), kept per-provider because
they differ on every axis that matters:

* **S3** — 3–63, ``[a-z0-9.-]``, alnum edges (dots legal, hyphens legal);
* **Azure storage accounts** — 3–24, lowercase letters and digits *only*;
* **GCS** — 3–63, ``[a-z0-9._-]``, alnum edges (underscores legal, dots legal).

A candidate is checked against the rules of the provider that claimed it —
never sanitized.  A sanitized name would be probed at the provider's cost for
a bucket nobody could own; refusal is the honest answer, and refusals are
counted in the report.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

#: Refusal reasons, in the wording the report uses.
REFUSED_TOO_SHORT = "shorter than the provider minimum"
REFUSED_TOO_LONG = "longer than the provider maximum"
REFUSED_CHARS = "characters outside the provider alphabet"
REFUSED_EDGES = "must start and end with a letter or digit"
REFUSED_EMPTY = "empty name"
REFUSED_PLACEHOLDER = "wildcard/placeholder name, not a bucket"
REFUSED_UNKNOWN_PROVIDER = "unknown provider"

#: Legal-name rules per provider: ``(min_len, max_len, shape, alphabet-note)``.
#: Documented during R&D (DESIGN.md §4); a candidate that fails its provider's
#: rule is refused, not fixed.
NAME_RULES: dict[str, tuple[int, int, re.Pattern[str]]] = {
    "s3": (3, 63, re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")),
    "azure": (3, 24, re.compile(r"^[a-z0-9]{3,24}$")),
    "gcs": (3, 63, re.compile(r"^[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$")),
}

#: Tokens that pattern-matched a provider host but are placeholders, not names:
#: a wildcard DNS answer or a documentation example.  Probing them is noise.
PLACEHOLDER_NAMES = frozenset({"*", "{name}", "$", "example", "your-bucket", "test"})


@dataclass
class Candidate:
    """One candidate bucket name, with every claim that produced it."""

    name: str
    provider: str
    #: Where the name came from — ``cname`` / ``url`` / ``javascript`` /
    #: ``endpoint`` / ``derived`` / ``explicit``.
    origins: set[str] = field(default_factory=set)
    #: Which sibling artifact carried each claim.
    sources: set[str] = field(default_factory=set)
    #: The exact strings that gave the name away (CNAME target, URL, …).
    evidence: list[str] = field(default_factory=list)
    #: The hostnames whose own DNS *claimed* this resource — for a CNAME-origin
    #: candidate, the target's hosts that point at it.  This is what lets the
    #: graph write a ``cname_points_to`` edge with both ends: the claim travels
    #: with the claim.
    claimants: list[str] = field(default_factory=list)
    #: False when every token behind the name is a generic word (``mail``,
    #: ``cdn``): provider names are globally namespaced, so such a name could
    #: belong to anyone.  An *observed* claim (CNAME/URL) is distinctive by
    #: definition — the target's own artifact carried it.
    distinctive: bool = True

    def merge(self, other: "Candidate") -> None:
        """Fold another claim on the same (provider, name) into this row."""
        self.origins |= other.origins
        self.sources |= other.sources
        for item in other.evidence:
            if item not in self.evidence:
                self.evidence.append(item)
        for item in other.claimants:
            if item not in self.claimants:
                self.claimants.append(item)
        if other.distinctive:
            self.distinctive = True

    @property
    def key(self) -> tuple[str, str]:
        return (self.provider, self.name)

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "provider": self.provider,
            "origins": sorted(self.origins),
            "sources": sorted(self.sources),
            "evidence": list(self.evidence),
            **({"claimants": sorted(self.claimants)} if self.claimants else {}),
            "distinctive": self.distinctive,
        }


def canonicalize_name(value: str) -> str:
    """Lowercased, edge-stripped name text, or ``""`` when nothing survives."""
    return (value or "").strip().lower().strip(".")


def validate_name(name: str, provider: str) -> str | None:
    """A refusal reason, or ``None`` when the name is legal for *provider*.

    Pure validation, never sanitization: a name that cannot exist at the
    provider is refused with the reason the report counts.
    """
    if provider not in NAME_RULES:
        return REFUSED_UNKNOWN_PROVIDER
    if not name:
        return REFUSED_EMPTY
    if name in PLACEHOLDER_NAMES or "*" in name or "{" in name:
        return REFUSED_PLACEHOLDER
    minimum, maximum, shape = NAME_RULES[provider]
    if len(name) < minimum:
        return REFUSED_TOO_SHORT
    if len(name) > maximum:
        return REFUSED_TOO_LONG
    if not shape.match(name):
        # Split the two failure classes so the report can say which rule bit.
        alphabet = re.compile(r"^[a-z0-9._-]+$" if provider == "s3" else r"^[a-z0-9_-]+$")
        return REFUSED_CHARS if not alphabet.match(name) else REFUSED_EDGES
    return None
