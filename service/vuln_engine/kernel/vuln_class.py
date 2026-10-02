"""The vuln_class vocabulary: one spelling convention, canonical names, variants.

NOVELTY.md §5's scar: ``vuln_class`` is a free string, and
``OBJECT-ACCESS``/``object-access`` fragmentation is one sloppy generator away
— two spellings of one class would split its history across the log, the
memory layer, and every cross-run join. DR-001 and the PRD's Phase 1 make this
string the join key downstream of everything, so it gets machinery, not a
convention.

Two mechanisms, deliberately different:

* **Normalization** (``normalize_vuln_class``) — every class string is folded
  to the lowercase-hyphen convention before it is stored anywhere. This is
  what kills fragmentation: ``OBJECT-ACCESS`` and ``object_access`` can no
  longer both exist, because both become ``object-access`` on arrival.
* **The canonical set** (``CANONICAL_VULN_CLASSES``) — the classes the engine
  has *named*, each anchored to its CWE. ``canonicalize`` is strict: it raises
  on a class outside the set, for the spots where a typo must be a loud
  failure (manifest checks, tests, joins).

What the canonical set is **not** is a gate on novelty. The spike's thesis —
an unregistered class can be proven — stays intact: a plan row (or a future
generator) may carry a class nobody has named yet, as long as it normalizes to
the convention. That is the novel-class lane; ``vuln_class_status`` reports it
honestly, so memory and reporting can treat an unknown class as new territory
rather than dropping it. Adding a canonical name is adding one constant here —
the one place, per the PRD's Phase 1 deliverable.
"""

from __future__ import annotations

import re

# --------------------------------------------------------------------------- #
# The canonical set — lowercase-hyphen spellings, CWE-anchored
# --------------------------------------------------------------------------- #

#: Insecure Direct Object Reference (CWE-639): the IDOR technique's class.
VULN_CLASS_IDOR = "idor"
#: Cross-site scripting (CWE-79): the three XSS techniques' class.
VULN_CLASS_XSS = "xss"
#: SQL injection (CWE-89): the blind-time technique's class.
VULN_CLASS_SQLI = "sqli"
#: Server-side request forgery (CWE-918): the OOB fetch technique's class.
VULN_CLASS_SSRF = "ssrf"
#: Improper authorization, generic form (CWE-285): the generic plan table's
#: object-read row. The family ``idor`` is the named instance of.
VULN_CLASS_OBJECT_ACCESS = "object-access"
#: OS command injection (CWE-78): the command-injection technique's class.
VULN_CLASS_COMMAND_INJECTION = "command-injection"
#: Interpretation conflict (CWE-436): the generic plan table's state-change
#: composition row — one request means something else to another handler.
VULN_CLASS_METHOD_CONFUSION = "method-confusion"

CANONICAL_VULN_CLASSES: frozenset[str] = frozenset(
    {
        VULN_CLASS_IDOR,
        VULN_CLASS_XSS,
        VULN_CLASS_SQLI,
        VULN_CLASS_SSRF,
        VULN_CLASS_OBJECT_ACCESS,
        VULN_CLASS_COMMAND_INJECTION,
        VULN_CLASS_METHOD_CONFUSION,
    }
)

#: CWE anchors, canonical spelling only. A novel class has no anchor yet;
#: ``cwe_of`` returns ``""`` for it rather than guessing.
_CWE_OF: dict[str, str] = {
    VULN_CLASS_IDOR: "CWE-639",
    VULN_CLASS_XSS: "CWE-79",
    VULN_CLASS_SQLI: "CWE-89",
    VULN_CLASS_SSRF: "CWE-918",
    VULN_CLASS_OBJECT_ACCESS: "CWE-285",
    VULN_CLASS_COMMAND_INJECTION: "CWE-78",
    VULN_CLASS_METHOD_CONFUSION: "CWE-436",
}

#: The spelling convention: lowercase words, single hyphens, alphanumeric.
#: This is the shape every stored class string has, canonical or novel.
VULN_CLASS_PATTERN = re.compile(r"^[a-z][a-z0-9]*(-[a-z0-9]+)*$")


class UnknownVulnClass(ValueError):
    """A class string outside the canonical set, where only canonical is allowed."""

    def __init__(self, raw: str, normalized: str) -> None:
        self.raw = raw
        self.normalized = normalized
        super().__init__(
            f"vuln_class {raw!r} (normalized {normalized!r}) is not in the "
            f"canonical vocabulary; known: {', '.join(sorted(CANONICAL_VULN_CLASSES))}. "
            "New classes join by adding one constant to kernel/vuln_class.py."
        )


# --------------------------------------------------------------------------- #
# normalization — the anti-fragmentation mechanism
# --------------------------------------------------------------------------- #


def normalize_vuln_class(raw: str) -> str:
    """Fold *raw* to the lowercase-hyphen convention.

    ``OBJECT-ACCESS`` → ``object-access``; ``object_access`` →
    ``object-access``; ``Object Access`` → ``object-access``. Whitespace and
    underscores become single hyphens; case is folded; leading/trailing
    separators are stripped. The result is the only spelling anyone stores.
    """
    folded = re.sub(r"[\s_]+", "-", raw.strip().lower())
    folded = re.sub(r"-{2,}", "-", folded).strip("-")
    return folded


def is_well_formed(normalized: str) -> bool:
    """True when *normalized* matches the convention (and is not empty)."""
    return bool(normalized) and bool(VULN_CLASS_PATTERN.match(normalized))


def vuln_class_status(raw: str) -> str:
    """``"canonical"`` or ``"novel"`` for *raw*.

    Novel is a **status, not an error**: it is the lane the spike opened (a
    class the registry never named) and the lane the abductive loop will live
    in. A novel class normalizes like any other so its records still join;
    what it lacks is a CWE anchor and history, which reporting states.
    """
    normalized = normalize_vuln_class(raw)
    if not is_well_formed(normalized):
        raise UnknownVulnClass(raw, normalized)
    return "canonical" if normalized in CANONICAL_VULN_CLASSES else "novel"


def canonicalize(raw: str) -> str:
    """*raw* folded and required to be canonical — for code-authored spots.

    Manifest validation, tests and joins use this: a typo here must be a loud
    failure, not a novel class. Plan rows and generated claims do **not** go
    through this function; they normalize and report status instead, so the
    novel-class lane stays open.
    """
    normalized = normalize_vuln_class(raw)
    if normalized not in CANONICAL_VULN_CLASSES:
        raise UnknownVulnClass(raw, normalized)
    return normalized


def cwe_of(canonical: str) -> str:
    """The CWE anchor for a canonical class; ``""`` for a novel one."""
    return _CWE_OF.get(normalize_vuln_class(canonical), "")


__all__ = [
    "CANONICAL_VULN_CLASSES",
    "UnknownVulnClass",
    "VULN_CLASS_COMMAND_INJECTION",
    "VULN_CLASS_IDOR",
    "VULN_CLASS_METHOD_CONFUSION",
    "VULN_CLASS_OBJECT_ACCESS",
    "VULN_CLASS_SQLI",
    "VULN_CLASS_SSRF",
    "VULN_CLASS_XSS",
    "VULN_CLASS_PATTERN",
    "canonicalize",
    "cwe_of",
    "is_well_formed",
    "normalize_vuln_class",
    "vuln_class_status",
]
