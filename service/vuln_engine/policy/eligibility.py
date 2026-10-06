"""Bounty eligibility — does a *proven* finding fall inside what the program pays for?

The engine proves a bug; this module answers the separate, program-specific
question: *would the program consider it in scope for a bounty?*  It is pure and
deterministic (no clock, no model, no transport), because eligibility is a
published rule, not a judgement call — and a finding whose eligibility depended
on an opinion would be unauditable.

Three answers, and the middle one matters:

``POTENTIALLY_ELIGIBLE``
    the program's accepted list contains a class this finding belongs to;
``INELIGIBLE``
    the asset is out of scope, or the class is on a published exclusion;
``UNKNOWN``
    nothing published matches — **not** a refusal.  A program that lists no
    class, or lists classes phrased in words this module cannot tie to the
    engine's canonical classes, yields ``UNKNOWN``: the honest answer when the
    source does not say, never a defaulted yes or no.

The module never claims ``ELIGIBLE``.  Only the program can decide that, on
submission; the engine's job is to say what is worth submitting and why.
"""

from __future__ import annotations

from dataclasses import dataclass, field

POTENTIALLY_ELIGIBLE = "potentially_eligible"
INELIGIBLE = "ineligible"
UNKNOWN = "unknown"

#: Engine ``vuln_class`` -> the lowercase fragments a program's own wording may
#: use.  The engine speaks the seven canonical classes of
#: ``kernel.vuln_class.CANONICAL_VULN_CLASSES``; programs publish prose
#: ("Cross-site Scripting (XSS) - Reflected", "SQL Injection", "SSRF", "Broken
#: Object Level Authorization", "HTTP Request Smuggling").  This table is the
#: deterministic bridge, and it is a table rather than a fuzzy matcher so every
#: decision is explainable: a fragment either appeared in the program's text or
#: it did not.
#:
#: The ``idor``/``object-access`` pair is the one subtlety, and it is
#: deliberate: ``object-access`` (CWE-285) is the *family* and ``idor``
#: (CWE-639) its named instance.  The family claim therefore matches the
#: family's published names — the object-level-authorization (BOLA) wording
#: and the generic authorization prose — while the instance claim stays
#: narrower: IDOR's own prose plus the BOLA wording programs use for exactly
#: this bug, but not the generic authorization phrases.  The asymmetry means a
#: program publishing exactly "Improper Authorization" yields UNKNOWN for an
#: IDOR finding: the source did not say it pays for the named instance, and
#: this module never defaults to yes.
CLASS_FRAGMENTS: dict[str, tuple[str, ...]] = {
    "xss": ("cross-site scripting", "cross site scripting", "xss"),
    "sqli": ("sql injection", "sqli"),
    "ssrf": ("server-side request forgery", "server side request forgery", "ssrf"),
    "idor": (
        "insecure direct object reference",
        "idor",
        "broken object level authorization",
        "object level authorization",
        "bola",
    ),
    "object-access": (
        "object level authorization",
        "broken object level authorization",
        "bola",
        "improper authorization",
        "improper access control",
        "broken access control",
        "access control",
        "authorization bypass",
    ),
    "command-injection": (
        "command injection",
        "os command injection",
        "command execution",
    ),
    "method-confusion": (
        "request smuggling",
        "http request smuggling",
        "method confusion",
        "interpretation conflict",
    ),
}


def class_fragments(vuln_class: str) -> tuple[str, ...]:
    """The lowercase substrings that tie *vuln_class* to a program's wording."""
    key = (vuln_class or "").strip().lower()
    if key in CLASS_FRAGMENTS:
        return CLASS_FRAGMENTS[key]
    return (key,) if key else ()


def _mentions(vuln_class: str, text: str) -> bool:
    haystack = (text or "").lower()
    return any(fragment in haystack for fragment in class_fragments(vuln_class))


@dataclass(frozen=True)
class ProgramPolicy:
    """The program rules that bear on bounty eligibility, in the engine's hands.

    Built from the scraper's tables (accepted weakness names + published
    exclusions).  Deliberately just what the source provides: there is no bounty
    amount, no minimum severity and no submission requirement here because
    HackerOne's structured data does not publish them, and inventing them would
    corrupt the answer this module exists to give.
    """

    handle: str = ""
    #: The program's *accepted* vulnerability classes (weakness names), free text.
    eligible_classes: tuple[str, ...] = ()
    #: Published class exclusions (free text).  Usually empty from structured data.
    ineligible_classes: tuple[str, ...] = ()
    #: Free-text exclusions (categories / details) — carried for the report.
    exclusions: tuple[str, ...] = ()
    #: Minimum/maximum severity, when the program publishes one per asset.
    max_severity: str = ""

    def to_dict(self) -> dict:
        return {
            "handle": self.handle,
            "eligible_classes": len(self.eligible_classes),
            "ineligible_classes": len(self.ineligible_classes),
            "exclusions": len(self.exclusions),
        }


@dataclass(frozen=True)
class Eligibility:
    """The answer for one finding, with the reason that produced it."""

    state: str
    reason: str
    handle: str = ""

    @property
    def eligible(self) -> bool:
        return self.state == POTENTIALLY_ELIGIBLE

    def to_dict(self) -> dict:
        return {
            "state": self.state,
            "reason": self.reason,
            "program": self.handle,
        }


def assess(vuln_class: str, scope_state: str, policy: ProgramPolicy | None) -> Eligibility:
    """Classify one finding's potential bounty eligibility — always with a reason.

    Ordered cheapest-and-most-fundamental first: scope, then a published
    exclusion, then a published acceptance, then the honest unknown.
    """
    handle = policy.handle if policy else ""
    if scope_state == "out_of_scope":
        return Eligibility(
            INELIGIBLE,
            "the asset is explicitly out of scope for this program, so no report "
            "on it can be eligible",
            handle,
        )
    if policy is None:
        return Eligibility(UNKNOWN, "no program policy was loaded for this run", handle)

    for text in policy.ineligible_classes:
        if _mentions(vuln_class, text):
            return Eligibility(
                INELIGIBLE,
                f"the program explicitly excludes this class: {text!r}",
                handle,
            )
    for text in policy.eligible_classes:
        if _mentions(vuln_class, text):
            return Eligibility(
                POTENTIALLY_ELIGIBLE,
                f"the program's accepted classes include {text!r}, which covers "
                f"the {vuln_class} family",
                handle,
            )
    if not policy.eligible_classes:
        return Eligibility(
            UNKNOWN,
            "the program publishes no accepted vulnerability-class list, so "
            "eligibility cannot be determined from the available data",
            handle,
        )
    return Eligibility(
        UNKNOWN,
        f"the program's accepted classes do not mention the {vuln_class} family; "
        "the finding may still be reportable, so it is not treated as ineligible",
        handle,
    )


def annotate_findings(
    findings: list[dict],
    *,
    policy: ProgramPolicy | None,
    scope_lookup=None,
) -> list[dict]:
    """Attach ``scope_state`` / ``eligibility`` / ``eligibility_reason`` to findings.

    ``scope_lookup`` is an optional ``host -> scope state`` callable (the scope
    engine's ``check_host().state``); without one, scope is reported as unknown
    and the assessment proceeds on class alone.  Returns new dicts — the input is
    never mutated, so a caller can keep the unannotated view.
    """
    annotated: list[dict] = []
    for finding in findings:
        surface = finding.get("surface") or {}
        host = str(surface.get("host") or "")
        scope_state = ""
        if scope_lookup is not None and host:
            try:
                scope_state = str(scope_lookup(host))
            except Exception:  # noqa: BLE001 - a lookup failure must not lose the finding
                scope_state = ""
        eligibility = assess(str(finding.get("vuln_class") or ""), scope_state, policy)
        annotated.append(
            {
                **finding,
                "scope_state": scope_state or "unknown",
                "eligibility": eligibility.state,
                "eligibility_reason": eligibility.reason,
            }
        )
    return annotated


def policy_from_document(doc: dict) -> ProgramPolicy:
    """Build a :class:`ProgramPolicy` from a program graph document.

    Reuses the ``program_graph`` document the graph loader builds, so the policy
    the engine reasons about and the policy in Neo4j cannot drift: one read path,
    one shape.  Only ``weakness_class`` nodes are the accepted list; the
    ``vulnerability_policy`` node carries the free-text exclusions.
    """
    handle = str(doc.get("handle") or "")
    eligible: list[str] = []
    exclusions: list[str] = []
    for node in doc.get("nodes") or ():
        kind = node.get("kind")
        props = node.get("props") or {}
        if kind == "weakness_class":
            name = str(props.get("name") or "").strip()
            if name:
                eligible.append(name)
        elif kind == "vulnerability_policy":
            for item in props.get("exclusions") or ():
                text = " ".join(
                    part
                    for part in (str(item.get("category") or ""), str(item.get("details") or ""))
                    if part
                ).strip()
                if text:
                    exclusions.append(text)
    return ProgramPolicy(
        handle=handle,
        eligible_classes=tuple(eligible),
        exclusions=tuple(exclusions),
    )


__all__ = [
    "CLASS_FRAGMENTS",
    "Eligibility",
    "INELIGIBLE",
    "POTENTIALLY_ELIGIBLE",
    "ProgramPolicy",
    "UNKNOWN",
    "annotate_findings",
    "assess",
    "class_fragments",
    "policy_from_document",
]
