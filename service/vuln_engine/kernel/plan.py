"""Plan serialization: an experiment the log can *explain*, not just replay.

DR-001 chose replay by re-derivation: a hypothesis's plan was data on the
hypothesis, and a replay recomputed it. That made the log silent about the
*experiment* — a reader could see that a plan ran, but not which pair of
requests and predicates it was. Phase 8 (PRD §6.11) makes the plan explicit:
serialized canonically, carried in the world log's whitelisted fields, and
digested so a replay can check that the experiment it re-derived is the one the
run actually measured.

"Canonically" is the whole discipline: the same plan always serializes to the
same bytes, so the digest is stable across dict ordering and float formatting.
This mirrors ``llm.client.opinion_digest``'s content-addressing — here it is the
*plan*, not the model question, that gets a stable identity.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

#: The log field a serialized plan rides under.
PLAN_EVENT_FIELD = "plan"
#: The log field carrying the plan's content digest.
PLAN_DIGEST_FIELD = "plan_digest"


def canonical(value: Any) -> Any:
    """A deterministic, JSON-safe form: dict keys sorted, floats rounded.

    Recurses through dicts/lists so nested plan structures (actor/target/
    expectation) canonicalize the same way. Non-JSON values fall back to their
    ``str`` — the same tolerance ``opinion_digest`` takes — because a plan that
    will not serialize must not silently vanish.
    """
    if isinstance(value, dict):
        return {str(key): canonical(value[key]) for key in sorted(value, key=str)}
    if isinstance(value, (list, tuple)):
        return [canonical(item) for item in value]
    if isinstance(value, float):
        return round(value, 6)
    if isinstance(value, (str, int, bool)) or value is None:
        return value
    return str(value)


def serialize_plan(plan: dict) -> str:
    """The plan as canonical JSON — stable bytes for stable content."""
    return json.dumps(canonical(plan), sort_keys=True, separators=(",", ":"), default=str)


def plan_digest(plan: dict) -> str:
    """A content digest of a plan: the identity a replay can check against."""
    return hashlib.sha256(serialize_plan(plan).encode("utf-8")).hexdigest()


def canonical_plan(plan: dict) -> dict:
    """The plan as a canonical dict (sorted keys, rounded floats)."""
    result = canonical(plan)
    return result if isinstance(result, dict) else {}


__all__ = [
    "PLAN_DIGEST_FIELD",
    "PLAN_EVENT_FIELD",
    "canonical",
    "canonical_plan",
    "plan_digest",
    "serialize_plan",
]
