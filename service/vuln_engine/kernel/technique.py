"""The technique contract: what a technique is, and the shapes it works in.

A technique is **pure**: no I/O, no clock, no LLM. Same discipline as the recon
side's ``scoring.py``. A technique takes typed observations and returns probe
*specs* and evidence — never a request. Determinism at module level is what makes
offline testing possible without touching a single real target.

The acid test of the contract, from ``engine_principles.md`` §5: **adding SSTI
must never require editing anything outside ``techniques/ssti/``.** So the four
things a technique does are four functions in its own folder:

``hypotheses(surface)``
    What might be true here, given only the surface.  Cheap, quiet, pure.
``probes(hypothesis)``
    What to send to find out.  Emits *specs*, gated on nothing but the hypothesis.
``interpret(hypothesis, observations)``
    What the answers mean — candidates, handed to a verifier.
``surfaces(seed)``
    Which declared surfaces this technique can even consider.

Note what is *not* here: a technique never confirms its own candidate. The
confirmation spec travels on the candidate (``confirm``) and a verifier in a
different evidence class executes it.

The kind and oracle constants live here rather than in ``policy/`` so a technique
can name them without importing the policy layer — which is what keeps the import
graph one-way. ``tests/vuln_engine/test_invariants.py`` pins them against the
policy layer's own spellings, so the two cannot drift apart.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from .manifest import TechniqueManifest
from .observation import Observation
from .verdict import Candidate

# --------------------------------------------------------------------------- #
# Effect kinds — must equal the policy layer's own names
# --------------------------------------------------------------------------- #

KIND_HTTP = "http.request"
KIND_BROWSER = "browser.run"

#: What a probe is *for*.  A proposal looks at the target and produces a lead; a
#: confirmation is the loud, independent half — a browser run or a collaborator
#: lookup — and the **verifier** executes it, not the driver.  The distinction lives
#: here because it is the technique that knows which of its probes would constitute
#: its own proof, and a technique that could run its own confirmation would be a
#: closed loop.
PURPOSE_PROPOSE = "propose"
PURPOSE_CONFIRM = "confirm"

#: Oracle predicates.  An oracle is a *question with a boolean answer*, not an
#: adjective: "looks bad" cannot be verified, "the script executed" can.
ORACLE_REFLECTION = "reflection_at_least_once"
ORACLE_CONTEXT = "reflection_context_known"
ORACLE_SCRIPT_EXECUTION = "script_execution"
ORACLE_OOB_INTERACTION = "oob_interaction"
#: Two populations of the same request differ beyond a declared margin — the
#: blind-SQLi timing oracle. The *proposer* compares recorded populations; the
#: verifier re-measures both fresh, which is what makes the confirmation
#: independent rather than a re-reading of the proposer's numbers.
ORACLE_TIMING_DIFFERENTIAL = "timing_differential"

ORACLES: tuple[str, ...] = (
    ORACLE_REFLECTION,
    ORACLE_CONTEXT,
    ORACLE_SCRIPT_EXECUTION,
    ORACLE_OOB_INTERACTION,
    ORACLE_TIMING_DIFFERENTIAL,
)

# --------------------------------------------------------------------------- #
# Claimed capabilities — what a surface says it is
# --------------------------------------------------------------------------- #

#: The surface exposes a parameter a client can set.
CAP_PUBLIC_PARAM = "public_param"
#: The response contains our input (claimed, then measured).
CAP_RESPONSE_REFLECTS_INPUT = "http_response_reflects_input"
#: The server will fetch a URL we supply.  **Claimed only in Phase 1**: the
#: engine takes the operator's word for it and lets verification do the proving,
#: which is the honest ordering — a capability we cannot measure cheaply should
#: be a claim that produces a lead, never a fact.
CAP_INFLUENCE_REMOTE_FETCH = "can_influence_remote_fetch"
#: The surface's processing time depends on this parameter's value — the claim a
#: timing-based blind technique tests. Claimed only, like the remote-fetch claim:
#: the engine lets verification do the proving, and the differential verifier is
#: what turns the claim into a finding or a lead.
CAP_DELAYED_RESPONSE = "delayed_response"
#: The surface establishes script execution when it succeeds — a postcondition,
#: not a capability, but the same vocabulary so chaining is a plain lookup.
CAP_SCRIPT_EXECUTION = "script_execution"

CAPABILITIES: tuple[str, ...] = (
    CAP_PUBLIC_PARAM,
    CAP_RESPONSE_REFLECTS_INPUT,
    CAP_INFLUENCE_REMOTE_FETCH,
    CAP_DELAYED_RESPONSE,
    CAP_SCRIPT_EXECUTION,
)

# --------------------------------------------------------------------------- #
# The collaborator placeholder
# --------------------------------------------------------------------------- #

#: A technique that needs a collaborator URL is pure, so it cannot ask the OOB
#: transport for one — it emits a *sentinel* in the probe instead, and the driver
#: replaces it with the real per-probe URL before the request is built. The
#: function below is shared so the two halves cannot disagree about the spelling,
#: and the sentinel is alphanumeric-only on purpose: it travels through
#: percent-encoding, and a sentinel that URL-encoding rewrote would never be
#: found again.
OOB_URL_SENTINEL_PREFIX = "ooburlsentinel"


def oob_sentinel(probe_id: str) -> str:
    """The placeholder *probe_id*'s URL should carry, URL-encoding-proof."""
    cleaned = "".join(char if char.isalnum() else "_" for char in probe_id)
    return f"{OOB_URL_SENTINEL_PREFIX}_{cleaned.lower()}"


# --------------------------------------------------------------------------- #
# The input: what the operator declared
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Surface:
    """One declared input surface: a URL, a parameter, and what it claims to be.

    ``capability`` carries the operator's claim about the surface, which is how
    ``oob_fetch`` decides it may fire at all. Claims are cheap and producing a
    lead from one is honest; only verification turns a lead into a finding.
    """

    url: str
    host: str
    param: str = ""
    #: ``query`` | ``body`` | ``path`` | ``header`` | ``url`` (a value the server fetches).
    where: str = "query"
    capability: str = ""
    #: Free-form surface label used in the log and in report lines.
    label: str = ""

    @property
    def key(self) -> str:
        return f"{self.url}#{self.param}" if self.param else self.url

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "host": self.host,
            "param": self.param,
            "where": self.where,
            "capability": self.capability,
            "label": self.label,
        }


@dataclass(frozen=True)
class EngagementSeed:
    """Everything the engine knows before it starts: declared surfaces only.

    Phase 1 makes no discovery of its own — the operator declares the surfaces,
    because the engine's claim is about *proving* one finding, not about finding
    somewhere to look. Discovery breadth is Phase 2's problem.
    """

    target: str
    surfaces: tuple[Surface, ...] = ()

    def for_capability(self, capability: str) -> list[Surface]:
        """Surfaces claiming exactly *capability*."""
        return [surface for surface in self.surfaces if surface.capability == capability]

    def with_param(self) -> list[Surface]:
        """Surfaces an ordinary parameter probe can be aimed at."""
        return [
            surface
            for surface in self.surfaces
            if surface.param and surface.where in ("query", "body", "path")
        ]


# --------------------------------------------------------------------------- #
# The middle shapes
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Hypothesis:
    """Something that might be true about a surface, and what would show it."""

    id: str
    technique: str
    surface: Surface
    #: A short factual claim: "param q is reflected in the response".
    claim: str
    #: Which capability or precondition this hypothesis rests on.
    rests_on: str = ""
    #: Preconditions the world must satisfy for this to be worth trying at all.
    preconditions: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "technique": self.technique,
            "claim": self.claim,
            "rests_on": self.rests_on,
            "surface": self.surface.to_dict(),
        }


@dataclass(frozen=True)
class ProbeSpec:
    """What to send, and what an answer would have to look like to mean anything.

    The important part is the *oracle*: an explicit predicate, so a result is
    either true or false and never a judgement call.  ``noise`` is carried because
    the scheduler's objective (progress per unit of visibility) needs it at the
    same moment the probe is chosen, not later.
    """

    id: str
    kind: str
    host: str
    #: Transport parameters: url, method, markers, params…
    detail: dict = field(default_factory=dict)
    oracle: str = ""
    #: The string to look for in the response, for reflection oracles.
    canary: str = ""
    #: A distinctive part of the canary used to detect *transformed* reflections.
    mark: str = ""
    #: Declared cost in visibility.
    noise: dict = field(default_factory=dict)
    #: Contexts this probe is only meaningful in (the "when" of the probe grammar).
    requires_context: tuple[str, ...] = ()
    #: What evidence class an answer at this probe can produce.
    produces: str = ""
    #: ``propose`` (the driver runs it) or ``confirm`` (the verifier does).
    purpose: str = PURPOSE_PROPOSE
    #: The payload, when the probe carries one (used for reproducibility).
    payload: str = ""

    def to_dict(self) -> dict:
        payload: dict = {
            "id": self.id,
            "kind": self.kind,
            "host": self.host,
            "detail": dict(self.detail),
            "oracle": self.oracle,
            "produces": self.produces,
            "purpose": self.purpose,
        }
        for key in ("noise", "requires_context", "canary", "payload"):
            value = getattr(self, key)
            if value:
                payload[key] = list(value) if isinstance(value, tuple) else value
        return payload


# --------------------------------------------------------------------------- #
# The protocol
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ProbeGrammar:
    """What the Phase 3 synthesis junction may reuse of a technique's own grammar.

    A technique MAY expose ``synthesis_grammar()`` returning one of these. The
    junction receives it **as an argument** (the driver reads it off the
    technique with ``getattr``) and never imports the technique's modules —
    which is what keeps the removability contract intact: delete the technique
    folder and the junction simply has nothing to synthesize for, exactly as
    the registry discovery already tolerates a missing folder.

    Every callable takes ``(hypothesis, context)`` and returns the technique's
    own deterministic string. The model never supplies any of these — it picks
    among rows the grammar already contains.
    """

    #: The technique's registered name (the synthesized spec id's prefix).
    technique_name: str
    #: The distinctive canary mark, for transformed-reflection detection.
    mark: str
    #: The script a payload runs (marker assignment + dialog), per context.
    script_body_for: Callable[["Hypothesis", str], str]
    #: The breakout prefix that closes the enclosing structure, per context.
    breakout_prefix_for: Callable[["Hypothesis", str], str]
    #: The stock payload for a context — the duplicate check: a synthesized
    #: payload equal to the stock one adds nothing and is not proposed.
    stock_payload_for: Callable[["Hypothesis", str], str]


@runtime_checkable
class Technique(Protocol):
    """The behavioural half of the technique contract.

    Deliberately four pure functions.  Anything a technique needs from the world
    arrives as arguments, which is why ``interpret`` can be tested against a
    recorded page and why deleting a technique folder cannot break the engine.
    """

    manifest: TechniqueManifest

    def surfaces(self, seed: EngagementSeed) -> list[Surface]: ...

    def hypotheses(self, surface: Surface) -> list[Hypothesis]: ...

    def probes(self, hypothesis: Hypothesis) -> list[ProbeSpec]: ...

    def interpret(
        self, hypothesis: Hypothesis, observations: list[Observation]
    ) -> list[Candidate]: ...


__all__ = [
    "CAPABILITIES",
    "CAP_INFLUENCE_REMOTE_FETCH",
    "CAP_PUBLIC_PARAM",
    "CAP_RESPONSE_REFLECTS_INPUT",
    "CAP_SCRIPT_EXECUTION",
    "EngagementSeed",
    "ProbeGrammar",
    "Hypothesis",
    "KIND_BROWSER",
    "KIND_HTTP",
    "ORACLES",
    "ORACLE_CONTEXT",
    "ORACLE_OOB_INTERACTION",
    "ORACLE_REFLECTION",
    "ORACLE_SCRIPT_EXECUTION",
    "OOB_URL_SENTINEL_PREFIX",
    "PURPOSE_CONFIRM",
    "PURPOSE_PROPOSE",
    "ProbeSpec",
    "Surface",
    "Technique",
    "oob_sentinel",
]
