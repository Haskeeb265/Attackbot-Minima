"""What ``generic_differential`` declares about itself.

This technique is the spike that answers one question: **can a hypothesis be
data, not code?** Every other technique's hypothesis is a hand-written claim
about one vuln class; this one's hypotheses are *rows in a plan table* — a pair
of behavior predicates plus a comparison, phrased over HTTP status codes, with
the confirmation riding an existing verifier. Adding a differential vuln class
here is adding a row pair, not a module.

The manifest-level novelty, stated plainly: ``preconditions`` names only
``public_param`` — the cheapest, most commonly claimable capability in the
kernel — and the *session* rows carry no per-class claim string at all. Where
``idor_differential`` fires on ``access_differs_by_session`` (a claim that
already says "these two sessions differ"), this technique's session differential
derives the inequality from **method roles**: one surface declared "does
something to the world" (``method_role=target``), another "gets hit by it"
(``method_role=victim``). Both halves are the operator's own declarations on
ordinary ``public_param`` surfaces — nothing is inferred, nothing invented.

``produces`` is ``hypothesis``: the comparison of two status codes is the
weakest class in the engine, which is the honest description of any
propose-time differential. ``verification_needs`` is ``differential`` —
the existing ``authorization.differential`` verifier, unchanged. The technique
adds no verifier, no transport, no gate rule.
"""

from __future__ import annotations

from ...kernel.evidence import EVIDENCE_DIFFERENTIAL, EVIDENCE_HYPOTHESIS
from ...kernel.manifest import NoiseProfile, TechniqueManifest
from ...kernel.technique import CAP_ACCESS_DIFFERS_BY_SESSION, CAP_PUBLIC_PARAM, KIND_HTTP

NAME = "generic_differential"

MANIFEST = TechniqueManifest(
    name=NAME,
    # ``method-confusion`` is deliberately not one of the six registry classes:
    # the spike's whole question is whether a plan row can define a class the
    # folder tree never named.
    vuln_class="method-confusion",
    title="Generic two-request differential, from plans as data",
    description=(
        "Each hypothesis is a plan: two requests whose expected behaviors are "
        "declared as status-code predicate rows, plus the comparison that makes "
        "the pair a differential claim. Session-role plans derive the two "
        "identities from declared method roles (one surface changes state, one "
        "reads it) instead of a per-class access claim; confirmation rides the "
        "existing authorization-differential verifier, flipped order, unchanged."
    ),
    preconditions=(CAP_PUBLIC_PARAM, CAP_ACCESS_DIFFERS_BY_SESSION),
    postconditions=("cross_behavior_readable",),
    produces=(EVIDENCE_HYPOTHESIS,),
    verification_needs=EVIDENCE_DIFFERENTIAL,
    noise=NoiseProfile(
        requests_per_surface=3,
        burstiness=0.6,
        fingerprint_distance=0.6,
        requires_browser=False,
    ),
    transports=(KIND_HTTP,),
)

__all__ = ["MANIFEST", "NAME"]
