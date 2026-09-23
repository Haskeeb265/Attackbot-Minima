"""What ``oob_fetch`` declares about itself.

The blind technique: the server is asked to fetch a URL we control, and the proof
is that our own collaborator recorded the server arriving. There is no other
evidence class strong enough for this family — a response that *looks* like it
fetched something is a lead (and can be a cached page, a proxy, or an error
message quoting our input back).

Read the two evidence fields together:

* ``produces`` is **reflection** — all this technique can honestly establish on its
  own, and it is a *lead* class;
* ``verification_needs`` is **oob** — a fact recorded on our own infrastructure.

``preconditions`` names the capability the surface must claim
(:data:`CAP_INFLUENCE_REMOTE_FETCH`). Phase 1 takes the operator's word for it —
the claim is what makes the hypothesis worth testing, and verification is what
decides whether it was true. That ordering is deliberate: a capability nobody can
check cheaply should produce a lead, never a fact.
"""

from __future__ import annotations

from ...kernel.evidence import EVIDENCE_OOB, EVIDENCE_REFLECTION, EVIDENCE_SEMANTIC
from ...kernel.manifest import NoiseProfile, TechniqueManifest
from ...kernel.technique import (
    CAP_INFLUENCE_REMOTE_FETCH,
    KIND_BROWSER,
    KIND_HTTP,
)

NAME = "oob_fetch"

#: The postcondition: an outbound request from the target was observed.  Named
#: rather than described so chaining ("what can follow from this?") is a lookup.
POSTCONDITION_SERVER_SIDE_FETCH = "server_side_request_observed"

MANIFEST = TechniqueManifest(
    name=NAME,
    vuln_class="ssrf",
    title="Server-side fetch of a caller-supplied URL (blind)",
    description=(
        "A parameter's value is fetched by the server. Proposed from the response "
        "echoing our collaborator's answer; confirmed by an interaction record on "
        "the collaborator itself."
    ),
    preconditions=(CAP_INFLUENCE_REMOTE_FETCH,),
    postconditions=(POSTCONDITION_SERVER_SIDE_FETCH,),
    produces=(EVIDENCE_REFLECTION, EVIDENCE_SEMANTIC),
    verification_needs=EVIDENCE_OOB,
    noise=NoiseProfile(
        requests_per_surface=1,
        burstiness=0.0,
        fingerprint_distance=0.0,
        requires_browser=False,
    ),
    transports=(KIND_HTTP, KIND_BROWSER),
)

__all__ = ["MANIFEST", "NAME", "POSTCONDITION_SERVER_SIDE_FETCH"]
