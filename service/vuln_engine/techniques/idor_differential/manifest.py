"""What ``idor_differential`` declares about itself.

The manifest's story, in the same two fields every technique tells:

* ``preconditions`` — this technique fires *only* on a surface the operator
  declared with the ``access_differs_by_session`` claim **and** two declared
  sessions (the second via the gate's session-B shim). One session means one
  identity, and an authorization claim with one identity is not even a
  hypothesis — ``surfaces()`` returns nothing, by construction.
* ``verification_needs`` is **differential** — the finding class that exists
  for claims like this one. But where the timing verifier re-measures the
  *same* comparison fresh, the authorization verifier flips the comparison's
  axis: fresh *requests*, under fresh *identities*, in both directions. A
  verifier that reused session A's response bytes would be the proposer
  confirming itself; flipping the sessions makes the confirmation a different
  measurement in kind, not just a repeat.

``noise`` is cheap in volume (four requests per surface) but distinctive in
shape (paired same-URL requests with different identities), which is why the
declared ``fingerprint_distance`` is honest rather than flattering.
"""

from __future__ import annotations

from ...kernel.evidence import (
    DIFFERENTIAL_SESSIONS,
    EVIDENCE_DIFFERENTIAL,
    EVIDENCE_HYPOTHESIS,
)
from ...kernel.manifest import NoiseProfile, TechniqueManifest
from ...kernel.technique import (
    CAP_ACCESS_DIFFERS_BY_SESSION,
    CAP_CROSS_ACCOUNT_READ,
    KIND_HTTP,
)

NAME = "idor_differential"

MANIFEST = TechniqueManifest(
    name=NAME,
    vuln_class="idor",
    title="IDOR via two-session differential",
    description=(
        "The operator declares one endpoint and two sessions with different "
        "access (typically admin and low-privilege). The proposer asks both "
        "sessions for the same object and compares status codes; the verifier "
        "flips the comparison — fresh requests, fresh identities, both "
        "directions — so the confirmation re-measures with different sessions "
        "rather than re-reading the proposer's answer."
    ),
    preconditions=(CAP_ACCESS_DIFFERS_BY_SESSION,),
    postconditions=(CAP_CROSS_ACCOUNT_READ,),
    produces=(EVIDENCE_HYPOTHESIS,),
    verification_needs=EVIDENCE_DIFFERENTIAL,
    noise=NoiseProfile(
        requests_per_surface=4,
        burstiness=0.6,
        fingerprint_distance=0.6,
        requires_browser=False,
    ),
    transports=(KIND_HTTP,),
)

#: The differential evidence every finding of this class carries names the
#: oracle it satisfies — pinned against the verifier by a test so the two
#: cannot drift apart silently.
ORACLE = DIFFERENTIAL_SESSIONS

__all__ = ["MANIFEST", "NAME", "ORACLE"]
