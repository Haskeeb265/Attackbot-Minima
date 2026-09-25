"""What ``xss_stored`` declares about itself.

Same shape as every technique's manifest, with the fields that make this one
different from its reflected sibling:

* ``preconditions`` names **persistence**, not reflection — the operator claims
  the surface *stores* what is submitted, which is the only thing that makes a
  two-page technique meaningful;
* ``noise.requests_per_surface`` is 2, not 1: a stored technique cannot propose
  with one request. The inject and the read-back are two different pages, and a
  technique that only did the first would be guessing.

``verification_needs`` stays **execution** — the browser is still the only honest
answer to "did the script run?" — but the confirmation is now a *sequence* (re-inject,
then read back in a browser), which is why the engine has a fourth verifier and
why this manifest's prose says so.
"""

from __future__ import annotations

from ...kernel.evidence import EVIDENCE_EXECUTION, EVIDENCE_REFLECTION, EVIDENCE_SEMANTIC
from ...kernel.manifest import NoiseProfile, TechniqueManifest
from ...kernel.technique import CAP_PERSISTENT_STORAGE, CAP_SCRIPT_EXECUTION, KIND_HTTP

NAME = "xss_stored"

MANIFEST = TechniqueManifest(
    name=NAME,
    vuln_class="xss",
    title="Stored cross-site scripting",
    description=(
        "Input submitted to a surface that *stores* it renders back later — on the "
        "store page itself or a page that serves what was stored. Proposed from the "
        "read-back reflection (injected by POST, observed by GET), confirmed by a "
        "two-step verifier: re-inject the payload, then run the read-back page in a "
        "browser and require the payload's script to have executed."
    ),
    preconditions=(CAP_PERSISTENT_STORAGE,),
    postconditions=(CAP_SCRIPT_EXECUTION,),
    produces=(EVIDENCE_REFLECTION, EVIDENCE_SEMANTIC),
    verification_needs=EVIDENCE_EXECUTION,
    noise=NoiseProfile(
        requests_per_surface=2,
        burstiness=0.0,
        fingerprint_distance=0.0,
        requires_browser=False,
    ),
    transports=(KIND_HTTP,),
)

__all__ = ["MANIFEST", "NAME"]
