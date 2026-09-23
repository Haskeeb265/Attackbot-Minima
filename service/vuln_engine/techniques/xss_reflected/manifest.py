"""What ``xss_reflected`` declares about itself.

The manifest is the technique's registration, its chain edges and its noise
budget in one place. Two of its fields are the ones to read carefully:

* ``produces`` is **reflection and semantic** — the classes this technique can
  honestly establish on its own. Neither is a finding grade;
* ``verification_needs`` is **execution** — a browser, which this technique never
  runs. The gap between the two fields *is* the independent-verification rule, so
  a manifest that listed ``execution`` in both would be reporting a closed loop as
  a finding.

``noise`` is low on purpose: one canary request, no browser. The technique is the
cheap half; the loud half is the verifier, which is why the scheduler can afford
to try this hypothesis on a lot of surfaces.
"""

from __future__ import annotations

from ...kernel.evidence import EVIDENCE_EXECUTION, EVIDENCE_REFLECTION, EVIDENCE_SEMANTIC
from ...kernel.manifest import NoiseProfile, TechniqueManifest
from ...kernel.technique import CAP_PUBLIC_PARAM, CAP_SCRIPT_EXECUTION, KIND_BROWSER, KIND_HTTP

NAME = "xss_reflected"

MANIFEST = TechniqueManifest(
    name=NAME,
    vuln_class="xss",
    title="Reflected cross-site scripting",
    description=(
        "A parameter's value is reflected into the response inside an executable "
        "context. Proposed from the reflection (and its parsed context), confirmed "
        "by a browser recording that a script actually ran."
    ),
    preconditions=(CAP_PUBLIC_PARAM,),
    postconditions=(CAP_SCRIPT_EXECUTION,),
    produces=(EVIDENCE_REFLECTION, EVIDENCE_SEMANTIC),
    verification_needs=EVIDENCE_EXECUTION,
    noise=NoiseProfile(
        requests_per_surface=1,
        burstiness=0.0,
        fingerprint_distance=0.0,
        requires_browser=False,
    ),
    transports=(KIND_HTTP, KIND_BROWSER),
)

__all__ = ["MANIFEST", "NAME"]
