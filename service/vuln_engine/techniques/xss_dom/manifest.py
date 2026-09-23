"""What ``xss_dom`` declares about itself.

Same shape as every other manifest; the interesting fields are the pair that
keeps the independence rule honest:

* ``produces`` is **semantic** — a DOM placement with a named context is mapped
  knowledge (the wire lens calls that ``semantic`` too), and this technique
  never establishes more than that on its own;
* ``verification_needs`` is **execution** — a browser, which the verifier runs.

``noise`` declares the browser up front: the placement probe is a browser run,
so this technique is the *loud* sibling of ``xss_reflected`` (whose canary is
one cheap request). The scheduler's noise division is what keeps the two from
both firing at every surface — the quiet question is asked first, the loud one
only where it can see something the quiet one cannot.
"""

from __future__ import annotations

from ...kernel.evidence import EVIDENCE_EXECUTION, EVIDENCE_SEMANTIC
from ...kernel.manifest import NoiseProfile, TechniqueManifest
from ...kernel.technique import CAP_PUBLIC_PARAM, CAP_SCRIPT_EXECUTION, KIND_BROWSER, KIND_HTTP

NAME = "xss_dom"

MANIFEST = TechniqueManifest(
    name=NAME,
    vuln_class="xss",
    title="DOM-based cross-site scripting",
    description=(
        "A parameter's value is rendered into the page's DOM by client-side "
        "JavaScript, in a placement where injected markup becomes live. Proposed "
        "from a browser-observed DOM placement, confirmed by a browser recording "
        "that the payload's script actually ran."
    ),
    preconditions=(CAP_PUBLIC_PARAM,),
    postconditions=(CAP_SCRIPT_EXECUTION,),
    produces=(EVIDENCE_SEMANTIC,),
    verification_needs=EVIDENCE_EXECUTION,
    noise=NoiseProfile(
        requests_per_surface=1,
        burstiness=0.0,
        fingerprint_distance=0.0,
        requires_browser=True,
    ),
    transports=(KIND_HTTP, KIND_BROWSER),
)

__all__ = ["MANIFEST", "NAME"]
