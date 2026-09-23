"""What ``sqli_blind_time`` declares about itself.

The manifest's two fields tell the whole story of a blind timing technique:

* ``produces`` is **semantic** — "the two populations differ" is a parsed,
  structured claim about measured responses, and it is the most this technique
  can honestly establish on its own. A timing difference is famously producible
  by a cold cache, a GC pause, or network weather; the technique says so by
  claiming no finding-grade class;
* ``verification_needs`` is **differential** — the finding class that exists
  precisely for claims like this one: the *same* comparison, re-measured fresh,
  with a declared margin and enough repetitions to survive jitter.

``noise`` is the loudest declaration in the engine — deliberately. A timing probe
is a request that announces itself in a latency graph: bursty by construction
(the two populations are sent back to back), distinctive by payload. The frozen
cost scalar makes this technique expensive per attempt, which is exactly what the
noise-budgeted scheduler is for: it will rank this arm behind cheaper ones unless
its prior is genuinely promising.
"""

from __future__ import annotations

from ...kernel.evidence import EVIDENCE_DIFFERENTIAL, EVIDENCE_REFLECTION, EVIDENCE_SEMANTIC
from ...kernel.manifest import NoiseProfile, TechniqueManifest
from ...kernel.technique import (
    CAP_DELAYED_RESPONSE,
    CAP_PUBLIC_PARAM,
    KIND_HTTP,
)

NAME = "sqli_blind_time"

MANIFEST = TechniqueManifest(
    name=NAME,
    vuln_class="sqli",
    title="Blind SQL injection via time-based side channel",
    description=(
        "The surface's response time depends on this parameter's value. Proposed "
        "from a measured difference between a baseline and an injected population; "
        "confirmed by a fresh differential with a declared margin. Slow servers are "
        "not findings: the verifier refuses an inconclusive separation."
    ),
    preconditions=(CAP_PUBLIC_PARAM,),
    postconditions=(CAP_DELAYED_RESPONSE,),
    produces=(EVIDENCE_SEMANTIC, EVIDENCE_REFLECTION),
    verification_needs=EVIDENCE_DIFFERENTIAL,
    noise=NoiseProfile(
        requests_per_surface=6,
        burstiness=0.9,
        fingerprint_distance=0.7,
        requires_browser=False,
    ),
    transports=(KIND_HTTP,),
)

__all__ = ["MANIFEST", "NAME"]
