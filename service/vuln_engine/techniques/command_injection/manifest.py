"""What ``command_injection`` declares about itself.

Blind OS command injection via a timing side channel: the surface's response
time depends on this parameter's value, and the *explanation* this technique
tests is that the value reaches a shell. It is the third technique to share the
timing grammar (after ``sqli_blind_time``), and the honest reading of the design
is that a single declared timing claim has more than one possible explanation —
injection of SQL, or of shell metacharacters. The operator declares the surface
fact ("time depends on this parameter"); the technique names one hypothesis for
*why*.

``produces`` is **semantic** — "the two populations differ" is all a timing
measurement can claim on its own; a difference is equally producible by a cold
cache or network weather, which the technique says by claiming no finding-grade
class. ``verification_needs`` is **differential**: the same comparison,
re-measured fresh with a declared margin, is the finding class that exists for
claims like this one.

``noise`` is as loud as the SQLi timing technique's, for the same reason: a
timing probe announces itself in a latency graph (two populations sent back to
back, distinctive payloads), so the scheduler must weigh it against cheaper
arms.
"""

from __future__ import annotations

from ...kernel.evidence import EVIDENCE_DIFFERENTIAL, EVIDENCE_REFLECTION, EVIDENCE_SEMANTIC
from ...kernel.manifest import NoiseProfile, TechniqueManifest
from ...kernel.technique import (
    CAP_DELAYED_RESPONSE,
    CAP_PUBLIC_PARAM,
    KIND_HTTP,
)

NAME = "command_injection"

MANIFEST = TechniqueManifest(
    name=NAME,
    vuln_class="command-injection",
    title="Blind OS command injection via time-based side channel",
    description=(
        "The surface runs a caller-supplied value through a shell, so a value "
        "carrying a shell metacharacter and a delay command makes the response "
        "slow. Proposed from a measured difference between a baseline and an "
        "injected population; confirmed by a fresh differential with a declared "
        "margin. Slow servers are not findings: the verifier refuses an "
        "inconclusive separation."
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
