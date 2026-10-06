"""The timing elicitor's manifest."""

from __future__ import annotations

from ...kernel.manifest import NoiseProfile, TechniqueManifest
from ...kernel.technique import CAP_DELAYED_RESPONSE
from ..common import ELICITOR_CLASS

NAME = "timing"

MANIFEST = TechniqueManifest(
    name=NAME,
    vuln_class=ELICITOR_CLASS,
    preconditions=(CAP_DELAYED_RESPONSE,),
    postconditions=("capability_established",),
    produces=("differential",),
    verification_needs="hypothesis",
    noise=NoiseProfile(
        requests_per_surface=6, burstiness=0.9, fingerprint_distance=0.7
    ),
    transports=("http1",),
    title="timing elicitor",
    description=(
        "baseline vs sleep populations with a dose-response pair; a dose-tracking "
        "delay establishes delayed_response at differential grade"
    ),
)
