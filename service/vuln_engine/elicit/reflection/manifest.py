"""The reflection elicitor's manifest — the same shape a technique declares."""

from __future__ import annotations

from ...kernel.manifest import NoiseProfile, TechniqueManifest
from ...kernel.technique import CAP_RESPONSE_REFLECTS_INPUT
from ..common import ELICITOR_CLASS

NAME = "reflection"

MANIFEST = TechniqueManifest(
    name=NAME,
    vuln_class=ELICITOR_CLASS,
    preconditions=(CAP_RESPONSE_REFLECTS_INPUT,),
    postconditions=("capability_established",),
    produces=("reflection",),
    verification_needs="hypothesis",
    noise=NoiseProfile(
        requests_per_surface=1, burstiness=0.0, fingerprint_distance=0.2
    ),
    transports=("http1",),
    title="reflection elicitor",
    description=(
        "one canary GET per surface; a positive answer establishes "
        "http_response_reflects_input at reflection grade"
    ),
)
