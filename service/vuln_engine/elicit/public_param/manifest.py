"""The public_param elicitor's manifest — the same shape a technique declares."""

from __future__ import annotations

from ...kernel.manifest import NoiseProfile, TechniqueManifest
from ...kernel.technique import CAP_PUBLIC_PARAM
from ..common import ELICITOR_CLASS

NAME = "public_param"

MANIFEST = TechniqueManifest(
    name=NAME,
    vuln_class=ELICITOR_CLASS,
    preconditions=(CAP_PUBLIC_PARAM,),
    postconditions=("capability_established",),
    produces=("differential",),
    verification_needs="hypothesis",
    noise=NoiseProfile(
        requests_per_surface=2, burstiness=0.0, fingerprint_distance=0.0
    ),
    transports=("http1",),
    title="public_param elicitor",
    description=(
        "a paired request per surface — the parameter carrying our canary, then "
        "the same request carrying a name nothing observes — establishes "
        "public_param at differential grade when the pair differs"
    ),
)
