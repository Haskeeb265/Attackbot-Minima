"""The storage elicitor's manifest."""

from __future__ import annotations

from ...kernel.manifest import NoiseProfile, TechniqueManifest
from ...kernel.technique import CAP_PERSISTENT_STORAGE
from ..common import ELICITOR_CLASS

NAME = "storage"

MANIFEST = TechniqueManifest(
    name=NAME,
    vuln_class=ELICITOR_CLASS,
    preconditions=(CAP_PERSISTENT_STORAGE,),
    postconditions=("capability_established",),
    produces=("reflection",),
    verification_needs="hypothesis",
    noise=NoiseProfile(
        requests_per_surface=2, burstiness=0.3, fingerprint_distance=0.4
    ),
    transports=("http1",),
    title="storage elicitor",
    description=(
        "submit a unique canary, then read the surface back; the canary on the "
        "read-back establishes server_stores_input at reflection grade"
    ),
)
