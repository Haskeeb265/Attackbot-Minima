"""The remote-fetch elicitor's manifest."""

from __future__ import annotations

from ...kernel.manifest import NoiseProfile, TechniqueManifest
from ...kernel.technique import CAP_INFLUENCE_REMOTE_FETCH
from ..common import ELICITOR_CLASS

NAME = "remote_fetch"

MANIFEST = TechniqueManifest(
    name=NAME,
    vuln_class=ELICITOR_CLASS,
    preconditions=(CAP_INFLUENCE_REMOTE_FETCH,),
    postconditions=("capability_established",),
    produces=("reflection", "oob"),
    verification_needs="hypothesis",
    noise=NoiseProfile(
        requests_per_surface=1, burstiness=0.0, fingerprint_distance=0.2
    ),
    transports=("http1",),
    title="remote-fetch elicitor",
    description=(
        "one request carrying a collaborator URL; an interaction record "
        "establishes can_influence_remote_fetch at oob grade"
    ),
)
