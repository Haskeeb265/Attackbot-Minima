"""The sessions elicitor's manifest."""

from __future__ import annotations

from ...kernel.manifest import NoiseProfile, TechniqueManifest
from ...kernel.technique import CAP_ACCESS_DIFFERS_BY_SESSION
from ..common import ELICITOR_CLASS

NAME = "sessions"

MANIFEST = TechniqueManifest(
    name=NAME,
    vuln_class=ELICITOR_CLASS,
    preconditions=(CAP_ACCESS_DIFFERS_BY_SESSION,),
    postconditions=("capability_established",),
    produces=("differential",),
    verification_needs="hypothesis",
    noise=NoiseProfile(
        requests_per_surface=2, burstiness=0.6, fingerprint_distance=0.6
    ),
    transports=("http1",),
    title="sessions elicitor",
    description=(
        "one object read under both declared identities; a status or content "
        "difference establishes access_differs_by_session at differential grade"
    ),
)
