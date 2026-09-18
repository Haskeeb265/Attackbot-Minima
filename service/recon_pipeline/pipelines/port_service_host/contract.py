"""Pipeline contract module — the only registration point for this pipeline.

The ports pipeline's *implementation* module is ``pipeline.py`` (its historical
name); this contract module adapts it to the platform.
"""

from __future__ import annotations

from typing import Any

from service.recon_pipeline.platform.contract import BasePipeline, Manifest, RunContext, Stage

MANIFEST = Manifest(
    name="port_service_host",
    title="Ports/services pipeline — what is listening",
    asset_types=("IP", "Service", "Host"),
    description=(
        "Addresses from the names pipeline's DNS records + declared scope -> "
        "passive intel -> CDN classification -> L0-L3 scan ladder -> services."
    ),
    provides=("IP", "Service", "Host"),
    consumes=("subdomain_domain_wildcards",),
    stages=(
        Stage("scan", "seed, classify, ladder-scan and fingerprint services"),
    ),
    passive_only=False,
)


class PortsPipeline(BasePipeline):
    def run(self, stage: str, context: RunContext) -> dict[str, Any]:
        from . import pipeline as psh

        run_pipeline = getattr(psh, "run_pipeline", None)
        if run_pipeline is None:
            return {
                "ok": False,
                "error": "pipeline.py exposes no run_pipeline()",
                "counts": {},
            }
        summary = run_pipeline(target=context.target)
        return {
            "ok": bool(getattr(summary, "ok", True)),
            "counts": dict(getattr(summary, "counts", {}) or {}),
            "seconds": float(getattr(summary, "seconds", 0.0)),
        }


PIPELINE = PortsPipeline()
