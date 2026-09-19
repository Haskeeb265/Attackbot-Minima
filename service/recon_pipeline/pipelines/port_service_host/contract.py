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
    #: Addresses this stage reached — the frontier the network pipeline and the
    #: next round's scan set both grow from.
    frontier_artifacts=("output/ips_raw.txt", "output/hosts.txt"),
    #: A second round exists to scan addresses round 1 did not know about.  Known
    #: addresses are re-scanned on the way, because there is still no scan
    #: *receipt* (an address scanned with nothing open stays indistinguishable
    #: from one never scanned); the convergence ledger is the first half of that
    #: receipt, and the stage does not consult it yet.
    repeat_stages=("scan",),
    #: Packets are spent for *addresses*.  A round that discovered only names (not
    #: yet resolved) or URLs nothing is listening on owes this stage nothing, so a
    #: converged run re-scans only when the address set actually grew.
    repeat_on=("ip",),
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
