"""Pipeline contract module — the only registration point for this pipeline."""

from __future__ import annotations

from typing import Any

from service.recon_pipeline.platform.contract import BasePipeline, Manifest, RunContext, Stage

MANIFEST = Manifest(
    name="subdomain_domain_wildcards",
    title="Names pipeline — domains, subdomains, wildcards",
    asset_types=("Domain", "Subdomain", "Wildcard"),
    description=(
        "Passive source union -> active resolution -> permutation, producing "
        "the live-host list every other pipeline consumes."
    ),
    provides=("Domain", "Subdomain", "Wildcard"),
    consumes=(),
    stages=(
        Stage("passive", "passive source union (CT logs, datasets, Docker tools)"),
        Stage("active", "resolver-validated DNS resolution"),
        Stage("permutation", "capped name permutation and re-resolution"),
    ),
    passive_only=False,
)


class NamesPipeline(BasePipeline):
    """Adapter: platform contract -> the names pipeline's main module."""

    def run(self, stage: str, context: RunContext) -> dict[str, Any]:
        from .main import run_pipeline

        summary = run_pipeline(context.target, stages=[stage])
        return {
            "ok": bool(summary.ok),
            "counts": dict(summary.counts),
            "seconds": summary.seconds,
            "outputs": {k: str(v) for k, v in summary.outputs.items()},
        }


PIPELINE = NamesPipeline()
