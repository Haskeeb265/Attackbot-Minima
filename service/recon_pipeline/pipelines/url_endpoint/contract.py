"""Pipeline contract module — the only registration point for this pipeline."""

from __future__ import annotations

from typing import Any

from service.recon_pipeline.platform.contract import BasePipeline, Manifest, RunContext, Stage

MANIFEST = Manifest(
    name="url_endpoint",
    title="URLs/endpoints pipeline — what was exposed over HTTP",
    asset_types=("URL", "Endpoint", "Parameter", "JavaScript"),
    description=(
        "Historical-URL harvest (Wayback, Common Crawl, urlscan, gau) into a "
        "canonical union, then endpoint/parameter/JS/finding extraction. "
        "Passive: reads third-party datasets only."
    ),
    provides=("URL", "Endpoint", "Parameter"),
    consumes=("subdomain_domain_wildcards",),
    stages=(
        Stage("passive", "keyless archives + gau -> canonical URL union"),
        Stage("extract", "URLs -> endpoints, parameters, JS, source maps, findings"),
    ),
    passive_only=True,
)


class UrlEndpointPipeline(BasePipeline):
    def run(self, stage: str, context: RunContext) -> dict[str, Any]:
        from .main import run_pipeline

        summary = run_pipeline(context.target, stages=[stage])
        return {
            "ok": bool(summary.ok),
            "counts": dict(summary.counts),
            "seconds": summary.seconds,
            "outputs": {k: str(v) for k, v in summary.outputs.items()},
        }


PIPELINE = UrlEndpointPipeline()
