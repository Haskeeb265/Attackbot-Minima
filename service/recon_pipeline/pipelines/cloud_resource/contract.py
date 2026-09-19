"""Pipeline contract module — the only registration point for this pipeline.

The manifest keeps ``passive_only=True`` on the same reading ``asn_cidr`` uses:
the probes touch the *providers* (``acme.s3.amazonaws.com``), never the target's
own infrastructure.  The dispatcher may still gate the run; the flag is what
the report and the safety checks read.
"""

from __future__ import annotations

from typing import Any

from service.recon_pipeline.platform.contract import BasePipeline, Manifest, RunContext, Stage


def _output_dir() -> Any:
    from . import settings

    return settings.OUTPUT_DIR

MANIFEST = Manifest(
    name="cloud_resource",
    title="Cloud-resources pipeline — storage buckets on S3 / Azure / GCS",
    asset_types=("CloudResource",),
    description=(
        "Harvests candidate storage-bucket names from the sibling artifacts "
        "(CNAMEs, URLs, JS bundles, endpoints, brand shapes), then probes the "
        "providers for existence. Probes touch the providers, never the target; "
        "dangling CNAME claims are the takeover detector's raw material."
    ),
    provides=("CloudResource",),
    consumes=("subdomain_domain_wildcards", "url_endpoint"),
    stages=(
        Stage("harvest", "sibling artifacts + brand shapes -> candidate names"),
        Stage("probe", "one GET per candidate against its provider -> verdicts"),
    ),
    passive_only=True,
    #: Candidate bucket names — the pipeline's own discovery surface.
    frontier_artifacts=("passive/output/candidates.txt",),
    #: Frontier-driven by construction: the harvest derives candidates from the
    #: siblings' artifacts (CNAME claims, provider hosts in URLs/JS, brand shapes),
    #: so a round in which those artifacts grew genuinely produces new candidates.
    #: Probes touch the providers, never the target.
    repeat_stages=("harvest", "probe"),
    #: Candidates are derived from names and from provider hosts inside URLs/JS, so
    #: a new name or a new URL can name a bucket nobody has probed yet — and nothing
    #: else can.  Provider probes cost one request each, so the gate matters here.
    repeat_on=("host", "url"),
)


class CloudResourcePipeline(BasePipeline):
    """Stage-wise adapter over :mod:`~.main`'s orchestrator.

    Later stages re-run the earlier ones when the intermediate artifact is
    absent (probing needs candidates), and say so in their ``notes``.

    Each declared stage is invoked for real.  This adapter used to cache the
    first stage's report and return it for the second, which meant ``probe``
    never ran on the platform path while the report claimed both stages had —
    and, once rounds existed, that a later round would report the previous
    round's artifacts.
    """

    manifest = MANIFEST

    def run(self, stage: str, context: RunContext) -> dict[str, Any]:
        from .main import run_pipeline

        report = run_pipeline(
            context.target,
            stages=[stage],
            output_dir=context.options.get("output_dir") or _output_dir(),
        )
        return {
            "ok": bool(report.ok),
            "counts": dict(report.counts),
            "seconds": report.seconds,
            "outputs": dict(report.outputs),
            "notes": list(report.notes),
        }


PIPELINE = CloudResourcePipeline()
