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
)


class CloudResourcePipeline(BasePipeline):
    """Stage-wise adapter over :mod:`~.main`'s orchestrator.

    Later stages re-run the earlier ones when the intermediate artifact is
    absent (probing needs candidates), and say so in their ``notes``.
    """

    manifest = MANIFEST

    def __init__(self) -> None:
        self._last: dict[str, Any] | None = None

    def run(self, stage: str, context: RunContext) -> dict[str, Any]:
        if self._last is not None:
            return {
                **self._last,
                "note": f"artifacts already produced (stage {stage!r} is part of the same pass)",
            }
        from .main import run_pipeline

        report = run_pipeline(
            context.target,
            stages=[stage],
            output_dir=context.options.get("output_dir") or _output_dir(),
        )
        self._last = {
            "ok": bool(report.ok),
            "counts": dict(report.counts),
            "seconds": report.seconds,
            "outputs": dict(report.outputs),
            "notes": list(report.notes),
        }
        return dict(self._last)


PIPELINE = CloudResourcePipeline()
