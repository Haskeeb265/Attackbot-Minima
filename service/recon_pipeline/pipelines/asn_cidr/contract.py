"""Pipeline contract module — the only registration point for this pipeline."""

from __future__ import annotations

from typing import Any

from service.recon_pipeline.platform.contract import BasePipeline, Manifest, RunContext, Stage

MANIFEST = Manifest(
    name="asn_cidr",
    title="Network-ownership pipeline — ASNs & CIDRs (discovery only, never scans)",
    asset_types=("ASN", "CIDR"),
    description=(
        "RIPEstat + RDAP (keyless) expand an address or AS seed into the "
        "networks behind the target, and emit ports-stage-compatible "
        "discovered scope files. Never sends traffic to the target."
    ),
    provides=("ASN", "CIDR"),
    consumes=("port_service_host",),
    stages=(
        Stage("lookup", "seed expansion: addresses -> origin ASNs -> prefixes"),
        Stage("emit", "merge claims, annotate, write scope files + report"),
    ),
    passive_only=True,
)


class AsnCidrPipeline(BasePipeline):
    """Adapter for the platform contract.

    The implementation expands seeds → claims → artifacts in one pass, so the
    first stage run does the work and later stage calls report the same
    (already-produced) artifacts rather than re-hitting RIPEstat/RDAP.
    """

    def __init__(self) -> None:
        self._last: dict[str, Any] | None = None

    def run(self, stage: str, context: RunContext) -> dict[str, Any]:
        if self._last is not None:
            return {**self._last, "note": f"artifacts already produced (stage {stage!r} is part of the same pass)"}
        from .main import run_pipeline

        report = run_pipeline(context.target)
        self._last = {
            "ok": bool(report.ok),
            "counts": dict(report.counts),
            "seconds": report.seconds,
            "outputs": {k: str(v) for k, v in report.outputs.items()},
        }
        return dict(self._last)


PIPELINE = AsnCidrPipeline()
