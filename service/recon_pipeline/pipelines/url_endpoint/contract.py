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
        "canonical union, then endpoint/parameter/JS/finding extraction, then a "
        "policy-gated live HTTP validation of the candidates that deserve it. "
        "Discovery stays passive; only the validate stage sends packets, and only "
        "to in-scope hosts the escalation policy allowed."
    ),
    provides=("URL", "Endpoint", "Parameter"),
    consumes=("subdomain_domain_wildcards",),
    stages=(
        Stage("passive", "keyless archives + gau -> canonical URL union"),
        Stage("extract", "URLs -> endpoints, parameters, JS, source maps, findings"),
        Stage(
            "validate",
            "policy-gated live HTTP check of URL candidates -> url_validation.jsonl",
        ),
    ),
    # The pipeline is no longer passive-only: the ``validate`` stage sends real
    # requests.  Saying so here is what makes the platform's safety checks and the
    # report honest — a run that validates URLs is an active run, even though the
    # two stages before it read nothing but other people's archives.  Operators
    # who want the old behaviour set URL_VALIDATE=off (or ask for stages
    # ``passive,extract``), and the stage records that it was switched off.
    passive_only=False,
)


class UrlEndpointPipeline(BasePipeline):
    def run(self, stage: str, context: RunContext) -> dict[str, Any]:
        from .main import run_pipeline

        # The platform's own services are handed to the active stage rather than
        # rebuilt inside it: the scope engine is the run's declared scope (not a
        # fresh ``from_domain``), and the dispatcher is the run's gate, so the URL
        # validation stage is budgeted and audited exactly like every other active
        # step in the engagement.
        summary = run_pipeline(
            context.target,
            stages=[stage],
            scope=context.scope,
            validation_dispatcher=context.dispatcher,
            validation_session=context.stealth,
        )
        return {
            "ok": bool(summary.ok),
            "counts": dict(summary.counts),
            "seconds": summary.seconds,
            "outputs": {k: str(v) for k, v in summary.outputs.items()},
        }


PIPELINE = UrlEndpointPipeline()
