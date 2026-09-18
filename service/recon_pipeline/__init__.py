"""``service.recon_pipeline`` — the ASM platform plus the asset pipelines.

Two layers, strictly separated:

* **platform/** — the services every pipeline consumes (scope, scoring, cache,
  queue, dispatcher, graph, lifecycle, enrichment, observability, stealth, the
  shared common primitives).  Asset-agnostic.
* **pipelines/** — one folder per asset pipeline.  Each folder satisfies the
  contract in ``platform/contract.py`` (``MANIFEST`` + ``PIPELINE``) and is
  discovered automatically by ``platform/registry.py``.  Adding a pipeline is
  nothing but adding a folder.

Entry points:

- ``python -m service.recon_pipeline``            — the canonical CLI (list/run/history/dlq/replay)
- ``python -m service.recon_pipeline.<name>.main`` — a pipeline's own CLI (unchanged)
- ``run_recon.py`` (repo root)                    — the legacy combined-report workflow
"""

__all__ = ["platform", "pipelines"]
