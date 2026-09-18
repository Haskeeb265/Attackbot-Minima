"""
chaos — the ProjectDiscovery Chaos dataset.

Requires ``CHAOS_KEY`` in the project-root ``.env``.  A missing key makes the
source *skip* rather than raise: this module is imported by the pipeline, and a
single optional credential must never take down a whole enumeration run
(``IMPLEMENTATION_PLAN_V2.md`` convention #12, keyed-API graceful degradation).

Note the module is ``chaos`` (not ``chaos-client``) so it stays importable —
Python module names cannot contain a hyphen.  The image is still
``projectdiscovery/chaos-client``.

    python -m service.recon_pipeline.pipelines.subdomain_domain_wildcards.passive.chaos
"""

from __future__ import annotations

from pathlib import Path

from service.recon_pipeline.platform.common.config import TARGET

from .sources import run_source_checked

NAME = "chaos"


def run(domain: str = TARGET) -> Path:
    """Enumerate *domain* with chaos; return the raw output file path."""
    return run_source_checked(NAME, domain)


if __name__ == "__main__":
    print(f"chaos results saved to: {run()}")
