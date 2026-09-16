"""
amass — graph relations (DNS / MX / NS / ASN), not a subdomain list.

amass v4 is intentionally thin on plain subdomains for small targets; the other
sources cover discovery.  amass's value here is the *relations* it prints, e.g.::

    qbsco.net (FQDN) --> mx_record --> qbsco-net.mail.protection.outlook.com (FQDN)
    autodiscover.qbsco.net (FQDN) --> cname_record --> autodiscover.outlook.com (FQDN)

``amass.txt`` therefore holds one relation per line and is **never** merged as a
host list.  Hosts that appear in those relations are extracted separately by
:func:`..normalize.relation_subdomains`, so amass still contributes names the
list-based tools may have missed — including CNAME/NS targets.

Requires ``passive/config/`` (gitignored) holding ``config.yaml`` with datasource
API keys.  Without it amass still runs, but keyless-only and with much thinner
output; the wrapper logs a warning rather than failing.

    python -m service.recon_pipeline.asset_pipelines.subdomain_domain_wildcards.passive.amass
"""

from __future__ import annotations

from pathlib import Path

from service.recon_pipeline.asset_pipelines.config import TARGET

from .sources import run_source_checked

NAME = "amass"


def run(domain: str = TARGET) -> Path:
    """Run amass passive enum for *domain*; return the relations file path."""
    return run_source_checked(NAME, domain)


if __name__ == "__main__":
    print(f"amass results saved to: {run()}")
