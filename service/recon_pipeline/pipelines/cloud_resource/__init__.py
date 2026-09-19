"""``cloud_resource`` — storage-bucket discovery across AWS S3, Azure Blob and GCS.

Passive stage (`harvest`): the sibling pipelines already carry bucket claims
nobody interprets — CNAMEs pointing at ``*.s3.amazonaws.com``, JS bundle URLs
hosted on ``*.storage.googleapis.com``.  This stage reads those artifacts and
derives candidate bucket names (brand tokens × a small name-shape vocabulary),
every candidate keeping its provenance.  Zero network.

Active stage (`probe`): one GET per candidate against its **provider** (never
the target), classified by the provider's response matrix into
``open`` / ``auth_required`` / ``dangling`` / ``absent`` /
``exists_other_region`` / ``unavailable``.  Dangling CNAME-claimed names are
the takeover detector's (S25) raw material.

See ``README.md`` for usage, ``DESIGN.md`` for the R&D behind every choice.
"""

from service.recon_pipeline.pipelines.cloud_resource.contract import MANIFEST, PIPELINE

__all__ = ["MANIFEST", "PIPELINE"]
