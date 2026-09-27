"""Program intelligence + the typed scope boundary.

The scraper has always fetched more than it persisted: ``_flatten_scope`` pulls
``eligible_for_bounty``, ``eligible_for_submission`` and the CIA requirements,
and the program object carries status, policy, disclosure and safe-harbour
text — the mapper dropped all of it.  Worse, an out-of-scope asset had no
typed row at all: it survived only as free text in ``bounty_exclusion``.

This migration adds the columns the mapper will now keep, which is what lets
the recon side treat out-of-scope assets as a boundary/reference set
(``bounty_detail.in_scope = false``) instead of disappearing the fact.

Every column is nullable and added with ``IF NOT EXISTS`` — idempotent, and
existing rows keep their meaning (NULL means "the source did not say", never a
defaulted guess).

Revision ID: 0004
Revises: 0003
Create Date: 2026-09-26
"""

from alembic import op


revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


_MASTER_COLUMNS = {
    "platform": "TEXT",
    "program_url": "TEXT",
    "program_name": "TEXT",
    "program_status": "TEXT",
    "description": "TEXT",
    "policy": "TEXT",
    "disclosure_policy": "TEXT",
    "safe_harbor": "TEXT",
    "offers_bounties": "BOOLEAN",
    "open_scope": "BOOLEAN",
    "gold_standard_safe_harbor": "BOOLEAN",
}

_DETAIL_COLUMNS = {
    "asset_id": "TEXT",
    "in_scope": "BOOLEAN",
    "eligible_for_bounty": "BOOLEAN",
    "eligible_for_submission": "BOOLEAN",
    "confidentiality_requirement": "TEXT",
    "integrity_requirement": "TEXT",
    "availability_requirement": "TEXT",
}


def upgrade():
    for name, kind in _MASTER_COLUMNS.items():
        op.execute(f"ALTER TABLE bounty_master ADD COLUMN IF NOT EXISTS {name} {kind}")
    for name, kind in _DETAIL_COLUMNS.items():
        op.execute(f"ALTER TABLE bounty_detail ADD COLUMN IF NOT EXISTS {name} {kind}")


def downgrade():
    for name in _DETAIL_COLUMNS:
        op.execute(f"ALTER TABLE bounty_detail DROP COLUMN IF EXISTS {name}")
    for name in _MASTER_COLUMNS:
        op.execute(f"ALTER TABLE bounty_master DROP COLUMN IF EXISTS {name}")
