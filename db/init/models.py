import uuid
from sqlalchemy import Column, Text, Integer, Boolean, TIMESTAMP, ForeignKey, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class TimestampMixin:
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())
    is_active = Column(Boolean, nullable=False, default=True)


class BountyMaster(TimestampMixin, Base):
    """One ingested program and its program-level intelligence.

    The ``program_*`` fields are the source's own words about the program
    (status, policy, disclosure, safe harbour); they are NULL when the source
    did not provide them — never invented. ``scope_count`` stays the count of
    declared scope rows the scraper saw.
    """
    __tablename__ = "bounty_master"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    handle = Column(Text, nullable=False, unique=True)
    scope_count = Column(Integer, nullable=False, default=0)

    # --- program-level intelligence (nullable: absent, not invented) ---
    platform = Column(Text)
    program_url = Column(Text)
    program_name = Column(Text)
    program_status = Column(Text)
    description = Column(Text)
    policy = Column(Text)
    disclosure_policy = Column(Text)
    safe_harbor = Column(Text)
    offers_bounties = Column(Boolean)
    open_scope = Column(Boolean)
    gold_standard_safe_harbor = Column(Boolean)


class BountyDetail(TimestampMixin, Base):
    """One declared scope asset — in scope *or* explicitly out of scope.

    ``in_scope`` is the boundary flag: ``False`` means the program declared the
    asset but does not accept reports on it (HackerOne's
    ``eligible_for_submission = false``). An out-of-scope row is a first-class
    asset so recon can recognise it as a boundary rather than invent a target.
    ``eligible_for_bounty`` is separate: an asset can be submittable without
    being bounty-eligible.
    """
    __tablename__ = "bounty_detail"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    master_id = Column(
        UUID(as_uuid=True),
        ForeignKey("bounty_master.id", ondelete="CASCADE"),
        nullable=False)

    scope_type = Column(Text, nullable=False)
    scope_identifier = Column(Text, nullable=False)
    max_severity = Column(Text)
    scope_instructions = Column(Text)

    # --- per-asset eligibility and boundary (nullable: absent, not invented) ---
    #: The source's scope id, kept as the row's provenance identity.
    asset_id = Column(Text)
    #: True / False / NULL (the source did not say; treat as in scope).
    in_scope = Column(Boolean)
    eligible_for_bounty = Column(Boolean)
    eligible_for_submission = Column(Boolean)
    confidentiality_requirement = Column(Text)
    integrity_requirement = Column(Text)
    availability_requirement = Column(Text)

    __table_args__ = (
        UniqueConstraint("master_id", "scope_type", "scope_identifier"),
    )


class BountyWeakness(TimestampMixin, Base):
    __tablename__ = "bounty_weaknesses"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    master_id = Column(UUID(as_uuid=True), ForeignKey("bounty_master.id", ondelete="CASCADE"), nullable=False)
    weakness_id = Column(Text, nullable=False)
    hackerone_weakness_id = Column(Text)
    weakness_name = Column(Text)
    weakness_description = Column(Text)

    __table_args__ = (
        UniqueConstraint("master_id", "weakness_id"),
    )


class BountyExclusion(TimestampMixin, Base):
    __tablename__ = "bounty_exclusion"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    master_id = Column(UUID(as_uuid=True), ForeignKey("bounty_master.id", ondelete="CASCADE"), nullable=False)
    exclusion_category = Column(Text, nullable=False)
    exclusion_details = Column(Text)