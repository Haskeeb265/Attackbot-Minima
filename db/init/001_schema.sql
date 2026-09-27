CREATE EXTENSION IF NOT EXISTS "uuid-ossp";


CREATE TABLE bounty_master (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    handle          TEXT NOT NULL UNIQUE,
    scope_count     INTEGER NOT NULL DEFAULT 0,
    platform                TEXT,
    program_url             TEXT,
    program_name            TEXT,
    program_status          TEXT,
    description             TEXT,
    policy                  TEXT,
    disclosure_policy       TEXT,
    safe_harbor             TEXT,
    offers_bounties         BOOLEAN,
    open_scope              BOOLEAN,
    gold_standard_safe_harbor BOOLEAN,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    is_active       BOOLEAN NOT NULL DEFAULT TRUE
);


CREATE TABLE bounty_detail (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    master_id       UUID NOT NULL REFERENCES bounty_master(id) ON DELETE CASCADE,
    scope_type      TEXT NOT NULL,
    scope_identifier TEXT NOT NULL,
    max_severity    TEXT,
    scope_instructions    TEXT,
    asset_id                TEXT,
    in_scope                BOOLEAN,
    eligible_for_bounty     BOOLEAN,
    eligible_for_submission BOOLEAN,
    confidentiality_requirement TEXT,
    integrity_requirement       TEXT,
    availability_requirement    TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    UNIQUE (master_id, scope_type, scope_identifier)
);


CREATE TABLE bounty_weaknesses (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    master_id       UUID NOT NULL REFERENCES bounty_master(id) ON DELETE CASCADE,
    weakness_id     TEXT NOT NULL,
    hackerone_weakness_id   TEXT,
    weakness_name   TEXT,
    weakness_description    TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    UNIQUE (master_id, weakness_id)
);


CREATE TABLE bounty_exclusion (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    master_id       UUID NOT NULL REFERENCES bounty_master(id) ON DELETE CASCADE,
    exclusion_category        TEXT NOT NULL,
    exclusion_details         TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    is_active       BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE INDEX idx_bounty_exclusion_master_id ON bounty_exclusion(master_id);