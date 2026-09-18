# Attackbot_v2 — Scraper Database Schema

**Status:** Current — verified against the schema files and repos on 2026-09-16.
**Sources of truth:** `db/init/001_schema.sql` (fresh containers) · `db/init/models.py` (SQLAlchemy mirror used by Alembic) · `db/migrations/versions/0001_baseline_schema.py`, `0002_moving_max_severity_to_bounty_detail_table.py`, `0003_add_hackerone_weakness_id_and_rename_weakness_table.py`
**Data source:** HackerOne API via `service/scraper/` → mapped by `db/mapper/hackerone_mapper.py` → persisted by `db/persistence/persistence.py`

---

## Entity-Relationship Diagram

```
bounty_master (1) ──── (N) bounty_detail
       │
       ├── (N) bounty_weaknesses
       └── (N) bounty_exclusion
```

Every child table uses `master_id` as a foreign key referencing `bounty_master.id` with `ON DELETE CASCADE`.

---

## Table: `bounty_master`

| Column | Type | Constraints | Notes |
|--------|------|-------------|-------|
| `id` | UUID | PK, default `uuid_generate_v4()` | Auto-generated primary key |
| `handle` | TEXT | NOT NULL, UNIQUE | HackerOne program handle (e.g. "cloudflare") |
| `scope_count` | INTEGER | NOT NULL, default 0 | Total scopes returned by the structured_scopes endpoint |
| `created_at` | TIMESTAMPTZ | NOT NULL, default `now()` | Row creation timestamp |
| `updated_at` | TIMESTAMPTZ | NOT NULL, default `now()` | Last update timestamp |
| `is_active` | BOOLEAN | NOT NULL, default TRUE | Soft-delete flag |

**Source data (HackerOne API → mapper):** `handle` + `scope_count` from program detail response.

**Relevant repos:** `db/repos/bounty_master.py` — `add_program`, `upsert_program`, `get_program_by_name`, `get_program_by_id`, `list_active_programs`, `update_program`, `deactivate_program`, `delete_program`

---

## Table: `bounty_detail`

| Column | Type | Constraints | Notes |
|--------|------|-------------|-------|
| `id` | UUID | PK, default `uuid_generate_v4()` | Auto-generated primary key |
| `master_id` | UUID | FK → `bounty_master.id` ON DELETE CASCADE, NOT NULL | Parent program |
| `scope_type` | TEXT | NOT NULL | HackerOne `asset_type` — one of `URL`, `WILDCARD`, `CIDR`, `IP`, `OTHER` |
| `scope_identifier` | TEXT | NOT NULL | The actual scope value (e.g., `*.example.com`, `192.168.0.0/16`) |
| `max_severity` | TEXT | nullable | Scope-level max severity (`none`, `low`, `medium`, `high`, `critical`). Added in migration 0002 — previously lived on `bounty_master` |
| `scope_instructions` | TEXT | nullable | HackerOne `instruction` field — testing guidelines for this scope |
| `created_at` | TIMESTAMPTZ | NOT NULL, default `now()` | |
| `updated_at` | TIMESTAMPTZ | NOT NULL, default `now()` | |
| `is_active` | BOOLEAN | NOT NULL, default TRUE | Soft-delete flag |

**Unique constraint:** `(master_id, scope_type, scope_identifier)` — prevents duplicate scope registrations for the same program.

**Source data (HackerOne API → mapper → DB mapping):**

| `_flatten_scope` key | mapper key | DB column | Notes |
|---------------------|------------|-----------|-------|
| `asset_type` | `scope_type` | `scope_type` | Direct mapping |
| `asset_identifier` | `scope_identifier` | `scope_identifier` | Direct mapping |
| `max_severity` | `max_severity` | `max_severity` | Nullable — not all scopes have severity |
| `instruction` | `scope_instructions` | `scope_instructions` | Renamed from `instruction` to `scope_instructions` |

**Mapping code in `db/mapper/hackerone_mapper.py` → `_map_scopes`:**
```python
{
    "scope_type": scope.get("asset_type"),
    "scope_identifier": scope.get("asset_identifier"),
    "max_severity": scope.get("max_severity"),
    "scope_instructions": scope.get("instruction"),
}
```

**Persistence strategy (`db/repos/bounty_detail.py` → `update_scopes`):** Full delete + re-insert for the entire scope list of a program. This is a hard delete (not soft), run in an atomic block.

**Relevant repos:** `db/repos/bounty_detail.py` — `add_scope`, `get_scope_by_id`, `get_scopes_by_master_id`, `list_active_scopes`, `update_scope`, `deactivate_scope`, `delete_scope`, `delete_scopes_for_program`, `update_scopes`

---

## Table: `bounty_weaknesses`

| Column | Type | Constraints | Notes |
|--------|------|-------------|-------|
| `id` | UUID | PK, default `uuid_generate_v4()` | Auto-generated primary key |
| `master_id` | UUID | FK → `bounty_master.id` ON DELETE CASCADE, NOT NULL | Parent program |
| `weakness_id` | TEXT | NOT NULL | HackerOne API top-level `id` — a sequential numeric identifier assigned by HackerOne (e.g. `"1"`, `"2"`). Functions as the local primary identifier for this weakness record within the program. |
| `hackerone_weakness_id` | TEXT | nullable | HackerOne `attributes.weakness_id` — the CWE identifier (e.g. `"CWE-79"`, `"CWE-89"`). Optional; not all weaknesses have a CWE mapping. |
| `weakness_name` | TEXT | nullable | Human-readable name (e.g. `"Cross-Site Scripting (XSS)"`) |
| `weakness_description` | TEXT | nullable | Description of the weakness |
| `created_at` | TIMESTAMPTZ | NOT NULL, default `now()` | |
| `updated_at` | TIMESTAMPTZ | NOT NULL, default `now()` | |
| `is_active` | BOOLEAN | NOT NULL, default TRUE | Soft-delete flag |

**Unique constraint:** `(master_id, weakness_id)` — prevents duplicate weakness registrations for the same program.

**Source data (HackerOne API → mapper → DB mapping):**

| HackerOne API field | mapper key | DB column | Notes |
|--------------------|------------|-----------|-------|
| `id` (top-level) | `weakness_id` | `weakness_id` | The API's sequential numeric ID for this weakness. |
| `attributes.weakness_id` | `hackerone_weakness_id` | `hackerone_weakness_id` | The CWE identifier (e.g. `"CWE-79"`). Nullable — not all weaknesses carry one. |
| `attributes.name` | `weakness_name` | `weakness_name` | Direct mapping |
| `attributes.description` | `weakness_description` | `weakness_description` | Direct mapping |

**Mapping code in `db/mapper/hackerone_mapper.py` → `_map_weaknesses`:**
```python
{
    "weakness_id": weakness.get("id"),                  # top-level API id
    "hackerone_weakness_id": attrs.get("weakness_id"),  # CWE identifier (nullable)
    "weakness_name": attrs.get("name"),
    "weakness_description": attrs.get("description"),
}
```

> **✅ Fixed:** Table renamed from `program_weaknesses` to `bounty_weaknesses` throughout all schema files, migrations, and repos to match the existing naming convention (`bounty_master`, `bounty_detail`, `bounty_exclusion`).

**Persistence strategy (`db/repos/bounty_weaknesses.py` → `replace_weaknesses`):** Full delete + re-insert for the entire weakness list of a program. This is a hard delete, run in an atomic block.

**Relevant repos:** `db/repos/bounty_weaknesses.py` — `add_weakness`, `get_weakness_by_id`, `get_weaknesses_by_master_id`, `list_active_weaknesses`, `delete_weaknesses_for_program`, `replace_weaknesses`

---

## Table: `bounty_exclusion`

| Column | Type | Constraints | Notes |
|--------|------|-------------|-------|
| `id` | UUID | PK, default `uuid_generate_v4()` | Auto-generated primary key |
| `master_id` | UUID | FK → `bounty_master.id` ON DELETE CASCADE, NOT NULL | Parent program |
| `exclusion_category` | TEXT | NOT NULL | HackerOne exclusion category (e.g. `"physical"`, `"dos"`, `"spam"`, `"general"`) |
| `exclusion_details` | TEXT | nullable | Description of the exclusion (e.g. `"social engineering out of scope"`) |
| `created_at` | TIMESTAMPTZ | NOT NULL, default `now()` | |
| `updated_at` | TIMESTAMPTZ | NOT NULL, default `now()` | |
| `is_active` | BOOLEAN | NOT NULL, default TRUE | Soft-delete flag |

**Note:** No unique constraint on `(master_id, exclusion_category)` — the same program can have multiple exclusions of the same category.

**Source data (HackerOne API → mapper → DB mapping):**

| HackerOne API field | mapper key | DB column | Notes |
|--------------------|------------|-----------|-------|
| `attributes.category` | `exclusion_category` | `exclusion_category` | Direct mapping |
| `attributes.details` | `exclusion_details` | `exclusion_details` | Direct mapping |

**Mapping code in `db/mapper/hackerone_mapper.py` → `_map_exclusions`:**
```python
{
    "exclusion_category": attrs.get("category"),
    "exclusion_details": attrs.get("details"),
}
```

**Index:** `idx_bounty_exclusion_master_id` on `master_id` — for efficient lookups of all exclusions for a program.

**Persistence strategy (`db/repos/bounty_exclusions.py` → `replace_exclusions`):** Full delete + re-insert for the entire exclusion list of a program. Hard delete in an atomic block.

**Relevant repos:** `db/repos/bounty_exclusions.py` — `add_exclusion`, `get_exclusion_by_id`, `get_exclusions_by_master_id`, `list_active_exclusions`, `delete_exclusions_for_program`, `replace_exclusions`

---

## Data Flow

```
HackerOne API
    │
    ▼
service/scraper/program_detail_scraper.py
    ├── _fetch_handle_scopes(handle)            → scopes[]
    ├── get_weaknesses(handle)                  → weaknesses[] (raw API JSON)
    └── get_scope_exclusions(handle)            → exclusions[] (raw API JSON)
    │
    ▼
db/mapper/hackerone_mapper.py
    └── map_program(program)                    → { master, scopes[], weaknesses[], exclusions[] }
    │
    ▼
db/persistence/persistence.py
    └── persist_program(conn, mapped)
        ├── bounty_master.upsert_program(...)    → master_id (INSERT ON CONFLICT UPDATE)
        ├── bounty_detail.update_scopes(...)     → DELETE + INSERT scopes
        ├── bounty_weaknesses.replace_weaknesses(...) → DELETE + INSERT weaknesses
        └── bounty_exclusions.replace_exclusions(...) → DELETE + INSERT exclusions
```

---

## Known Issues (all resolved)

### 1. `program_weaknesses` table name mismatch — **✅ Fixed**

Table renamed to `bounty_weaknesses` across `001_schema.sql`, `models.py`, migration `0001` (and migration `0003` renames a legacy `program_weaknesses` table if present), matching the `bounty_*` naming convention.

### 2. Smoke test called nonexistent functions — **✅ Fixed**

`tests/scraper/smoke_test_db.py` was rewritten:
- `weakness_q.update_weaknesses(...)` → `weakness_q.replace_weaknesses(...)`
- `exclusion_q.update_exclusions(...)` → `exclusion_q.replace_exclusions(...)`
- Removed stale `max_severity` kwargs to `add_program`/`upsert_program` (column moved to `bounty_detail` in migration 0002)
- Weakness fixture data now uses `weakness_id` (API id) + `hackerone_weakness_id` (CWE)
- Section 8 now **asserts** the `is_active` cascade to all child tables instead of printing an INFO note

### 3. `weakness_id` mapping ambiguity — **✅ Fixed**

`weakness_id` now stores the HackerOne API top-level `id`; the CWE identifier from `attributes.weakness_id` is stored in the new nullable `hackerone_weakness_id` column.

### 4. `LABEL_WEAKNESSSES` typo — **✅ Fixed**

Renamed to `LABEL_WEAKNESSES` in `service/recon_pipeline/platform/graph/schema.py` and `docs/recon_docs/recon.md`.

### 5. `is_active` cascade gap — **✅ Fixed**

`deactivate_program` in `db/repos/bounty_master.py` now sets `is_active = FALSE` on all child rows (`bounty_detail`, `bounty_weaknesses`, `bounty_exclusion`) inside one atomic block.