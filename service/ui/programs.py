"""Everything the UI's Program panel shows, read from the scraper's tables.

One read-only module over ``bounty_master`` / ``bounty_detail`` /
``bounty_exclusion`` / ``bounty_weaknesses`` — the four tables the scraper
ingests. The shape deliberately mirrors the data a program's HackerOne page
publishes: identity and policy on the master row, the typed scope on the
detail rows (in scope and **out of scope** — the boundary set is data, not a
footnote), exclusions and weakness classes on their own tables.

Nothing here imports the DB layer at module import time: a UI served on a
machine without PostgreSQL still shows the recon, graph and engine panels.
The first call that actually needs the database imports ``shared.db`` and
fails with a plain ``DbUnavailable`` — every caller degrades to an empty
program block with the reason attached, the same degrade contract the recon
platform's services follow.
"""

from __future__ import annotations

import re
from typing import Any

#: Sanitizer for anything echoed from a program's policy text into the API.
#: The scraper stores HTML-ish prose; the UI renders every string as text, and
#: this strips the tags so a stray ``<script>`` in a policy can never travel.
_TAG_RE = re.compile(r"<[^>]+>")


class DbUnavailable(RuntimeError):
    """The database layer is not importable or refused a connection."""


def _clean(text: Any) -> str:
    """Policy prose as plain text: tags stripped, whitespace collapsed."""
    if text is None:
        return ""
    flat = _TAG_RE.sub(" ", str(text))
    return " ".join(flat.split())


def _row_dict(row: Any) -> dict:
    """One DB row (dict or mapping-like) as a plain dict."""
    if isinstance(row, dict):
        return dict(row)
    return {key: row[key] for key in row.keys()}


def _fetch(query: str, params: tuple = ()) -> list[dict]:
    """The one place the UI touches Postgres; everything above is pure."""
    try:
        from shared import db
    except Exception as exc:  # pragma: no cover - import path is environment-dependent
        raise DbUnavailable(f"database layer unavailable: {exc}") from exc
    try:
        with db.get_conn() as conn:
            return [ _row_dict(row) for row in db.fetch_all(conn, query, params) ]
    except DbUnavailable:
        raise
    except Exception as exc:
        raise DbUnavailable(f"database query failed: {exc}") from exc


def list_programs() -> list[dict]:
    """Every ingested program, newest-scope first, with its row counts.

    One query, best-effort by design: a program with zero scope rows is
    shown (it exists), with its zeros — an operator choosing what to engage
    needs to see the empty ones too, not have them vanish.
    """
    rows = _fetch(
        """
        SELECT m.handle, m.program_name, m.program_status, m.platform,
               m.scope_count, m.offers_bounties, m.open_scope,
               count(d.id) FILTER (WHERE d.in_scope IS NOT FALSE)   AS in_scope_rows,
               count(d.id) FILTER (WHERE d.in_scope IS FALSE)       AS out_of_scope_rows,
               (SELECT count(*) FROM bounty_exclusion e WHERE e.master_id = m.id) AS exclusion_rows,
               (SELECT count(*) FROM bounty_weaknesses w WHERE w.master_id = m.id) AS weakness_rows
        FROM bounty_master m
        LEFT JOIN bounty_detail d ON d.master_id = m.id
        GROUP BY m.id
        ORDER BY m.handle
        """,
    )
    return [
        {
            "handle": str(row.get("handle") or ""),
            "program_name": _clean(row.get("program_name")),
            "status": _clean(row.get("program_status")),
            "platform": _clean(row.get("platform")),
            "scope_count": int(row.get("scope_count") or 0),
            "in_scope_rows": int(row.get("in_scope_rows") or 0),
            "out_of_scope_rows": int(row.get("out_of_scope_rows") or 0),
            "exclusions": int(row.get("exclusion_rows") or 0),
            "weaknesses": int(row.get("weakness_rows") or 0),
            "offers_bounties": row.get("offers_bounties"),
            "open_scope": row.get("open_scope"),
        }
        for row in rows
    ]


_MASTER_QUERY = "SELECT * FROM bounty_master WHERE handle = %s"

_DETAIL_QUERY = (
    "SELECT scope_type, scope_identifier, max_severity, scope_instructions, "
    "asset_id, in_scope, eligible_for_bounty, eligible_for_submission, "
    "confidentiality_requirement, integrity_requirement, availability_requirement "
    "FROM bounty_detail WHERE master_id = %s ORDER BY in_scope DESC NULLS LAST, scope_identifier"
)

_EXCLUSION_QUERY = (
    "SELECT exclusion_category, exclusion_details FROM bounty_exclusion "
    "WHERE master_id = %s ORDER BY exclusion_category"
)

_WEAKNESS_QUERY = (
    "SELECT weakness_id, weakness_name, weakness_description FROM bounty_weaknesses "
    "WHERE master_id = %s ORDER BY weakness_name"
)


def program_detail(handle: str) -> dict:
    """One program, complete: master, every scope row, exclusions, weaknesses.

    The boundary rule the engine enforces is visible as data here: a row with
    ``in_scope: false`` lands in ``out_of_scope`` with its type and identifier
    whole, so the operator can see exactly what the gate will refuse and why
    (``*.api.example.com`` under a declared ``*.example.com``, an explicitly
    excluded mobile app, and so on). Nothing is summarised away: "EVERYTHING"
    is the requirement, and a scope row the engine cannot act on still shows —
    under ``unsupported`` with the classifier's reason.
    """
    canonical = (handle or "").strip().lstrip("@").lower()
    masters = _fetch(_MASTER_QUERY, (canonical,))
    if not masters:
        return {}
    master = masters[0]
    master_id = master.get("id")

    details = _fetch(_DETAIL_QUERY, (master_id,))
    exclusions = _fetch(_EXCLUSION_QUERY, (master_id,))
    weaknesses = _fetch(_WEAKNESS_QUERY, (master_id,))

    in_scope: list[dict] = []
    out_of_scope: list[dict] = []
    unsupported: list[dict] = []
    for row in details:
        entry = {
            "type": _clean(row.get("scope_type")),
            "identifier": _clean(row.get("scope_identifier")),
            "max_severity": _clean(row.get("max_severity")),
            "instructions": _clean(row.get("scope_instructions")),
            "asset_id": _clean(row.get("asset_id")),
            "eligible_for_bounty": row.get("eligible_for_bounty"),
            "eligible_for_submission": row.get("eligible_for_submission"),
            "cia": {
                "confidentiality": _clean(row.get("confidentiality_requirement")),
                "integrity": _clean(row.get("integrity_requirement")),
                "availability": _clean(row.get("availability_requirement")),
            },
        }
        if row.get("in_scope") is False:
            out_of_scope.append(entry)
        elif not _clean(row.get("scope_identifier")):
            continue
        else:
            # A scope_type the recon classifier refuses (ANDROID, OTHER, …)
            # still shows as declared — it is the program's data, and the UI
            # does not re-run the classifier's opinions, only marks the
            # well-known non-asset types so an operator can tell them apart.
            if _clean(row.get("scope_type")).upper() in {
                "ANDROID", "IOS", "MOBILE", "APK", "IPA", "OTHER", "GITHUB",
                "CODE_REPOSITORY", "REPOSITORY", "HARDWARE", "SMARTCONTRACT",
                "AI_MODEL", "EXTENSION", "DESKTOP_APP",
            }:
                unsupported.append(entry)
            else:
                in_scope.append(entry)

    return {
        "handle": canonical,
        "program_name": _clean(master.get("program_name")),
        "status": _clean(master.get("program_status")),
        "platform": _clean(master.get("platform")),
        "program_url": _clean(master.get("program_url")),
        "description": _clean(master.get("description")),
        "policy": _clean(master.get("policy")),
        "disclosure_policy": _clean(master.get("disclosure_policy")),
        "safe_harbor": _clean(master.get("safe_harbor")),
        "gold_standard_safe_harbor": master.get("gold_standard_safe_harbor"),
        "offers_bounties": master.get("offers_bounties"),
        "open_scope": master.get("open_scope"),
        "scope_count": int(master.get("scope_count") or 0),
        "in_scope": in_scope,
        "out_of_scope": out_of_scope,
        "unsupported": unsupported,
        "exclusions": [
            {
                "category": _clean(row.get("exclusion_category")),
                "details": _clean(row.get("exclusion_details")),
            }
            for row in exclusions
        ],
        "weaknesses": [
            {
                "id": _clean(row.get("weakness_id")),
                "name": _clean(row.get("weakness_name")),
                "description": _clean(row.get("weakness_description")),
            }
            for row in weaknesses
        ],
        "counts": {
            "in_scope": len(in_scope),
            "out_of_scope": len(out_of_scope),
            "unsupported": len(unsupported),
            "exclusions": len(exclusions),
            "weaknesses": len(weaknesses),
        },
    }
