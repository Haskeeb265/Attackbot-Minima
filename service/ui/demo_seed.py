"""A demo program, seeded into the scraper's tables for the guided demo.

Why seed a program at all: the Program panel reads the scraper's tables, and
a demo that ends at "a program was scraped" needs a program to show. Rather
than touching HackerOne (or fabricating an API), this writes **the same rows
the scraper would persist** into the same tables, so the UI's Program panel
shows a real program document — identity, policy, the typed in-scope and
**out-of-scope** assets, exclusions — for a target that actually exists in
the demo environment.

Idempotent: re-running replaces the demo program's rows in one transaction.
Scoped: it touches only the ``attackbot-demo`` handle; nothing else in the
database is read or written.
"""

from __future__ import annotations

from service.ui.programs import DbUnavailable, _row_dict


class DemoSeedError(RuntimeError):
    """The demo program could not be seeded — always with the reason."""


#: The demo program, in the shape the scraper's mapper persists. The fixture
#: app is declared as an **address** (127.0.0.1) — the same honest declaration
#: the engine's fixture profile makes — and the boundary set names a path the
#: demo does not engage, so the panel shows a real boundary, not an empty one.
DEMO_HANDLE = "attackbot-demo"

PROGRAM = {
    "handle": DEMO_HANDLE,
    "program_name": "Attackbot Demo Program",
    "program_status": "public",
    "platform": "local-demo",
    "program_url": "http://127.0.0.1:8080/",
    "description": (
        "Local demonstration program: the compose fixture app plus DVWA, "
        "declared the way a real program declares assets. Not a real bounty."
    ),
    "policy": (
        "Demo policy: automated testing of the declared in-scope assets is "
        "authorized for this local demonstration only. Out-of-scope assets are "
        "refused by the engine's gate. No real bounty is attached."
    ),
    "disclosure_policy": "full",
    "safe_harbor": "Local demo: nothing leaves this machine.",
    "offers_bounties": False,
    "open_scope": False,
    "gold_standard_safe_harbor": False,
}

#: (scope_type, identifier, in_scope, instructions, max_severity)
DETAILS = [
    ("URL", "http://127.0.0.1:8080/", True,
     "Fixture app: planted vulns, one endpoint per technique.", "critical"),
    ("IP", "127.0.0.1", True,
     "The fixture's host address — declared as an address, the honest way "
     "to authorise a local replica.", "critical"),
    ("WILDCARD", "*.demo.invalid", True,
     "A declared wildcard whose hosts do not exist; shows how wildcards "
     "appear in scope.", "high"),
    ("URL", "http://127.0.0.1:4280/", True,
     "DVWA (low security): server-rendered PHP the engine's lenses map onto.",
     "critical"),
    ("DOMAIN", "forbidden.demo.invalid", False,
     "Explicitly OUT of scope: the gate refuses this host even if a surface "
     "names it.", ""),
    ("URL", "http://127.0.0.1:9999/", False,
     "Explicitly OUT of scope: a port the demo does not engage.", ""),
    ("ANDROID", "com.attackbot.demo", True,
     "A mobile app id the recon classifier refuses — shown as a declared "
     "non-asset, never a target.", ""),
]

EXCLUSIONS = [
    ("Denial of Service", "No load or volume testing against the fixture."),
    ("Physical / Social", "Out of band for a local demo."),
    ("Spam", "No content spamming of the guestbook beyond the engine's probes."),
]

WEAKNESSES = [
    ("W-1", "XSS (Reflected)", "Reflected cross-site scripting."),
    ("W-2", "SQL Injection", "SQL injection, including blind/time-based."),
    ("W-3", "SSRF", "Server-side request forgery."),
    ("W-4", "IDOR", "Insecure direct object references."),
]


def seed(cursor=None) -> dict:
    """Write the demo program; idempotent, scoped to the demo handle.

    Uses ``shared.db``'s pool like every other DB consumer. When *cursor* is
    given (tests pass one), the writes run through it instead and the caller
    owns the transaction.
    """
    try:
        if cursor is not None:
            return _seed_with(cursor)
        from shared import db

        with db.get_conn() as conn:
            with conn.transaction():
                return _seed_with(conn)
    except DbUnavailable as exc:
        raise DemoSeedError(str(exc)) from exc
    except Exception as exc:
        raise DemoSeedError(f"demo seed failed: {exc}") from exc


def _seed_with(conn) -> dict:
    """The writes, on the caller's connection/transaction."""
    master_id = _upsert_master(conn)
    details = _upsert_details(conn, master_id)
    exclusions = _upsert_exclusions(conn, master_id)
    weaknesses = _upsert_weaknesses(conn, master_id)
    return {
        "handle": DEMO_HANDLE,
        "master_id": str(master_id),
        "details": details,
        "exclusions": exclusions,
        "weaknesses": weaknesses,
    }


def _upsert_master(conn) -> object:
    existing = _fetch_one(
        conn,
        "SELECT id FROM bounty_master WHERE handle = %s",
        (DEMO_HANDLE,),
    )
    if existing is not None:
        conn.execute(
            """
            UPDATE bounty_master
            SET program_name = %s, program_status = %s, platform = %s,
                program_url = %s, description = %s, policy = %s,
                disclosure_policy = %s, safe_harbor = %s, offers_bounties = %s,
                open_scope = %s, gold_standard_safe_harbor = %s,
                scope_count = %s, updated_at = now()
            WHERE handle = %s
            """,
            (
                PROGRAM["program_name"], PROGRAM["program_status"], PROGRAM["platform"],
                PROGRAM["program_url"], PROGRAM["description"], PROGRAM["policy"],
                PROGRAM["disclosure_policy"], PROGRAM["safe_harbor"],
                PROGRAM["offers_bounties"], PROGRAM["open_scope"],
                PROGRAM["gold_standard_safe_harbor"], len(DETAILS), DEMO_HANDLE,
            ),
        )
        row = _fetch_one(conn, "SELECT id FROM bounty_master WHERE handle = %s", (DEMO_HANDLE,))
        if row is None:
            raise DemoSeedError("demo master row vanished mid-upsert")
        return row["id"]

    conn.execute(
        """
        INSERT INTO bounty_master
            (handle, program_name, program_status, platform, program_url,
             description, policy, disclosure_policy, safe_harbor,
             offers_bounties, open_scope, gold_standard_safe_harbor, scope_count)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (
            DEMO_HANDLE, PROGRAM["program_name"], PROGRAM["program_status"],
            PROGRAM["platform"], PROGRAM["program_url"], PROGRAM["description"],
            PROGRAM["policy"], PROGRAM["disclosure_policy"], PROGRAM["safe_harbor"],
            PROGRAM["offers_bounties"], PROGRAM["open_scope"],
            PROGRAM["gold_standard_safe_harbor"], len(DETAILS),
        ),
    )
    row = _fetch_one(conn, "SELECT id FROM bounty_master WHERE handle = %s", (DEMO_HANDLE,))
    if row is None:
        raise DemoSeedError("demo master row missing after insert")
    return row["id"]


def _upsert_details(conn, master_id) -> int:
    conn.execute("DELETE FROM bounty_detail WHERE master_id = %s", (master_id,))
    for scope_type, identifier, in_scope, instructions, max_severity in DETAILS:
        conn.execute(
            """
            INSERT INTO bounty_detail
                (master_id, scope_type, scope_identifier, in_scope,
                 scope_instructions, max_severity, eligible_for_bounty,
                 eligible_for_submission)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                master_id, scope_type, identifier, in_scope, instructions,
                max_severity, in_scope, in_scope,
            ),
        )
    return len(DETAILS)


def _upsert_exclusions(conn, master_id) -> int:
    conn.execute("DELETE FROM bounty_exclusion WHERE master_id = %s", (master_id,))
    for category, details in EXCLUSIONS:
        conn.execute(
            """
            INSERT INTO bounty_exclusion (master_id, exclusion_category, exclusion_details)
            VALUES (%s, %s, %s)
            """,
            (master_id, category, details),
        )
    return len(EXCLUSIONS)


def _upsert_weaknesses(conn, master_id) -> int:
    conn.execute("DELETE FROM bounty_weaknesses WHERE master_id = %s", (master_id,))
    for weakness_id, name, description in WEAKNESSES:
        conn.execute(
            """
            INSERT INTO bounty_weaknesses (master_id, weakness_id, weakness_name, weakness_description)
            VALUES (%s, %s, %s, %s)
            """
            ,
            (master_id, weakness_id, name, description),
        )
    return len(WEAKNESSES)


def _fetch_one(conn, query: str, params: tuple) -> dict | None:
    try:
        from shared import db
        return _row_dict(db.fetch_one(conn, query, params) or {})
    except ImportError:
        # A raw psycopg connection (tests): fetch directly.
        cur = conn.cursor()
        cur.execute(query, params)
        row = cur.fetchone()
        return {desc.name: value for desc, value in zip(cur.description, row)} if row else None
