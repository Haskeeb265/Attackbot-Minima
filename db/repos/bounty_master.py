import shared.db as db

#: Every program-level intelligence column, in one place: the two write paths
#: below build their SQL from it, and a new field is added here once. It is the
#: DB side of the contract; the mapper names the *source* fields that fill it.
PROGRAM_COLUMNS = (
    "platform",
    "program_url",
    "program_name",
    "program_status",
    "description",
    "policy",
    "disclosure_policy",
    "safe_harbor",
    "offers_bounties",
    "open_scope",
    "gold_standard_safe_harbor",
)


def _program_values(handle: str, scope_count: int, fields: dict) -> tuple:
    return (handle, scope_count, *(fields.get(column) for column in PROGRAM_COLUMNS))


def _columns_sql() -> str:
    return ", ".join(("handle", "scope_count", *PROGRAM_COLUMNS))


def _placeholders_sql() -> str:
    return ", ".join(["%s"] * (2 + len(PROGRAM_COLUMNS)))


def add_program(
    conn,
    handle: str,
    scope_count: int = 0,
    **fields,
):
    row = db.fetch_one(
        conn,
        f"""
        INSERT INTO bounty_master
            ({_columns_sql()})
        VALUES ({_placeholders_sql()})
        RETURNING id
        """,
        _program_values(handle, scope_count, fields),
    )

    return row["id"]


def upsert_program(
    conn,
    handle: str,
    scope_count: int = 0,
    **fields,
):
    """Insert or refresh one program, absorbing its program-level intelligence.

    An absent field arrives as ``None``; because the column list is fixed, a
    refresh always writes every column, so a field the source stops reporting
    becomes NULL rather than quietly keeping a stale value.
    """
    updates = ", ".join(
        ["scope_count = EXCLUDED.scope_count"]
        + [f"{column} = EXCLUDED.{column}" for column in PROGRAM_COLUMNS]
    )
    row = db.fetch_one(
        conn,
        f"""
        INSERT INTO bounty_master
            ({_columns_sql()})
        VALUES ({_placeholders_sql()})

        ON CONFLICT (handle)
        DO UPDATE
            SET
                {updates},
                updated_at = %s

        RETURNING id
        """,
        (*_program_values(handle, scope_count, fields), db.now()),
    )

    return row["id"]


def get_program_by_name(conn, handle: str):
    return db.fetch_one(
        conn,
        """
        SELECT *
        FROM bounty_master
        WHERE handle = %s
          AND is_active = TRUE
        """,
        (handle,),
    )


def get_program_by_id(conn, master_id):
    return db.fetch_one(
        conn,
        """
        SELECT *
        FROM bounty_master
        WHERE id = %s
          AND is_active = TRUE
        """,
        (master_id,),
    )


def list_active_programs(conn):
    return db.fetch_all(
        conn,
        """
        SELECT *
        FROM bounty_master
        WHERE is_active = TRUE
        ORDER BY handle
        """,
    )


def update_program(
    conn,
    master_id,
    scope_count: int | None = None,
):
    fields = []
    params = []

    if scope_count is not None:
        fields.append("scope_count = %s")
        params.append(scope_count)

    if not fields:
        return 0

    fields.append("updated_at = %s")
    params.append(db.now())
    params.append(master_id)

    query = f"""
        UPDATE bounty_master
        SET {', '.join(fields)}
        WHERE id = %s
    """

    return db.execute(conn, query, tuple(params))


def deactivate_program(conn, master_id):
    with db.atomic(conn):
        # Soft-delete the master program
        db.execute(
            conn,
            """
            UPDATE bounty_master
            SET
                is_active = FALSE,
                updated_at = %s
            WHERE id = %s
            """,
            (db.now(), master_id),
        )

        # Cascade soft-delete to child tables
        for child_table in ("bounty_detail", "bounty_weaknesses", "bounty_exclusion"):
            db.execute(
                conn,
                f"""
                UPDATE {child_table}
                SET
                    is_active = FALSE,
                    updated_at = %s
                WHERE master_id = %s
                  AND is_active = TRUE
                """,
                (db.now(), master_id),
            )


def delete_program(conn, master_id):
    return db.execute(
        conn,
        """
        DELETE FROM bounty_master
        WHERE id = %s
        """,
        (master_id,),
    )