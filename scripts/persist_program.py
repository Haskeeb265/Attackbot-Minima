"""MANUAL SCRIPT — not a test. It writes to your real database.

This lived at ``tests/scraper/test_persistence.py``, where pytest ignored it
(it collects zero tests) while its name implied it was covered. It is a
one-shot operator tool: it scrapes one program, maps it, and persists it
against the configured PostgreSQL.

    python scripts/persist_program.py

It hits the live HackerOne API and writes real rows. Read ``.env`` first and
confirm you mean it.
"""

from service.scraper.program_detail_scraper import ProgramDetailScraper

from db.mapper.hackerone_mapper import HackerOneMapper
from db.persistence.persistence import persist_program

from shared.db import get_conn

from db.repos.bounty_master import get_program_by_name
from db.repos.bounty_detail import get_scopes_by_master_id
from db.repos.bounty_weaknesses import get_weaknesses_by_master_id
from db.repos.bounty_exclusions import get_exclusions_by_master_id


def main():

    print("=" * 80)
    print("SCRAPING PROGRAM")
    print("=" * 80)

    detail_scraper = ProgramDetailScraper()

    program = detail_scraper._fetch_handle_scopes("cloudflare")

    program["weaknesses"] = detail_scraper.get_weaknesses("cloudflare")
    program["exclusions"] = detail_scraper.get_scope_exclusions("cloudflare")

    mapped = HackerOneMapper.map_program(program)

    print()
    print("MAPPED PROGRAM")
    print(mapped.keys())
    print("exclusions count:", len(mapped["exclusions"]))   # add this
    print("exclusions sample:", mapped["exclusions"][:1]) 

    print()
    print("Persisting...")

    with get_conn() as conn:

        master_id = persist_program(
            conn,
            mapped
        )

        master = get_program_by_name(
            conn,
            "cloudflare"
        )

        scopes = get_scopes_by_master_id(
            conn,
            master_id
        )

        weaknesses = get_weaknesses_by_master_id(
            conn,
            master_id
        )

        exclusions = get_exclusions_by_master_id(
            conn,
            master_id
        )


    print()

    print("=" * 80)
    print("DATABASE RESULTS")
    print("=" * 80)


    print()
    print("MASTER")
    print(master)


    print()

    print(f"SCOPES      : {len(scopes)}")
    print(f"WEAKNESSES  : {len(weaknesses)}")
    print(f"EXCLUSIONS  : {len(exclusions)}")


    print()

    if scopes:
        print("FIRST SCOPE")
        print(scopes[0])


    print()

    if weaknesses:
        print("FIRST WEAKNESS")
        print(weaknesses[0])


    print()

    if exclusions:
        print("FIRST EXCLUSION")
        print(exclusions[0])


if __name__ == "__main__":
    main()