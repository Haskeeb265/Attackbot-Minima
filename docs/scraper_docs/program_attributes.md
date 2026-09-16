# Program Attributes — What the Scraper Uses

Which fields from the HackerOne program endpoint actually affect what gets
ingested, and how. Verified against `service/scraper/program_scraper.py` and
`service/scraper/program_detail_scraper.py` on 2026-09-16.

## Attribute → use

| API attribute | Used for | Where |
|---|---|---|
| `handle` | The key for everything else: the detail endpoints are `hackers/programs/{handle}/...`, and it is the unique column in `bounty_master` | `program_scraper.py`, `program_detail_scraper.py`, `db/repos/bounty_master.py` |
| `submission_state` | Only programs that still accept reports are worth enumerating. Accepted values (lower-cased) are `open`, `paused`, `disabled`, `api_only`. **Note `paused` is included** — a paused program is not closed | `high_priority_handle_scraping()` |
| `offers_bounties` | Payout signal; every tier requires it | both tier methods |
| `open_scope` | `False` means the program publishes only an explicit asset list. Used permissively in the high tier (`is not False`) and strictly in the low tier (`is True`) | both tier methods |
| `gold_standard_safe_harbor` | Legal-protection signal. Same permissive/strict split as `open_scope` | both tier methods |
| `policy` | **Not used.** The scraper never reads or persists it; testing guidelines per scope come from the scope's `instruction` field instead | — |

## The two tiers

`program_scraper.py` calls the program list **once** and derives both tiers from
that single response (`_fetch_all_programs`), so a run does not re-list programs:

```
high_priority_handle_scraping():
    submission_state in {open, paused, disabled, api_only}
    AND offers_bounties
    AND open_scope             is not False
    AND gold_standard_safe_harbor is not False

low_priority_handle_scraping():
    offers_bounties
    AND NOT (open_scope is True AND gold_standard_safe_harbor is True)
```

- **High priority** — in-scope-by-default, paying, safe-harboured programs: the
  ones whose unlisted assets may still be in scope.
- **Low priority** — paying but either explicitly scoped or without a
  gold-standard safe harbour. Included because they are still in program, but they
  carry less freedom to probe beyond published assets.
- `all_handles_scraping()` is available for a full pull with no filtering, and
  `find_specific_program(handle)` resolves one program case-insensitively.

Both tier methods log their counts via `shared.colorlog`
(`log.success(f"High priority handles found: {len(high_priority)}")`).

## What this implies downstream

The tiers are a **selection** mechanism, not a scope decision: the scope values
themselves are stored per program in `bounty_detail`
(`scope_type`, `scope_identifier`, `max_severity`, `scope_instructions`) and the
exclusions in `bounty_exclusion`. Anything that later targets assets — the recon
pipeline included — has to read those tables rather than trust that a
high-priority handle means "everything is fair game".

See [`schema.md`](schema.md) for those tables and the API→column mapping.

## Evidence

- `service/scraper/program_scraper.py` (the two filter methods and their literal
  conditions)
- `service/scraper/program_detail_scraper.py` (`fetch_program`, `_fetch_handle_scopes`)
- `shared/connectors/hackerone_client.py` (which API fields are even fetched)
- Absence of any `policy` reference under `service/scraper/`, `db/mapper/`,
  `db/repos/`, `db/init/`
