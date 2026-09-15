"""
Tests for :mod:`passive.normalize`.

Two kinds of verification:

1. *Synthetic raw files* — known-good raw outputs (copied from the 2026-09-06
   tool run) are written to temp directories and fed through the normalizer.
   This verifies per-tool normalization logic without depending on files being
   present on disk.

2. *Normalized output file* — ``passive/output/normalized_subs.txt`` is the
   single source of truth for the merged subdomain list.  The test checks that
   it exists, is clean, and matches the expected merged result.

Run from the project root with::

    python tests/recon/test_passive_normalize.py
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT))

from service.recon_pipeline.asset_pipelines.subdomain_domain_wildcards.passive.normalize import (
    AmassRelation,
    merge_subdomains,
    normalize_amass_relations,
    normalize_subdomain_file,
)

PASS = []
FAIL = []


def check(label: str, condition: bool, detail: str = ""):
    if condition:
        PASS.append(label)
        print(f"  [PASS] {label}")
    else:
        FAIL.append(label)
        print(f"  [FAIL] {label}  {detail}")


PASSIVE = _ROOT / "service" / "recon_pipeline" / "asset_pipelines" / "subdomain_domain_wildcards" / "passive"
OUTPUT = PASSIVE / "output"
APEX = "qbsco.net"

SUBDOMAIN_TOOLS = ("subfinder", "assetfinder", "findomain", "chaos")


# ------------------------------------------------------------------ #
# 1. normalize_subdomain_file — per-file correctness (synthetic raw files)
# ------------------------------------------------------------------ #

# Known-good raw outputs from the 2026-09-06 passive tool run.
# These are the exact byte contents of each tool's output file before
# normalization.  Used to verify the normalizer handles each tool's quirks.

RAW_SUBDOMAIN = {
    "subfinder": "cpcontacts.qbsco.net\nserver.qbsco.net\nwww.qbsco.net\napp.qbsco.net\ncpanel.qbsco.net\nmail.qbsco.net\nocac.qbsco.net\nwebdisk.qbsco.net\nwebmail.qbsco.net\ncpcalendars.qbsco.net\n",
    "assetfinder": "qbsco.net\r\napp.qbsco.net\r\nmail.qbsco.net\r\nwww.qbsco.net\r\nocac.qbsco.net\r\n",
    "findomain": "qbsco.net\r\nocac.qbsco.net\r\n",
    "chaos": "ftp.qbsco.net\ncpanel.qbsco.net\nwww.qbsco.net\nwebdisk.qbsco.net\nwebmail.qbsco.net\napp.qbsco.net\nserver.qbsco.net\nocac.qbsco.net\nmail.qbsco.net\nautodiscover.qbsco.net\ncpcontacts.qbsco.net\ncpcalendars.qbsco.net\n",
}


def test_per_file():
    print("\n--- 1. normalize_subdomain_file (per-file, synthetic raw) ---")

    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)

        # subfinder: clean already — 10 subs, no apex, no CRLF, no foreign
        (tmp / "subfinder.txt").write_text(RAW_SUBDOMAIN["subfinder"], encoding="utf-8")
        subfinder = normalize_subdomain_file(tmp / "subfinder.txt", APEX)
        check("subfinder returns 10 subdomains", len(subfinder) == 10, detail=str(subfinder))
        check("subfinder includes cpcontacts.qbsco.net", "cpcontacts.qbsco.net" in subfinder)
        check("subfinder includes webdisk.qbsco.net", "webdisk.qbsco.net" in subfinder)
        check("subfinder excludes apex", "qbsco.net" not in subfinder)
        check("subfinder is sorted", subfinder == sorted(subfinder))
        check("subfinder has no CRLF remnants", all("\r" not in s for s in subfinder))

        # assetfinder: 4 subs + apex, CRLF — after normalization should be 4
        (tmp / "assetfinder.txt").write_text(RAW_SUBDOMAIN["assetfinder"], encoding="utf-8")
        assetfinder = normalize_subdomain_file(tmp / "assetfinder.txt", APEX)
        check("assetfinder returns 4 subdomains", len(assetfinder) == 4, detail=str(assetfinder))
        check("assetfinder excludes apex", "qbsco.net" not in assetfinder)
        check("assetfinder includes app.qbsco.net", "app.qbsco.net" in assetfinder)
        check("assetfinder includes ocac.qbsco.net", "ocac.qbsco.net" in assetfinder)
        check("assetfinder is sorted", assetfinder == sorted(assetfinder))
        check("assetfinder has no CRLF remnants", all("\r" not in s for s in assetfinder))

        # findomain: 1 sub + apex, CRLF — after normalization should be 1
        (tmp / "findomain.txt").write_text(RAW_SUBDOMAIN["findomain"], encoding="utf-8")
        findomain = normalize_subdomain_file(tmp / "findomain.txt", APEX)
        check("findomain returns 1 subdomain", len(findomain) == 1, detail=str(findomain))
        check("findomain excludes apex", "qbsco.net" not in findomain)
        check("findomain includes ocac.qbsco.net", findomain == ["ocac.qbsco.net"])

        # chaos: 12 subs, clean — should stay 12
        (tmp / "chaos.txt").write_text(RAW_SUBDOMAIN["chaos"], encoding="utf-8")
        chaos = normalize_subdomain_file(tmp / "chaos.txt", APEX)
        check("chaos returns 12 subdomains", len(chaos) == 12, detail=str(chaos))
        check("chaos excludes apex", "qbsco.net" not in chaos)
        check("chaos includes autodiscover.qbsco.net", "autodiscover.qbsco.net" in chaos)
        check("chaos includes ftp.qbsco.net", "ftp.qbsco.net" in chaos)
        check("chaos is sorted", chaos == sorted(chaos))

    # amass: must not be treatable as a subdomain list — it's relations.
    # normalize_subdomain_file *correctly* rejects the relation line as foreign.
    amass_raises = False
    amass_err = None
    try:
        normalize_subdomain_file(OUTPUT / "amass.txt", APEX)
    except ValueError as e:
        amass_raises = True
        amass_err = e
    check("amass raises ValueError (not a subdomain list)", amass_raises,
          detail=str(amass_err))
    check("amass error mentions the outlook foreign target",
          "qbsco-net.mail.protection.outlook.com" in str(amass_err),
          detail=str(amass_err))
    # The *correct* way to consume amass is normalize_amass_relations (tested below).
    # That function parses the relation without trying to validate it as a subdomain.


# ------------------------------------------------------------------ #
# 2. merge_subdomains — union across all four subdomain tools
# ------------------------------------------------------------------ #

EXPECTED_12 = [
    "app.qbsco.net",
    "autodiscover.qbsco.net",
    "cpanel.qbsco.net",
    "cpcalendars.qbsco.net",
    "cpcontacts.qbsco.net",
    "ftp.qbsco.net",
    "mail.qbsco.net",
    "ocac.qbsco.net",
    "server.qbsco.net",
    "webdisk.qbsco.net",
    "webmail.qbsco.net",
    "www.qbsco.net",
]


def test_merge():
    print("\n--- 2. merge_subdomains (union of 4 tools, synthetic raw) ---")

    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)

        for tool, raw in RAW_SUBDOMAIN.items():
            (tmp / f"{tool}.txt").write_text(raw, encoding="utf-8")

        merged = merge_subdomains(APEX, tmp)

        # 12 unique subs across subfinder+assetfinder+findomain+chaos
        check("merged union has 12 unique subdomains", len(merged) == 12, detail=str(merged))
        check("merged list is lexicographically sorted", merged == sorted(merged))
        check("merged union matches expected 12", merged == EXPECTED_12,
              detail=f"{merged}\n!=\n{EXPECTED_12}")

        # Apex must not appear in the merged set
        check("merged union has no apex", "qbsco.net" not in merged)

        # Foreign domain must not appear
        check("merged union has no foreign domain",
              "qbsco-net.mail.protection.outlook.com" not in merged)

        # Every entry ends in .qbsco.net
        check("every merged entry ends with .qbsco.net",
              all(s.endswith(".qbsco.net") for s in merged))

        # No CRLF remnants anywhere
        check("no CRLF remnants in merged set", all("\r" not in s for s in merged))

        # Cross-tool dedup: www.qbsco.net appears in subfinder, assetfinder, AND chaos
        www_count = sum(
            1 for tool in ("subfinder", "assetfinder", "chaos")
            if "www.qbsco.net" in normalize_subdomain_file(tmp / f"{tool}.txt", APEX)
        )
        check("www.qbsco.net appears in 3 raw tools", www_count == 3)
        check("www.qbsco.net appears exactly once in merged set",
              merged.count("www.qbsco.net") == 1)


# ------------------------------------------------------------------ #
# 3. normalize_subdomain_file — edge cases and error paths
# ------------------------------------------------------------------ #
def test_edge_cases():
    print("\n--- 3. normalize_subdomain_file (edge cases) ---")

    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)

        # Empty file
        (tmp / "empty.txt").write_text("")
        check("empty file returns []", normalize_subdomain_file(tmp / "empty.txt", APEX) == [])

        # Whitespace-only lines collapse to blank and are skipped
        (tmp / "blank_lines.txt").write_text("\n\n  \r\n\t\n")
        check("blank-only file returns []",
              normalize_subdomain_file(tmp / "blank_lines.txt", APEX) == [])

        # Only the apex
        (tmp / "apex_only.txt").write_text("qbsco.net\nQBscO.NET\r\n")
        check("apex-only file returns []",
              normalize_subdomain_file(tmp / "apex_only.txt", APEX) == [])

        # CRLF normalization: lines that would break with \r left on
        (tmp / "crlf.txt").write_text("app.qbsco.net\r\nmail.qbsco.net\r\n")
        crlf_result = normalize_subdomain_file(tmp / "crlf.txt", APEX)
        check("CRLF stripped: no \\r in results",
              all("\r" not in s for s in crlf_result))
        check("CRLF file returns both subs", set(crlf_result) == {"app.qbsco.net", "mail.qbsco.net"})

        # Foreign domain raises by default
        (tmp / "foreign.txt").write_text("evil.com\n")
        try:
            normalize_subdomain_file(tmp / "foreign.txt", APEX)
            check("foreign domain raises ValueError", False, detail="no exception raised")
        except ValueError as e:
            check("foreign domain raises ValueError", "evil.com" in str(e), detail=str(e))

        # Foreign domain allowed when reject_foreign=False
        foreign_lenient = normalize_subdomain_file(tmp / "foreign.txt", APEX, reject_foreign=False)
        check("foreign allowed when reject_foreign=False",
              "evil.com" in foreign_lenient, detail=str(foreign_lenient))

        # Case-insensitive: apex variants and mixed-case subdomain
        (tmp / "apex_case.txt").write_text(
            "QBsco.Net\nQBscO.NET\r\nAPP.qbsco.net\r\nMaIl.qbsco.net\n"
        )
        case_result = normalize_subdomain_file(tmp / "apex_case.txt", APEX)
        check("case-insensitive apex exclusion",
              "qbsco.net" not in case_result, detail=str(case_result))
        check("case-insensitive subdomain lowercased",
              case_result == ["app.qbsco.net", "mail.qbsco.net"],
              detail=str(case_result))

        # Non-existent file returns []
        check("non-existent file returns []",
              normalize_subdomain_file(tmp / "does_not_exist.txt", APEX) == [])

        # Duplicate lines in one file dedupe
        (tmp / "dupes.txt").write_text("www.qbsco.net\nwww.qbsco.net\nwww.qbsco.net\n")
        check("duplicates in one file dedupe",
              normalize_subdomain_file(tmp / "dupes.txt", APEX) == ["www.qbsco.net"])

        # Deeply nested subdomains (multi-level) must still match.
        # Tesla.com uses names like a.energy.smf12.tcs.tesla.com (5 labels).
        # The regex must accept arbitrary subdomain depth, not just *.apex.
        (tmp / "deep.txt").write_text(
            "www.tesla.com\n"
            "a.energy.smf12.tcs.tesla.com\n"
            "account.analytics-relay.tesla.com\n"
            "ui.a.smf11.tcs.tesla.com\n"
            "api.location-services-prd.tesla.com\n"
        )
        deep_result = normalize_subdomain_file(tmp / "deep.txt", "tesla.com")
        check("deeply nested subs are accepted", len(deep_result) == 5,
              detail=str(deep_result))
        check("deep nested subs are sorted", deep_result == sorted(deep_result))
        check("deep nested includes 5-label sub",
              "a.energy.smf12.tcs.tesla.com" in deep_result)

        # A domain that is NOT a subdomain of the apex must still be rejected
        # (e.g. one-tesla.com is a different domain, not *.tesla.com).
        (tmp / "foreign_deep.txt").write_text(
            "one-tesla.com\nwww.tesla.com\n"
        )
        try:
            normalize_subdomain_file(tmp / "foreign_deep.txt", "tesla.com")
            check("non-subdomain domain rejected (one-tesla.com)", False,
                  detail="no exception raised")
        except ValueError as e:
            check("non-subdomain domain rejected (one-tesla.com)",
                  "one-tesla.com" in str(e), detail=str(e))


# ------------------------------------------------------------------ #
# 4. normalize_amass_relations — structured parsing
# ------------------------------------------------------------------ #
def test_amass_relations():
    print("\n--- 4. normalize_amass_relations ---")

    relations = normalize_amass_relations(OUTPUT / "amass.txt")

    check("amass has 1 relation parsed", len(relations) == 1, detail=str(relations))
    if relations:
        r = relations[0]
        check("source is qbsco.net", r.source == "qbsco.net", detail=r.source)
        check("relation_type is mx_record", r.relation_type == "mx_record", detail=r.relation_type)
        check("target is outlook mail server",
              r.target == "qbsco-net.mail.protection.outlook.com", detail=r.target)

    # amass file has CRLF — make sure it doesn't break parsing
    check("amass parsed without CRLF in fields",
          all("\r" not in r.source and "\r" not in r.target for r in relations))

    # String representation
    if relations:
        check("AmassRelation.__str__ is round-trippable",
              str(relations[0]) == "qbsco.net --> mx_record --> qbsco-net.mail.protection.outlook.com",
              detail=str(relations[0]))

    # Non-existent file
    check("amass non-existent file returns []",
          normalize_amass_relations(Path("/nonexistent/amass.txt")) == [])

    # Blank file
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        (tmp / "blank.txt").write_text("\n\r\n")
        check("blank amass file returns []",
              normalize_amass_relations(tmp / "blank.txt") == [])


# ------------------------------------------------------------------ #
# 5. normalized_subs.txt — the single source of truth in output/
# ------------------------------------------------------------------ #
def test_normalized_output_file():
    print("\n--- 5. normalized_subs.txt (output source of truth) ---")

    norm_path = OUTPUT / "normalized_subs.txt"
    check("normalized_subs.txt exists", norm_path.is_file(), detail=str(norm_path))

    if norm_path.is_file():
        content = norm_path.read_text(encoding="utf-8")
        lines = [ln for ln in content.splitlines() if ln.strip()]
        check("normalized_subs.txt is non-empty", len(lines) > 0, detail=str(lines))
        check("normalized_subs.txt has no CRLF remnants",
              all("\r" not in ln for ln in lines), detail=str(lines))
        check("normalized_subs.txt has no apex",
              "qbsco.net" not in lines, detail=str(lines))
        check("normalized_subs.txt has no foreign domains",
              all(ln.endswith(".qbsco.net") for ln in lines), detail=str(lines))
        check("normalized_subs.txt is sorted", lines == sorted(lines), detail=str(lines))
        check("normalized_subs.txt has no duplicates", len(lines) == len(set(lines)), detail=str(lines))
        check("normalized_subs.txt matches expected 12 subdomains",
              lines == EXPECTED_12, detail=f"{lines}\n!=\n{EXPECTED_12}")


# ------------------------------------------------------------------ #
# 6. Cross-tool consistency — synthetic raw files all valid for target
# ------------------------------------------------------------------ #
def test_all_tool_files_valid():
    print("\n--- 6. All subdomain-tool synthetic files are valid for the target ---")

    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)

        for tool in SUBDOMAIN_TOOLS:
            (tmp / f"{tool}.txt").write_text(RAW_SUBDOMAIN[tool], encoding="utf-8")
            try:
                result = normalize_subdomain_file(tmp / f"{tool}.txt", APEX)
                check(f"{tool}.txt parses cleanly", isinstance(result, list), detail=str(result))
            except ValueError as e:
                check(f"{tool}.txt parses cleanly", False, detail=str(e))


# ------------------------------------------------------------------ #
# main
# ------------------------------------------------------------------ #
def main():
    print("=" * 70)
    print("Passive subdomain normalization — verification against real outputs")
    print(f"Target apex: {APEX!r}")
    print(f"Output dir:  {OUTPUT}")
    print("=" * 70)

    test_per_file()
    test_merge()
    test_edge_cases()
    test_amass_relations()
    test_normalized_output_file()
    test_all_tool_files_valid()

    print("\n" + "=" * 70)
    print(f"RESULTS: {len(PASS)} passed, {len(FAIL)} failed")
    print("=" * 70)
    if FAIL:
        print("Failed checks:")
        for f in FAIL:
            print(f"  - {f}")
        sys.exit(1)
    print("All checks passed.")
    sys.exit(0)


if __name__ == "__main__":
    main()
