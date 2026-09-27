"""The mapper's program-intelligence contract, pinned hermetically.

The scraper's ingestion used to *fetch* eligibility flags and drop them in the
mapper; out-of-scope assets had no typed row at all. These tests describe what
must now survive the mapping, using the exact shape
``ProgramDetailScraper.fetch_program`` produces — no database, no network, so
the contract cannot silently drift while a live run is the only thing that
notices.
"""

from __future__ import annotations

from db.mapper.hackerone_mapper import HackerOneMapper


def _sample_program() -> dict:
    return {
        "handle": "acme",
        "scope_count": 3,
        "program": {
            "name": "Acme Corp",
            "submission_state": "open",
            "offers_bounties": True,
            "open_scope": True,
            "gold_standard_safe_harbor": True,
            "policy": "Do not test production.",
            "disclosure_policy": "coordinated",
            "safe_harbor": "https://example.test/safe-harbor",
            "url": "https://hackerone.com/acme",
        },
        "scopes": [
            {
                "id": "s1",
                "asset_type": "DOMAIN",
                "asset_identifier": "acme.test",
                "eligible_for_bounty": True,
                "eligible_for_submission": True,
                "max_severity": "critical",
                "instruction": "no DoS",
                "confidentiality_requirement": "high",
                "integrity_requirement": "high",
                "availability_requirement": "low",
            },
            {
                "id": "s2",
                "asset_type": "DOMAIN",
                "asset_identifier": "thirdparty.example.net",
                "eligible_for_bounty": False,
                "eligible_for_submission": False,
                "max_severity": None,
                "instruction": "listed but excluded",
            },
            {
                "id": "s3",
                "asset_type": "WILDCARD",
                "asset_identifier": "*.acme.test",
                "eligible_for_bounty": None,
                "eligible_for_submission": None,
            },
        ],
        "weaknesses": [],
        "scope_exclusions": [],
    }


def test_program_level_intelligence_survives_the_mapping() -> None:
    master = HackerOneMapper.map_program(_sample_program())["master"]

    assert master["handle"] == "acme"
    assert master["platform"] == "hackerone"
    assert master["program_status"] == "open"
    assert master["offers_bounties"] is True
    assert master["policy"] == "Do not test production."
    assert master["safe_harbor"] == "https://example.test/safe-harbor"
    assert master["program_url"] == "https://hackerone.com/acme"


def test_absent_program_detail_maps_to_none_not_invented_facts() -> None:
    program = _sample_program()
    program["program"] = {}

    master = HackerOneMapper.map_program(program)["master"]

    assert master["platform"] == "hackerone"
    assert master["program_status"] is None
    assert master["policy"] is None
    assert master["safe_harbor"] is None


def test_per_asset_eligibility_and_requirements_are_kept() -> None:
    scopes = HackerOneMapper.map_program(_sample_program())["scopes"]

    in_scope = scopes[0]
    assert in_scope["asset_id"] == "s1"
    assert in_scope["in_scope"] is True
    assert in_scope["eligible_for_bounty"] is True
    assert in_scope["eligible_for_submission"] is True
    assert in_scope["confidentiality_requirement"] == "high"
    assert in_scope["integrity_requirement"] == "high"
    assert in_scope["availability_requirement"] == "low"


def test_an_ineligible_asset_becomes_an_out_of_scope_boundary_row() -> None:
    scopes = HackerOneMapper.map_program(_sample_program())["scopes"]

    boundary = scopes[1]
    assert boundary["scope_identifier"] == "thirdparty.example.net"
    assert boundary["in_scope"] is False
    assert boundary["eligible_for_submission"] is False


def test_a_missing_eligibility_flag_is_in_scope() -> None:
    """``None`` is the source not saying; treating it as exclusion is a data loss."""
    scopes = HackerOneMapper.map_program(_sample_program())["scopes"]

    wildcard = scopes[2]
    assert wildcard["in_scope"] is True
    assert wildcard["eligible_for_bounty"] is None
