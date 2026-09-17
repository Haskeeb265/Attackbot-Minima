"""Tests for the ASN/CIDR pipeline's normalize layer: identity and scope math.

No network, no Docker, no clock — the pipeline's identity rules are pure and
this file holds them to that: canonical spellings collapse, origins fold, and
non-routable space is refused with a reason rather than dropped silently.
"""

from __future__ import annotations

import pytest

from service.recon_pipeline.asset_pipelines.asn_cidr.normalize import (
    ORIGIN_ALLOCATION,
    ORIGIN_ANNOUNCEMENT,
    NetworkClaim,
    annotate_known_hosts,
    canonicalize_network,
    containment_map,
    is_globally_routable,
    merge_claims,
    parse_prefixes,
)


# --------------------------------------------------------------------------- #
# canonicalize_network
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("104.16.0.0/12", "104.16.0.0/12"),
        # host bits set are tolerated (announcements occasionally misalign)
        ("104.16.5.5/12", "104.16.0.0/12"),
        ("2001:db8::/32", "2001:db8::/32"),
        # RDAP's start/end spellings
        ("40.74.0.0_40.74.0.255", "40.74.0.0/24"),
        ("40.74.0.0-40.74.0.255", "40.74.0.0/24"),
        ("40.74.0.0 40.74.0.255", "40.74.0.0/24"),
        # bare address -> a /32
        ("1.2.3.4", "1.2.3.4/32"),
    ],
)
def test_canonicalize_network_accepts_the_real_spellings(raw: str, expected: str) -> None:
    assert canonicalize_network(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "not a network",
        "40.74.0.255_40.74.0.0",  # backwards
        "40.74.0.0_::1",  # mixed versions
        "40.74.0.0_40.74.0.10",  # a range that is not one aligned prefix
    ],
)
def test_canonicalize_network_refuses_without_inventing(raw: str) -> None:
    assert canonicalize_network(raw) is None


# --------------------------------------------------------------------------- #
# parse_prefixes
# --------------------------------------------------------------------------- #


def test_parse_prefixes_refuses_private_space_with_a_reason() -> None:
    accepted, refused = parse_prefixes(["10.0.0.0/8", "104.16.0.0/12"], min_prefix_len=0)
    assert accepted == ["104.16.0.0/12"]
    assert refused and "routable" in refused[0][1]


def test_parse_prefixes_floor_drops_vip_scale_announcements() -> None:
    accepted, refused = parse_prefixes(
        ["104.16.0.0/12", "104.16.1.0/25"], min_prefix_len=24
    )
    assert accepted == ["104.16.0.0/12"]
    assert "narrower" in refused[0][1]


def test_parse_prefixes_ceiling_drops_aggregate_supernets() -> None:
    # Measured live: AS8075 announces 40.0.0.0/8 — a routing aggregate that
    # contains one target address and 16 million addresses the AS does not
    # operate.  The /16 ceiling refuses it instead of presenting it as footprint.
    accepted, refused = parse_prefixes(
        ["40.104.0.0/16", "40.0.0.0/8"], min_prefix_len=0, max_prefix_len=16
    )
    assert accepted == ["40.104.0.0/16"]
    assert refused and "wider than" in refused[0][1]


def test_parse_prefixes_ceiling_is_v4_only_and_disablable() -> None:
    accepted, _ = parse_prefixes(
        ["2606:4700::/32", "104.16.0.0/12"], min_prefix_len=0, max_prefix_len=0
    )
    # v6 is untouched by the ceiling; the v4 /12 is kept when the wall is off.
    # Accepted order is by sort key, v4 networks after v6 here (version first).
    assert accepted == ["2606:4700::/32", "104.16.0.0/12"]


def test_parse_prefixes_ceiling_does_not_touch_v6() -> None:
    accepted, refused = parse_prefixes(
        ["2606:4700::/32"], min_prefix_len=0, max_prefix_len=16
    )
    assert accepted == ["2606:4700::/32"]
    assert refused == []


def test_parse_prefixes_deduplicates_and_keeps_order() -> None:
    # Note: 2001:db8::/32 is documentation-reserved in Python's ipaddress and
    # would be refused as non-routable; a real v6 announcement is used instead.
    accepted, _ = parse_prefixes(
        ["104.16.0.0/12", "104.16.0.0/12", "2606:4700::/32"], min_prefix_len=0
    )
    assert accepted == ["104.16.0.0/12", "2606:4700::/32"]


# --------------------------------------------------------------------------- #
# claim merge
# --------------------------------------------------------------------------- #


def _claim(network: str, origin: str, **kwargs: object) -> NetworkClaim:
    return NetworkClaim(network=network, origin=origin, **kwargs)  # type: ignore[arg-type]


def test_merge_claims_unions_both_origins_into_one_row() -> None:
    merged = merge_claims(
        [
            _claim("104.16.0.0/12", ORIGIN_ANNOUNCEMENT, asns={"13335"}, sources={"ripestat"}),
            _claim(
                "104.16.0.0/12", ORIGIN_ALLOCATION, org="Cloudflare", sources={"rdap"}
            ),
        ]
    )
    assert len(merged) == 1
    claim = merged[0]
    assert claim.announced and claim.allocated
    assert claim.asns == {"13335"}
    assert claim.org == "Cloudflare"
    assert claim.sources == {"ripestat", "rdap"}


def test_merge_claims_keeps_distinct_networks_apart() -> None:
    merged = merge_claims(
        [_claim("104.16.0.0/12", ORIGIN_ANNOUNCEMENT), _claim("104.17.0.0/16", ORIGIN_ANNOUNCEMENT)]
    )
    assert len(merged) == 2


def test_merge_claims_is_sorted_by_network_address() -> None:
    merged = merge_claims(
        [_claim("104.17.0.0/16", ORIGIN_ANNOUNCEMENT), _claim("104.16.0.0/12", ORIGIN_ANNOUNCEMENT)]
    )
    assert [claim.network for claim in merged] == ["104.16.0.0/12", "104.17.0.0/16"]


# --------------------------------------------------------------------------- #
# containment + annotation
# --------------------------------------------------------------------------- #


def test_containment_maps_a_prefix_to_its_wider_allocation() -> None:
    claims = [
        _claim("104.16.0.0/12", ORIGIN_ALLOCATION),
        _claim("104.16.1.0/24", ORIGIN_ANNOUNCEMENT),
    ]
    containment = containment_map(claims)
    assert containment["104.16.1.0/24"] == ["104.16.0.0/12"]
    assert containment["104.16.0.0/12"] == []


def test_annotate_known_hosts_marks_confirmed_networks_once() -> None:
    claim = _claim("104.16.0.0/12", ORIGIN_ALLOCATION)
    other = _claim("172.64.0.0/10", ORIGIN_ANNOUNCEMENT)
    matched = annotate_known_hosts([claim, other], ["104.16.1.5", "104.16.2.5", "9.9.9.9"])
    assert matched == 2
    assert claim.known_hosts == ["104.16.1.5", "104.16.2.5"]
    assert other.known_hosts == []


def test_annotate_known_hosts_tolerates_garbage_addresses() -> None:
    claim = _claim("104.16.0.0/12", ORIGIN_ALLOCATION)
    assert annotate_known_hosts([claim], ["not-an-ip"]) == 0
