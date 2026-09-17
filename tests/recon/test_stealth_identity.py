"""Identity tests: the coherence invariants are the whole point of the module.

Each test here corresponds to a real mismatch that bot scores look for — a
version disagreement between user agent and Client Hints, a browser that never
sends Client Hints sending them, a platform that contradicts the user agent.
"""

from __future__ import annotations

import dataclasses

import pytest

from service.recon_pipeline.stealth.identity import (
    BY_NAME,
    CHROME_WIN,
    FIREFOX_WIN,
    PROFILES,
    SAFARI_MAC,
    BrowserIdentity,
    IdentityPool,
    verify_all,
)


def test_every_bundled_profile_is_coherent():
    problems = {name: found for name, found in verify_all().items() if found}
    assert problems == {}


def test_pool_refuses_an_incoherent_profile():
    bad = dataclasses.replace(CHROME_WIN, ua=FIREFOX_WIN.ua)
    with pytest.raises(ValueError, match="incoherent"):
        IdentityPool(profiles=(bad,))


@pytest.mark.parametrize(
    "profile, expected_fragment",
    [
        (dataclasses.replace(CHROME_WIN, ua=CHROME_WIN.ua.replace("134", "999")), "missing Chrome/134."),
        (
            dataclasses.replace(
                CHROME_WIN,
                client_hints={**CHROME_WIN.client_hints, "sec-ch-ua": '"Chromium";v="999"'},
            ),
            "client hint brands",
        ),
        (dataclasses.replace(CHROME_WIN, platform="Linux"), "platform"),
        (dataclasses.replace(FIREFOX_WIN, client_hints=CHROME_WIN.client_hints), "must not send client hints"),
        (dataclasses.replace(SAFARI_MAC, accept_encoding="gzip, deflate, br, zstd"), "zstd"),
        (dataclasses.replace(CHROME_WIN, headers=tuple((n, v) for n, v in CHROME_WIN.headers if n != "accept")), "missing accept"),
    ],
)
def test_verify_catches_specific_mismatches(profile: BrowserIdentity, expected_fragment: str):
    assert any(expected_fragment in problem for problem in profile.verify())


def test_verify_catches_a_sec_ch_ua_header_that_contradicts_the_client_hints():
    headers = tuple(
        (name, '"Chromium";v="134", "Google Chrome";v="134"' if name == "sec-ch-ua" else value)
        for name, value in CHROME_WIN.headers
    )
    problems = dataclasses.replace(CHROME_WIN, headers=headers).verify()
    assert any("sec-ch-ua header disagrees" in problem for problem in problems)


def test_firefox_and_safari_send_no_client_hints():
    assert FIREFOX_WIN.client_hints is None
    assert SAFARI_MAC.client_hints is None
    assert "sec-ch-ua" not in dict(FIREFOX_WIN.headers)
    assert "sec-ch-ua" not in dict(SAFARI_MAC.headers)


def test_host_and_connection_are_left_to_the_transport():
    for profile in PROFILES:
        names = {name for name, _ in profile.headers}
        assert "host" not in names
        assert "connection" not in names


def test_assignment_is_stable_per_host_and_spreads_across_profiles():
    pool = IdentityPool(salt="target.example")
    hosts = [f"host{index}.target.example" for index in range(120)]

    first = pool.assignment(hosts)
    second = pool.assignment(list(reversed(hosts)))
    assert first == second
    assert pool.for_host(hosts[0]) == pool.for_host(hosts[0])

    used = set(first.values())
    assert len(used) >= 4, f"pool barely used: {used}"
    assert used <= {profile.name for profile in PROFILES}


def test_salt_changes_the_assignment():
    hosts = [f"h{index}.example.com" for index in range(60)]
    assert IdentityPool(salt="a").assignment(hosts) != IdentityPool(salt="b").assignment(hosts)


def test_pinned_identity_wins_for_every_host():
    pool = IdentityPool(salt="x", pinned="chrome-win")
    assert {pool.for_host(f"h{index}.example.com").name for index in range(20)} == {"chrome-win"}


def test_unknown_pinned_identity_is_rejected():
    with pytest.raises(ValueError, match="unknown identity"):
        IdentityPool(pinned="netscape")


def test_header_pairs_are_navigation_shaped():
    pairs = dict(CHROME_WIN.header_pairs())
    assert pairs["Sec-Fetch-Site"] == "none"  # typed/bookmarked URL: no referer
    assert pairs["Sec-Fetch-Mode"] == "navigate"
    assert pairs["Sec-Fetch-Dest"] == "document"
    assert pairs["Sec-Fetch-User"] == "?1"


def test_header_names_use_the_browser_spelling():
    """HTTP/1.1 keeps header-name case, and a browser spells it Title-Case."""
    pairs = CHROME_WIN.header_pairs()
    assert ("User-Agent", CHROME_WIN.ua) in pairs
    assert ("Sec-Ch-Ua", CHROME_WIN.client_hints["sec-ch-ua"]) in pairs
    assert not any(name.islower() for name, _ in pairs)


def test_referer_switches_fetch_site_and_keeps_chrome_ordering():
    pairs = CHROME_WIN.header_pairs(referer="https://www.example.com/")
    ordered = [name for name, _ in pairs]
    assert dict(pairs)["Sec-Fetch-Site"] == "cross-site"
    # Chrome sends Referer after the sec-fetch-* block and before the encodings.
    assert ordered.index("Referer") < ordered.index("Accept-Encoding")
    assert ordered.index("Referer") > ordered.index("Sec-Fetch-Dest")


def test_chromium_header_order_puts_client_hints_before_the_user_agent():
    ordered = [name for name, _ in CHROME_WIN.header_pairs()]
    assert ordered[:4] == ["Sec-Ch-Ua", "Sec-Ch-Ua-Mobile", "Sec-Ch-Ua-Platform", "Upgrade-Insecure-Requests"]
    assert ordered.index("Sec-Ch-Ua") < ordered.index("User-Agent")
    assert ordered.index("User-Agent") < ordered.index("Accept")


def test_httpx_header_args_are_name_colon_value():
    args = CHROME_WIN.httpx_header_args()
    assert len(args) % 2 == 0
    assert args[0] == "-H"
    assert args[1].lower().startswith("sec-ch-ua: ")
    assert all(": " in args[index] for index in range(1, len(args), 2))


def test_by_name_matches_the_pool():
    assert set(BY_NAME) == {profile.name for profile in PROFILES}
