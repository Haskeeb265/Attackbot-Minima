"""Tests for :mod:`url_endpoint.normalize` — the URL identity contract.

Every assertion here is about a *failure that happens in real archived data*:
the same resource spelled with a default port, a duplicated slash, a stray ``..``,
a campaign parameter or a fragment.  If any of these stops being folded into one
canonical string, one asset silently becomes dozens and every count downstream is
wrong.
"""

from __future__ import annotations

import pytest

from service.recon_pipeline.pipelines.url_endpoint.normalize import (
    KIND_API,
    KIND_JS,
    KIND_JSON,
    KIND_PAGE,
    KIND_SOURCEMAP,
    canonicalize_url,
    classify,
    extension_of,
    group_by_kind,
    is_interesting,
    parameter_index,
    parse_url,
    parse_urls,
    urls_for_apex,
)

APEX = "example.com"


# --------------------------------------------------------------------------- #
# Canonicalization
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        # host case, default ports, fragment
        ("HTTP://Example.com/Path", "http://example.com/Path"),
        ("https://example.com:443/x", "https://example.com/x"),
        ("http://example.com:80/x", "http://example.com/x"),
        ("https://example.com:8443/x", "https://example.com:8443/x"),
        ("https://example.com/a#frag", "https://example.com/a"),
        # trailing root dot on the host
        ("https://example.com./a", "https://example.com/a"),
        # empty path becomes "/"
        ("https://example.com", "https://example.com/"),
        # duplicate slashes and dot segments
        ("https://example.com/a//b", "https://example.com/a/b"),
        ("https://example.com/a/./b", "https://example.com/a/b"),
        ("https://example.com/a/../b", "https://example.com/b"),
        # a trailing slash is meaningful and is preserved
        ("https://example.com/a/", "https://example.com/a/"),
    ],
)
def test_canonicalize_folds_equivalent_spellings(raw: str, expected: str) -> None:
    assert canonicalize_url(raw) == expected


def test_tracking_parameters_are_stripped_and_the_rest_sorted() -> None:
    url = canonicalize_url("https://example.com/p?b=2&utm_source=x&a=1&utm_medium=email")
    assert url == "https://example.com/p?a=1&b=2"


def test_fragment_never_survives() -> None:
    assert "#" not in (canonicalize_url("https://example.com/a#section-2") or "")


@pytest.mark.parametrize(
    "raw",
    [
        "not a url",
        "example.com/a",  # schemeless
        "mailto:someone@example.com",
        "javascript:alert(1)",
        "ftp://example.com/file",
        "",
        "   ",
    ],
)
def test_non_urls_are_refused(raw: str) -> None:
    assert canonicalize_url(raw) is None


def test_out_of_scope_url_is_refused_when_an_apex_is_given() -> None:
    assert canonicalize_url("https://evil.com/a", apex=APEX) is None
    assert canonicalize_url("https://one-example.com/a", apex=APEX) is None
    assert canonicalize_url("https://api.example.com/a", apex=APEX) == "https://api.example.com/a"
    assert canonicalize_url("https://example.com/a", apex=APEX) == "https://example.com/a"


def test_ip_literal_hosts_parse_but_fail_domain_scope() -> None:
    # Parses on its own (archived URLs really do reference IPs) ...
    assert canonicalize_url("http://1.2.3.4/admin") == "http://1.2.3.4/admin"
    # ... but a domain target cannot claim it.
    assert canonicalize_url("http://1.2.3.4/admin", apex=APEX) is None


def test_bad_port_is_refused() -> None:
    assert canonicalize_url("https://example.com:99999/a") is None
    assert canonicalize_url("https://example.com:notaport/a") is None


def test_overlong_url_is_refused() -> None:
    long_url = "https://example.com/" + "a" * 100
    assert canonicalize_url(long_url, max_length=50) is None


# --------------------------------------------------------------------------- #
# Parsed structure
# --------------------------------------------------------------------------- #


def test_parse_url_exposes_endpoint_parameters_and_extension() -> None:
    parsed = parse_url("https://api.example.com/v1/user?id=7&role=admin&utm_source=x")
    assert parsed is not None
    assert parsed.endpoint == "https://api.example.com/v1/user"
    assert parsed.parameter_names == ("id", "role")
    assert parsed.params == (("id", "7"), ("role", "admin"))
    assert parsed.host == "api.example.com"
    assert parsed.path == "/v1/user"


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/assets/app.min.js", "js"),
        ("/.git", ""),  # a dotfile is not a ".git" file
        ("/archive.tar.gz", "gz"),
        ("/page", ""),
        ("/dir.with.dots/page", ""),
    ],
)
def test_extension_of(path: str, expected: str) -> None:
    assert extension_of(path) == expected


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/assets/app.js", KIND_JS),
        ("/data/config.json", KIND_JSON),
        ("/assets/app.js.map", KIND_SOURCEMAP),
        ("/api/v1/users", KIND_API),
        ("/graphql", KIND_API),
        ("/index.html", KIND_PAGE),
        ("/", KIND_PAGE),
        ("/v2/report", KIND_API),
    ],
)
def test_classify(path: str, expected: str) -> None:
    assert classify(path) == expected


def test_classify_treats_a_graphql_query_parameter_as_an_api() -> None:
    assert classify("/endpoint", "query=%7Bme%7Bid%7D%7D") == KIND_API


@pytest.mark.parametrize(
    "path",
    [
        "/.env",
        "/.git/config",
        "/backup.sql",
        "/swagger/index.html",
        "/actuator/health",
        "/admin",
        "/dump.zip",
        "/wp-config.php.bak",
    ],
)
def test_interesting_paths(path: str) -> None:
    assert is_interesting(path) is True


@pytest.mark.parametrize("path", ["/index.html", "/assets/app.js", "/robots.txt", "/api/v1/users"])
def test_ordinary_paths_are_not_flagged(path: str) -> None:
    assert is_interesting(path) is False


# --------------------------------------------------------------------------- #
# Batch operations
# --------------------------------------------------------------------------- #


def test_urls_for_apex_dedupes_and_sorts() -> None:
    urls = urls_for_apex(
        [
            "https://example.com/b",
            "https://example.com/a",
            "https://example.com/a",  # duplicate
            "https://example.com:443/a",  # same as above
            "https://other.com/x",  # out of scope
            "garbage",
        ],
        APEX,
    )
    assert urls == ["https://example.com/a", "https://example.com/b"]


def test_group_by_kind_and_parameter_index() -> None:
    parsed = parse_urls(
        [
            "https://example.com/a.js",
            "https://example.com/b.js",
            "https://example.com/api/x?id=1",
            "https://example.com/p?id=2&q=3",
        ],
        APEX,
    )
    grouped = group_by_kind(parsed)
    assert grouped[KIND_JS] == ["https://example.com/a.js", "https://example.com/b.js"]
    assert len(grouped[KIND_API]) == 1

    index = parameter_index(parsed)
    assert index["id"] == ["https://example.com/api/x?id=1", "https://example.com/p?id=2&q=3"]
    assert index["q"] == ["https://example.com/p?id=2&q=3"]


def test_parse_urls_dedupes_on_the_canonical_identity() -> None:
    parsed = parse_urls(
        ["https://example.com/a?utm_source=x", "https://example.com/a#frag"], APEX
    )
    assert len(parsed) == 1


# --------------------------------------------------------------------------- #
# Junk (URL-shaped debris)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "raw",
    [
        "https://example.com/${P}-doc.tar.bz2",
        "https://example.com/{{ var }}/x",
        "https://example.com/$(whoami)",
        "https://example.com/a%00b",
        "https://example.com/a b",
        "https://example.com/p?next=https://other.com/x",
    ],
)
def test_junk_urls_are_flagged_but_still_parse(raw: str) -> None:
    parsed = parse_url(raw)
    assert parsed is not None
    assert parsed.junk is True


def test_junk_is_excluded_by_the_batch_helpers() -> None:
    values = ["https://example.com/${P}.tar.gz", "https://example.com/real"]
    assert urls_for_apex(values, APEX) == ["https://example.com/real"]
    assert [item.url for item in parse_urls(values, APEX)] == ["https://example.com/real"]


def test_ordinary_urls_are_not_junk() -> None:
    parsed = parse_url("https://example.com/a?q=hello%20world&page=2")
    assert parsed is not None and parsed.junk is False


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("id", True),
        ("user_id", True),
        ("filter[status]", True),
        ("report[email]", True),
        # A dot inside brackets is a nested member; the same dot at the top level
        # makes the token a hostname or a filename, which is what live harvests
        # of real targets actually contained.
        ("filter[user.name]", True),
        ("hackddos.com", False),
        ("index.html", False),
        ("x" * 65, False),
        ("also does it come with ddos protection", False),
        ("/usr/lib/nginx/modules", False),
        ("", False),
    ],
)
def test_is_plausible_parameter(name: str, expected: bool) -> None:
    from service.recon_pipeline.pipelines.url_endpoint.normalize import (
        is_plausible_parameter,
    )

    assert is_plausible_parameter(name) is expected
