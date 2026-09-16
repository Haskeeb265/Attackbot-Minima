"""
Tests for :mod:`passive.normalize`.

Everything here is hermetic: fixtures are written to ``tmp_path`` and no file
outside the repo is read, so the suite cannot be broken (or silently satisfied)
by whatever happens to be sitting in ``passive/output/`` from the last live run.

The raw fixtures reproduce the exact quirks of the real 2026-09-06 ``qbsco.net``
tool run — CRLF from assetfinder/findomain, the apex included by those two tools,
and duplicated names across sources.
"""

from __future__ import annotations

import pytest

from service.recon_pipeline.asset_pipelines.subdomain_domain_wildcards.passive import normalize as nz

APEX = "qbsco.net"

RAW = {
    "subfinder": (
        "cpcontacts.qbsco.net\nserver.qbsco.net\nwww.qbsco.net\napp.qbsco.net\n"
        "cpanel.qbsco.net\nmail.qbsco.net\nocac.qbsco.net\nwebdisk.qbsco.net\n"
        "webmail.qbsco.net\ncpcalendars.qbsco.net\n"
    ),
    "assetfinder": "qbsco.net\r\napp.qbsco.net\r\nmail.qbsco.net\r\nwww.qbsco.net\r\nocac.qbsco.net\r\n",
    "findomain": "qbsco.net\r\nocac.qbsco.net\r\n",
    "chaos": (
        "ftp.qbsco.net\ncpanel.qbsco.net\nwww.qbsco.net\nwebdisk.qbsco.net\n"
        "webmail.qbsco.net\napp.qbsco.net\nserver.qbsco.net\nocac.qbsco.net\n"
        "mail.qbsco.net\nautodiscover.qbsco.net\ncpcontacts.qbsco.net\ncpcalendars.qbsco.net\n"
    ),
}

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

AMASS_RELATIONS = (
    "qbsco.net (FQDN) --> mx_record --> qbsco-net.mail.protection.outlook.com (FQDN)\r\n"
    "autodiscover.qbsco.net (FQDN) --> cname_record --> autodiscover.outlook.com (FQDN)\r\n"
    "qbsco.net (FQDN) --> ns_record --> jason.ns.cloudflare.com (FQDN)\n"
    "not a relation line at all\n"
    "\n"
)


def _write_dir(tmp_path, files: dict[str, str]) -> None:
    for name, body in files.items():
        (tmp_path / f"{name}.txt").write_text(body, encoding="utf-8", newline="")


# --------------------------------------------------------------------------- #
# canonicalize_host
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("APP.Qbsco.NET", "app.qbsco.net"),
        ("app.qbsco.net.", "app.qbsco.net"),
        ("app.qbsco.net\r", "app.qbsco.net"),
        ("*.qbsco.net", "qbsco.net"),
        ("*.APP.qbsco.net", "app.qbsco.net"),
        ("https://app.qbsco.net/path?x=1", "app.qbsco.net"),
        ("app.qbsco.net:8443", "app.qbsco.net"),
        ("user@app.qbsco.net", "app.qbsco.net"),
        ("a.energy.smf12.tcs.tesla.com", "a.energy.smf12.tcs.tesla.com"),
        ("münchen.example.com", "xn--mnchen-3ya.example.com"),
        ("app.1.2.3.4", "app.1.2.3.4"),
        # rejected: not hostnames
        ("", None),
        ("   ", None),
        ("[INFO] banner text", None),
        ("1.2.3.4", None),
        ("2606:4700::1111", None),
        ("localhost", None),
        ("*", None),
        ("*." , None),
        ("-bad.qbsco.net", None),
        ("bad-.qbsco.net", None),
        ("a..qbsco.net", None),
        ("app.qbsco.net:notaport", None),
        ("x" * 64 + ".example.com", None),
        (
            "qbsco.net (FQDN) --> mx_record --> qbsco-net.mail.protection.outlook.com (FQDN)",
            None,
        ),
    ],
)
def test_canonicalize_host(raw: str, expected: str | None) -> None:
    assert nz.canonicalize_host(raw) == expected


def test_is_subdomain_of_is_label_aware() -> None:
    assert nz.is_subdomain_of("www.tesla.com", "tesla.com")
    assert nz.is_subdomain_of("a.energy.smf12.tcs.tesla.com", "tesla.com")
    # the apex is not its own subdomain
    assert not nz.is_subdomain_of("tesla.com", "tesla.com")
    # a lookalike domain must not match on a bare suffix test
    assert not nz.is_subdomain_of("one-tesla.com", "tesla.com")
    assert not nz.is_subdomain_of("nottesla.com", "tesla.com")


def test_parent_of() -> None:
    assert nz.parent_of("www.tesla.com") == "tesla.com"
    assert nz.parent_of("tesla.com") is None
    assert nz.parent_of("a.b.c.example.com") == "b.c.example.com"


# --------------------------------------------------------------------------- #
# scan / normalize one file
# --------------------------------------------------------------------------- #


def test_scan_separates_hosts_foreign_and_junk(tmp_path) -> None:
    path = tmp_path / "mixed.txt"
    path.write_text(
        "qbsco.net\n"                       # apex -> not a subdomain
        "APP.qbsco.net\n"                   # accepted, lowercased
        "app.qbsco.net\r\n"                 # duplicate after normalization
        "evil.com\n"                        # foreign
        "[INFO] banner\n"                   # junk
        "1.2.3.4\n"                         # junk (IP)
        "\n"                                # blank
        "app.qbsco.net (FQDN) --> x (FQDN)\n",  # junk (relation)
        encoding="utf-8",
        newline="",
    )

    result = nz.scan_subdomain_file(path, APEX)

    assert result.hosts == ["app.qbsco.net"]
    assert result.foreign == ["evil.com"]
    assert result.ignored == 4
    assert result.total_lines == 6


def test_scan_missing_file_is_empty_not_error(tmp_path) -> None:
    result = nz.scan_subdomain_file(tmp_path / "nope.txt", APEX)
    assert result.hosts == []
    assert result.foreign == []
    assert result.ignored == 0


@pytest.mark.parametrize("tool", list(RAW))
def test_normalize_subdomain_file_matches_expected_counts(tmp_path, tool: str) -> None:
    _write_dir(tmp_path, {tool: RAW[tool]})
    hosts = nz.normalize_subdomain_file(tmp_path / f"{tool}.txt", APEX)

    assert hosts == sorted(hosts)
    assert len(hosts) == len(set(hosts))
    assert APEX not in hosts
    assert all(h.endswith(".qbsco.net") for h in hosts)
    assert all("\r" not in h for h in hosts)

    expected_len = {"subfinder": 10, "assetfinder": 4, "findomain": 1, "chaos": 12}[tool]
    assert len(hosts) == expected_len


def test_foreign_domain_raises_by_default(tmp_path) -> None:
    path = tmp_path / "leak.txt"
    path.write_text("evil.com\napp.qbsco.net\n", encoding="utf-8")

    with pytest.raises(nz.ForeignDomainError) as excinfo:
        nz.normalize_subdomain_file(path, APEX)

    # Backwards compatible with the old ValueError contract.
    assert isinstance(excinfo.value, ValueError)
    assert "evil.com" in str(excinfo.value)
    assert excinfo.value.offenders == {"leak.txt": ["evil.com"]}


def test_foreign_domain_allowed_when_lenient(tmp_path) -> None:
    path = tmp_path / "leak.txt"
    path.write_text("evil.com\n", encoding="utf-8")
    assert nz.normalize_subdomain_file(path, APEX, reject_foreign=False) == []


def test_normalize_host_list() -> None:
    assert nz.normalize_host_list(
        ["*.App.Qbsco.net", "qbsco.net", "evil.com", "junk"], APEX
    ) == ["app.qbsco.net"]


# --------------------------------------------------------------------------- #
# merge with provenance
# --------------------------------------------------------------------------- #


def test_merge_subdomains_unions_all_four_tools(tmp_path) -> None:
    _write_dir(tmp_path, RAW)
    merged = nz.merge_subdomains(
        APEX, tmp_path, sources=("subfinder", "assetfinder", "findomain", "chaos")
    )
    assert merged == EXPECTED_12
    assert APEX not in merged


def test_merge_observations_records_provenance(tmp_path) -> None:
    _write_dir(tmp_path, RAW)
    observations = nz.merge_observations(
        APEX, tmp_path, sources=("subfinder", "assetfinder", "findomain", "chaos")
    )

    assert observations["www.qbsco.net"] == {"subfinder", "assetfinder", "chaos"}
    assert observations["autodiscover.qbsco.net"] == {"chaos"}
    assert observations["ftp.qbsco.net"] == {"chaos"}


def test_merge_ignores_absent_source_files(tmp_path) -> None:
    _write_dir(tmp_path, {"subfinder": RAW["subfinder"]})
    assert len(nz.merge_subdomains(APEX, tmp_path, sources=("subfinder", "chaos"))) == 10


def test_merge_foreign_raises_with_all_offenders(tmp_path) -> None:
    _write_dir(tmp_path, {"subfinder": "a.qbsco.net\nevil.com\n", "chaos": "other.net\n"})

    with pytest.raises(nz.ForeignDomainError) as excinfo:
        nz.merge_subdomains(APEX, tmp_path, sources=("subfinder", "chaos"))

    assert set(excinfo.value.offenders) == {"subfinder.txt", "chaos.txt"}


def test_find_foreign_never_raises(tmp_path) -> None:
    _write_dir(tmp_path, {"subfinder": "a.qbsco.net\nevil.com\n"})
    assert nz.find_foreign(APEX, tmp_path, sources=("subfinder",)) == {
        "subfinder.txt": ["evil.com"]
    }


def test_default_sources_exclude_amass() -> None:
    sources = nz.subdomain_sources()
    assert "amass" not in sources
    assert {"subfinder", "crtsh", "chaos", "assetfinder", "findomain", "wayback"} == set(sources)


# --------------------------------------------------------------------------- #
# amass relations
# --------------------------------------------------------------------------- #


def test_normalize_amass_relations(tmp_path) -> None:
    path = tmp_path / "amass.txt"
    path.write_text(AMASS_RELATIONS, encoding="utf-8", newline="")

    relations = nz.normalize_amass_relations(path)

    assert len(relations) == 3
    assert relations[0] == nz.AmassRelation(
        source="qbsco.net",
        relation_type="mx_record",
        target="qbsco-net.mail.protection.outlook.com",
    )
    assert str(relations[1]) == (
        "autodiscover.qbsco.net --> cname_record --> autodiscover.outlook.com"
    )
    assert all("\r" not in r.source and "\r" not in r.target for r in relations)


def test_relation_subdomains_extracts_both_sides(tmp_path) -> None:
    path = tmp_path / "amass.txt"
    path.write_text(AMASS_RELATIONS, encoding="utf-8", newline="")

    hosts = nz.normalize_amass_subdomains(path, APEX)

    # `autodiscover.qbsco.net` appears as a relation source; the third-party
    # targets (outlook.com, cloudflare.com) are correctly out of scope.
    assert hosts == {"autodiscover.qbsco.net"}


def test_amass_relation_file_is_not_mergeable_as_a_host_list(tmp_path) -> None:
    """The relations stream must never contribute names via the list path."""
    path = tmp_path / "amass.txt"
    path.write_text(AMASS_RELATIONS, encoding="utf-8", newline="")

    assert nz.looks_like_amass_relations(path)
    assert nz.scan_subdomain_file(path, APEX).hosts == []
    assert "amass" not in nz.subdomain_sources()


def test_relation_subdomains_handles_empty() -> None:
    assert nz.relation_subdomains([], APEX) == set()


# --------------------------------------------------------------------------- #
# writing
# --------------------------------------------------------------------------- #


def test_write_host_list_sorts_dedupes_and_is_atomic(tmp_path) -> None:
    path = tmp_path / "out" / "subdomains.txt"
    nz.write_host_list(path, ["b.qbsco.net", "a.qbsco.net", "b.qbsco.net", ""])

    assert path.read_text(encoding="utf-8") == "a.qbsco.net\nb.qbsco.net\n"
    assert not (path.with_name(path.name + ".tmp")).exists()
