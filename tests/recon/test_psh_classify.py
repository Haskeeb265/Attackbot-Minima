"""
Tests for :mod:`port_service_host.classify.cdn`.

This module is the stage's safety property, so the tests are written the way the
failure would be: for each signal, assert that the address is classified as ``cdn``
*and* that the evidence names the signal.  A verdict without evidence is what a
future reader cannot audit, and it is also how a stale range file would silently
become a wrong answer.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from service.recon_pipeline.asset_pipelines.port_service_host.classify import cdn


@dataclass
class FakeIntel:
    indexed: bool = True
    ports: tuple[int, ...] = ()
    tags: tuple[str, ...] = ()
    hostnames: tuple[str, ...] = ()


@dataclass
class FakeOwnership:
    org: str = ""
    as_name: str = ""
    resolved: bool = False


# --------------------------------------------------------------------------- #
# Range snapshot
# --------------------------------------------------------------------------- #


def test_bundled_range_snapshot_parses_without_unparsed_lines() -> None:
    table = cdn.load_ranges()
    assert table.networks, "the bundled snapshot should contain networks"
    assert table.unparsed == []


# --------------------------------------------------------------------------- #
# Hosted (SaaS) classification
# --------------------------------------------------------------------------- #


def test_an_outlook_cname_chain_classifies_hosted_not_dedicated() -> None:
    """The measured qbsco.net case: autodiscover -> autodiscover.outlook.com."""
    verdict = cdn.classify(
        "40.104.56.152",
        cname_targets=("autodiscover.outlook.com", "autodiscover.outlook.cloud.microsoft"),
        in_scope=True,
    )
    assert verdict.verdict == cdn.VERDICT_HOSTED
    assert verdict.is_hosted is True
    assert verdict.is_cdn is False
    assert verdict.provider == "Microsoft 365"
    assert verdict.confidence == cdn.CONFIDENCE_HIGH
    assert any("autodiscover.outlook.com" in line for line in verdict.evidence)
    assert any("third-party hosted" in line for line in verdict.evidence)


def test_whole_label_matching_applies_to_hosted_suffixes_too() -> None:
    """``notoutlook.com`` must never match ``outlook.com``."""
    verdict = cdn.classify("8.8.8.8", cname_targets=("mail.notoutlook.com",), in_scope=True)
    assert verdict.verdict == cdn.VERDICT_DEDICATED


def test_a_cdn_signal_outranks_the_hosted_verdict() -> None:
    """If the address is also known edge infrastructure, it is a CDN address."""
    verdict = cdn.classify(
        "104.16.0.1",
        cname_targets=("autodiscover.outlook.com",),
        in_scope=True,
    )
    assert verdict.verdict == cdn.VERDICT_CDN
    assert verdict.provider == "Cloudflare"


def test_hosted_without_a_cdn_signal_or_cname_stays_dedicated() -> None:
    verdict = cdn.classify("8.8.8.8", in_scope=True)
    assert verdict.verdict == cdn.VERDICT_DEDICATED
    assert verdict.is_hosted is False


def test_range_snapshot_matches_a_cloudflare_address() -> None:
    verdict = cdn.classify("104.16.0.1")
    assert verdict.verdict == cdn.VERDICT_CDN
    assert verdict.provider == "Cloudflare"
    assert verdict.confidence == cdn.CONFIDENCE_HIGH
    assert any("Cloudflare range" in line for line in verdict.evidence)


def test_range_file_collects_bad_lines_instead_of_raising(tmp_path) -> None:
    path = tmp_path / "ranges.txt"
    path.write_text(
        "# comment\n"
        "cloudflare 104.16.0.0/13\n"
        "notaprovider 1.2.3.0/24\n"
        "fastly not-a-network\n"
        "lonely\n",
        encoding="utf-8",
    )
    table = cdn.load_ranges(path)
    assert len(table.networks) == 1
    assert len(table.unparsed) == 3


# --------------------------------------------------------------------------- #
# Signals
# --------------------------------------------------------------------------- #


def test_no_evidence_at_all_is_unknown_not_dedicated() -> None:
    verdict = cdn.classify("8.8.8.8")
    assert verdict.verdict == cdn.VERDICT_UNKNOWN
    assert verdict.to_dict()["evidence"]


def test_in_scope_without_a_cdn_signal_is_dedicated() -> None:
    verdict = cdn.classify("8.8.8.8", in_scope=True)
    assert verdict.verdict == cdn.VERDICT_DEDICATED
    assert any("resolves here" in line for line in verdict.evidence)


def test_ptr_naming_identifies_a_provider() -> None:
    verdict = cdn.classify("8.8.8.8", ptr_names=["a1-67.akamaiedge.net."])
    assert verdict.verdict == cdn.VERDICT_CDN
    assert verdict.provider == "Akamai"


def test_ptr_matching_is_whole_label_and_cannot_be_fooled_by_a_lookalike() -> None:
    verdict = cdn.classify("8.8.8.8", ptr_names=["notcloudflare.net"])
    assert verdict.verdict == cdn.VERDICT_UNKNOWN


def test_cname_evidence_is_reported_as_a_cname_not_as_a_ptr() -> None:
    verdict = cdn.classify("8.8.8.8", cname_targets=["www.example.com.edgekey.net"])
    assert verdict.verdict == cdn.VERDICT_CDN
    assert verdict.provider == "Akamai"
    assert any(line.startswith("CNAME chain") for line in verdict.evidence)


def test_ownership_names_the_provider_for_a_pure_edge_network() -> None:
    verdict = cdn.classify(
        "8.8.8.8", ownership=FakeOwnership(org="Cloudflare, Inc.", as_name="CLOUDFLARENET", resolved=True)
    )
    assert verdict.verdict == cdn.VERDICT_CDN
    assert verdict.provider == "Cloudflare"
    assert any("ownership record" in line for line in verdict.evidence)


def test_a_hosting_provider_name_is_not_by_itself_edge_evidence() -> None:
    """Regression: Linode is owned by Akamai, so Cymru reports its AS as
    ``AKAMAI-LINODE-AP - Akamai Connected Cloud``.  A substring match on
    "akamai" classified a plain cloud-hosting VPS (``scanme.nmap.org``) as CDN
    edge, which would have skipped it from the scan entirely.
    """
    verdict = cdn.classify(
        "45.33.32.156",
        ownership=FakeOwnership(
            org="LINODE", as_name="AKAMAI-LINODE-AP - Akamai Connected Cloud, SG", resolved=True
        ),
    )
    assert verdict.verdict == cdn.VERDICT_UNKNOWN
    assert verdict.provider == ""
    # The observation is still reported, with the reason it did not decide.
    assert any("Akamai" in line and "not treated as CDN edge" in line for line in verdict.evidence)
    assert "akamai" not in cdn.EDGE_NETWORKS


def test_a_hosting_provider_name_plus_real_edge_naming_is_enough() -> None:
    """A genuine Akamai edge always resolves through Akamai edge naming."""
    verdict = cdn.classify(
        "45.33.32.156",
        ownership=FakeOwnership(org="Akamai Technologies", resolved=True),
        cname_targets=["www.example.com.edgekey.net"],
    )
    assert verdict.verdict == cdn.VERDICT_CDN
    assert verdict.provider == "Akamai"
    assert len(verdict.evidence) >= 2


def test_a_generic_edge_tag_raises_the_verdict_without_naming_a_provider() -> None:
    verdict = cdn.classify("8.8.8.8", intel=FakeIntel(tags=("cdn", "cloud")))
    assert verdict.verdict == cdn.VERDICT_CDN
    assert verdict.confidence == cdn.CONFIDENCE_MEDIUM
    # "this is a CDN" and "this is Cloudflare" are different claims.
    assert verdict.provider == ""


def test_a_cloud_tag_alone_is_not_a_cdn() -> None:
    """Regression: a plain Linode VPS is tagged ``cloud`` by Shodan.

    Treating that as a CDN classified ``scanme.nmap.org`` as Cloudflare, which
    would have excluded a real host from the scan and labelled it as somebody
    else's infrastructure.  The two errors are not symmetric, so ``cloud`` is not
    an edge tag.
    """
    verdict = cdn.classify("8.8.8.8", intel=FakeIntel(tags=("cloud",)))
    assert verdict.verdict == cdn.VERDICT_UNKNOWN
    assert "cloud" not in cdn.EDGE_TAGS


def test_a_waf_tag_alone_is_enough_to_stay_off_the_port_scan() -> None:
    verdict = cdn.classify("8.8.8.8", intel=FakeIntel(tags=("waf",)))
    assert verdict.verdict == cdn.VERDICT_CDN


def test_passive_intel_hostname_identifies_a_provider() -> None:
    verdict = cdn.classify("8.8.8.8", intel=FakeIntel(hostnames=("x.cloudfront.net",)))
    assert verdict.provider == "Amazon CloudFront"


def test_response_headers_identify_a_provider_after_a_probe() -> None:
    verdict = cdn.classify("8.8.8.8", headers={"cf-ray": "8a1b2c3d", "server": "cloudflare"})
    assert verdict.verdict == cdn.VERDICT_CDN
    assert verdict.provider == "Cloudflare"


def test_a_header_prefix_marker_matches_a_whole_header_family() -> None:
    """akamai emits families of headers; only the prefix is stable."""
    verdict = cdn.classify("8.8.8.8", headers={"x-akamai-request-id": "12345"})
    assert verdict.provider == "Akamai"


def test_a_generic_proxy_header_does_not_make_something_cloudfront() -> None:
    """``Via: 1.1`` is emitted by every caching proxy on the internet."""
    verdict = cdn.classify("8.8.8.8", headers={"via": "1.1 some-proxy"})
    assert verdict.verdict == cdn.VERDICT_UNKNOWN


def test_cloudflare_wins_when_two_signals_disagree_about_the_provider() -> None:
    verdict = cdn.classify(
        "104.16.0.1", ownership=FakeOwnership(org="Akamai Technologies", resolved=True)
    )
    # The range is checked first and is the stronger signal; both are recorded.
    assert verdict.provider == "Cloudflare"
    assert len(verdict.evidence) >= 2


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def test_invalid_address_is_unknown_with_a_reason() -> None:
    verdict = cdn.classify("not-an-ip")
    assert verdict.verdict == cdn.VERDICT_UNKNOWN
    assert verdict.to_dict()["ip"] == "not-an-ip"


def test_classify_all_keeps_one_verdict_per_address() -> None:
    verdicts = cdn.classify_all(
        ["104.16.0.1", "104.16.0.1", "8.8.8.8"],
        intel_by_ip={"8.8.8.8": FakeIntel()},
        in_scope=["8.8.8.8"],
    )
    assert [verdict.verdict for verdict in verdicts] == [
        cdn.VERDICT_CDN,
        cdn.VERDICT_DEDICATED,
    ]


def test_classify_all_accepts_per_address_headers() -> None:
    verdicts = cdn.classify_all(
        ["8.8.8.8"],
        headers_by_ip={"8.8.8.8": {"server": "cloudflare"}},
    )
    assert verdicts[0].provider == "Cloudflare"


def test_summarise_counts_verdicts_and_providers() -> None:
    summary = cdn.summarise(cdn.classify_all(["104.16.0.1", "8.8.8.8"], in_scope=["8.8.8.8"]))
    assert summary["by_verdict"] == {"cdn": 1, "dedicated": 1}
    assert summary["by_provider"] == {"Cloudflare": 1}


def test_labelled_includes_the_provider_only_when_known() -> None:
    assert cdn.classify("104.16.0.1").labelled == "cdn (Cloudflare)"
    assert cdn.classify("8.8.8.8").labelled == "unknown"
