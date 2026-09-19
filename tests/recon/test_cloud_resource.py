"""Tests for the cloud_resource pipeline: providers → candidates → verdicts.

The HTTP layer is injected, so the whole pipeline runs in-process: pattern
matching, name validation, sibling-artifact harvesting, provider probing and
the exact artifact shapes the design promises.  No test touches the network.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from service.recon_pipeline.pipelines.cloud_resource import emit, providers, verify
from service.recon_pipeline.pipelines.cloud_resource.main import run_pipeline
from service.recon_pipeline.pipelines.cloud_resource.normalize import (
    Candidate,
    canonicalize_name,
    validate_name,
)
from service.recon_pipeline.pipelines.cloud_resource.seeds import (
    brand_tokens,
    derive_names,
    harvest,
)
from service.recon_pipeline.pipelines.cloud_resource.verify import (
    FetchResult,
    STATE_ABSENT,
    STATE_AUTH,
    STATE_DANGLING,
    STATE_EXISTS_OTHER_REGION,
    STATE_OPEN,
    STATE_UNAVAILABLE,
    classify,
    evidence_class_for,
)

# --------------------------------------------------------------------------- #
# providers: the claim surface
# --------------------------------------------------------------------------- #


def test_a_cname_claim_is_matched_and_captured() -> None:
    assert providers.match_provider("acme.s3.amazonaws.com") == [("s3", "acme")]


def test_a_url_claim_yields_the_same_name_as_a_bare_host() -> None:
    url = "https://ACME.storage.googleapis.com/some/asset.js"
    assert providers.match_provider(url) == [("gcs", "acme")]


def test_a_claim_is_reported_once_per_provider() -> None:
    """A trailing-dot CNAME spelling must not double-report a claim."""
    value = "acme.s3.amazonaws.com."
    pairs = providers.match_provider(value)
    assert pairs.count(("s3", "acme")) == 1


def test_region_style_s3_hosts_are_matched() -> None:
    assert providers.match_provider("acme.s3.eu-west-1.amazonaws.com") == [("s3", "acme")]


def test_a_multi_label_middle_is_not_claimed() -> None:
    assert providers.match_provider("a.b.s3.amazonaws.com") == []


def test_non_provider_hosts_claim_nothing() -> None:
    for value in ("example.com", "autodiscover.outlook.com", "acme.s3.amazonaws.com.evil.io"):
        assert providers.match_provider(value) == []


def test_every_provider_probe_template_contains_the_name() -> None:
    for spec in providers.PROVIDERS.values():
        assert "{name}" in spec.probe_template
        assert "example-bucket" in spec.probe_url("example-bucket")


# --------------------------------------------------------------------------- #
# normalize: the identity layer
# --------------------------------------------------------------------------- #


def test_canonicalize_name_lowercases_and_strips_edges() -> None:
    assert canonicalize_name("  ACME-Bucket. ") == "acme-bucket"


def test_azure_rejects_dots_and_long_names() -> None:
    assert validate_name("acme.assets", "azure") is not None
    assert validate_name("a" * 25, "azure") is not None
    assert validate_name("acmeassets", "azure") is None


def test_s3_accepts_dots_but_rejects_bad_edges() -> None:
    assert validate_name("acme.assets", "s3") is None
    assert validate_name("-acme", "s3") is not None
    assert validate_name("acme!", "s3") is not None


def test_gcs_accepts_underscores() -> None:
    assert validate_name("acme_assets", "gcs") is None


def test_placeholder_names_are_refused() -> None:
    assert validate_name("*", "s3") is not None
    assert validate_name("example", "s3") is not None


def test_unknown_provider_is_refused() -> None:
    assert validate_name("acme", "digitalocean") is not None


def test_candidate_merge_unions_provenance() -> None:
    first = Candidate("acme", "s3", origins={"cname"}, sources={"records.jsonl"}, evidence=["a"])
    second = Candidate("acme", "s3", origins={"url"}, sources={"urls.jsonl"}, evidence=["b"])
    first.merge(second)
    assert first.origins == {"cname", "url"}
    assert first.evidence == ["a", "b"]


# --------------------------------------------------------------------------- #
# seeds: harvest and derivation
# --------------------------------------------------------------------------- #


def _write_sibling_artifacts(tmp_path: Path) -> tuple[Path, Path]:
    names = tmp_path / "names"
    urls = tmp_path / "urls"
    (names / "active" / "output").mkdir(parents=True)
    (names / "output").mkdir(parents=True)
    (urls / "output").mkdir(parents=True)
    (urls / "passive" / "output").mkdir(parents=True)

    (names / "active" / "output" / "records.jsonl").write_text(
        json.dumps(
            {
                "host": "assets.qbsco.net",
                "cname": ["qbsco-static.s3.amazonaws.com", "autodiscover.outlook.com"],
            }
        )
        + "\n"
        + json.dumps({"host": "cdn.qbsco.net", "cname": ["qbsco-static.storage.googleapis.com"]})
        + "\n",
        encoding="utf-8",
    )
    (names / "output" / "live_hosts.txt").write_text(
        "www.qbsco.net\nmail.qbsco.net\n", encoding="utf-8"
    )
    # Azure accounts cannot carry hyphens, so the fixture name is hyphen-free:
    # a hyphenated "azure" host in a sibling artifact is a claim the validator
    # refuses (that account cannot exist), which is its own tested behaviour.
    (urls / "output" / "urls.jsonl").write_text(
        json.dumps({"url": "https://qbscomedia.blob.core.windows.net/assets/logo.png"})
        + "\n",
        encoding="utf-8",
    )
    (urls / "output" / "javascript.txt").write_text(
        "https://qbsco-js.s3.amazonaws.com/app.js\n", encoding="utf-8"
    )
    (urls / "output" / "endpoints.txt").write_text("", encoding="utf-8")
    return names, urls


def test_harvest_folds_claims_and_keeps_provenance(tmp_path: Path) -> None:
    names, urls = _write_sibling_artifacts(tmp_path)
    out = tmp_path / "passive"
    candidates, counts, states = harvest(
        "qbsco.net",
        output_dir=out,
        names_dir=names,
        urls_dir=urls,
        max_derived=4,
    )
    by_key = {c.key: c for c in candidates}

    # CNAME claims from records.jsonl — both providers on the shared name.
    assert ("s3", "qbsco-static") in by_key
    assert ("gcs", "qbsco-static") in by_key
    s3_row = by_key[("s3", "qbsco-static")]
    assert "cname" in s3_row.origins
    assert "records.jsonl" in s3_row.sources
    assert any("s3.amazonaws.com" in item for item in s3_row.evidence)

    # URL + JS claims carry their own origins.
    assert ("azure", "qbscomedia") in by_key
    assert by_key[("azure", "qbscomedia")].origins == {"url"}
    assert ("s3", "qbsco-js") in by_key
    assert by_key[("s3", "qbsco-js")].origins == {"javascript"}

    # Derivation ran (capped at 4 per provider).
    derived = [c for c in candidates if "derived" in c.origins]
    assert derived
    assert all(len(c.name) >= 3 for c in derived)

    # A derived candidate on the same name folds its origin in — one row,
    # two origins (the merge discipline every sibling enforces).
    assert "derived" in s3_row.origins or any(
        c.key != s3_row.key and "derived" in c.origins for c in candidates
    )

    # A non-provider CNAME claimed nothing.
    assert not any("outlook" in c.name for c in candidates)

    # Counts and artifact states are recorded.
    assert counts["cname_claims"] == 2  # the s3 + gcs CNAMEs; outlook matched nothing
    assert counts["url_claims"] == 1
    assert counts["js_claims"] == 1
    assert counts["derived_candidates"] > 0
    assert {row["artifact"] for row in states} >= {"records", "urls", "javascript"}

    # Artifacts written: candidates.jsonl / candidates.txt / report.json
    assert (out / "candidates.jsonl").is_file()
    assert (out / "candidates.txt").is_file()
    report = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert report["counts"]["cname_claims"] == 2


def test_harvest_is_deterministic_across_runs(tmp_path: Path) -> None:
    names, urls = _write_sibling_artifacts(tmp_path)
    first, _, _ = harvest("qbsco.net", output_dir=tmp_path / "a", names_dir=names, urls_dir=urls)
    second, _, _ = harvest("qbsco.net", output_dir=tmp_path / "b", names_dir=names, urls_dir=urls)
    assert [c.to_dict() for c in first] == [c.to_dict() for c in second]


def test_missing_siblings_are_a_state_not_an_error(tmp_path: Path) -> None:
    """Every artifact missing: the apex's own brand token still feeds
    derivation (that is by design — the target is always known), but no claim
    exists and every consulted artifact is recorded as missing."""
    candidates, counts, states = harvest(
        "example.com", output_dir=tmp_path / "out", names_dir=tmp_path / "none1",
        urls_dir=tmp_path / "none2",
    )
    assert all("derived" in c.origins for c in candidates)
    assert counts["cname_claims"] == 0 and counts["url_claims"] == 0
    assert counts["artifacts_missing"] >= 5
    assert all(row["state"] == "missing" for row in states)


def test_no_sibling_input_leaves_explicit_names_only(tmp_path: Path) -> None:
    """Explicit names are probed against every provider whose rules they pass
    (Azure refuses the hyphen — that account cannot exist)."""
    candidates, counts, states = harvest(
        "qbsco.net",
        output_dir=tmp_path / "out",
        names_dir=tmp_path / "none1",
        urls_dir=tmp_path / "none2",
        explicit_names=["acme-backups"],
        use_siblings=False,
    )
    assert {c.name for c in candidates} == {"acme-backups"}
    assert {(c.provider, c.name) for c in candidates} == {("s3", "acme-backups"), ("gcs", "acme-backups")}
    assert counts["explicit_candidates"] == 2
    assert counts["derived_candidates"] == 0
    assert any(row["state"].startswith("skipped") for row in states)


def test_explicit_names_merge_with_harvest(tmp_path: Path) -> None:
    names, urls = _write_sibling_artifacts(tmp_path)
    candidates, counts, _ = harvest(
        "qbsco.net",
        output_dir=tmp_path / "out",
        names_dir=names,
        urls_dir=urls,
        explicit_names=["qbsco-static"],
        max_derived=2,
    )
    row = {c.key: c for c in candidates}[("s3", "qbsco-static")]
    assert row.origins == {"cname", "explicit"}  # one row, two origins


def test_brand_tokens_strip_the_apex_and_drops_www() -> None:
    tokens = brand_tokens("qbsco.net", ["www.qbsco.net", "mail.qbsco.net"])
    assert "qbsco" in tokens
    assert "mail" in tokens
    assert "www" not in tokens


def test_derive_names_respects_the_provider_ceiling() -> None:
    long_token = "a" * 30
    derived = derive_names([long_token], "azure", max_derived=64)
    assert derived == []  # every shape exceeds Azure's 24-char ceiling


def test_derive_names_caps_the_vocabulary() -> None:
    derived = derive_names(["acme"], "s3", max_derived=5)
    assert len(derived) == 5


def test_generic_tokens_are_marked_not_distinctive() -> None:
    from service.recon_pipeline.pipelines.cloud_resource.seeds import token_is_distinctive

    assert token_is_distinctive("qbsco")
    assert token_is_distinctive("ocac")
    assert not token_is_distinctive("mail")
    assert not token_is_distinctive("cdn")


def test_derive_names_flags_generic_and_distinctive_tokens() -> None:
    derived = dict(derive_names(["mail", "qbsco"], "s3", max_derived=64))
    assert derived["mail-app"] is False  # generic: could be anyone's bucket
    assert derived["qbsco-app"] is True  # distinctive: the target's namespace


# --------------------------------------------------------------------------- #
# verify: the response matrices
# --------------------------------------------------------------------------- #


def _result(
    status: int | None, body: str = "", headers: dict | None = None, error: str = ""
) -> FetchResult:
    return FetchResult(status=status, text=body, headers=headers or {}, error=error)


def test_s3_matrix() -> None:
    assert classify("s3", _result(200, "<ListBucketResult>")) == (STATE_OPEN, "listable")
    assert classify("s3", _result(200, "hello")) == (STATE_OPEN, "")
    assert classify("s3", _result(403, "<Code>AccessDenied</Code>")) == (STATE_AUTH, "accessdenied")
    assert classify("s3", _result(404, "<Code>NoSuchBucket</Code>")) == (STATE_DANGLING, "nosuchbucket")
    assert classify(
        "s3", _result(301, "", {"Location": "acme.s3.eu-west-1.amazonaws.com"})
    ) == (STATE_EXISTS_OTHER_REGION, "acme.s3.eu-west-1.amazonaws.com")
    assert classify(
        "s3", _result(301, "", {"x-amz-bucket-region": "eu-west-1"})
    ) == (STATE_EXISTS_OTHER_REGION, "eu-west-1")
    assert classify("s3", _result(301)) == (STATE_EXISTS_OTHER_REGION, "301")
    assert classify("s3", _result(400, "<Code>AuthorizationHeaderMalformed</Code>"
                                     "<Region>eu-west-1</Region>")) == (
        STATE_EXISTS_OTHER_REGION, "eu-west-1")
    assert classify("s3", _result(500, "<Code>InternalError</Code>")) == (STATE_UNAVAILABLE, "internalerror")
    assert classify("s3", _result(None, error="refused"))[0] == STATE_UNAVAILABLE


def test_azure_matrix_keys_on_the_body_code() -> None:
    assert classify("azure", _result(403, "<Code>PublicAccessNotPermitted</Code>")) == (
        STATE_AUTH, "publicaccessnotpermitted")
    # THE quirk: absent account = 409, not 404.
    assert classify("azure", _result(409, "<Code>AccountNotFound</Code>")) == (STATE_DANGLING, "accountnotfound")
    assert classify("azure", _result(404, "<Code>ContainerNotFound</Code>")) == (STATE_DANGLING, "containernotfound")
    assert classify("azure", _result(200, "blob-content")) == (STATE_OPEN, "")
    # Unclassified Azure answers are an honest unknown.
    assert classify("azure", _result(418, "<Code>Teapot</Code>"))[0] == STATE_UNAVAILABLE


def test_gcs_matrix_handles_both_dialects() -> None:
    assert classify("gcs", _result(404, "<Code>NoSuchBucket</Code>")) == (STATE_DANGLING, "nosuchbucket")
    assert classify("gcs", _result(404, '{"error": {"reason": "notFound"}}')) == (STATE_DANGLING, "notfound")
    assert classify("gcs", _result(403, "denied")) == (STATE_AUTH, "")
    assert classify("gcs", _result(400, '<Code>InvalidArgument</Code>')) == (STATE_ABSENT, "invalidargument")


def test_every_unavailable_verdict_is_not_a_negative() -> None:
    for provider in ("s3", "azure", "gcs"):
        state, _ = classify(provider, _result(None, error="connect timeout"))
        assert state == STATE_UNAVAILABLE


def test_evidence_class_precedence() -> None:
    cname = Candidate("a", "s3", origins={"cname", "url"})
    observed = Candidate("b", "s3", origins={"url"})
    explicit = Candidate("c", "s3", origins={"explicit"})
    derived = Candidate("d", "s3", origins={"derived"})
    generic = Candidate("e", "s3", origins={"derived"}, distinctive=False)
    assert evidence_class_for(cname) == verify.EVIDENCE_CNAME_CLAIMED
    assert evidence_class_for(observed) == verify.EVIDENCE_OBSERVED
    assert evidence_class_for(explicit) == verify.EVIDENCE_EXPLICIT
    assert evidence_class_for(derived) == verify.EVIDENCE_DERIVED
    assert evidence_class_for(generic) == verify.EVIDENCE_DERIVED_GENERIC


def test_probe_candidates_one_get_per_candidate_and_the_cap_bites() -> None:
    probes: list[str] = []

    def fetcher(url: str, **kwargs) -> FetchResult:  # noqa: ANN003
        probes.append(url)
        return _result(404, "<Code>NoSuchBucket</Code>")

    candidates = [
        Candidate(f"name-{index}", "s3", origins={"derived"}) for index in range(5)
    ]
    verdicts, counts = verify.probe_candidates(candidates, fetcher=fetcher, max_probes=3)
    assert len(probes) == 3
    assert len(verdicts) == 3
    assert counts["truncated"] == 2
    assert counts[STATE_DANGLING] == 3
    assert counts["probed"] == 3


def test_probe_candidates_skips_disabled_providers() -> None:
    def fetcher(url: str, **kwargs) -> FetchResult:  # noqa: ANN003
        raise AssertionError("no probe should fire")

    candidates = [Candidate("acme", "digitalocean", origins={"derived"})]
    verdicts, counts = verify.probe_candidates(candidates, fetcher=fetcher)
    assert verdicts == []
    assert counts["skipped_provider_disabled"] == 1


# --------------------------------------------------------------------------- #
# emit: the artifact contract
# --------------------------------------------------------------------------- #


def _verdict(name: str, provider: str, state: str, evidence: str = "derived") -> verify.Verdict:
    return verify.Verdict(
        name=name,
        provider=provider,
        state=state,
        code="",
        probe_url=f"https://{name}.example/",
        evidence_class=evidence,
        origins=["derived"],
        sources=["brand-shapes"],
        http_status=200 if state == STATE_OPEN else 404,
        probed_at="2026-09-18T00:00:00+00:00",
    )


def test_bucket_rows_keep_only_existing_states(tmp_path: Path) -> None:
    verdicts = [
        _verdict("open-one", "s3", STATE_OPEN, evidence="cname-claimed"),
        _verdict("auth-one", "s3", STATE_AUTH),
        _verdict("gone", "s3", STATE_DANGLING),
        _verdict("elsewhere", "s3", STATE_EXISTS_OTHER_REGION),
    ]
    rows = emit.bucket_rows(verdicts)
    assert [row["name"] for row in rows] == ["auth-one", "elsewhere", "open-one"]


def test_dangling_rows_need_a_cname_claim(tmp_path: Path) -> None:
    verdicts = [
        _verdict("claimed", "s3", STATE_DANGLING, evidence="cname-claimed"),
        _verdict("invented", "s3", STATE_DANGLING, evidence="derived"),
    ]
    rows = emit.dangling_rows(verdicts)
    assert [row["name"] for row in rows] == ["claimed"]


def test_probe_report_is_honest_about_unavailable() -> None:
    verdicts = [
        _verdict("fine", "s3", STATE_OPEN),
        _verdict("dead", "s3", STATE_UNAVAILABLE),
    ]
    report = emit.probe_report("example.com", verdicts, {"probed": 2}, 1.0)
    assert report["ok"] is False
    assert report["by_state"] == {STATE_OPEN: 1, STATE_UNAVAILABLE: 1}


def test_emission_is_deterministic(tmp_path: Path) -> None:
    verdicts = [_verdict("b", "s3", STATE_AUTH), _verdict("a", "gcs", STATE_OPEN)]
    first = tmp_path / "a.jsonl"
    second = tmp_path / "b.jsonl"
    emit.write_jsonl(first, emit.bucket_rows(verdicts))
    emit.write_jsonl(second, emit.bucket_rows(verdicts))
    assert first.read_bytes() == second.read_bytes()


# --------------------------------------------------------------------------- #
# main: the orchestrator
# --------------------------------------------------------------------------- #


def _dead_fetcher(url: str, **kwargs) -> FetchResult:  # noqa: ANN003
    return _result(404, "<Code>NoSuchBucket</Code>")


def test_run_pipeline_harvest_then_probe_end_to_end(tmp_path: Path) -> None:
    names, urls = _write_sibling_artifacts(tmp_path)
    report = run_pipeline(
        "qbsco.net",
        stages=["harvest", "probe"],
        output_dir=tmp_path / "out",
        passive_output_dir=tmp_path / "passive",
        names_dir=names,
        urls_dir=urls,
        max_derived=3,
        fetcher=_dead_fetcher,
    )
    assert report.ok
    # Every candidate in the artifact was probed exactly once.
    candidates_rows = (
        (tmp_path / "passive" / "candidates.jsonl").read_text(encoding="utf-8").splitlines()
    )
    assert report.counts["probed"] == len([row for row in candidates_rows if row.strip()])
    assert (tmp_path / "out" / "verdicts.jsonl").is_file()
    assert (tmp_path / "out" / "buckets.jsonl").is_file()
    assert (tmp_path / "out" / "dangling.jsonl").is_file()
    assert (tmp_path / "out" / "report.json").is_file()
    # A dangling CNAME claim landed in dangling.jsonl (404 fetcher + CNAMEs).
    dangling = [
        json.loads(line)
        for line in (tmp_path / "out" / "dangling.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert any(row["name"] == "qbsco-static" for row in dangling)
    assert all(row["evidence_class"] == "cname-claimed" for row in dangling)


def test_probe_reuses_the_existing_candidate_artifact(tmp_path: Path) -> None:
    names, urls = _write_sibling_artifacts(tmp_path)
    passive = tmp_path / "passive"
    harvest("qbsco.net", output_dir=passive, names_dir=names, urls_dir=urls, max_derived=1)
    report = run_pipeline(
        "qbsco.net",
        stages=["probe"],
        output_dir=tmp_path / "out",
        passive_output_dir=passive,
        names_dir=names,
        urls_dir=urls,
        fetcher=_dead_fetcher,
    )
    assert any("re-used" in note for note in report.notes)
    assert report.counts["probed"] > 0


def test_probe_runs_the_harvest_first_when_candidates_are_absent(tmp_path: Path) -> None:
    names, urls = _write_sibling_artifacts(tmp_path)
    report = run_pipeline(
        "qbsco.net",
        stages=["probe"],
        output_dir=tmp_path / "out",
        passive_output_dir=tmp_path / "passive",
        names_dir=names,
        urls_dir=urls,
        max_derived=1,
        fetcher=_dead_fetcher,
    )
    assert any("harvest first" in note for note in report.notes)
    assert report.counts["probed"] > 0


def test_unavailable_probes_fail_the_run(tmp_path: Path) -> None:
    def dead(url: str, **kwargs) -> FetchResult:  # noqa: ANN003
        return _result(None, error="refused")

    names, urls = _write_sibling_artifacts(tmp_path)
    report = run_pipeline(
        "qbsco.net",
        stages=["harvest", "probe"],
        output_dir=tmp_path / "out",
        passive_output_dir=tmp_path / "passive",
        names_dir=names,
        urls_dir=urls,
        max_derived=1,
        fetcher=dead,
    )
    assert not report.ok
    assert report.counts["unavailable"] == report.counts["probed"]


def test_unknown_stage_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="unknown stage"):
        run_pipeline(
            "example.com",
            stages=["nonexistent"],
            output_dir=tmp_path,
            passive_output_dir=tmp_path,
        )


def test_bad_target_is_refused() -> None:
    with pytest.raises(ValueError, match="not a valid domain"):
        run_pipeline("not a domain", output_dir=Path("."), passive_output_dir=Path("."))


# --------------------------------------------------------------------------- #
# contract: registry acceptance
# --------------------------------------------------------------------------- #


def test_the_contract_satisfies_the_platform() -> None:
    from service.recon_pipeline.pipelines.cloud_resource.contract import MANIFEST, PIPELINE

    assert MANIFEST.name == "cloud_resource"
    assert "CloudResource" in MANIFEST.asset_types
    assert MANIFEST.passive_only is True
    assert MANIFEST.stage_names() == ("harvest", "probe")
    assert "subdomain_domain_wildcards" in MANIFEST.consumes
    assert "url_endpoint" in MANIFEST.consumes
    # The pipeline object satisfies the platform's protocol.
    from service.recon_pipeline.platform.contract import Pipeline

    assert isinstance(PIPELINE, Pipeline)


def test_the_registry_discovers_the_pipeline() -> None:
    from service.recon_pipeline.platform.registry import Registry

    registry = Registry.discover()
    assert "cloud_resource" in registry.names()
    manifest = registry.get("cloud_resource").manifest
    assert manifest.name == "cloud_resource"


def test_the_pipeline_runs_a_stage_through_the_platform_contract(tmp_path: Path) -> None:
    from service.recon_pipeline.platform.contract import RunContext
    from service.recon_pipeline.pipelines.cloud_resource.contract import PIPELINE

    context = RunContext(
        target="qbsco.net",
        options={"output_dir": str(tmp_path / "out")},
        output_dir=tmp_path,
    )
    row = PIPELINE.run("harvest", context)
    assert row["ok"] is True
    assert "candidates" in row["outputs"]


def test_graph_normalize_consumes_the_new_pipeline_after_its_vocabulary_grows() -> None:
    """A forward-looking pin: the model's vocabulary has no cloudresource kind
    yet, and this test documents exactly what changes when it does."""
    from service.recon_pipeline.pipelines.graph_normalize.contract import MANIFEST as GN

    assert "cloud_resource" not in GN.consumes  # P2: wire when a kind exists


# --------------------------------------------------------------------------- #
# the live-run lessons (2026-09-18, qbsco.net) — pinned so they stay learned
# --------------------------------------------------------------------------- #


def test_azure_nxdomain_with_corroboration_is_an_absence_fact() -> None:
    """Azure has no wildcard DNS: a nonexistent account does not resolve.
    When a sibling S3/GCS probe answered this run (network provably up), the
    resolution failure is an absence fact, not a source failure."""
    nxdomain = _result(None, error="NameResolutionError: getaddrinfo failed")
    assert classify("azure", nxdomain, corroborated=True) == (
        verify.STATE_NXDOMAIN_ABSENT, nxdomain.error)
    # Without corroboration the honest answer is still 'unavailable'.
    assert classify("azure", nxdomain, corroborated=False)[0] == STATE_UNAVAILABLE
    # And a non-resolution transport failure never becomes an absence fact.
    refused = _result(None, error="ConnectionError: refused")
    assert classify("azure", refused, corroborated=True)[0] == STATE_UNAVAILABLE


def test_an_azure_nxdomain_is_counted_separately_and_fails_nothing() -> None:
    """End to end: an S3 404 answering first corroborates the network, so the
    later Azure NXDOMAINs are absence facts and the run stays ok=True."""

    def fetcher(url: str, **kwargs) -> FetchResult:  # noqa: ANN003
        if ".blob.core.windows.net" in url:
            return _result(None, error="NameResolutionError: getaddrinfo failed")
        return _result(404, "<Code>NoSuchBucket</Code>")

    candidates = [
        Candidate("acme", "s3", origins={"derived"}),
        Candidate("acme", "azure", origins={"derived"}),
    ]
    verdicts, counts = verify.probe_candidates(candidates, fetcher=fetcher)
    assert counts[verify.STATE_NXDOMAIN_ABSENT] == 1
    assert counts[STATE_UNAVAILABLE] == 0
    assert verdicts[1].state == verify.STATE_NXDOMAIN_ABSENT


def test_dangling_rows_accept_the_azure_nxdomain_dialect() -> None:
    verdict = _verdict("claimed", "azure", verify.STATE_NXDOMAIN_ABSENT, evidence="cname-claimed")
    rows = emit.dangling_rows([verdict])
    assert [row["name"] for row in rows] == ["claimed"]


def test_generic_derived_buckets_carry_the_weak_evidence_class(tmp_path: Path) -> None:
    """The mail-app lesson: a 200 on a generic-token name must arrive in the
    artifacts marked as possibly-someone-else's bucket."""
    verdicts = [_verdict("mail-app", "gcs", STATE_OPEN, evidence=verify.EVIDENCE_DERIVED_GENERIC)]
    rows = emit.bucket_rows(verdicts)
    assert rows[0]["evidence_class"] == verify.EVIDENCE_DERIVED_GENERIC
