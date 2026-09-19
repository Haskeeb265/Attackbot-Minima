"""Tests for S25 — the subdomain-takeover detector.

The rules the detector lives by, each pinned here: only fingerprint-matched
claims are probed (one GET each, nothing else is ever requested); the marker
decides and the status corroborates; a transport failure is an honest
``inconclusive``, never a guess; and the policy gate decides whether a
vulnerable finding scores or stays informational — with the gate's position
always visible in the run notes.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from service.recon_pipeline.pipelines.cloud_resource import main as cloud_main
from service.recon_pipeline.pipelines.cloud_resource import takeover
from service.recon_pipeline.pipelines.cloud_resource.verify import FetchResult


# --------------------------------------------------------------------------- #
# the fingerprint list
# --------------------------------------------------------------------------- #


def test_fingerprints_match_longest_suffix_first() -> None:
    assert takeover.fingerprint_for("acme.github.io")["suffix"] == "github.io"
    # A subdomain chain still matches the provider suffix.
    assert takeover.fingerprint_for("deep.sub.acme.s3.amazonaws.com")["suffix"] == "s3.amazonaws.com"
    # Vercel and Cloudflare Pages share a marker family but not a suffix.
    assert takeover.fingerprint_for("acme.vercel.app")["suffix"] == "vercel.app"
    assert takeover.fingerprint_for("acme.pages.dev")["suffix"] == "pages.dev"


def test_a_claim_outside_the_list_matches_nothing() -> None:
    assert takeover.fingerprint_for("random.example.com") is None
    assert takeover.fingerprint_for("outlook.com") is None


# --------------------------------------------------------------------------- #
# classification: the marker decides, the status corroborates
# --------------------------------------------------------------------------- #


def _entry(suffix: str) -> dict[str, object]:
    entry = takeover.fingerprint_for(f"acme.{suffix}")
    assert entry is not None
    return entry


def test_an_unclaimed_page_is_the_vulnerable_state() -> None:
    result = FetchResult(status=404, text="There isn't a GitHub Pages site here.")
    assert takeover.classify_probe(result, _entry("github.io")) == takeover.STATE_VULNERABLE


def test_a_live_page_is_claimed_even_at_the_expected_status() -> None:
    result = FetchResult(status=404, text="<html>custom 404 page</html>")
    assert takeover.classify_probe(result, _entry("github.io")) == takeover.STATE_CLAIMED


def test_a_wrong_status_is_claimed_without_reading_the_body() -> None:
    # A 200 with the marker text is a live site that *quotes* the marker —
    # the status must rule first.
    result = FetchResult(status=200, text="There isn't a GitHub Pages site here.")
    assert takeover.classify_probe(result, _entry("github.io")) == takeover.STATE_CLAIMED


def test_a_transport_failure_is_inconclusive_never_a_guess() -> None:
    result = FetchResult(status=None, error="connection timed out")
    assert takeover.classify_probe(result, _entry("github.io")) == takeover.STATE_INCONCLUSIVE


# --------------------------------------------------------------------------- #
# claims extraction
# --------------------------------------------------------------------------- #


def test_claims_are_claimant_target_pairs_from_the_records_stream() -> None:
    rows = [
        {"host": "A.Test", "cname": ["X.GitHub.IO", "unknown.test"]},
        {"host": "b.test", "cname": ["y.herokuapp.com"]},
        {"host": "b.test", "cname": ["y.herokuapp.com"]},  # duplicate folds
    ]
    pairs = takeover.claims_from_records(rows)
    assert pairs == [
        ("a.test", "x.github.io"),
        ("a.test", "unknown.test"),
        ("b.test", "y.herokuapp.com"),
    ]


# --------------------------------------------------------------------------- #
# the run: one GET per fingerprint-matched claim, nothing else
# --------------------------------------------------------------------------- #


def test_run_probes_only_fingerprint_matched_claims() -> None:
    probed: list[str] = []

    def fetcher(url: str) -> FetchResult:
        probed.append(url)
        if "github.io" in url:
            return FetchResult(status=404, text="There isn't a GitHub Pages site here.")
        return FetchResult(status=200, text="hello")

    rows = [
        {"host": "docs.test", "cname": ["docs-site.github.io", "unrelated.test"]},
        {"host": "legacy.test", "cname": ["old.herokuapp.com"]},
    ]
    findings, counts = takeover.run_takeover(rows, fetcher=fetcher)

    # Exactly two GETs: the fingerprint-matched claims. The unmatched target
    # was never requested.
    assert len(probed) == 2
    assert counts["claims"] == 3
    assert counts["no_fingerprint"] == 1
    assert counts["fingerprint_matched"] == 2
    assert counts[takeover.STATE_VULNERABLE] == 1
    assert counts[takeover.STATE_CLAIMED] == 1

    vulnerable = [f for f in findings if f.vulnerable]
    assert len(vulnerable) == 1
    assert vulnerable[0].claimant == "docs.test"
    assert vulnerable[0].provider_suffix == "github.io"


def test_informational_policy_records_but_does_not_score(tmp_path: Path) -> None:
    def fetcher(url: str) -> FetchResult:
        return FetchResult(status=404, text="No such app")

    findings, counts = takeover.run_takeover(
        [{"host": "old.test", "cname": ["gone.herokuapp.com"]}],
        fetcher=fetcher,
        policy=takeover.POLICY_INFORMATIONAL,
        output_dir=tmp_path,
    )

    assert counts["scored"] == 0
    assert counts["informational"] == 1
    assert findings[0].policy == takeover.POLICY_INFORMATIONAL
    # The artifact exists and carries the gate's decision per finding.
    rows = [json.loads(line) for line in (tmp_path / "takeover.jsonl").read_text(encoding="utf-8").splitlines()]
    assert rows[0]["policy"] == "informational"
    assert rows[0]["state"] == "takeover_vulnerable"


def test_enforced_policy_scores_the_finding(tmp_path: Path) -> None:
    def fetcher(url: str) -> FetchResult:
        return FetchResult(status=404, text="No such app")

    _, counts = takeover.run_takeover(
        [{"host": "old.test", "cname": ["gone.herokuapp.com"]}],
        fetcher=fetcher,
        policy=takeover.POLICY_ENFORCED,
        output_dir=tmp_path,
    )
    assert counts["scored"] == 1
    assert counts["informational"] == 0


# --------------------------------------------------------------------------- #
# the stage, end to end through run_pipeline
# --------------------------------------------------------------------------- #


def test_takeover_stage_runs_from_the_names_records(tmp_path: Path) -> None:
    names_dir = tmp_path / "names"
    (names_dir / "active" / "output").mkdir(parents=True)
    (names_dir / "active" / "output" / "records.jsonl").write_text(
        json.dumps({"host": "old.test", "cname": ["gone.herokuapp.com"]}) + "\n",
        encoding="utf-8",
    )

    def fetcher(url: str) -> FetchResult:
        return FetchResult(status=404, text="No such app")

    report = cloud_main.run_pipeline(
        "test",
        stages=("takeover",),
        output_dir=tmp_path / "out",
        names_dir=names_dir,
        fetcher=fetcher,
    )

    assert report.counts["claims"] == 1
    assert report.counts[takeover.STATE_VULNERABLE] == 1
    # The gate's position is in the notes — an informational finding is named
    # as such, never silently absorbed.
    assert any("policy gate set to 'informational'" in note for note in report.notes)
    assert (tmp_path / "out" / "takeover.jsonl").is_file()


def test_takeover_stage_with_no_records_is_a_state_not_a_failure(tmp_path: Path) -> None:
    empty = tmp_path / "names"  # exists with no records artifact at all
    empty.mkdir()

    report = cloud_main.run_pipeline(
        "test",
        stages=("takeover",),
        output_dir=tmp_path / "out",
        names_dir=empty,
        fetcher=lambda url: FetchResult(status=200, text="x"),
    )
    assert report.counts.get("claims", 0) == 0
    assert report.ok is True
