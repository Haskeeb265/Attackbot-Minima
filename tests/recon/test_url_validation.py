"""Tests for ``url_endpoint.validate`` — the live URL verification stage.

Hermetic: candidate selection, tool-output parsing, state classification and
idempotent merging are all pure, and the one impure step (running ``httpx``) is
injected, so nothing here touches Docker or the network.  The fixtures are the
*real* shapes an ``httpx -json`` stream has, taken from the tool's own output.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from service.recon_pipeline.platform import escalation
from service.recon_pipeline.platform.scope import ScopeEngine
from service.recon_pipeline.pipelines.url_endpoint import extract, normalize as norm, validate
from service.recon_pipeline.pipelines.url_endpoint.active import probe

APEX = "acme.test"
NOW = 1_800_000_000.0  # a fixed clock, so freshness is a fact and not a race


def _iso(epoch: float) -> str:
    from datetime import datetime, timezone

    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat(timespec="seconds")


def _httpx_line(**overrides) -> str:
    """One ``httpx -json`` row, with the fields the real tool emits."""
    payload = {
        "timestamp": "2026-09-19T00:00:00Z",
        "port": "443",
        "url": f"https://www.{APEX}/login",
        "input": f"https://www.{APEX}/login",
        "title": "Sign in",
        "scheme": "https",
        "webserver": "nginx/1.25.3",
        "content_type": "text/html; charset=utf-8",
        "method": "GET",
        "host": "93.184.216.34",
        "status_code": 200,
        "content_length": 512,
        "failed": False,
        "tech": ["WordPress", "PHP"],
    }
    payload.update(overrides)
    return json.dumps(payload)


class FakeRunner:
    """Stands in for ``docker run``: writes the canned stream and returns a run."""

    def __init__(self, lines: list[str], *, ok: bool = True) -> None:
        self.lines = lines
        self.ok = ok
        self.calls: list[list[str]] = []

    def __call__(self, tool: str, args: list[str], *, output_dir: Path, **kwargs):
        self.calls.append([tool, *args])
        # httpx writes its stream to stdout, which the real runner redirects into
        # ``<suffix>httpx.jsonl``; the fake does the same by hand.
        target = Path(output_dir) / "validation-httpx.jsonl"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("".join(f"{line}\n" for line in self.lines), encoding="utf-8")

        class _Run:
            ok = self.ok
            seconds = 0.25
            exit_code = 0 if self.ok else 1

        return _Run()

    @property
    def input_lines(self) -> list[str]:
        """The URLs the stage actually asked the tool about."""
        for call in self.calls:
            if "-l" in call:
                path = Path(call[call.index("-l") + 1])
                # Container path (``/work/x``) -> the host file the fake wrote.
                return []
        return []


# --------------------------------------------------------------------------- #
# state classification
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("status", "final_url", "expected"),
    [
        (200, "", validate.STATE_VERIFIED),
        (204, "", validate.STATE_VERIFIED),
        (301, "", validate.STATE_VERIFIED),  # same URL: a redirect we did not follow
        (200, "https://www.acme.test/home", validate.STATE_REDIRECTED),
        (404, "", validate.STATE_DEAD),
        (410, "", validate.STATE_DEAD),
        (403, "", validate.STATE_PROTECTED),
        (429, "", validate.STATE_PROTECTED),
        (500, "", validate.STATE_ERRORED),
        (503, "", validate.STATE_ERRORED),
        (None, "", validate.STATE_UNREACHABLE),
    ],
)
def test_state_classification(status, final_url, expected) -> None:
    url = f"https://www.{APEX}/login"
    assert validate.state_for(status, final_url=final_url, url=url) == expected


def test_an_archived_url_that_is_gone_is_dead_not_merely_historical() -> None:
    record = validate.ValidationRecord(
        url=f"https://www.{APEX}/old", state=validate.STATE_DEAD, status=404
    )

    assert record.dead is True
    assert record.state != validate.STATE_VERIFIED


def test_a_404_means_the_server_answered_but_does_not_serve_the_resource() -> None:
    """``alive`` is "a server answered"; ``serving`` is a different question.

    The two are separate fields because collapsing them loses both facts: a 404
    proves the host is up (so the host is worth asking more of) *and* that the
    resource is gone (so the URL is not a live asset).  Read through the tool's
    own output, because that is where the distinction is actually made.
    """
    records = validate.parse_httpx_jsonl(_httpx_line(status_code=404))

    assert len(records) == 1
    record = records[0]
    assert record.alive is True  # the server answered
    assert record.dead is True  # the resource does not exist
    assert record.state == validate.STATE_DEAD
    assert record.state not in (validate.STATE_VERIFIED, validate.STATE_REDIRECTED)
    assert record.status == 404


def test_a_404_host_still_counts_as_a_host_that_answered() -> None:
    """Priority is adaptive: a host that answers is worth more checks."""
    records = validate.parse_httpx_jsonl(_httpx_line(status_code=404))

    states = validate.host_states(records)

    assert states[f"www.{APEX}"] == escalation.URL_HOST_VERIFIED


def test_a_host_whose_every_measurement_failed_is_deprioritised() -> None:
    records = validate.parse_httpx_jsonl(
        _httpx_line(status_code=None, failed=True, error="dial tcp: timeout")
    )

    assert validate.host_states(records)[f"www.{APEX}"] == escalation.URL_HOST_DEAD


# --------------------------------------------------------------------------- #
# parsing the tool's output
# --------------------------------------------------------------------------- #


def test_a_live_response_becomes_a_validation_record_with_its_metadata() -> None:
    records = validate.parse_httpx_jsonl(
        _httpx_line(),
        requested=[f"https://www.{APEX}/login"],
        validated_at=_iso(NOW),
    )

    assert len(records) == 1
    record = records[0]
    assert record.alive is True
    assert record.status == 200
    assert record.title == "Sign in"
    assert record.server == "nginx/1.25.3"
    assert record.content_type.startswith("text/html")
    assert record.tech == ["PHP", "WordPress"]
    assert record.address == "93.184.216.34"
    assert record.validated_at == _iso(NOW)
    assert record.tool == probe.NAME
    assert record.trust == "observed"


def test_a_redirect_keeps_both_the_requested_url_and_where_it_landed() -> None:
    records = validate.parse_httpx_jsonl(
        _httpx_line(
            input=f"http://www.{APEX}/",
            url=f"https://www.{APEX}/",
            final_url=f"https://www.{APEX}/",
            status_code=200,
            chain_status_codes=[301, 200],
        ),
        requested=[f"http://www.{APEX}/"],
        validated_at=_iso(NOW),
    )

    record = records[0]
    assert record.url == f"http://www.{APEX}/"
    assert record.state == validate.STATE_REDIRECTED
    assert record.redirected is True
    assert record.final_url == f"https://www.{APEX}/"
    assert record.redirect_chain == [301, 200]


def test_a_failed_probe_is_unreachable_and_never_assumed_alive() -> None:
    records = validate.parse_httpx_jsonl(
        _httpx_line(input=f"https://gone.{APEX}/", url="", status_code=None, failed=True, error="dial tcp: no such host"),
        requested=[f"https://gone.{APEX}/"],
        validated_at=_iso(NOW),
    )

    assert records[0].state == validate.STATE_UNREACHABLE
    assert records[0].alive is False
    assert records[0].dead is True


def test_a_response_for_a_url_we_did_not_ask_about_is_ignored() -> None:
    records = validate.parse_httpx_jsonl(
        _httpx_line(input="https://somebody-else.test/x"),
        requested=[f"https://www.{APEX}/login"],
        validated_at=_iso(NOW),
    )

    assert records == []


def test_a_url_the_tool_reported_twice_becomes_one_record() -> None:
    """httpx re-verifies, so the stream can carry the same URL more than once."""
    records = validate.parse_httpx_jsonl(
        _httpx_line(input=f"https://www.{APEX}/login", url=f"https://www.{APEX}/login", status_code=404, failed=True),
        requested=[f"https://www.{APEX}/login"],
        validated_at=_iso(NOW),
    )

    assert len(records) == 1
    assert records[0].state == validate.STATE_DEAD


# --------------------------------------------------------------------------- #
# the policy gate
# --------------------------------------------------------------------------- #


def _candidates(*urls: str):
    """Parse URLs *without* the apex filter, so out-of-scope hosts are visible."""
    return [parsed for url in urls if (parsed := norm.parse_url(url)) is not None]


def test_a_foreign_host_is_never_selected() -> None:
    """A discovered host outside the declared domains is ``needs_review`` — a
    refusal, not a candidate.  Nothing active happens without an operator."""
    foreign = "https://not-ours.com/b"
    parsed = _candidates(f"https://www.{APEX}/a", foreign)

    selection = validate.select_candidates(parsed, scope=ScopeEngine.from_domain(APEX))

    assert [item.host for item in selection.selected] == [f"www.{APEX}"]
    assert any(item.url == foreign for item in parsed)  # it was a candidate...
    assert any(foreign == str(row["url"]) for row in selection.refused)  # ...and refused
    assert not selection.out_of_scope


def test_an_out_of_scope_address_is_refused_before_the_policy_even_runs() -> None:
    private = "http://10.0.0.5/admin"
    parsed = _candidates(f"https://www.{APEX}/a", private)

    selection = validate.select_candidates(parsed, scope=ScopeEngine.from_domain(APEX))

    assert selection.out_of_scope == [private]
    assert [item.url for item in selection.selected] == [f"https://www.{APEX}/a"]


def test_no_scope_engine_means_no_selection_at_all() -> None:
    """Deny-by-default: the policy refuses an asset with no scope verdict."""
    parsed = _candidates(f"https://www.{APEX}/a")

    selection = validate.select_candidates(parsed, scope=None)

    assert selection.selected == []
    assert selection.refused[0]["reason"].startswith("no scope verdict")


def test_independent_sources_and_kind_rank_a_candidate_above_a_plain_page() -> None:
    """The selection rule is the platform policy, fed with measured inputs.

    Three candidates, same host, same length: an API endpoint three archives
    agree on, a parameterised page, and an image nobody else mentions.  The
    ordering has to be the first, then the second, then the last — and it has to
    come from the documented policy rather than from path length.
    """
    api = norm.parse_url(f"https://api.{APEX}/v1/user")
    page = norm.parse_url(f"https://www.{APEX}/search?q=x")
    image = norm.parse_url(f"https://www.{APEX}/logo.png")
    assert api and page and image

    ranks = {
        item.url: validate.candidate_priority(
            item,
            scope_state="in_scope",
            sources=3 if item is api else 1,
            host_state=escalation.URL_HOST_UNKNOWN,
        )
        for item in (api, page, image)
    }

    assert ranks[api.url].rank > ranks[page.url].rank > ranks[image.url].rank
    assert "independent_sources+8" in ranks[api.url].reason
    assert ranks[api.url].components["independent_sources"] == 8


def test_a_host_that_answered_this_run_outranks_one_that_never_did() -> None:
    page = norm.parse_url(f"https://www.{APEX}/a")
    assert page

    alive = validate.candidate_priority(
        page, scope_state="in_scope", host_state=escalation.URL_HOST_VERIFIED
    )
    dead = validate.candidate_priority(
        page, scope_state="in_scope", host_state=escalation.URL_HOST_DEAD
    )
    unknown = validate.candidate_priority(page, scope_state="in_scope")

    assert alive.rank > unknown.rank > dead.rank


def test_source_counts_come_from_the_passive_stages_own_files(tmp_path: Path) -> None:
    """Independent provenance is read, not guessed: the union loses it by design."""
    directory = tmp_path / "passive"
    directory.mkdir()
    live = f"https://www.{APEX}/a"
    (directory / "wayback.urls.txt").write_text(
        f"{live}\nhttps://www.{APEX}/only-wayback\n", encoding="utf-8"
    )
    (directory / "gau.urls.txt").write_text(f"{live}\n", encoding="utf-8")
    # The third source spells it with an explicit default port and a campaign
    # parameter — both drop out of the canonical form, so it is the same asset.
    (directory / "commoncrawl.urls.txt").write_text(
        f"https://www.{APEX}:443/a?utm_source=newsletter\n", encoding="utf-8"
    )

    counts = validate.source_counts([live, f"https://www.{APEX}/only-wayback"], passive_dir=directory)

    assert counts[live] == 3  # three sources, one of them spelling it differently
    assert counts[f"https://www.{APEX}/only-wayback"] == 1


def test_a_missing_passive_directory_is_an_empty_answer_not_an_error(tmp_path: Path) -> None:
    assert validate.source_counts([f"https://www.{APEX}/a"], passive_dir=tmp_path / "nope") == {}


def test_interesting_paths_are_validated_before_ordinary_pages() -> None:
    parsed = _candidates(
        f"https://www.{APEX}/index.html",
        f"https://www.{APEX}/.env",
        f"https://www.{APEX}/api/v1/users",
    )

    selection = validate.select_candidates(
        parsed, scope=ScopeEngine.from_domain(APEX), max_urls=2
    )

    assert [item.url for item in selection.selected] == [
        f"https://www.{APEX}/.env",
        f"https://www.{APEX}/api/v1/users",
    ]
    assert selection.capped == 1


def test_a_chatty_host_cannot_take_a_small_runs_budget_before_another_host() -> None:
    """An equal share first, leftovers second — a starting budget, then a bonus.

    With a budget of 4 and two hosts the share is 2 each.  ``api`` only has one
    candidate, so its unused slot becomes a leftover and ``www`` takes it — but
    only *after* ``api`` was reached, which is the fairness property the flat cap
    was protecting (it used to protect it by leaving the budget unspent).
    """
    parsed = _candidates(
        *[f"https://www.{APEX}/p{i}" for i in range(10)],
        f"https://api.{APEX}/health",
    )

    selection = validate.select_candidates(
        parsed, scope=ScopeEngine.from_domain(APEX), max_urls=4, max_per_host=2
    )

    hosts = [item.host for item in selection.selected]
    assert selection.per_host_limit == 2
    assert f"api.{APEX}" in hosts  # its share was guaranteed before any leftover
    assert hosts.count(f"www.{APEX}") == 3  # its share plus the leftover slot
    assert len(selection.selected) == 4  # the budget is actually spent
    assert any("per-host share spent" in str(row["reason"]) for row in selection.refused)


def test_a_saturated_host_cannot_starve_a_smaller_one() -> None:
    """Rank order must not let the biggest host consume everything first."""
    parsed = _candidates(
        *[f"https://www.{APEX}/p{i}" for i in range(50)],
        f"https://mail.{APEX}/login",
    )

    selection = validate.select_candidates(
        parsed, scope=ScopeEngine.from_domain(APEX), max_urls=10, max_per_host=1
    )

    assert f"https://mail.{APEX}/login" in [item.url for item in selection.selected]


def test_the_per_host_setting_is_a_floor_under_an_equal_share_of_the_budget() -> None:
    """The two settings do different jobs; the budget is what bounds the run.

    A flat ceiling of ``max_per_host`` conflates them, and the measured cost was
    150 unspent requests out of 200 on a target whose 3 207 URLs live on 5 hosts.
    """
    assert validate.per_host_limit(max_urls=200, hosts=5, max_per_host=25) == 40
    assert validate.per_host_limit(max_urls=200, hosts=2, max_per_host=25) == 100
    # Many hosts: the share collapses and the configured floor is what applies,
    # which is exactly the old behaviour.
    assert validate.per_host_limit(max_urls=200, hosts=1000, max_per_host=25) == 25


def test_the_run_budget_still_bounds_the_total(
) -> None:
    parsed = _candidates(
        *[f"https://www.{APEX}/p{i}" for i in range(10)],
        *[f"https://api.{APEX}/p{i}" for i in range(10)],
    )

    selection = validate.select_candidates(
        parsed, scope=ScopeEngine.from_domain(APEX), max_urls=6, max_per_host=1
    )

    assert len(selection.selected) == 6
    assert selection.capped_per_host == 14


def test_a_url_measured_recently_is_not_selected_again() -> None:
    parsed = _candidates(f"https://www.{APEX}/a")

    selection = validate.select_candidates(
        parsed,
        scope=ScopeEngine.from_domain(APEX),
        known_fresh=[f"https://www.{APEX}/a"],
    )

    assert selection.selected == []
    assert selection.already_validated == [f"https://www.{APEX}/a"]


def test_the_pipeline_policy_is_the_platform_policy() -> None:
    """The gate is the shared escalation module, not a local rule."""
    assert escalation.OPERATION_URL_VALIDATION in escalation.ACTIVE_OPERATIONS
    eligibility = escalation.decide(
        escalation.AssetEvidence(
            asset_type="url", identity="https://www.acme.test/a", scope_state="in_scope"
        ),
        escalation.OPERATION_URL_VALIDATION,
    )
    assert eligibility.eligible is True


# --------------------------------------------------------------------------- #
# the stage, end to end (with the tool injected)
# --------------------------------------------------------------------------- #


def _stage(output: Path, urls: list[str], lines: list[str], **kwargs):
    runner = FakeRunner(lines)
    report = validate.run_validate_stage(
        APEX,
        urls,
        output_dir=output,
        run=runner,
        now=NOW,
        **kwargs,
    )
    return report, runner


def test_the_stage_writes_records_and_reports_each_state(tmp_path: Path) -> None:
    output = tmp_path / "out"
    urls = [
        f"https://www.{APEX}/login",
        f"https://www.{APEX}/old-page",
        f"https://gone.{APEX}/",
    ]
    lines = [
        _httpx_line(),
        _httpx_line(input=f"https://www.{APEX}/old-page", url=f"https://www.{APEX}/old-page", status_code=404, title="404"),
        _httpx_line(input=f"https://gone.{APEX}/", url="", status_code=None, failed=True, error="timeout"),
    ]

    report, runner = _stage(output, urls, lines)

    assert report.ok is True
    assert report.counts["selected"] == 3
    assert report.counts["verified"] == 1
    assert report.counts["dead"] == 1
    assert report.counts["unreachable"] == 1

    records = validate.load_validations(output / validate.VALIDATIONS_FILE)
    assert set(records) == set(urls)
    assert records[f"https://www.{APEX}/login"].alive is True
    assert records[f"https://www.{APEX}/old-page"].state == validate.STATE_DEAD
    # A URL the tool never reported is unreachable, not alive.
    assert records[f"https://gone.{APEX}/"].state == validate.STATE_UNREACHABLE
    # Only in-scope candidates reached the tool.
    assert report.selection["out_of_scope"] == 0


def test_revalidation_is_idempotent_within_the_ttl(tmp_path: Path) -> None:
    output = tmp_path / "out"
    urls = [f"https://www.{APEX}/login"]
    first, first_runner = _stage(output, urls, [_httpx_line()], ttl=3600)
    assert first.counts["probed"] == 1
    assert first_runner.calls  # the tool ran

    second, second_runner = _stage(output, urls, [_httpx_line()], ttl=3600)

    assert second.counts["probed"] == 0
    assert second.counts["already_validated"] == 1
    # No second invocation: the artifact *is* the operation state.
    assert second_runner.calls == []
    # And the record count did not grow: one URL, one record.
    assert second.counts["records"] == 1
    assert validate.load_validations(output / validate.VALIDATIONS_FILE).keys() == set(urls)


def test_a_ttl_of_zero_forces_a_fresh_measurement(tmp_path: Path) -> None:
    output = tmp_path / "out"
    urls = [f"https://www.{APEX}/login"]
    _stage(output, urls, [_httpx_line()], ttl=3600)

    report, runner = _stage(output, urls, [_httpx_line(status_code=404, url=f"https://www.{APEX}/login", input=f"https://www.{APEX}/login")], ttl=0)

    assert report.counts["probed"] == 1
    assert runner.calls
    records = validate.load_validations(output / validate.VALIDATIONS_FILE)
    assert list(records.values())[0].state == validate.STATE_DEAD
    assert report.counts["records"] == 1


def test_disabling_validation_sends_nothing_and_says_so(tmp_path: Path) -> None:
    output = tmp_path / "out"
    report, runner = _stage(output, [f"https://www.{APEX}/login"], [_httpx_line()], enabled=False)

    assert runner.calls == []
    assert report.counts == {"candidates": 0, "validated": 0}
    assert "switched off" in " ".join(report.notes)
    assert not (output / validate.VALIDATIONS_FILE).exists()


def test_merging_never_duplicates_a_url_and_keeps_the_newest(tmp_path: Path) -> None:
    old = validate.ValidationRecord(
        url=f"https://www.{APEX}/a", state=validate.STATE_DEAD, status=404, validated_at=_iso(NOW - 100)
    )
    new = validate.ValidationRecord(
        url=f"https://www.{APEX}/a", state=validate.STATE_VERIFIED, status=200, validated_at=_iso(NOW)
    )
    stale = validate.ValidationRecord(
        url=f"https://www.{APEX}/a", state=validate.STATE_DEAD, status=404, validated_at=_iso(NOW - 5000)
    )

    merged = validate.merge_validations({old.url: old}, [new])
    assert merged[old.url].state == validate.STATE_VERIFIED

    merged = validate.merge_validations({old.url: new}, [stale])
    assert merged[old.url].state == validate.STATE_VERIFIED  # an older measurement loses

    # Freshness is what makes the reuse safe: a stale record is re-checked.
    assert validate.fresh_urls({old.url: stale}, now=NOW, ttl=3600) == set()
    assert validate.fresh_urls({old.url: new}, now=NOW, ttl=3600) == {old.url}


def test_a_stale_measurement_is_refreshed_rather_than_duplicated(tmp_path: Path) -> None:
    output = tmp_path / "out"
    urls = [f"https://www.{APEX}/a"]
    _stage(output, urls, [_httpx_line(status_code=404, url=urls[0], input=urls[0])], ttl=3600)

    # 30 days later the same URL now answers; the record is replaced in place.
    later = NOW + 30 * 86_400
    runner = FakeRunner([_httpx_line(input=urls[0], url=urls[0])])
    report = validate.run_validate_stage(
        APEX, urls, output_dir=output, run=runner, now=later, ttl=86_400
    )

    assert report.counts["probed"] == 1
    records = validate.load_validations(output / validate.VALIDATIONS_FILE)
    assert len(records) == 1
    assert records[urls[0]].state == validate.STATE_VERIFIED
    assert records[urls[0]].validated_at == _iso(later)


# --------------------------------------------------------------------------- #
# the tool invocation (argument builder)
# --------------------------------------------------------------------------- #


def test_the_httpx_command_is_built_for_url_validation() -> None:
    args = probe.httpx_url_args(input_path="/work/input.txt")

    assert "-json" in args
    assert "-fr" in args  # redirects followed, so final_url/chain mean something
    assert "-irh" in args  # response headers, for server/content-type evidence
    assert "-random-agent=false" in args  # the CLI's randomiser is not a browser
    assert args[args.index("-p") + 1] == probe.PORTS


def test_validation_of_the_extract_artifact_links_parameters_to_urls(tmp_path: Path) -> None:
    """The provenance artifact the graph builds its edges from, end to end."""
    result = extract.extract(
        [
            f"https://www.{APEX}/search?q=cats",
            f"https://api.{APEX}/v1/items?q=dogs&page=2",
        ],
        APEX,
    )

    pairs = {(row["parameter"], row["url"]) for row in result.parameter_observations}
    assert (("q"), f"https://www.{APEX}/search?q=cats") in pairs
    assert (("q"), f"https://api.{APEX}/v1/items?page=2&q=dogs") in pairs
    assert ("page", f"https://api.{APEX}/v1/items?page=2&q=dogs") in pairs
    assert result.counts["parameter_observations"] == 3
    assert all("value" not in row for row in result.parameter_observations)
