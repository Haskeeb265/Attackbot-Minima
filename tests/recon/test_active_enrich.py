"""
Tests for :mod:`...active.enrich` — the stage's record and HTTP-probe layer.

Nothing tested this module directly before, and it is the layer that produces the
data every downstream consumer reads: ``records.jsonl`` (raw dnsx output) is what
the ports stage resolves addresses from, and ``records.txt`` is the human summary.
So the parsers here are pinned hard — record normalisation, which dnsx keys are
metadata rather than records, and the fact that asking and getting nothing is
*kept* as a distinct outcome from not asking at all.

The HTTP probe is the opposite: it is the one step in the DNS stages that sends
application traffic, so its guards get tested too — a quarantined host is never
probed, and a challenge or block is classified rather than counted as a response.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from service.recon_pipeline.pipelines.subdomain_domain_wildcards.active import enrich
from service.recon_pipeline.platform.common.docker_tool import (
    ContainerRun,
    DockerTimeoutError,
    DockerUnavailableError,
)


# --------------------------------------------------------------------------- #
# Fakes
# --------------------------------------------------------------------------- #


class FakeRunner:
    """Writes canned stdout and reports a scripted status, like the real runner."""

    def __init__(self, *, stdout: str = "", ok: bool = True, exit_code: int = 0,
                 raises: BaseException | None = None, log_tail: str = "") -> None:
        self.stdout = stdout
        self.ok = ok
        self.exit_code = exit_code
        self.raises = raises
        self.log_tail = log_tail
        self.calls: list[dict] = []

    def __call__(self, tool, args, *, output_dir, stdout_name=None, stderr_name=None, suffix="", **_kwargs):  # noqa: ANN001
        self.calls.append({"tool": tool, "args": list(args), "suffix": suffix})
        if self.raises is not None:
            raise self.raises
        stdout_path = Path(output_dir, stdout_name or "out")
        stderr_path = Path(output_dir, stderr_name or "err")
        stdout_path.write_text(self.stdout, encoding="utf-8")
        stderr_path.write_text(self.log_tail, encoding="utf-8")
        return ContainerRun(
            name="fake", image="img",
            exit_code=self.exit_code if not self.ok else 0,
            seconds=0.4,
            stdout_path=stdout_path, stderr_path=stderr_path,
        )


@pytest.fixture
def runner(monkeypatch):
    def build(fake: FakeRunner) -> FakeRunner:
        monkeypatch.setattr(enrich, "run_tool", fake)
        return fake

    return build


def dnsx_line(host: str, **records: object) -> str:
    return json.dumps({"host": host, "status_code": "NOERROR", "resolver": ["1.1.1.1:53"], **records})


# --------------------------------------------------------------------------- #
# parse_dnsx_jsonl
# --------------------------------------------------------------------------- #


def test_records_are_normalised_deduplicated_and_sorted() -> None:
    """One canonical form, so two hosts with the same answer compare equal."""
    text = dnsx_line(
        "API.Example.COM.",
        a=["10.0.0.2", "10.0.0.1", "10.0.0.1"],
        cname=["Edge.Example.COM."],
    )
    records = enrich.parse_dnsx_jsonl(text)

    assert set(records) == {"api.example.com"}
    record = records["api.example.com"]
    assert record.records["a"] == ["10.0.0.1", "10.0.0.2"]
    assert record.records["cname"] == ["edge.example.com"], "the trailing root dot is stripped"
    assert record.status == "NOERROR"


def test_metadata_keys_are_not_mistaken_for_records() -> None:
    """``all`` holds the raw record dump; counting it would double every type."""
    text = json.dumps(
        {
            "host": "a.example.com",
            "ttl": 300,
            "resolver": ["1.1.1.1:53"],
            "timestamp": "2026-09-17T00:00:00Z",
            "query-time": 0.01,
            "status_code": "NOERROR",
            "status_code_raw": 0,
            "all": ["a.example.com.\t300\tIN\tA\t10.0.0.1"],
            "axfr": [],
            "a": ["10.0.0.1"],
        }
    )
    record = enrich.parse_dnsx_jsonl(text)["a.example.com"]
    assert record.records == {"a": ["10.0.0.1"]}
    assert record.types == ("a",)


def test_non_list_values_are_ignored_rather_than_coerced() -> None:
    """A scalar where a list belongs means the shape changed, not that we guess."""
    text = json.dumps({"host": "a.example.com", "a": "10.0.0.1", "cname": ["b.example.com"]})
    record = enrich.parse_dnsx_jsonl(text)["a.example.com"]
    assert record.records == {"cname": ["b.example.com"]}


def test_empty_record_lists_do_not_become_record_types() -> None:
    text = json.dumps({"host": "a.example.com", "a": [], "txt": ["v=spf1"]})
    record = enrich.parse_dnsx_jsonl(text)["a.example.com"]
    assert record.records == {"txt": ["v=spf1"]}


def test_a_host_that_answered_nothing_is_kept_but_not_counted_as_resolved() -> None:
    """The distinction the summary depends on: asked-and-empty vs not asked.

    ``hosts`` counts every host dnsx was given; ``with_records`` counts the ones
    that produced something.  Dropping the empty entries would make those two
    numbers identical and a dead host list look healthy.
    """
    text = "\n".join([dnsx_line("live.example.com", a=["10.0.0.1"]), dnsx_line("dead.example.com")])

    result = enrich.EnrichResult(hosts=2, records=enrich.parse_dnsx_jsonl(text))

    assert set(result.records) == {"live.example.com", "dead.example.com"}
    assert result.with_records == 1
    assert result.records["dead.example.com"].has_records is False


def test_malformed_lines_are_skipped_individually() -> None:
    """One bad line must not cost the whole pass."""
    text = "\n".join(
        [
            "",
            "   ",
            "[INF] dnsx log line",
            '{"host": "a.example.com", "a": ["10.0.0.1"]',
            '["a", "list", "not", "an", "object"]',
            "{}",
            dnsx_line("b.example.com", a=["10.0.0.2"]),
        ]
    )
    assert set(enrich.parse_dnsx_jsonl(text)) == {"b.example.com"}


def test_a_repeated_host_line_replaces_the_earlier_one() -> None:
    """dnsx prints one line per host, so this is deterministic-if-it-happens."""
    text = "\n".join([dnsx_line("a.example.com", a=["10.0.0.1"]), dnsx_line("a.example.com", a=["10.0.0.9"])])
    assert enrich.parse_dnsx_jsonl(text)["a.example.com"].records["a"] == ["10.0.0.9"]


# --------------------------------------------------------------------------- #
# RecordSet / EnrichResult summaries
# --------------------------------------------------------------------------- #


def test_a_record_summary_line_names_every_type_deterministically() -> None:
    record = enrich.RecordSet(
        host="a.example.com",
        status="NOERROR",
        records={"cname": ["b.example.com"], "a": ["10.0.0.1", "10.0.0.2"]},
    )
    assert record.summary() == "a.example.com\tA=10.0.0.1,10.0.0.2  CNAME=b.example.com"
    assert record.types == ("a", "cname")


def test_a_record_summary_of_nothing_is_just_the_host() -> None:
    assert enrich.RecordSet(host="dead.example.com").summary() == "dead.example.com"


def test_the_enrich_summary_counts_types_across_hosts() -> None:
    result = enrich.EnrichResult(
        hosts=2,
        records={
            "a.example.com": enrich.RecordSet("a.example.com", records={"a": ["1.1.1.1"], "txt": ["x"]}),
            "b.example.com": enrich.RecordSet("b.example.com", records={"a": ["2.2.2.2"]}),
        },
        seconds=1.239,
        outputs={"records": "out/records.txt"},
    )
    payload = result.to_dict()

    assert payload["hosts"] == 2
    assert payload["resolved"] == 2
    assert payload["record_types"] == {"a": 2, "txt": 1}
    assert payload["seconds"] == 1.24
    assert payload["outputs"] == {"records": "out/records.txt"}
    assert "error" not in payload


def test_an_empty_enrich_result_omits_the_outputs() -> None:
    payload = enrich.EnrichResult().to_dict()
    assert payload["hosts"] == 0 and payload["resolved"] == 0
    assert "outputs" not in payload


# --------------------------------------------------------------------------- #
# enrich_records
# --------------------------------------------------------------------------- #


def test_enriching_nothing_does_not_start_a_container(runner, tmp_path: Path) -> None:
    fake = runner(FakeRunner())
    result = enrich.enrich_records([], output_dir=tmp_path, timeout=10)

    assert fake.calls == []
    assert result.hosts == 0
    assert result.records == {}


def test_enrichment_writes_the_input_deduplicated_and_in_order(runner, tmp_path: Path) -> None:
    fake = runner(FakeRunner(stdout=dnsx_line("a.example.com", a=["10.0.0.1"])))

    enrich.enrich_records(
        ["b.example.com", "a.example.com", "b.example.com"], output_dir=tmp_path, timeout=10
    )

    written = (tmp_path / enrich.DNSX_INPUT).read_text(encoding="utf-8").split()
    assert written == ["b.example.com", "a.example.com"]
    assert fake.calls[0]["tool"] == "dnsx"


def test_enrichment_writes_the_summary_from_the_parsed_records(runner, tmp_path: Path) -> None:
    """The summary is derived from the parse, so a parse bug is visible in it."""
    runner(
        FakeRunner(
            stdout="\n".join(
                [
                    dnsx_line("live.example.com", a=["10.0.0.1"]),
                    dnsx_line("dead.example.com"),
                ]
            )
        )
    )

    result = enrich.enrich_records(["live.example.com", "dead.example.com"], output_dir=tmp_path, timeout=10)

    summary = (tmp_path / enrich.RECORDS_SUMMARY).read_text(encoding="utf-8").splitlines()
    assert summary == ["dead.example.com", "live.example.com\tA=10.0.0.1"], "sorted by host"
    assert result.ok is True
    assert result.with_records == 1


def test_a_timeout_is_reported_with_the_host_count(runner, tmp_path: Path) -> None:
    runner(FakeRunner(raises=DockerTimeoutError("dnsx exceeded 900s", name="psh-dnsx")))
    result = enrich.enrich_records(["a.example.com", "b.example.com"], output_dir=tmp_path, timeout=900)

    assert result.ok is False
    assert "900s" in result.error
    assert result.hosts == 2
    assert result.records == {}


def test_no_docker_is_reported_rather_than_raised(runner, tmp_path: Path) -> None:
    runner(FakeRunner(raises=DockerUnavailableError("cannot connect to the Docker daemon")))
    result = enrich.enrich_records(["a.example.com"], output_dir=tmp_path, timeout=10)
    assert result.ok is False and "Docker daemon" in result.error


def test_a_non_zero_exit_is_reported_and_no_records_are_claimed(runner, tmp_path: Path) -> None:
    runner(FakeRunner(ok=False, exit_code=1, log_tail="fatal: bad resolvers"))
    result = enrich.enrich_records(["a.example.com"], output_dir=tmp_path, timeout=10)

    assert result.ok is False
    assert "exit code 1" in result.error
    assert result.records == {}


# --------------------------------------------------------------------------- #
# httpx parsing and header normalisation
# --------------------------------------------------------------------------- #


def test_header_names_are_restored_to_their_wire_spelling() -> None:
    """Detection signatures are written ``cf-ray``; httpx JSON emits ``cf_ray``."""
    assert enrich.normalize_response_headers({"cf_ray": "abc", "Content_Type": "text/html"}) == {
        "cf-ray": "abc",
        "content-type": "text/html",
    }


def test_header_normalisation_rejects_anything_that_is_not_a_map() -> None:
    assert enrich.normalize_response_headers("cf_ray: abc") == {}
    assert enrich.normalize_response_headers(None) == {}
    assert enrich.normalize_response_headers(["cf-ray", "abc"]) == {}


def test_header_normalisation_drops_absent_values_and_blank_names() -> None:
    assert enrich.normalize_response_headers({"cf_ray": None, "": "x", "server": "nginx"}) == {
        "server": "nginx"
    }


def test_a_probe_line_reads_both_host_and_input() -> None:
    text = "\n".join(
        [
            json.dumps({"host": "A.Example.com.", "status_code": 200, "title": "Home", "tech": ["nginx"]}),
            json.dumps({"input": "b.example.com", "status-code": 301}),
        ]
    )
    probes = enrich.parse_httpx_jsonl(text)

    assert [probe.host for probe in probes] == ["a.example.com", "b.example.com"]
    assert probes[0].technologies == ("nginx",)
    assert probes[1].status_code == 301, "the alternative key spelling is accepted"


def test_a_status_that_did_not_arrive_as_a_number_is_not_invented() -> None:
    text = json.dumps({"host": "a.example.com", "status_code": "200"})
    assert enrich.parse_httpx_jsonl(text)[0].status_code is None


def test_malformed_probe_lines_are_skipped() -> None:
    text = "\n".join(["", "not json", "[1, 2]", "{}", json.dumps({"host": "a.example.com"})])
    assert [probe.host for probe in enrich.parse_httpx_jsonl(text)] == ["a.example.com"]


def test_a_probe_summary_shows_the_waf_when_one_was_detected() -> None:
    probe = enrich.HttpProbe(
        host="a.example.com",
        status_code=403,
        title="Attention Required",
        technologies=("cloudflare",),
        verdict=SimpleNamespace(waf="cloudflare"),
    )
    assert probe.summary() == "a.example.com\t403\tAttention Required\t[cloudflare]\t(cloudflare)"


def test_a_clean_probe_summary_carries_no_verdict_noise() -> None:
    probe = enrich.HttpProbe(host="a.example.com", status_code=200, title="Home")
    assert probe.summary() == "a.example.com\t200\tHome"
    assert "verdict" not in probe.to_dict()


# --------------------------------------------------------------------------- #
# HttpResult
# --------------------------------------------------------------------------- #


def verdict(*, waf: str | None = None, is_ok: bool = True, is_block: bool = False):
    return SimpleNamespace(
        waf=waf, is_ok=is_ok, is_block=is_block, to_dict=lambda: {"waf": waf, "verdict": "blocked"}
    )


def test_the_probe_summary_separates_responses_from_blocks() -> None:
    result = enrich.HttpResult(
        hosts=3,
        probes=[
            enrich.HttpProbe(host="a.example.com", status_code=200, verdict=verdict()),
            enrich.HttpProbe(host="b.example.com", status_code=403, verdict=verdict(waf="cloudflare", is_ok=False, is_block=True)),
            enrich.HttpProbe(host="c.example.com", status_code=None, verdict=verdict(is_ok=False)),
        ],
        skipped=["d.example.com"],
        seconds=1.239,
    )
    payload = result.to_dict()

    assert payload["responded"] == 2, "a host that never answered is not a response"
    assert payload["status_codes"] == {"200": 1, "403": 1, "none": 1}
    assert payload["blocked"] == ["b.example.com"]
    assert payload["waf"] == {"cloudflare": 1}
    assert payload["skipped_quarantined"] == ["d.example.com"]
    assert payload["seconds"] == 1.24


def test_a_clean_probe_run_reports_no_blocks_or_wafs() -> None:
    payload = enrich.HttpResult(hosts=1, probes=[enrich.HttpProbe("a.example.com", 200)]).to_dict()
    assert "blocked" not in payload and "waf" not in payload
    assert payload["status_codes"] == {"200": 1}


# --------------------------------------------------------------------------- #
# probe_http — the guards on the one step that sends application traffic
# --------------------------------------------------------------------------- #


class FakeIdentity:
    """The two attributes the httpx argument builder reads off a real identity."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.tls_profile = name

    def httpx_header_args(self, *, url: str = "", referer: str = "") -> list[str]:
        del url, referer
        return ["-H", f"User-Agent: {self.name}"]


class FakeSession:
    """A stealth session stub: quarantine decisions plus per-host identities."""

    def __init__(self, *, blocked=(), identities=None, verdicts=None) -> None:
        self.blocked = set(blocked)
        self.identities = identities or {}
        self.verdicts = verdicts or {}
        self.recorded: list[tuple[str, object, object, object]] = []

    def is_allowed(self, host: str) -> bool:
        return host not in self.blocked

    def identity_for(self, host: str):  # noqa: ANN201
        return FakeIdentity(self.identities.get(host, "chrome-win"))

    def httpx_max_host_errors(self) -> int:
        return 1

    def record_probe(self, host, *, status=None, headers=None, body=""):  # noqa: ANN001
        self.recorded.append((host, status, headers, body))
        return self.verdicts.get(host, verdict())


def test_a_quarantined_host_is_never_probed(runner, tmp_path: Path) -> None:
    """Re-asking a host that already refused us is what turns a soft block hard."""
    fake = runner(FakeRunner(stdout=json.dumps({"host": "live.example.com", "status_code": 200})))
    session = FakeSession(blocked={"blocked.example.com"})

    result = enrich.probe_http(
        ["live.example.com", "blocked.example.com"],
        output_dir=tmp_path,
        timeout=60,
        rate_limit=2,
        threads=1,
        session=session,
    )

    assert (tmp_path / enrich.HTTPX_INPUT).read_text(encoding="utf-8").split() == ["live.example.com"]
    assert result.skipped == ["blocked.example.com"]
    assert result.hosts == 1


def test_a_fully_quarantined_run_probes_nothing_at_all(runner, tmp_path: Path) -> None:
    fake = runner(FakeRunner())
    session = FakeSession(blocked={"a.example.com", "b.example.com"})

    result = enrich.probe_http(
        ["a.example.com", "b.example.com"], output_dir=tmp_path, timeout=60, rate_limit=2, threads=1, session=session
    )

    assert fake.calls == [], "no container should be started"
    assert result.hosts == 0
    assert sorted(result.skipped) == ["a.example.com", "b.example.com"]


def test_the_batch_uses_the_most_common_identity(runner, tmp_path: Path) -> None:
    """One CLI call takes one header set, so the batch goes out as the majority."""
    fake = runner(FakeRunner(stdout=json.dumps({"host": "a.example.com", "status_code": 200})))
    session = FakeSession(
        identities={"a.example.com": "chrome-win", "b.example.com": "chrome-win", "c.example.com": "firefox-win"}
    )

    enrich.probe_http(
        ["a.example.com", "b.example.com", "c.example.com"],
        output_dir=tmp_path,
        timeout=60,
        rate_limit=2,
        threads=1,
        session=session,
    )

    args = fake.calls[0]["args"]
    assert "chrome-win" in " ".join(args), "the majority identity is the one presented"


def test_every_probe_response_is_fed_back_for_classification(runner, tmp_path: Path) -> None:
    runner(FakeRunner(stdout=json.dumps({"host": "a.example.com", "status_code": 403, "header": {"cf_ray": "x"}})))
    session = FakeSession(verdicts={"a.example.com": verdict(waf="cloudflare", is_ok=False, is_block=True)})

    result = enrich.probe_http(
        ["a.example.com"], output_dir=tmp_path, timeout=60, rate_limit=2, threads=1, session=session
    )

    host, status, headers, _body = session.recorded[0]
    assert (host, status, headers) == ("a.example.com", 403, {"cf-ray": "x"})
    assert result.blocked == ["a.example.com"], "a block is surfaced, not counted as a live host"
    assert result.live == 1, "403 is still an answer from the host"


def test_a_probe_timeout_is_reported_with_what_was_skipped(runner, tmp_path: Path) -> None:
    runner(FakeRunner(raises=DockerTimeoutError("httpx exceeded 60s", name="psh-httpx")))
    session = FakeSession(blocked={"b.example.com"})

    result = enrich.probe_http(
        ["a.example.com", "b.example.com"],
        output_dir=tmp_path,
        timeout=60,
        rate_limit=2,
        threads=1,
        session=session,
    )

    assert result.ok is False
    assert "60s" in result.error
    assert result.skipped == ["b.example.com"]


def test_a_probe_run_without_a_session_still_works(runner, tmp_path: Path) -> None:
    """The probe is usable with no stealth layer at all (no quarantine, no identities)."""
    runner(FakeRunner(stdout=json.dumps({"host": "a.example.com", "status_code": 200})))

    result = enrich.probe_http(
        ["a.example.com"], output_dir=tmp_path, timeout=60, rate_limit=2, threads=1, session=None
    )

    assert result.ok is True
    assert result.live == 1
    assert result.skipped == []
