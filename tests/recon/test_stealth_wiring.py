"""How the stages *use* the stealth layer.

The stealth package has its own tests; these pin the wiring, because that is
where a correct layer quietly stops being applied — arguments that are never
passed, verdicts that are never recorded, a gate that is never consulted.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from service.recon_pipeline.pipelines.subdomain_domain_wildcards.active import (
    enrich as enrich_mod,
)
from service.recon_pipeline.pipelines.subdomain_domain_wildcards.active import axfr as axfr_mod
from service.recon_pipeline.pipelines.subdomain_domain_wildcards.active import pipeline as active_pipeline
from service.recon_pipeline.pipelines.subdomain_domain_wildcards.active.tools import httpx_args
from service.recon_pipeline.pipelines.subdomain_domain_wildcards.permutation import (
    pipeline as permutation_pipeline,
)
from service.recon_pipeline.platform.stealth.detect import CHALLENGE, OK, Verdict
from service.recon_pipeline.platform.stealth.identity import CHROME_WIN
from service.recon_pipeline.platform.stealth.pacing import FakeClock
from service.recon_pipeline.platform.stealth.quarantine import Quarantine, host_scope
from service.recon_pipeline.platform.stealth.session import StealthConfig, StealthSession

APEX = "example.com"


@pytest.fixture
def session(tmp_path: Path) -> StealthSession:
    """A stealth session with an injected clock and no inter-batch waiting."""
    return StealthSession(
        StealthConfig(
            qps=1000.0,
            burst=1000.0,
            jitter=0.0,
            quarantine_path=tmp_path / "quarantine.json",
        ),
        clock=FakeClock(),
    )


# --------------------------------------------------------------------------- #
# The httpx command line
# --------------------------------------------------------------------------- #


def test_httpx_args_turns_the_random_user_agent_off_and_pins_the_identity():
    """The CLI's randomiser is on by default and is a UA/TLS mismatch factory."""
    args = httpx_args(rate_limit=2, threads=5, identity=CHROME_WIN)

    assert "-random-agent=false" in args
    assert args[args.index("-tlsi") + 1] == "chrome"
    assert "-irh" in args  # response headers, so blocks are detectable
    lowered = [argument.lower() for argument in args]
    assert f"user-agent: {CHROME_WIN.ua}".lower() in lowered
    assert any(argument.startswith("sec-ch-ua: ") for argument in lowered)
    assert args[args.index("-l") + 1].endswith("tool-input.txt")


def test_httpx_args_without_an_identity_still_disables_the_randomiser():
    args = httpx_args()
    assert "-random-agent=false" in args
    assert "-tlsi" not in args
    assert not any(argument.startswith("user-agent: ") for argument in args)


def test_httpx_args_can_drop_impersonation_and_header_capture():
    args = httpx_args(identity=CHROME_WIN, impersonate=False, include_headers=False)
    assert "-tlsi" not in args
    assert "-irh" not in args
    assert any(argument.lower().startswith("user-agent: ") for argument in args)


def test_httpx_args_max_host_errors_is_opt_in():
    assert "-maxhr" not in httpx_args(identity=CHROME_WIN)
    args = httpx_args(identity=CHROME_WIN, max_host_errors=3)
    assert args[args.index("-maxhr") + 1] == "3"


# --------------------------------------------------------------------------- #
# The HTTP probe
# --------------------------------------------------------------------------- #


def test_response_headers_are_normalised_from_httpx_json_spelling():
    """httpx -irh emits ``cf_ray``; signatures are written ``cf-ray``."""
    normalised = enrich_mod.normalize_response_headers({"cf_ray": "abc", "content_type": "text/html"})
    assert normalised == {"cf-ray": "abc", "content-type": "text/html"}
    assert enrich_mod.normalize_response_headers(None) == {}
    assert enrich_mod.normalize_response_headers(["nope"]) == {}


def test_a_cloudflare_challenge_found_by_the_bulk_probe_quarantines_the_host(session):
    payload = {
        "host": "blocked.example.com",
        "status_code": 403,
        "title": "Just a moment...",
        "header": {"cf_ray": "8a1b-LHR", "server": "cloudflare"},
    }
    probes = enrich_mod.parse_httpx_jsonl(json.dumps(payload))
    assert probes[0].headers["cf-ray"] == "8a1b-LHR"

    verdict = session.record_probe(
        probes[0].host, status=probes[0].status_code, headers=probes[0].headers, body=probes[0].title
    )
    assert verdict.kind == CHALLENGE
    assert session.quarantine.is_host_quarantined("blocked.example.com")


def test_a_normal_probe_is_not_a_block(session):
    verdict = session.record_probe(
        "healthy.example.com", status=200, headers={"server": "nginx"}, body="Welcome to our site"
    )
    assert verdict.kind == OK
    assert not session.quarantine.is_host_quarantined("healthy.example.com")


def test_quarantined_hosts_are_never_probed(session, tmp_path, monkeypatch):
    """Re-probing a blocked host is what turns a soft block into a hard one."""
    session.quarantine.record(host_scope("blocked.example.com"), _challenge(), host="blocked.example.com")
    sent: list[list[str]] = []

    def fake_run_tool(name, args, **kwargs):  # noqa: ANN001 - mirrors run_tool
        sent.append(list(args))
        output = Path(kwargs["output_dir"]) / kwargs["stdout_name"]
        output.write_text("", encoding="utf-8")
        raise enrich_mod.DockerUnavailableError("stop here: the input is what we assert")

    monkeypatch.setattr(enrich_mod, "run_tool", fake_run_tool)
    result = enrich_mod.probe_http(
        ["blocked.example.com", "healthy.example.com"],
        output_dir=tmp_path,
        timeout=5,
        rate_limit=2,
        threads=1,
        session=session,
    )
    assert result.skipped == ["blocked.example.com"]
    assert Path(tmp_path / enrich_mod.HTTPX_INPUT).read_text(encoding="utf-8").split() == ["healthy.example.com"]


def _challenge() -> Verdict:
    return Verdict(CHALLENGE, status=403, waf="cloudflare", confidence=0.9)


def test_probe_sends_the_identity_and_the_stealth_flags(session, tmp_path, monkeypatch):
    captured: dict[str, list[str]] = {}

    def fake_run_tool(name, args, **kwargs):  # noqa: ANN001
        captured["args"] = list(args)
        Path(kwargs["output_dir"], kwargs["stdout_name"]).write_text("", encoding="utf-8")
        raise enrich_mod.DockerUnavailableError("captured")

    monkeypatch.setattr(enrich_mod, "run_tool", fake_run_tool)
    enrich_mod.probe_http(
        ["a.example.com"],
        output_dir=tmp_path,
        timeout=5,
        rate_limit=2,
        threads=1,
        session=session,
    )
    args = captured["args"]
    assert "-random-agent=false" in args
    assert "-tlsi" in args
    assert args[args.index("-rl") + 1] == "2"
    assert "-irh" in args


# --------------------------------------------------------------------------- #
# Zone transfers
# --------------------------------------------------------------------------- #


def test_axfr_attempts_are_spaced_with_an_injected_sleep(tmp_path):
    slept: list[float] = []
    transfers = axfr_mod.zone_transfer(
        APEX,
        nameservers=["ns1.example.com", "ns2.example.com", "ns3.example.com"],
        output_dir=tmp_path,
        spacing=10.0,
        sleep=slept.append,
        runner=lambda *a, **k: (_ for _ in ()).throw(RuntimeError("no docker in this test")),
    )
    assert len(transfers) == 3
    assert len(slept) == 2  # no pause before the first attempt
    assert all(6.5 <= delay <= 13.5 for delay in slept)  # jittered around 10s


def test_axfr_without_spacing_does_not_sleep(tmp_path):
    slept: list[float] = []
    axfr_mod.zone_transfer(
        APEX,
        nameservers=["ns1.example.com", "ns2.example.com"],
        output_dir=tmp_path,
        spacing=0.0,
        sleep=slept.append,
        runner=lambda *a, **k: (_ for _ in ()).throw(RuntimeError("no docker")),
    )
    assert slept == []


# --------------------------------------------------------------------------- #
# Stage gates and reports
# --------------------------------------------------------------------------- #


def test_active_stage_refuses_to_run_in_passive_only_mode(tmp_path, query_factory):
    session = StealthSession(
        StealthConfig(passive_only=True, quarantine_path=tmp_path / "q.json"),
        clock=FakeClock(),
    )
    report = active_pipeline.run_active_stage(
        APEX,
        output_dir=tmp_path,
        query=query_factory(healthy=["192.0.2.1"]),
        session=session,
    )
    assert report.ok is False
    assert "passive-only" in (report.fatal or "")
    assert not (tmp_path / active_pipeline.RESOLVED_FILE).exists()


def test_active_stage_reports_the_stealth_state(tmp_path, query_factory, fake_engine):
    session = StealthSession(
        StealthConfig(qps=1000.0, burst=1000.0, jitter=0.0, quarantine_path=tmp_path / "q.json"),
        clock=FakeClock(),
    )
    engine = fake_engine(resolves={f"www.{APEX}"})
    report = active_pipeline.run_active_stage(
        APEX,
        engine=engine.as_engine(),
        from_passive=False,
        candidates=[f"www.{APEX}", f"api.{APEX}"],
        bruteforce=False,
        recursion=False,
        axfr=False,
        enrich=False,
        resolvers=["192.0.2.1", "192.0.2.2", "192.0.2.3"],
        trusted_resolvers=[],
        output_dir=tmp_path,
        query=query_factory(healthy=["192.0.2.1", "192.0.2.2", "192.0.2.3"]),
        session=session,
    )
    assert report.stealth
    assert report.stealth["transport"]["name"]
    assert report.stealth["identities"]["pool"]
    assert report.stealth["pacing"]["qps"] == 1000.0
    # The plan is recorded, so an operator can see the volume each resolver saw.
    assert report.stealth["dns_plan"]["names"] == 2
    assert (tmp_path / "q.json").is_file()  # quarantine state is persisted


def test_permutation_stage_refuses_to_run_in_passive_only_mode(tmp_path, query_factory):
    session = StealthSession(
        StealthConfig(passive_only=True, quarantine_path=tmp_path / "q.json"),
        clock=FakeClock(),
    )
    report = permutation_pipeline.run_permutation_stage(
        APEX,
        output_dir=tmp_path,
        known_hosts=[f"www.{APEX}"],
        from_active=False,
        from_passive=False,
        query=query_factory(healthy=["192.0.2.1"]),
        session=session,
    )
    assert report.ok is False
    assert "passive-only" in (report.fatal or "")
