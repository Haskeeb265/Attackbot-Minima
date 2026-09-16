"""
Tests for :mod:`active.tools` — the argument builders and image preflight.

The builders are pure functions precisely so the command lines can be asserted
without Docker, which matters because several of these flags are easy to get
subtly wrong in ways that only show up as bad results:

* dnsx must query the *named record types* and never ``-recon`` (which fires an
  AXFR at every host);
* puredns must be told explicitly either where the trusted resolvers are or that
  validation is being skipped — silently inheriting puredns' built-in trusted
  list would hide that no poisoning check happened;
* shuffledns takes ``-w`` in bruteforce mode but ``-l`` in resolve mode.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from service.recon_pipeline.asset_pipelines.subdomain_domain_wildcards.active import (
    tools,
)
from service.recon_pipeline.asset_pipelines.subdomain_domain_wildcards.active.tools import (
    ToolImageMissingError,
    amass_active_args,
    dig_axfr_args,
    dnsgen_args,
    dnsx_args,
    ensure_image,
    get_tool,
    httpx_args,
    massdns_args,
    puredns_bruteforce_args,
    puredns_resolve_args,
    shuffledns_args,
)

WORK = tools.WORKDIR


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #


def test_every_documented_tool_is_registered() -> None:
    for name in ("puredns", "dnsx", "shuffledns", "massdns", "dig", "amass", "httpx", "dnsgen"):
        assert get_tool(name).name == name


def test_unknown_tool_error_lists_known_names() -> None:
    with pytest.raises(KeyError, match="unknown active tool"):
        get_tool("nmap")


# --------------------------------------------------------------------------- #
# Image preflight
# --------------------------------------------------------------------------- #


def test_missing_image_raises_with_the_build_command(monkeypatch) -> None:
    monkeypatch.setattr(tools, "image_exists", lambda image, **_: False)
    with pytest.raises(ToolImageMissingError) as excinfo:
        ensure_image("subdomain_domain_wildcards_image")
    message = str(excinfo.value)
    assert "docker build -t subdomain_domain_wildcards_image" in message
    assert "not built" in message


def test_present_image_passes_preflight(monkeypatch) -> None:
    monkeypatch.setattr(tools, "image_exists", lambda image, **_: True)
    ensure_image("subdomain_domain_wildcards_image")


def test_run_tool_refuses_when_the_image_is_missing(monkeypatch, tmp_path: Path) -> None:
    """The check happens before any container is started."""
    monkeypatch.setattr(tools, "require_docker", lambda: None)
    monkeypatch.setattr(tools, "image_exists", lambda image, **_: False)
    with pytest.raises(ToolImageMissingError):
        tools.run_tool("dnsx", [], output_dir=tmp_path)


# --------------------------------------------------------------------------- #
# puredns
# --------------------------------------------------------------------------- #


def test_puredns_resolve_uses_trusted_file_when_available() -> None:
    args = puredns_resolve_args(
        input_path=f"{WORK}/candidates.txt",
        output_path=f"{WORK}/out.txt",
        wildcards_path=f"{WORK}/wild.txt",
        trusted=f"{WORK}/resolvers-trusted.txt",
    )
    assert args[0] == "resolve"
    assert args[1] == f"{WORK}/candidates.txt"
    assert ["-r", f"{WORK}/resolvers.txt"] == args[2:4]
    assert "--resolvers-trusted" in args
    assert "--skip-validation" not in args
    assert args[args.index("--write-wildcards") + 1] == f"{WORK}/wild.txt"
    assert args[args.index("-w") + 1] == f"{WORK}/out.txt"


def test_puredns_skips_validation_explicitly_when_no_trusted_pool() -> None:
    """Otherwise the run silently inherits puredns' own trusted list."""
    args = puredns_resolve_args(trusted=None)
    assert "--skip-validation" in args
    assert "--resolvers-trusted" not in args


def test_puredns_rate_limit_is_only_passed_when_set() -> None:
    assert "--rate-limit" not in puredns_resolve_args(rate_limit=0)
    args = puredns_resolve_args(rate_limit=500)
    assert args[args.index("--rate-limit") + 1] == "500"


def test_puredns_bruteforce_puts_wordlist_before_domain() -> None:
    args = puredns_bruteforce_args("example.com", wordlist=f"{WORK}/wordlist.txt")
    assert args[0] == "bruteforce"
    assert args[1] == f"{WORK}/wordlist.txt"
    assert args[2] == "example.com"


# --------------------------------------------------------------------------- #
# dnsx
# --------------------------------------------------------------------------- #


def test_dnsx_queries_named_record_types_and_never_recon() -> None:
    """``-recon`` would AXFR every host; enrichment must stay record queries."""
    args = dnsx_args(record_types=("a", "cname"))
    assert "-a" in args and "-cname" in args
    assert "-recon" not in args and "-axfr" not in args
    assert "-json" in args
    assert args[args.index("-l") + 1] == f"{WORK}/tool-input.txt"
    assert args[args.index("-r") + 1] == f"{WORK}/resolvers.txt"


def test_dnsx_disables_its_own_update_check() -> None:
    """A run must not depend on the tool reaching GitHub."""
    assert "-duc" in dnsx_args()


# --------------------------------------------------------------------------- #
# shuffledns
# --------------------------------------------------------------------------- #


def test_shuffledns_resolve_mode_uses_the_list_flag() -> None:
    args = shuffledns_args(
        "example.com", mode="resolve", wordlist=None, list_path=f"{WORK}/candidates.txt"
    )
    assert args[args.index("-mode") + 1] == "resolve"
    assert args[args.index("-l") + 1] == f"{WORK}/candidates.txt"
    assert "-w" not in args


def test_shuffledns_bruteforce_mode_uses_the_wordlist_flag() -> None:
    args = shuffledns_args("example.com", mode="bruteforce", wordlist=f"{WORK}/wordlist.txt")
    assert args[args.index("-w") + 1] == f"{WORK}/wordlist.txt"
    assert "-l" not in args


def test_shuffledns_refuses_a_mode_without_its_input() -> None:
    with pytest.raises(ValueError, match="list_path"):
        shuffledns_args("example.com", mode="resolve", list_path=None)
    with pytest.raises(ValueError, match="wordlist"):
        shuffledns_args("example.com", mode="bruteforce", wordlist=None)


# --------------------------------------------------------------------------- #
# Enrichment / HTTP / AXFR / generator
# --------------------------------------------------------------------------- #


def test_httpx_is_silent_json_with_a_rate_limit() -> None:
    args = httpx_args(rate_limit=25, threads=10)
    assert "-silent" in args and "-json" in args
    assert args[args.index("-rl") + 1] == "25"
    assert args[args.index("-t") + 1] == "10"
    assert args[args.index("-l") + 1] == f"{WORK}/tool-input.txt"


def test_massdns_writes_simple_records_to_a_file() -> None:
    args = massdns_args(output_path=f"{WORK}/massdns.txt")
    assert args[args.index("-o") + 1] == "S"
    assert args[args.index("-w") + 1] == f"{WORK}/massdns.txt"


def test_dig_axfr_targets_one_nameserver_and_strips_noise() -> None:
    args = dig_axfr_args("example.com", "ns1.example.com")
    assert args[-1] == "@ns1.example.com"
    assert "AXFR" in args
    assert "+noall" in args and "+answer" in args


def test_amass_active_omits_config_when_absent(monkeypatch, tmp_path: Path) -> None:
    """amass exits 1 on a missing ``-config`` path; omitting it is the fix."""
    monkeypatch.setattr(tools, "PASSIVE_DIR", tmp_path)
    args = amass_active_args("example.com", timeout_minutes=5)
    assert "-active" in args
    assert "-config" not in args


def test_amass_active_uses_config_when_present(monkeypatch, tmp_path: Path) -> None:
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    (config_dir / "config.yaml").write_text("datasources: {}\n", encoding="utf-8")
    monkeypatch.setattr(tools, "PASSIVE_DIR", tmp_path)

    args = amass_active_args("example.com", timeout_minutes=5)

    assert args[args.index("-config") + 1] == "/home/user/.config/amass/config.yaml"
    assert tools.amass_volumes() == [(config_dir, "/home/user/.config/amass", "ro")]


def test_dnsgen_takes_a_file_and_only_passes_optional_flags_when_set() -> None:
    assert dnsgen_args(input_path=f"{WORK}/known.txt") == [f"{WORK}/known.txt"]
    args = dnsgen_args(input_path=f"{WORK}/known.txt", wordlen=6, wordlist=f"{WORK}/w.txt", fast=True)
    assert args[args.index("--wordlen") + 1] == "6"
    assert args[args.index("--wordlist") + 1] == f"{WORK}/w.txt"
    assert "--fast" in args
