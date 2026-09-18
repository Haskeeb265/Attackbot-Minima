"""
Tests for :mod:`passive.sources`, :mod:`platform.common.docker_tool`, and the keyless
HTTP sources.

No Docker container is started and no HTTP request is made: ``run_container``,
``subprocess.run``, and each source's ``fetch_text`` are replaced with stubs.
That keeps the suite fast and deterministic while still asserting the things
that actually break — argument construction, timeout handling, dependency
skipping, and response parsing.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from service.recon_pipeline.platform.common import (
    docker_tool,
)
from service.recon_pipeline.pipelines.subdomain_domain_wildcards.passive import (
    crtsh,
    sources,
    wayback,
)
from service.recon_pipeline.pipelines.subdomain_domain_wildcards.passive.sources import (
    DOCKER_SOURCES,
    HTTP_SOURCES,
)

APEX = "qbsco.net"


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #


def test_registry_contents() -> None:
    assert "amass" not in sources.SUBDOMAIN_SOURCES
    assert set(sources.RELATION_SOURCES) == {"amass"}
    assert set(sources.ALL_SOURCES) == set(sources.DOCKER_SOURCES) | set(
        sources.HTTP_SOURCES
    )


def test_get_source_unknown_raises_with_guidance() -> None:
    with pytest.raises(KeyError, match="unknown passive source"):
        sources.get_source("nmap")


def test_select_sources_only_and_skip() -> None:
    assert sources.select_sources(only=["crtsh", "subfinder"]) == ["crtsh", "subfinder"]
    assert "amass" not in sources.select_sources(skip=["amass"])
    assert "chaos" not in sources.select_sources(skip=["chaos", "amass"])


def test_select_sources_rejects_unknown_names() -> None:
    with pytest.raises(KeyError):
        sources.select_sources(only=["nope"])
    with pytest.raises(KeyError, match="unknown source"):
        sources.select_sources(skip=["nope"])


def test_describe_sources_covers_everything() -> None:
    rows = sources.describe_sources()
    assert {row["name"] for row in rows} == set(sources.ALL_SOURCES)
    assert all(row["flavour"] for row in rows)


# --------------------------------------------------------------------------- #
# Docker source execution
# --------------------------------------------------------------------------- #


def _stub_container(monkeypatch, *, exit_code: int = 0, raises: Exception | None = None):
    """Replace ``run_container`` and return the kwargs of the last call."""
    calls: list[dict] = []

    def fake_run_container(**kwargs):
        calls.append(kwargs)
        if raises is not None:
            raise raises
        Path(kwargs["stdout_path"]).write_text("app.qbsco.net\n", encoding="utf-8")
        Path(kwargs["stderr_path"]).write_text("", encoding="utf-8")
        return docker_tool.ContainerRun(
            name=kwargs.get("name", "x"),
            image=kwargs["image"],
            exit_code=exit_code,
            seconds=1.5,
            stdout_path=Path(kwargs["stdout_path"]),
            stderr_path=Path(kwargs["stderr_path"]),
        )

    monkeypatch.setattr(sources, "run_container", fake_run_container)
    monkeypatch.setattr(sources, "docker_available", lambda *a, **k: True)
    return calls


@pytest.mark.parametrize(
    ("name", "image", "expected_args"),
    [
        ("subfinder", "projectdiscovery/subfinder:v2.14.0", ["-d", APEX, "-silent"]),
        ("assetfinder", "lotuseatersec/assetfinder:latest", ["--subs-only", APEX]),
        ("findomain", "edu4rdshl/findomain:latest", ["-t", APEX, "-q"]),
    ],
)
def test_docker_source_builds_expected_command(
    monkeypatch, tmp_path, name: str, image: str, expected_args: list[str]
) -> None:
    calls = _stub_container(monkeypatch)

    result = sources.run_docker_source(sources.get_source(name), APEX, output_dir=tmp_path)

    assert result.ok
    assert result.hosts == 0  # filled in by the pipeline, not the runner
    assert calls[0]["image"] == image
    assert calls[0]["args"] == expected_args
    assert Path(calls[0]["stdout_path"]) == tmp_path / f"{name}.txt"
    assert Path(calls[0]["stderr_path"]) == tmp_path / f"{name}.log"


def test_amass_without_config_omits_the_config_flag(monkeypatch, tmp_path) -> None:
    """Pointing amass at a missing -config path makes it exit 1, so omit it."""
    monkeypatch.setattr(sources, "CONFIG_DIR", tmp_path / "absent-config")
    calls = _stub_container(monkeypatch)

    result = sources.run_docker_source(sources.get_source("amass"), APEX, output_dir=tmp_path)

    call = calls[0]
    assert result.ok
    assert call["image"] == "caffix/amass"
    assert "-config" not in call["args"]
    assert "-passive" in call["args"]
    assert call["args"][call["args"].index("-timeout") + 1].isdigit()
    assert call["volumes"] == []
    assert call["dns"] == ["8.8.8.8", "1.1.1.1"]


def test_amass_with_config_mounts_it_read_only(monkeypatch, tmp_path) -> None:
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    (config_dir / sources.AMASS_CONFIG_FILE).write_text(
        "options:\n  datasources: /home/user/.config/amass/datasources.yaml\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(sources, "CONFIG_DIR", config_dir)
    calls = _stub_container(monkeypatch)

    sources.run_docker_source(sources.get_source("amass"), APEX, output_dir=tmp_path)

    call = calls[0]
    assert "-config" in call["args"]
    assert call["args"][call["args"].index("-config") + 1] == "/home/user/.config/amass/config.yaml"
    assert call["volumes"] == [(config_dir, "/home/user/.config/amass", "ro")]


def test_amass_preflight_warns_without_config(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(sources, "CONFIG_DIR", tmp_path / "absent-config")

    warnings = sources._amass_preflight()

    assert len(warnings) == 1
    assert "keyless" in warnings[0]


def test_amass_preflight_is_silent_with_config(monkeypatch, tmp_path) -> None:
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    (config_dir / sources.AMASS_CONFIG_FILE).write_text("", encoding="utf-8")
    monkeypatch.setattr(sources, "CONFIG_DIR", config_dir)

    assert sources._amass_preflight() == []


def test_chaos_is_skipped_without_key(monkeypatch, tmp_path) -> None:
    monkeypatch.delenv("CHAOS_KEY", raising=False)

    def explode(**kwargs):  # pragma: no cover - must never run
        raise AssertionError("chaos must not start a container without a key")

    monkeypatch.setattr(sources, "run_container", explode)

    result = sources.run_docker_source(sources.get_source("chaos"), APEX, output_dir=tmp_path)

    assert not result.ok
    assert result.skipped and "CHAOS_KEY" in result.skipped
    assert result.error is None


def test_docker_timeout_is_reported_not_raised(monkeypatch, tmp_path) -> None:
    _stub_container(
        monkeypatch,
        raises=docker_tool.DockerTimeoutError("budget exceeded", name="passive-findomain-1"),
    )

    result = sources.run_docker_source(
        sources.get_source("findomain"), APEX, output_dir=tmp_path, timeout=5
    )

    assert not result.ok
    assert result.error and "budget exceeded" in result.error


def test_non_zero_exit_is_reported_with_log_tail(monkeypatch, tmp_path) -> None:
    def failing_container(**kwargs):
        Path(kwargs["stdout_path"]).write_text("", encoding="utf-8")
        Path(kwargs["stderr_path"]).write_text("error: rate limited\n", encoding="utf-8")
        return docker_tool.ContainerRun(
            name="passive-subfinder-1",
            image=kwargs["image"],
            exit_code=2,
            seconds=0.5,
            stdout_path=Path(kwargs["stdout_path"]),
            stderr_path=Path(kwargs["stderr_path"]),
        )

    monkeypatch.setattr(sources, "run_container", failing_container)
    monkeypatch.setattr(sources, "docker_available", lambda *a, **k: True)

    result = sources.run_docker_source(
        sources.get_source("subfinder"), APEX, output_dir=tmp_path
    )

    assert not result.ok
    assert "exit code 2" in result.error
    assert "rate limited" in result.error


def test_run_source_checked_raises_on_failure(monkeypatch, tmp_path) -> None:
    # Patch the container runner itself so the assertion can never be satisfied
    # by a real container (and no container can be started by the test suite).
    def unavailable(**kwargs):
        raise docker_tool.DockerUnavailableError("daemon not reachable")

    monkeypatch.setattr(sources, "run_container", unavailable)

    with pytest.raises(sources.SourceRunError, match="daemon not reachable"):
        sources.run_source_checked("subfinder", APEX, output_dir=tmp_path)


def test_run_all_marks_docker_sources_skipped_when_docker_is_down(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.setattr(sources, "docker_available", lambda *a, **k: False)
    monkeypatch.setattr(
        sources,
        "run_http_source",
        lambda source, domain, **kwargs: sources.SourceResult(
            name=source.name,
            output_path=Path(kwargs["output_dir"]) / f"{source.name}.txt",
            hosts=3,
        ),
    )

    results = {r.name: r for r in sources.run_all(APEX, output_dir=tmp_path)}

    assert results["crtsh"].ok
    assert results["subfinder"].skipped == "Docker is not available"
    assert not results["subfinder"].ok


# --------------------------------------------------------------------------- #
# HTTP source execution
# --------------------------------------------------------------------------- #


def test_run_http_source_writes_sorted_host_file(tmp_path) -> None:
    source = sources.HttpSource(
        name="crtsh", fetch=lambda domain, timeout: ["b.qbsco.net", "a.qbsco.net"]
    )

    result = sources.run_http_source(source, APEX, output_dir=tmp_path)

    assert result.ok and result.hosts == 2
    assert (tmp_path / "crtsh.txt").read_text(encoding="utf-8") == (
        "a.qbsco.net\nb.qbsco.net\n"
    )


def test_run_http_source_swallows_source_exceptions(tmp_path) -> None:
    def boom(domain, timeout):
        raise RuntimeError("upstream exploded")

    source = sources.HttpSource(name="crtsh", fetch=boom)

    result = sources.run_http_source(source, APEX, output_dir=tmp_path)

    assert not result.ok
    assert "upstream exploded" in result.error


# --------------------------------------------------------------------------- #
# crt.sh parsing
# --------------------------------------------------------------------------- #


def test_crtsh_extracts_names_from_json() -> None:
    body = (
        '[{"name_value":"a.qbsco.net\\nb.qbsco.net","common_name":"a.qbsco.net"},'
        '{"name_value":"*.qbsco.net"}]'
    )
    names = crtsh.extract_names(body)
    assert set(names) == {"a.qbsco.net", "b.qbsco.net", "*.qbsco.net"}


def test_crtsh_falls_back_to_regex_on_non_json_body() -> None:
    # crt.sh answers with an HTML error page under load.
    body = '<html>error</html> ... {"name_value":"c.qbsco.net","common_name":"x"}'
    assert "c.qbsco.net" in crtsh.extract_names(body)


def test_crtsh_falls_back_to_regex_on_truncated_body() -> None:
    body = '[{"name_value":"a.qbsco.net"},{"name_value":"b.qbsco.n'  # cut mid-record
    names = crtsh.extract_names(body)
    assert "a.qbsco.net" in names


def test_crtsh_fetch_filters_out_of_scope_sans(monkeypatch) -> None:
    monkeypatch.setattr(
        crtsh,
        "fetch_text",
        lambda *a, **k: '[{"name_value":"app.qbsco.net\\nunrelated.example.org"},'
        '{"name_value":"www.qbsco.net"}]',
    )

    assert crtsh.fetch(APEX) == ["app.qbsco.net", "www.qbsco.net"]


def test_crtsh_fetch_returns_empty_when_unavailable(monkeypatch) -> None:
    monkeypatch.setattr(crtsh, "fetch_text", lambda *a, **k: None)
    assert crtsh.fetch(APEX) == []


# --------------------------------------------------------------------------- #
# Wayback parsing
# --------------------------------------------------------------------------- #


def test_wayback_extracts_hosts_from_json_rows() -> None:
    body = '[["original"],["https://app.qbsco.net/admin"],["http://www.qbsco.net/x?a=1"]]'
    assert wayback.extract_hosts(body) == ["app.qbsco.net", "www.qbsco.net"]


def test_wayback_falls_back_to_regex_on_plain_url_dump() -> None:
    body = "https://a.qbsco.net/1\nhttp://b.qbsco.net/2\n"
    assert set(wayback.extract_hosts(body)) == {"a.qbsco.net", "b.qbsco.net"}


def test_wayback_fetch_keeps_only_in_scope_hosts(monkeypatch) -> None:
    monkeypatch.setattr(
        wayback,
        "fetch_text",
        lambda *a, **k: '[["original"],["https://old.qbsco.net/x"],["https://cdn.cloudflare.com/x"]]',
    )

    assert wayback.fetch(APEX) == ["old.qbsco.net"]


def test_wayback_fetch_returns_empty_when_unavailable(monkeypatch) -> None:
    monkeypatch.setattr(wayback, "fetch_text", lambda *a, **k: None)
    assert wayback.fetch(APEX) == []


# --------------------------------------------------------------------------- #
# Subtree-query invariant (why the passive stage needs no recursion loop)
# --------------------------------------------------------------------------- #


def test_crtsh_query_is_subtree_wide(monkeypatch) -> None:
    """crt.sh must be queried with ``%.<apex>``, matching EVERY depth.

    The ``%`` suffix wildcard makes one apex query return the whole zone —
    deep names included.  This is the contract that makes a passive recursion
    loop pointless (see the stage README, "Why the passive stage does not
    recurse"): re-feeding deep findings as new seeds re-queries a subset of a
    set the apex query already covered.  If this test fails because someone
    narrowed the query (e.g. to an exact host), the passive stage LOSES depth
    and the no-recursion decision must be revisited.
    """
    captured: dict = {}

    def fake_fetch_text(url, *, params, timeout):  # noqa: ANN001
        captured["url"] = url
        captured["params"] = params
        # A depth-3 name returned for an apex-level query: set-based results.
        return '{"name_value": "a.b.c.qbsco.net\\napp.qbsco.net"}'

    monkeypatch.setattr(crtsh, "fetch_text", fake_fetch_text)

    hosts = crtsh.fetch(APEX)

    assert captured["params"]["q"] == f"%.{APEX}", captured["params"]
    # ...and the harvest really does cross label levels in a single call:
    assert hosts == ["a.b.c.qbsco.net", "app.qbsco.net"]


def test_wayback_query_is_subtree_wide(monkeypatch) -> None:
    """Wayback must use ``matchType=domain``, which matches every depth.

    Per the CDX API, ``matchType=domain`` returns captures for the domain and
    all subdomains, at any depth — same set-based contract as crt.sh above.
    """
    captured: dict = {}

    def fake_fetch_text(url, *, params, timeout):  # noqa: ANN001
        captured["params"] = params
        return '[["original"],["https://x.y.z.qbsco.net/"]]'

    monkeypatch.setattr(wayback, "fetch_text", fake_fetch_text)

    hosts = wayback.fetch(APEX)

    assert captured["params"]["matchType"] == "domain", captured["params"]
    assert captured["params"]["url"] == APEX, captured["params"]
    assert hosts == ["x.y.z.qbsco.net"]  # depth-3 name from one apex query


def test_every_source_takes_exactly_one_seed_domain() -> None:
    """No source may accept a seed *list* or a deeper seed than the apex.

    The recursion question is settled at the registry level: every source is
    run exactly once with the apex.  A source that grew a multi-seed or
    per-host API would silently change that contract, so pin the signatures.
    """
    import inspect

    for name, source in DOCKER_SOURCES.items():
        params = inspect.signature(source.args).parameters
        assert len(params) == 1, f"{name}.args must take exactly one domain"
    for name, source in HTTP_SOURCES.items():
        params = inspect.signature(source.fetch).parameters
        first = next(iter(params))
        assert first == "apex", f"{name}.fetch's first parameter must be the apex"


# --------------------------------------------------------------------------- #
# docker_tool helpers
# --------------------------------------------------------------------------- #


def test_host_path_uses_forward_slashes() -> None:
    assert docker_tool._docker_host_path(r"C:\Users\me\config") == "C:/Users/me/config"
    assert docker_tool._docker_host_path(Path("/opt/config")) == "/opt/config"


def test_child_env_sets_msys_no_pathconv_on_git_bash(monkeypatch) -> None:
    monkeypatch.setenv("MSYSTEM", "MINGW64")
    assert docker_tool._child_env()["MSYS_NO_PATHCONV"] == "1"


def test_child_env_leaves_posix_alone(monkeypatch) -> None:
    import os

    monkeypatch.delenv("MSYSTEM", raising=False)
    monkeypatch.setattr(os, "name", "posix")
    assert "MSYS_NO_PATHCONV" not in docker_tool._child_env()


def test_read_tail(tmp_path) -> None:
    path = tmp_path / "tool.log"
    path.write_text("1\n2\n3\n4\n", encoding="utf-8")
    assert docker_tool.read_tail(path, 2) == "3\n4"
    assert docker_tool.read_tail(tmp_path / "missing.log") == ""


def test_docker_available_caches_result(monkeypatch) -> None:
    calls = {"n": 0}

    def fake_run(*args, **kwargs):
        calls["n"] += 1
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="29.0")

    monkeypatch.setattr(docker_tool.subprocess, "run", fake_run)
    monkeypatch.setattr(docker_tool, "_docker_ok", None)

    assert docker_tool.docker_available()
    assert docker_tool.docker_available()
    assert calls["n"] == 1  # probe ran once


def test_docker_available_false_when_probe_fails(monkeypatch) -> None:
    def fake_run(*args, **kwargs):
        raise FileNotFoundError("no docker")

    monkeypatch.setattr(docker_tool.subprocess, "run", fake_run)
    monkeypatch.setattr(docker_tool, "_docker_ok", None)

    assert not docker_tool.docker_available()
    with pytest.raises(docker_tool.DockerUnavailableError):
        docker_tool.require_docker()


def test_run_container_requires_docker(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(docker_tool, "docker_available", lambda *a, **k: False)

    with pytest.raises(docker_tool.DockerUnavailableError):
        docker_tool.run_container(
            image="alpine",
            args=["echo", "hi"],
            stdout_path=tmp_path / "o.txt",
            stderr_path=tmp_path / "e.txt",
        )


def test_force_remove_never_raises(monkeypatch) -> None:
    def fake_run(*args, **kwargs):
        raise OSError("docker gone")

    monkeypatch.setattr(docker_tool.subprocess, "run", fake_run)
    assert docker_tool.force_remove("some-container") is None
