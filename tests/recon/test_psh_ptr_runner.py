"""
Tests for :func:`port_service_host.passive.ptr.lookup` — the reverse-DNS *runner*.

The parser has its own tests; what this file pins is the part that only exists
when the tool actually runs: that the scan set is deduplicated and canonicalised
before it is written, that the container is asked for exactly the right command,
and that each of the four failure shapes (timeout, no Docker, non-zero exit,
misbehaving output) produces a result that says what happened instead of an empty
name map that reads like "nobody has a PTR record".

``dnsx`` is never invoked: the runner is injected, and the fake writes the stdout
file the real tool would have written.  That is also what keeps the module's real
file-handling exercised rather than mocked away.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from service.recon_pipeline.asset_pipelines.port_service_host.passive import ptr
from service.recon_pipeline.asset_pipelines.subdomain_domain_wildcards.passive.docker_tool import (
    ContainerRun,
    DockerTimeoutError,
    DockerUnavailableError,
)


# --------------------------------------------------------------------------- #
# Fakes
# --------------------------------------------------------------------------- #


class FakeRunner:
    """Records the invocation and writes the stdout the real tool would write."""

    def __init__(
        self,
        *,
        lines: list[dict] | None = None,
        text: str | None = None,
        exit_code: int = 0,
        seconds: float = 1.0,
        raises: BaseException | None = None,
        log_tail: str = "",
    ) -> None:
        self.lines = lines if lines is not None else [{"host": "8.8.8.8", "ptr": ["dns.google"]}]
        self.text = text
        self.exit_code = exit_code
        self.seconds = seconds
        self.raises = raises
        self.log_tail = log_tail
        self.calls: list[dict] = []

    def __call__(self, tool, args, *, output_dir, timeout, stdout_name, stderr_name, suffix=""):  # noqa: ANN001, ANN003
        self.calls.append(
            {
                "tool": tool,
                "args": list(args),
                "output_dir": Path(output_dir),
                "timeout": timeout,
                "stdout_name": stdout_name,
                "stderr_name": stderr_name,
                "suffix": suffix,
            }
        )
        stdout_path = Path(output_dir) / stdout_name
        stderr_path = Path(output_dir) / stderr_name
        if self.raises is not None:
            raise self.raises
        body = self.text if self.text is not None else "\n".join(
            json.dumps(line) for line in self.lines
        )
        stdout_path.write_text(body, encoding="utf-8")
        stderr_path.write_text(self.log_tail, encoding="utf-8")
        return ContainerRun(
            name="fake",
            image="port_service_host_image",
            exit_code=self.exit_code,
            seconds=self.seconds,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
        )


@pytest.fixture
def runner():
    def build(**kwargs) -> FakeRunner:
        return FakeRunner(**kwargs)

    return build


# --------------------------------------------------------------------------- #
# Nothing to do
# --------------------------------------------------------------------------- #


def test_no_addresses_is_a_skip_not_a_run(tmp_path: Path) -> None:
    """A skip must never look like a pass — the report distinguishes them."""
    calls: list[object] = []

    result = ptr.lookup([], output_dir=tmp_path, run=lambda *a, **k: calls.append(a))

    assert result.ok is True
    assert result.skipped == "no addresses to reverse-resolve"
    assert result.ran is False
    assert calls == []
    assert result.queried == 0


def test_blank_and_duplicate_addresses_do_not_count_as_input(tmp_path: Path) -> None:
    """Whitespace is not an address, and one invocation should ask once."""
    calls: list[object] = []

    result = ptr.lookup(
        ["", "   ", "not-an-ip"], output_dir=tmp_path, run=lambda *a, **k: calls.append(a)
    )

    assert result.skipped == "no addresses to reverse-resolve"
    assert calls == []


# --------------------------------------------------------------------------- #
# The invocation
# --------------------------------------------------------------------------- #


def test_the_addresses_are_canonicalised_deduplicated_and_written_once(tmp_path: Path, runner) -> None:
    fake = runner()
    ptr.lookup(["8.8.8.8", " 8.8.8.8 ", "8.8.8.8", "2001:4860:4860::8888"],
               output_dir=tmp_path, run=fake)

    written = (tmp_path / "ptr-input.txt").read_text(encoding="utf-8").splitlines()
    assert written == ["8.8.8.8", "2001:4860:4860::8888"]
    assert fake.calls[0]["args"].count("8.8.8.8") == 0, "the tool reads a file, not argv"


def test_the_invocation_asks_dnsx_for_json_ptr_records(tmp_path: Path, runner) -> None:
    """The plain stream echoes the input list; only ``-json`` carries names."""
    fake = runner()
    ptr.lookup(["8.8.8.8"], output_dir=tmp_path, run=fake)

    call = fake.calls[0]
    assert call["tool"] == ptr.TOOL == "dnsx"
    args = call["args"]
    assert "-ptr" in args
    assert "-json" in args
    # The addresses arrive as a mounted file, so ``-l`` must be followed by the
    # container-side path — and that is the only way the scan set reaches dnsx.
    assert args[args.index("-l") + 1] == "/work/ptr-input.txt"


def test_the_validated_resolver_pool_is_mounted_and_passed(tmp_path: Path, runner) -> None:
    fake = runner()
    resolvers = tmp_path / "resolvers.txt"
    resolvers.write_text("1.1.1.1\n", encoding="utf-8")

    ptr.lookup(["8.8.8.8"], output_dir=tmp_path, run=fake, resolvers=resolvers)

    args = fake.calls[0]["args"]
    assert args[args.index("-r") + 1] == "/work/resolvers.txt", (
        "the pool must be referenced at its mounted path, not the host path"
    )


def test_without_a_resolver_pool_no_resolver_flag_is_sent(tmp_path: Path, runner) -> None:
    """Absent pool is a documented degradation, not a failure — so no ``-r``."""
    fake = runner()
    ptr.lookup(["8.8.8.8"], output_dir=tmp_path, run=fake)
    assert "-r" not in fake.calls[0]["args"]
    assert fake.calls[0]["args"][fake.calls[0]["args"].index("-l") + 1] == "/work/ptr-input.txt"


def test_the_suffix_namespaces_every_artefact(tmp_path: Path, runner) -> None:
    """Ladder rungs re-run the tool; their outputs must not overwrite each other."""
    fake = runner()
    result = ptr.lookup(["8.8.8.8"], output_dir=tmp_path, run=fake, suffix="l2-")

    assert fake.calls[0]["suffix"] == "l2-"
    assert (tmp_path / "l2-ptr-input.txt").exists()
    assert (tmp_path / "l2-ptr.jsonl").exists()
    assert result.stdout_path == tmp_path / "l2-ptr.jsonl"
    assert result.log_path == tmp_path / "l2-ptr.log"


def test_the_output_directory_is_created_if_missing(tmp_path: Path, runner) -> None:
    target = tmp_path / "nested" / "out"
    ptr.lookup(["8.8.8.8"], output_dir=target, run=runner())
    assert target.is_dir()


# --------------------------------------------------------------------------- #
# Success
# --------------------------------------------------------------------------- #


def test_a_successful_run_returns_the_names_and_counts(tmp_path: Path, runner) -> None:
    fake = runner(
        lines=[
            {"host": "8.8.8.8", "ptr": ["dns.google"]},
            {"host": "1.1.1.1", "ptr": ["one.one.one.one"]},
            {"host": "9.9.9.9", "ptr": []},
        ],
        seconds=1.5,
    )

    result = ptr.lookup(["8.8.8.8", "1.1.1.1", "9.9.9.9"], output_dir=tmp_path, run=fake)

    assert result.ok is True
    assert result.ran is True
    assert result.queried == 3
    assert result.answered == 2, "an address with no PTR name is not an answer"
    assert result.names_for("8.8.8.8") == ["dns.google"]
    assert result.names_for("9.9.9.9") == []
    assert result.seconds == 1.5


def test_garbage_output_yields_no_names_without_failing(tmp_path: Path, runner) -> None:
    """A tool that prints nothing parseable is not a tool that failed."""
    fake = runner(text="not json at all\n\n{\"broken\": ")
    result = ptr.lookup(["8.8.8.8"], output_dir=tmp_path, run=fake)
    assert result.ok is True
    assert result.names == {}
    assert result.queried == 1
    assert result.answered == 0


# --------------------------------------------------------------------------- #
# Failure shapes — each must be distinguishable from "nobody has a PTR record"
# --------------------------------------------------------------------------- #


def test_a_timeout_is_reported_as_a_failure_with_the_address_count(tmp_path: Path, runner) -> None:
    fake = runner(
        raises=DockerTimeoutError("dnsx exceeded 900s", name="psh-ptr")
    )

    result = ptr.lookup(["8.8.8.8", "1.1.1.1"], output_dir=tmp_path, run=fake)

    assert result.ok is False
    assert "900s" in result.error
    assert result.queried == 2
    assert result.names == {}


def test_no_docker_is_reported_as_a_failure(tmp_path: Path, runner) -> None:
    fake = runner(raises=DockerUnavailableError("cannot connect to the Docker daemon"))
    result = ptr.lookup(["8.8.8.8"], output_dir=tmp_path, run=fake)

    assert result.ok is False
    assert "Docker daemon" in result.error
    assert result.queried == 1


def test_a_non_zero_exit_carries_the_log_tail(tmp_path: Path, runner) -> None:
    """The exit code alone rarely explains anything; the log usually does."""
    fake = runner(exit_code=1, seconds=0.4, log_tail="line one\nfailed to load resolvers")

    result = ptr.lookup(["8.8.8.8"], output_dir=tmp_path, run=fake)

    assert result.ok is False
    assert "exit code 1" in result.error
    assert "failed to load resolvers" in result.error
    assert result.seconds == 0.4


def test_a_non_zero_exit_with_an_empty_log_has_no_dangling_separator(tmp_path: Path, runner) -> None:
    fake = runner(exit_code=2, log_tail="")
    result = ptr.lookup(["8.8.8.8"], output_dir=tmp_path, run=fake)
    assert result.error == "exit code 2"
    assert not result.error.endswith(":")


def test_a_failed_run_never_reports_names_even_if_output_exists(tmp_path: Path, runner) -> None:
    """Partial output from a failed run must not be presented as a result."""
    fake = runner(exit_code=1, lines=[{"host": "8.8.8.8", "ptr": ["ghost.example"]}])
    result = ptr.lookup(["8.8.8.8"], output_dir=tmp_path, run=fake)
    assert result.ok is False
    assert result.names == {}


# --------------------------------------------------------------------------- #
# The report block
# --------------------------------------------------------------------------- #


def test_summarise_reports_queries_answers_and_total_names(tmp_path: Path, runner) -> None:
    fake = runner(
        lines=[
            {"host": "8.8.8.8", "ptr": ["dns.google", "dns2.google"]},
            {"host": "1.1.1.1", "ptr": ["one.one.one.one"]},
        ]
    )
    result = ptr.lookup(["8.8.8.8", "1.1.1.1", "9.9.9.9"], output_dir=tmp_path, run=fake)

    block = ptr.summarise(result)
    assert block == {"queried": 3, "answered": 2, "names": 3, "skipped": None}


def test_to_dict_omits_absent_fields_and_rounds_seconds(tmp_path: Path, runner) -> None:
    result = ptr.lookup(["8.8.8.8"], output_dir=tmp_path, run=runner(seconds=1.239))
    payload = result.to_dict()
    assert payload["seconds"] == 1.24
    assert payload["ok"] is True
    assert "error" not in payload and "skipped" not in payload
    assert payload["output"].endswith("ptr.jsonl")


def test_a_skipped_run_says_so_in_its_dict() -> None:
    payload = ptr.PtrResult(skipped="no addresses to reverse-resolve").to_dict()
    assert payload["skipped"] == "no addresses to reverse-resolve"
    assert payload["queried"] == 0
    assert "output" not in payload, "a run that never started has no artefact"


def test_a_failed_run_carries_its_error_into_the_report() -> None:
    payload = ptr.PtrResult(ok=False, error="exit code 1: bad resolvers", queried=2).to_dict()
    assert payload["ok"] is False
    assert payload["error"] == "exit code 1: bad resolvers"
    assert payload["queried"] == 2


def test_the_default_runner_is_the_registry_and_uses_the_real_tool_name(
    tmp_path: Path, monkeypatch, runner
) -> None:
    """Regression: the module's name and the *tool's* name are different strings.

    This is the one failure that cannot appear before a real run: the runner looks
    the tool up in the stage registry, so passing the module's own name (``ptr``)
    fails only when a container would have been started — which is how it was
    found, in a live run, rather than by any test.  The lazy import is what makes
    the wiring testable at all.
    """
    from service.recon_pipeline.asset_pipelines.port_service_host.active import tools as psh_tools

    fake = runner()
    monkeypatch.setattr(psh_tools, "run_tool", fake)

    result = ptr.lookup(["8.8.8.8"], output_dir=tmp_path)  # run=None: the real path

    assert fake.calls, "the default runner must have been reached"
    assert fake.calls[0]["tool"] == "dnsx"
    assert fake.calls[0]["tool"] != ptr.NAME, "the module name is not a tool name"
    assert result.ok is True
