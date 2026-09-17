"""
Tests for :mod:`...active.resolve` — artefact naming, tool output, and the engines.

The active stage's answers all come through this module, and until now it was only
exercised indirectly through the pipeline tests.  What is pinned here is the part
that decides *what the stage believes resolved*: the two file readers (a massdns
``-w`` output and a ``--write-wildcards`` output), the shared failure handling
around an engine invocation, and the recursion candidate derivation that decides
which parents get a second round of queries.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from service.recon_pipeline.asset_pipelines.subdomain_domain_wildcards.active import resolve
from service.recon_pipeline.asset_pipelines.subdomain_domain_wildcards.passive.docker_tool import (
    ContainerRun,
    DockerTimeoutError,
    DockerUnavailableError,
)


def context(tmp_path: Path, **overrides) -> resolve.ResolveContext:
    base = dict(
        apex="example.com",
        output_dir=tmp_path,
        resolvers=["1.1.1.1"],
        trusted=["8.8.8.8"],
        timeout=30.0,
    )
    base.update(overrides)
    return resolve.ResolveContext(**base)


class FakeRunner:
    """Writes the stdout a tool would print; reports a scripted outcome.

    ``stdout`` is what lands in the captured stdout file.  That file *is* the
    result for engines that print to stdout (shuffledns), so a fake that wrote
    nothing there would make those engines look like they found nothing.
    """

    def __init__(self, *, ok: bool = True, raises: BaseException | None = None,
                 exit_code: int = 0, log_tail: str = "", stdout: str = "") -> None:
        self.ok = ok
        self.raises = raises
        self.exit_code = exit_code
        self.log_tail = log_tail
        self.stdout = stdout
        self.calls: list[dict] = []

    def __call__(self, tool, args, *, output_dir, timeout=None, suffix="", stdout_name=None, **_kwargs):  # noqa: ANN001
        self.calls.append({"tool": tool, "args": list(args), "suffix": suffix, "stdout_name": stdout_name})
        if self.raises is not None:
            raise self.raises
        out = Path(output_dir, stdout_name or f"stdout{suffix}.txt")
        err = Path(output_dir, f"stderr{suffix}.log")
        out.write_text(self.stdout or self.log_tail, encoding="utf-8")
        err.write_text(self.log_tail, encoding="utf-8")
        return ContainerRun(
            name="fake", image="img",
            exit_code=self.exit_code if not self.ok else 0,
            seconds=0.7, stdout_path=out, stderr_path=err,
        )


@pytest.fixture
def runner(monkeypatch):
    def install(fake: FakeRunner) -> FakeRunner:
        monkeypatch.setattr(resolve, "run_tool", fake)
        return fake

    return install


# --------------------------------------------------------------------------- #
# Artefact naming and writing
# --------------------------------------------------------------------------- #


def test_a_phase_label_namespaces_every_artefact_it_touches() -> None:
    """Recursion re-runs the same engine; without labels it would overwrite."""
    plain = context(Path("."))
    labelled = context(Path("."), label="recursive-1")

    assert resolve.phase_name("puredns.txt", plain) == "puredns.txt"
    assert resolve.phase_name("puredns.txt", labelled) == "puredns-recursive-1.txt"
    assert resolve.phase_name("candidates.txt", labelled) == "candidates-recursive-1.txt"
    assert resolve.phase_name("noextension", labelled) == "noextension-recursive-1"


def test_write_list_file_preserves_the_order_it_was_given(tmp_path: Path) -> None:
    """Recursion shortlists the *first* N words, so ordering is load-bearing."""
    path = resolve.write_list_file(tmp_path / "words.txt", ["z", "a", "m"])
    assert path.read_text(encoding="utf-8") == "z\na\nm\n"


def test_write_list_file_drops_blanks_and_creates_the_directory(tmp_path: Path) -> None:
    path = resolve.write_list_file(tmp_path / "nested" / "words.txt", ["a", "", "b"])
    assert path.read_text(encoding="utf-8") == "a\nb\n"


def test_write_list_file_leaves_no_temporary_behind(tmp_path: Path) -> None:
    resolve.write_list_file(tmp_path / "words.txt", ["a"])
    assert [entry.name for entry in tmp_path.iterdir()] == ["words.txt"]


def test_a_context_without_trusted_resolvers_skips_validation() -> None:
    """An empty trusted file would make the engine validate against nothing."""
    assert context(Path(".")).trusted_path is not None
    assert context(Path("."), trusted=[]).trusted_path is None


# --------------------------------------------------------------------------- #
# Reading tool output
# --------------------------------------------------------------------------- #


def test_a_resolve_output_file_is_canonicalised_and_scoped_to_the_apex(tmp_path: Path) -> None:
    """Only the apex's own names count, whatever the engine happened to print."""
    path = tmp_path / "puredns.txt"
    path.write_text(
        "\n".join(["API.Example.COM.", "dev.example.com", "a.b.example.com", "other.test", "", "not a host"]),
        encoding="utf-8",
    )

    assert resolve.read_resolved_file(path, "example.com") == {
        "api.example.com",
        "dev.example.com",
        "a.b.example.com",
    }


def test_a_missing_resolve_output_file_is_empty_not_fatal(tmp_path: Path) -> None:
    assert resolve.read_resolved_file(tmp_path / "missing.txt", "example.com") == set()


def test_a_wildcard_file_accepts_both_forms_the_engines_have_printed(tmp_path: Path) -> None:
    path = tmp_path / "wildcards.txt"
    path.write_text("\n".join(["*.example.com", "example.com", "*.DEV.example.com", "nonsense", ""]), encoding="utf-8")

    assert resolve.read_wildcard_file(path) == ["dev.example.com", "example.com"]


def test_a_missing_wildcard_file_is_empty_not_fatal(tmp_path: Path) -> None:
    assert resolve.read_wildcard_file(tmp_path / "missing.txt") == []


def test_stdout_capture_is_read_by_artefact_name(tmp_path: Path) -> None:
    (tmp_path / "shuffledns-resolve.txt").write_text("a.example.com\nb.example.com\n", encoding="utf-8")
    assert resolve.read_stdout_output(context(tmp_path), "shuffledns-resolve.txt") == [
        "a.example.com",
        "b.example.com",
    ]
    assert resolve.read_stdout_output(context(tmp_path), "nope.txt") == []


# --------------------------------------------------------------------------- #
# The engine registry
# --------------------------------------------------------------------------- #


def test_every_engine_is_described_and_addressable() -> None:
    described = resolve.describe_engines()
    assert {row["name"] for row in described} == {"puredns", "shuffledns"}
    assert all(row["description"] for row in described)


def test_engine_aliases_resolve_to_the_real_engine() -> None:
    assert resolve.get_engine("dnsx").name == "shuffledns"
    assert resolve.get_engine("massdns").name == "puredns"
    assert resolve.get_engine("puredns").name == "puredns"


def test_an_unknown_engine_names_the_known_ones() -> None:
    with pytest.raises(KeyError, match="unknown engine 'bogus'"):
        resolve.get_engine("bogus")


def test_selecting_an_unknown_engine_raises_rather_than_substituting() -> None:
    """Quietly running a different engine would change results invisibly."""
    with pytest.raises(KeyError):
        resolve.select_engine(["bogus", "puredns"])


def test_selecting_with_no_request_uses_the_default() -> None:
    assert resolve.select_engine([]).name == resolve.DEFAULT_ENGINE
    assert resolve.select_engine(["shuffledns"]).name == "shuffledns"


# --------------------------------------------------------------------------- #
# Candidate derivation and recursion
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("example.com", 0),
        ("api.example.com", 1),
        ("api.dev.example.com", 2),
        ("other.test", 0),
        ("notexample.com", 0),
    ],
)
def test_depth_is_counted_relative_to_the_apex(name: str, expected: int) -> None:
    assert resolve.depth_below(name, "example.com") == expected


def test_apex_candidates_are_first_level_and_deduplicated_in_order() -> None:
    assert resolve.apex_candidates(["www", "api", "www"], "example.com") == [
        "www.example.com",
        "api.example.com",
    ]


def test_recursion_parents_include_ancestors_that_never_resolved() -> None:
    """A child proves the parent is a real environment even if it has no A record."""
    parents = resolve.recursion_parents(["api.dev.example.com"], "example.com")

    assert parents == ["dev.example.com"], "the intermediate level is the useful parent"
    assert "api.dev.example.com" not in parents, "one label below the parent is already depth 2"


def test_recursion_parents_prefer_hosts_that_actually_resolved() -> None:
    """A proven-live parent is likelier to answer than an unresolved ancestor."""
    parents = resolve.recursion_parents(
        ["deep.a.example.com", "b.example.com"],
        "example.com",
        prefer=["b.example.com"],
        max_depth=5,
    )
    assert parents[0] == "b.example.com"


def test_recursion_parents_are_capped_and_shallowest_first() -> None:
    """The cap keeps a level to a bounded number of parents; shallow wins ties."""
    known = [f"h{index}.a.example.com" for index in range(10)]
    parents = resolve.recursion_parents(known, "example.com", max_depth=5, max_parents=3)

    assert len(parents) == 3
    assert parents == ["a.example.com", "h0.a.example.com", "h1.a.example.com"]


def test_recursion_never_offers_the_apex() -> None:
    """The apex's children are the level-1 set, which was already queried."""
    assert resolve.recursion_parents(["example.com"], "example.com") == []
    assert resolve.recursion_parents(["example.com", "api.example.com"], "example.com") == [
        "api.example.com"
    ]


def test_recursion_never_offers_a_name_outside_the_apex() -> None:
    """Regression: an out-of-scope name used to become a parent.

    Recursion would then send DNS queries for ``word.other.test`` — traffic that
    belongs to somebody else — and ``other.test`` itself, because the ancestor
    walk climbs one label at a time regardless of scope.
    """
    assert resolve.recursion_parents(["other.test", "a.other.test"], "example.com") == []
    assert resolve.recursion_parents(
        ["notexample.com", "api.dev.example.com"], "example.com"
    ) == ["dev.example.com"]


def test_recursion_candidates_are_bounded_by_the_word_shortlist() -> None:
    """Recursion is a widening step, not an open-ended sweep."""
    candidates = resolve.recursive_candidates(
        ["dev.example.com", "stage.example.com"],
        ["api", "admin", "internal"],
        word_limit=2,
    )

    assert candidates == [
        "api.dev.example.com",
        "admin.dev.example.com",
        "api.stage.example.com",
        "admin.stage.example.com",
    ]


def test_recursion_with_no_parents_or_words_yields_nothing() -> None:
    assert resolve.recursive_candidates([], ["api"]) == []
    assert resolve.recursive_candidates(["dev.example.com"], []) == []


# --------------------------------------------------------------------------- #
# Running an engine
# --------------------------------------------------------------------------- #


def test_resolving_nothing_does_not_start_a_container(runner, tmp_path: Path) -> None:
    fake = runner(FakeRunner())
    ctx = context(tmp_path)

    assert resolve.puredns_resolve([], ctx).candidates == 0
    assert resolve.puredns_bruteforce([], ctx).candidates == 0
    assert resolve.shuffledns_resolve([], ctx).candidates == 0
    assert resolve.shuffledns_bruteforce([], ctx).candidates == 0
    assert fake.calls == []


def test_puredns_resolve_writes_candidates_and_reads_its_own_output(runner, tmp_path: Path) -> None:
    runner(FakeRunner())
    (tmp_path / resolve.RESOLVE_OUTPUT).write_text("api.example.com\n", encoding="utf-8")
    (tmp_path / resolve.RESOLVE_WILDCARDS).write_text("*.wild.example.com\n", encoding="utf-8")

    result = resolve.puredns_resolve(["api.example.com", "api.example.com"], context(tmp_path))

    assert (tmp_path / resolve.CANDIDATES_NAME).read_text(encoding="utf-8") == "api.example.com\n"
    assert result.ok is True
    assert result.resolved == {"api.example.com"}
    assert result.wildcards == ["wild.example.com"], "the engine's own wildcard list is kept"
    assert result.candidates == 1


def test_puredns_bruteforce_writes_the_wordlist_without_the_apex(runner, tmp_path: Path) -> None:
    runner(FakeRunner())
    (tmp_path / resolve.BRUTEFORCE_OUTPUT).write_text("www.example.com\n", encoding="utf-8")

    result = resolve.puredns_bruteforce(["www", "api"], context(tmp_path))

    assert (tmp_path / resolve.WORDLIST_NAME).read_text(encoding="utf-8") == "www\napi\n"
    assert result.resolved == {"www.example.com"}


def test_a_labelled_phase_writes_labelled_artefacts(runner, tmp_path: Path) -> None:
    runner(FakeRunner())
    (tmp_path / "puredns-recursive-1.txt").write_text("deep.api.example.com\n", encoding="utf-8")

    result = resolve.puredns_resolve(["deep.api.example.com"], context(tmp_path, label="recursive-1"))

    assert (tmp_path / "candidates-recursive-1.txt").exists()
    assert result.resolved == {"deep.api.example.com"}


def test_shuffledns_reads_its_stdout_capture(runner, tmp_path: Path) -> None:
    """shuffledns writes results to stdout, so the capture *is* the output."""
    runner(FakeRunner(stdout="a.example.com\nb.example.com\n"))

    result = resolve.shuffledns_resolve(["a.example.com", "b.example.com"], context(tmp_path))

    assert result.resolved == {"a.example.com", "b.example.com"}
    assert result.wildcards == [], "shuffledns reports no wildcard list of its own"


def test_shuffledns_bruteforce_passes_the_wordlist_as_a_file(runner, tmp_path: Path) -> None:
    fake = runner(FakeRunner(stdout="www.example.com\n"))

    result = resolve.shuffledns_bruteforce(["www"], context(tmp_path))

    assert result.resolved == {"www.example.com"}
    args = fake.calls[0]["args"]
    assert args[args.index("-w") + 1] == "/work/wordlist.txt", "the wordlist is mounted, not inlined"


def test_a_timeout_is_reported_with_the_candidate_count(runner, tmp_path: Path) -> None:
    runner(FakeRunner(raises=DockerTimeoutError("puredns exceeded 900s", name="res")))
    result = resolve.puredns_resolve(["a.example.com", "b.example.com"], context(tmp_path))

    assert result.ok is False
    assert "900s" in result.error
    assert result.candidates == 2
    assert result.resolved == set()


def test_no_docker_is_reported_rather_than_raised(runner, tmp_path: Path) -> None:
    runner(FakeRunner(raises=DockerUnavailableError("cannot connect to the Docker daemon")))
    result = resolve.puredns_bruteforce(["www"], context(tmp_path))
    assert result.ok is False and "Docker daemon" in result.error


def test_a_non_zero_exit_reports_the_reason_and_still_names_the_output(runner, tmp_path: Path) -> None:
    """The raw output is the evidence for a failure, so the path is kept."""
    runner(FakeRunner(ok=False, exit_code=1, log_tail="fatal: no resolvers"))
    result = resolve.puredns_resolve(["a.example.com"], context(tmp_path))

    assert result.ok is False
    assert "exit code 1" in result.error
    assert result.output is not None, "a failed run still points at its output file"
    assert result.resolved == set()


def test_a_successful_run_records_how_long_it_took(runner, tmp_path: Path) -> None:
    runner(FakeRunner())
    result = resolve.puredns_resolve(["a.example.com"], context(tmp_path))
    assert result.seconds > 0
    assert result.engine == "puredns" and result.mode == "resolve"


def test_the_engine_summary_reports_counts_and_timing() -> None:
    payload = resolve.EngineResult(
        engine="puredns",
        mode="bruteforce",
        candidates=10,
        resolved={"a.example.com", "b.example.com"},
        wildcards=["w.example.com"],
        seconds=1.239,
        output="out/puredns.txt",
    ).to_dict()

    assert payload["resolved"] == 2, "the count, not the set"
    assert payload["candidates"] == 10
    assert payload["wildcards"] == ["w.example.com"]
    assert payload["seconds"] == 1.24
    assert "error" not in payload


def test_a_failed_engine_summary_carries_the_error() -> None:
    payload = resolve.EngineResult(engine="puredns", mode="resolve", ok=False, error="boom").to_dict()
    assert payload["ok"] is False and payload["error"] == "boom"
