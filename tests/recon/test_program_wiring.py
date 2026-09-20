"""The program seam, end to end hermetically: runner context assembly and the
CLI's fail-fast engagement loop.

No Postgres required: the loader is injected at the module boundary, and every
platform service the runner builds degrades gracefully without one — which is
exactly the situation a program run is in on a machine that only collected.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from types import SimpleNamespace

import pytest

import service.recon_pipeline.cli as cli
from service.recon_pipeline.platform import runner as runner_mod
from service.recon_pipeline.platform.contract import (
    BasePipeline,
    Manifest,
    RunContext,
    Stage,
)
from service.recon_pipeline.platform.programs import ProgramScope, ProgramScopeError
from service.recon_pipeline.platform.observability import RunRegistry
from service.recon_pipeline.platform.registry import Registration, Registry


def _manifest(name: str) -> Manifest:
    return Manifest(
        name=name,
        title=f"{name} test manifest",
        asset_types=("Test",),
        stages=(Stage("collect", "collect"),),
        passive_only=True,
    )


class _StubHealth:
    def __init__(self) -> None:
        self.available = False
        self.reason = "redis stubbed out for this test"

    def to_dict(self) -> dict:
        return {"available": False, "reason": self.reason}


class _StubRedisService:
    """The two Redis-backed services, without the 17-second Windows SYN wait.

    A closed localhost port does not refuse instantly on Windows — each real
    ping waits out a dropped SYN, and ``build_context`` constructs two Redis
    services. The degrade these tests must exercise is the *program* seam's;
    Redis degrade is already covered hermetically in ``test_platform.py``, so
    the services are replaced at their modules with the same health shape.
    """

    def __init__(self, *args, **kwargs) -> None:
        self.health = _StubHealth()
        self.available = False

    def summary(self) -> dict:
        return {"decisions": {}}


@pytest.fixture(autouse=True)
def _instant_services(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "service.recon_pipeline.platform.cache.HotCache", _StubRedisService
    )
    monkeypatch.setattr(
        "service.recon_pipeline.platform.queueing.Queue", _StubRedisService
    )


def _scope(**overrides) -> ProgramScope:
    fields = {
        "handle": "acme",
        "domains": ("acme.test", "other.net"),
        "networks": ("45.60.0.0/16",),
        "addresses": (),
        "unsupported": (),
        "instructions": (),
    }
    fields.update(overrides)
    return ProgramScope(**fields)


def _patch_loader(
    monkeypatch: pytest.MonkeyPatch,
    scope: ProgramScope | None,
    error: str | None = None,
) -> list[str]:
    """Replace the loader at its module boundary; record the handles asked for."""
    handles: list[str] = []

    class _Loader:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def load(self, handle: str) -> ProgramScope:
            handles.append(handle)
            if error is not None:
                raise ProgramScopeError(error)
            assert scope is not None
            return scope

    monkeypatch.setattr(
        "service.recon_pipeline.platform.programs.ProgramScopeLoader", _Loader
    )
    return handles


# --------------------------------------------------------------------------- #
# the runner: a program run's context carries the program
# --------------------------------------------------------------------------- #


def test_build_context_applies_the_program_and_writes_the_scope_file(
    tmp_path: Path,
) -> None:
    runner = runner_mod.Runner(output_root=tmp_path)

    context, _services = runner.build_context(
        "acme.test", output_dir=tmp_path / "run", program_scope=_scope()
    )

    program = context.program
    assert program is not None and program["handle"] == "acme"
    assert program["declared_domains"] == 2
    assert program["declared_networks"] == 1
    scope_file = Path(program["scope_file"])
    assert scope_file.is_file()
    assert "45.60.0.0/16" in scope_file.read_text(encoding="utf-8")
    # The declarations landed on the engine, not just in the report block.
    assert context.scope.check_host("api.acme.test").state == "in_scope"
    assert context.scope.check_address("45.60.1.2").state == "in_scope"


def test_build_context_without_a_program_is_unchanged(tmp_path: Path) -> None:
    runner = runner_mod.Runner(output_root=tmp_path)

    context, _services = runner.build_context("acme.test", output_dir=tmp_path / "run")

    assert context.program is None
    # Only the apex is declared; the program's other domain is not.
    assert context.scope.check_host("other.net").state == "needs_review"


def test_a_program_run_records_itself_in_the_run_summary_and_registry(
    tmp_path: Path,
) -> None:
    class _Pipeline(BasePipeline):
        manifest = _manifest("stub")

        def __init__(self) -> None:
            self.programs: list = []

        def run(self, stage: str, context: RunContext) -> dict:
            self.programs.append(context.program)
            return {"ok": True, "counts": {}}

    pipeline = _Pipeline()
    registry = Registry(
        [Registration(name="stub", manifest=pipeline.manifest, pipeline=pipeline, module=object())]
    )
    result = runner_mod.Runner(registry=registry, output_root=tmp_path).run(
        "acme.test", program_scope=_scope(domains=("acme.test",))
    )

    assert result.ok is True
    assert result.summary["program"]["handle"] == "acme"
    assert result.summary["program"]["declared_domains"] == 1
    assert pipeline.programs[0]["scope_file"]
    # The engagement is findable in the timeline.
    rows = RunRegistry(tmp_path / runner_mod.RUNS_DIRNAME).history(limit=3)
    assert rows[0]["target"] == "acme.test"


# --------------------------------------------------------------------------- #
# the CLI: fail-fast, then one engagement per declared domain
# --------------------------------------------------------------------------- #


def _patch_runner(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, ProgramScope]]:
    calls: list[tuple[str, ProgramScope]] = []

    class _FakeRunner:
        def __init__(self, output_root=None, **kwargs) -> None:
            pass

        def run(self, target: str, **kwargs):
            calls.append((target, kwargs.get("program_scope")))
            return SimpleNamespace(summary={}, convergence={}, ok=True)

    monkeypatch.setattr(runner_mod, "Runner", _FakeRunner)
    return calls


def test_an_unknown_handle_ends_the_invocation_before_anything_runs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handles = _patch_loader(
        monkeypatch, None, error="unknown program handle 'ghost' — run the scraper first"
    )

    code = cli.main(["run", "--program", "ghost"])

    assert code == 2
    assert handles == ["ghost"]  # the load was attempted, nothing after it ran


def test_a_program_runs_one_engagement_per_declared_domain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_loader(monkeypatch, _scope(domains=("acme.test", "other.net")))
    calls = _patch_runner(monkeypatch)

    code = cli.main(["run", "--program", "acme"])

    assert code == 0
    assert [target for target, _scope_out in calls] == ["acme.test", "other.net"]
    scopes = dict(calls)
    # Each engagement carries only its apex's slice of the declared domains.
    assert scopes["acme.test"].domains == ("acme.test",)
    assert scopes["other.net"].domains == ("other.net",)
    # Places travel whole: both engagements carry the program's CIDR.
    assert scopes["acme.test"].networks == ("45.60.0.0/16",)
    assert scopes["other.net"].networks == ("45.60.0.0/16",)


def test_program_and_target_are_mutually_exclusive(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_loader(monkeypatch, _scope())

    code = cli.main(["run", "--program", "acme", "-t", "acme.test"])

    assert code == 2


def test_domain_selects_a_single_engagement(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_loader(monkeypatch, _scope(domains=("acme.test", "other.net")))
    calls = _patch_runner(monkeypatch)

    code = cli.main(["run", "--program", "acme", "--domain", "other.net"])

    assert code == 0
    assert [target for target, _scope_out in calls] == ["other.net"]


def test_a_domain_the_program_does_not_declare_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_loader(monkeypatch, _scope(domains=("acme.test",)))

    code = cli.main(["run", "--program", "acme", "--domain", "notours.test"])

    assert code == 2


def test_domain_without_program_is_a_usage_error() -> None:
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["run", "--domain", "acme.test"])

    assert excinfo.value.code == 2


def test_list_programs_prints_the_inventory(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        "service.recon_pipeline.platform.programs.list_programs",
        lambda *args, **kwargs: [{"handle": "acme", "scope_count": 7, "domains": 2}],
    )

    code = cli.main(["run", "--list-programs"])

    assert code == 0
    assert "acme" in capsys.readouterr().out


# --------------------------------------------------------------------------- #
# run_recon.py: the same fail-fast at the combined-report entry point
# --------------------------------------------------------------------------- #


def test_run_recon_fails_fast_on_an_unknown_handle(monkeypatch: pytest.MonkeyPatch) -> None:
    import run_recon

    _patch_loader(monkeypatch, None, error="unknown program handle 'ghost'")
    args = SimpleNamespace(program="ghost", domain=None, target=None)

    with pytest.raises(SystemExit) as excinfo:
        run_recon._run_program(args, argparse.ArgumentParser(), "20260920_0000")

    assert excinfo.value.code == 2


# --------------------------------------------------------------------------- #
# operator-authored scope: the CLI consumes --scope-file / --asset / -t
# --------------------------------------------------------------------------- #


def _write_scope_file(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "scope.txt"
    path.write_text(content, encoding="utf-8")
    return path


def _no_loader(monkeypatch: pytest.MonkeyPatch) -> None:
    """Operator scope must never touch the DB: any load attempt is a failure."""

    def _boom(*args, **kwargs):
        raise AssertionError("operator scope must not load programs from Postgres")

    monkeypatch.setattr(
        "service.recon_pipeline.platform.programs.ProgramScopeLoader", _boom
    )


def test_a_missing_scope_file_is_named_not_mistaken_for_an_empty_one(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """read_text returns \"\" for a missing file — the operator must hear the
    file is absent, not that its (nonexistent) content declares no domains."""
    _no_loader(monkeypatch)
    calls = _patch_runner(monkeypatch)

    code = cli.main(["run", "--scope-file", str(tmp_path / "absent.txt")])

    assert code == 2
    assert calls == []
    assert "not found" in capsys.readouterr().out


def test_a_scope_file_runs_one_engagement_at_its_minimal_root(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _no_loader(monkeypatch)
    calls = _patch_runner(monkeypatch)
    path = _write_scope_file(tmp_path, "# my lab\ndomain:acme.test\nsub.acme.test\n")

    code = cli.main(["run", "--scope-file", str(path)])

    assert code == 0
    assert [target for target, _s in calls] == ["acme.test"]  # sub folds into the root
    assert calls[0][1] is not None
    assert calls[0][1].domains == ("acme.test", "sub.acme.test")


def test_an_ambiguous_file_must_be_named_not_guessed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _no_loader(monkeypatch)
    calls = _patch_runner(monkeypatch)
    path = _write_scope_file(tmp_path, "acme.test\nother.net\n")

    code = cli.main(["run", "--scope-file", str(path)])

    assert code == 2
    assert calls == []


def test_minus_t_names_the_file_and_engages_it_whole(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _no_loader(monkeypatch)
    calls = _patch_runner(monkeypatch)
    path = _write_scope_file(tmp_path, "acme.test\nother.net\n")

    code = cli.main(["run", "--scope-file", str(path), "-t", "other.net"])

    assert code == 0
    assert [target for target, _s in calls] == ["other.net"]
    assert calls[0][1] is not None
    # The operator authored the file whole: nothing is sliced away.
    assert calls[0][1].domains == ("acme.test", "other.net")


def test_inline_assets_and_a_file_merge_into_one_scope(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _no_loader(monkeypatch)
    calls = _patch_runner(monkeypatch)
    path = _write_scope_file(tmp_path, "domain:acme.test\n")

    code = cli.main(
        ["run", "--scope-file", str(path), "--asset", "45.60.0.0/16", "-t", "acme.test"]
    )

    assert code == 0
    assert calls[0][1] is not None
    assert calls[0][1].domains == ("acme.test",)
    assert calls[0][1].networks == ("45.60.0.0/16",)


def test_domain_is_refused_before_the_operator_scope_is_even_parsed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """``--domain`` selects one engagement of a *program's* scope; the parser
    rejects the pair outright — the operator file is never read."""
    _no_loader(monkeypatch)
    calls = _patch_runner(monkeypatch)
    path = _write_scope_file(tmp_path, "acme.test\n")

    with pytest.raises(SystemExit) as excinfo:
        cli.main(["run", "--scope-file", str(path), "--domain", "acme.test"])

    assert excinfo.value.code == 2
    assert calls == []


def test_bare_run_is_still_the_legacy_env_target_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """``run`` with no scope inputs keeps its pre-existing meaning: the .env
    TARGET, apex-only scope, no program and no DB touch."""
    _no_loader(monkeypatch)
    calls = _patch_runner(monkeypatch)
    env_file = tmp_path / ".env"
    env_file.write_text("TARGET=envonly.test\n", encoding="utf-8")
    monkeypatch.setattr(cli, "_default_target", lambda: "envonly.test")

    code = cli.main(["run"])

    assert code == 0
    assert [target for target, scope in calls] == ["envonly.test"]
    assert calls[0][1] is None  # no program_scope — the legacy path is unchanged
