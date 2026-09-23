"""Discovery: the folder is the registration, and a bad manifest is loud.

The tests below discover the *real* technique folders — so they fail if the engine
and its registrations drift — and then build a throw-away package on disk to
exercise the skip paths, because those paths are the ones nobody notices until a
half-built folder is in the tree during a live engagement.

"Loud" is the interesting word here. The recon side's registry skips a broken
candidate with a warning, because it races many half-built pipelines. This registry
reports at ERROR and raises under ``strict=True``, because a manifest missing
``postconditions`` is a technique that can never be chained — and a chain query
returning nothing is a silent wrong answer rather than a loud missing one.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from service.vuln_engine.registry import ManifestError, TechniqueRegistry

VALID_TECHNIQUE = '''
"""A throw-away technique folder for the registry tests."""
from __future__ import annotations

from service.vuln_engine.kernel.evidence import EVIDENCE_EXECUTION, EVIDENCE_REFLECTION
from service.vuln_engine.kernel.manifest import NoiseProfile, TechniqueManifest
from service.vuln_engine.techniques.xss_reflected import TECHNIQUE

MANIFEST = TechniqueManifest(
    name="alpha",
    vuln_class="test",
    preconditions=("public_param",),
    postconditions=("something",),
    produces=(EVIDENCE_REFLECTION,),
    verification_needs=EVIDENCE_EXECUTION,
    noise=NoiseProfile(requests_per_surface=1),
)
TECHNIQUE = TECHNIQUE
'''

NO_POSTCONDITIONS = VALID_TECHNIQUE.replace('name="alpha"', 'name="beta"').replace(
    'postconditions=("something",)', "postconditions=()"
)
MISMATCHED_NAME = VALID_TECHNIQUE.replace('name="alpha"', 'name="not-gamma"')
NO_CONTRACT = '"""A folder with no contract at all."""\n'
RAISES_ON_IMPORT = '"""A folder that cannot even be imported."""\nraise RuntimeError("boom")\n'


@pytest.fixture
def fake_package(tmp_path: Path, monkeypatch):
    """A throw-away techniques package on disk, importable by name."""
    package = tmp_path / "faketechs"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")

    def write(folder: str, source: str) -> None:
        target = package / folder
        target.mkdir()
        (target / "__init__.py").write_text(source, encoding="utf-8")

    write("alpha", VALID_TECHNIQUE)
    write("beta", NO_POSTCONDITIONS)
    write("gamma", MISMATCHED_NAME)
    write("delta", NO_CONTRACT)
    write("epsilon", RAISES_ON_IMPORT)
    (package / "not_a_folder.py").write_text("", encoding="utf-8")

    monkeypatch.syspath_prepend(str(tmp_path))
    yield "faketechs"
    for name in list(sys.modules):
        if name.startswith("faketechs"):
            del sys.modules[name]


def test_the_real_technique_folders_are_discovered() -> None:
    registry = TechniqueRegistry.discover()
    # Phase 4 adds the DOM-lens technique; alphabetical discovery order.
    assert registry.names() == [
        "oob_fetch",
        "sqli_blind_time",
        "xss_dom",
        "xss_reflected",
    ]
    assert registry.problems == []


def test_the_manifest_table_is_what_a_report_embeds() -> None:
    described = {row["name"]: row for row in TechniqueRegistry.discover().describe()}
    assert described["xss_reflected"]["verification_needs"] == "execution"
    assert described["oob_fetch"]["verification_needs"] == "oob"
    assert described["xss_reflected"]["noise"]["requests_per_surface"] == 1


def test_a_lookup_of_an_unknown_technique_says_what_is_known() -> None:
    with pytest.raises(
        KeyError, match="known: oob_fetch, sqli_blind_time, xss_dom, xss_reflected"
    ):
        TechniqueRegistry.discover().get("ssti")


def test_a_throw_away_package_registers_what_qualifies(fake_package: str) -> None:
    registry = TechniqueRegistry.discover(package=fake_package)
    assert registry.names() == ["alpha"]


def test_a_manifest_missing_postconditions_is_reported_loudly(fake_package: str) -> None:
    registry = TechniqueRegistry.discover(package=fake_package)
    assert any("postconditions" in problem for problem in registry.problems)
    assert "beta" not in registry.names()


def test_a_manifest_missing_postconditions_raises_under_strict(fake_package: str) -> None:
    with pytest.raises(ManifestError) as error:
        TechniqueRegistry.discover(package=fake_package, strict=True)
    assert error.value.folder == "beta"
    assert any("postconditions" in problem for problem in error.value.problems)


def test_a_folder_whose_manifest_name_disagrees_is_skipped(fake_package: str) -> None:
    registry = TechniqueRegistry.discover(package=fake_package)
    assert "gamma" not in registry.names()


def test_a_folder_with_no_contract_is_skipped_with_a_reason(fake_package: str) -> None:
    registry = TechniqueRegistry.discover(package=fake_package)
    assert "delta" not in registry.names()
    assert any(problem.startswith("delta:") for problem in registry.problems)


def test_a_folder_that_cannot_be_imported_does_not_take_discovery_down(fake_package: str) -> None:
    # One broken experimental folder must not stop the engine: this mirrors the
    # recon registry's rule, and the fake package puts a broken folder *last* so a
    # fail-fast implementation would lose "alpha".
    registry = TechniqueRegistry.discover(package=fake_package)
    assert registry.names() == ["alpha"]


def test_a_missing_package_is_an_empty_registry_not_an_error() -> None:
    registry = TechniqueRegistry.discover(package="definitely.not.a.package")
    assert registry.names() == []
    assert len(registry) == 0


def test_the_order_is_deterministic() -> None:
    # ``all()`` sorts by name rather than yielding filesystem order, so two runs
    # send the same probes in the same sequence and a log diff is readable.
    assert TechniqueRegistry.discover().names() == TechniqueRegistry.discover().names()
