"""The invariants, each with the cheap test that proves it.

``engine_explained.md`` §14 lists eight invariants and pairs each with a test. These
are the mechanical ones — the properties that can be checked by reading the source
rather than by running an engagement — and their value is that they cannot be
argued away:

* a technique that started reading a clock or opening a socket would stop being
  replayable, and the grep finds it the moment it happens;
* a module outside ``policy/`` that imported a transport would be a second way to
  reach the network, and the import scan finds it;
* a text payload would make every downstream question a parsing problem.

The one non-mechanical test here is the last: that the empty ``llm/`` package is
still empty. "Zero LLM calls" is Phase 1's claim, and the honest way to keep it is to
have no code that could make one.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

ENGINE = Path("service/vuln_engine")
TECHNIQUES = ENGINE / "techniques"
POLICY = ENGINE / "policy"
LLM = ENGINE / "llm"

#: The cheat sheet's grep: a technique must not read a clock, open a socket, or
#: reach for a client directly.
IMPURE = re.compile(r"\b(time\.|socket\.|requests\.)")

#: What a module outside ``policy/`` must not import.
TRANSPORT_IMPORT = re.compile(r"^\s*(from|import)\s+[.\w]*transports\b", re.MULTILINE)


def _python_files(root: Path) -> list[Path]:
    return sorted(path for path in root.rglob("*.py") if "__pycache__" not in path.parts)


def test_techniques_are_pure_at_the_boundary() -> None:
    offenders: list[str] = []
    for path in _python_files(TECHNIQUES):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if IMPURE.search(line):
                offenders.append(f"{path}:{number}: {line.strip()}")
    assert offenders == [], (
        "a technique that reads a clock, opens a socket or imports a client stops "
        "being replayable and removable:\n" + "\n".join(offenders)
    )


def test_only_policy_imports_a_transport() -> None:
    offenders: list[str] = []
    for path in _python_files(ENGINE):
        if POLICY in path.parents or path.parent == POLICY:
            continue
        if TRANSPORT_IMPORT.search(path.read_text(encoding="utf-8")):
            offenders.append(str(path))
    assert offenders == [], (
        "these modules could reach the network without passing the gate: " + ", ".join(offenders)
    )


def test_the_policy_gate_is_the_only_importer_of_a_transport() -> None:
    importers = [
        path.name
        for path in _python_files(ENGINE)
        if TRANSPORT_IMPORT.search(path.read_text(encoding="utf-8"))
    ]
    assert set(importers) <= {"gate.py"}, importers


def test_no_observation_payload_is_typed_as_text() -> None:
    # The rule, checked on the annotation rather than on a sample: a payload that
    # could be a string would make "which context?" a parsing problem.
    tree = ast.parse((ENGINE / "kernel" / "observation.py").read_text(encoding="utf-8"))
    found = False
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef) or node.name != "Observation":
            continue
        for statement in node.body:
            if not isinstance(statement, ast.AnnAssign):
                continue
            target = getattr(statement.target, "id", "")
            if target == "payload":
                found = True
                annotation = ast.unparse(statement.annotation)
                assert annotation == "dict", annotation
    assert found, "Observation.payload is gone; the invariant test needs updating"


def test_no_evidence_or_observation_payload_is_typed_as_text() -> None:
    """Scoped to the two modules the invariant is actually about.

    Raw *exchanges* hold bytes and a *probe* payload is the string we send — both
    legitimately text, and neither is truth. What must never be text is what the
    engine records as knowledge, so the scan covers ``Evidence`` and
    ``Observation`` and says so rather than casting a net wide enough to be
    ignored.
    """
    offenders: list[str] = []
    for path in (ENGINE / "kernel" / "evidence.py", ENGINE / "kernel" / "observation.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.AnnAssign):
                continue
            target = getattr(node.target, "id", "")
            if target == "payload" and ast.unparse(node.annotation) != "dict":
                offenders.append(f"{path}: {target}: {ast.unparse(node.annotation)}")
    assert offenders == [], offenders


def test_the_engine_and_policy_agree_on_the_kind_spellings() -> None:
    # A technique names an effect kind without importing policy, so the two
    # spellings have to be pinned against each other somewhere.
    from service.vuln_engine.kernel.technique import KIND_BROWSER, KIND_HTTP
    from service.vuln_engine.policy.gate import KIND_BROWSER_RUN, KIND_HTTP_REQUEST

    assert (KIND_HTTP, KIND_BROWSER) == (KIND_HTTP_REQUEST, KIND_BROWSER_RUN)


def test_every_registered_manifest_declares_the_postconditions_it_promises() -> None:
    from service.vuln_engine.registry import TechniqueRegistry

    for registration in TechniqueRegistry.discover(strict=True).all():
        assert registration.manifest.postconditions, registration.name
        assert registration.manifest.verification_needs not in registration.manifest.produces


def test_every_technique_satisfies_the_protocol() -> None:
    from service.vuln_engine.kernel.technique import Technique
    from service.vuln_engine.registry import TechniqueRegistry

    for registration in TechniqueRegistry.discover().all():
        assert isinstance(registration.technique, Technique), registration.name


def test_every_llm_module_keeps_the_advisory_boundary() -> None:
    """The Phase 3 contract, as a source scan: what the junctions may not do.

    The Phase 1 test demanded an empty ``llm/`` — zero code that could call a
    model. Phase 3's claim is narrower and enforceable the same way: the
    junctions may ask, validate and advise, but they may not hold a transport
    (the gate is the only network), read a clock into a pure decision (the
    ``at`` travels in), or decide anything — there is no code path from an
    opinion to an effect, because no ``llm/`` module imports one.
    """
    forbidden = ("transports", "playwright", "socket", "subprocess")
    offenders: list[str] = []
    for path in _python_files(LLM):
        text = path.read_text(encoding="utf-8")
        for name in forbidden:
            if re.search(rf"^\s*(from|import)\s+[.\w]*{name}\b", text, re.MULTILINE):
                offenders.append(f"{path}: imports {name}")
    assert offenders == [], offenders


def test_the_llm_junctions_cannot_reach_the_network_except_through_the_client() -> None:
    """One door to the model, like one door to the network.

    ``requests`` may appear only in the client module (its default caller);
    every other ``llm/`` module reaches the model through the injectable
    :class:`LLMClient`, which is also what makes them testable with no key.
    """
    offenders = [
        path.name
        for path in _python_files(LLM)
        if path.name != "client.py"
        and re.search(r"^\s*import requests\b", path.read_text(encoding="utf-8"), re.MULTILINE)
    ]
    assert offenders == [], offenders


def test_no_module_outside_llm_asks_the_model_directly() -> None:
    """The junctions are reached through the wiring, not by side doors.

    The engine's modules never import ``requests`` or an SDK; the only modules
    allowed to name the client's env vars are the client itself and the wiring
    that builds it from the environment.
    """
    env_names = ("VULN_ENGINE_LLM_API_KEY", "VULN_ENGINE_LLM_API_URL")
    offenders: list[str] = []
    for path in _python_files(ENGINE):
        if LLM in path.parents or path.parent == LLM:
            continue
        text = path.read_text(encoding="utf-8")
        if any(name in text for name in env_names):
            offenders.append(str(path))
    assert offenders == [], offenders


def test_the_kernel_holds_no_io_imports() -> None:
    forbidden = {"httpx", "subprocess", "socket", "playwright", "urllib.request"}
    offenders: list[str] = []
    for path in _python_files(ENGINE / "kernel"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            module = ""
            if isinstance(node, ast.Import):
                module = ",".join(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
            if any(name in forbidden for name in module.split(",")):
                offenders.append(f"{path}: {module}")
    assert offenders == [], offenders


def test_technique_folders_declare_the_four_contract_modules() -> None:
    for folder in sorted(path for path in TECHNIQUES.iterdir() if path.is_dir()):
        if folder.name.startswith("_"):
            continue
        expected = {"manifest.py", "hypothesis.py", "probes.py", "interpret.py", "__init__.py"}
        present = {path.name for path in folder.glob("*.py")}
        assert expected <= present, f"{folder.name} is missing {expected - present}"


def test_a_technique_can_be_deleted_without_touching_anything_else() -> None:
    """The contract's acid test, as far as a source scan can express it.

    Nothing outside a technique's own folder may name it by hand — no registry
    entry, no import, no lookup table. The folders are found by walking the
    directory, which is what makes deleting one a no-op everywhere else.
    """
    offenders: list[str] = []
    for path in _python_files(ENGINE):
        if TECHNIQUES in path.parents:
            continue
        text = path.read_text(encoding="utf-8")
        for name in ("xss_reflected", "oob_fetch"):
            if re.search(rf"[\"']{name}[\"']", text):
                offenders.append(f"{path}: {name}")
    assert offenders == [], offenders


def test_the_receipt_outcomes_match_the_platform_vocabulary() -> None:
    # The engine inherits ``platform.receipt``'s semantics rather than inventing
    # its own; a drift here would break "a failed attempt is retried".
    from service.recon_pipeline.platform.receipt import INCONCLUSIVE, OUTCOME_FAILED
    from service.vuln_engine.scheduler.driver import OUTCOME_FAILED as ENGINE_FAILED

    assert ENGINE_FAILED == OUTCOME_FAILED
    assert ENGINE_FAILED in INCONCLUSIVE


def test_no_run_engine_import_reads_a_clock_in_a_pure_module() -> None:
    # A narrower version of the first test, applied to the whole engine except the
    # three modules that are *supposed* to be at the boundary.
    boundary = {
        ENGINE / "policy" / "gate.py",
        ENGINE / "scheduler" / "driver.py",
        # Phase 2: the campaign owns a round-budget clock exactly like the
        # driver owns the run clock — one callable, injectable, faked in tests.
        ENGINE / "scheduler" / "campaign.py",
        ENGINE / "transports" / "http1.py",
        ENGINE / "transports" / "browser.py",
        ENGINE / "transports" / "oob.py",
    }
    offenders: list[str] = []
    for path in _python_files(ENGINE):
        if path in boundary:
            continue
        if re.search(r"\btime\.time\(", path.read_text(encoding="utf-8")):
            offenders.append(str(path))
    assert offenders == [], offenders


@pytest.mark.parametrize(
    "module",
    [
        "service.vuln_engine.kernel.evidence",
        "service.vuln_engine.kernel.observation",
        "service.vuln_engine.world.views",
        "service.vuln_engine.world.observe",
    ],
)
def test_the_pure_modules_import_nothing_from_a_transport(module: str) -> None:
    source = Path(*module.split(".")).with_suffix(".py")
    assert TRANSPORT_IMPORT.search(source.read_text(encoding="utf-8")) is None
