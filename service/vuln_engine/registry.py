"""Technique discovery: a folder under ``techniques/`` that satisfies the contract.

Discovery rules, deliberately boring — and borrowed wholesale from the recon side
(``service/recon_pipeline/platform/registry.py``), because "add a folder, get a
pipeline, discovered at run time" is already this codebase's answer to extensibility:

1. every subdirectory of ``techniques/`` is a candidate;
2. the registry imports it and looks for module-level ``MANIFEST`` and
   ``TECHNIQUE``;
3. a folder missing either is **skipped with a logged reason** — a half-built
   technique directory is safe to keep in the tree;
4. a manifest whose ``name`` disagrees with its folder name is skipped (one name,
   everywhere, is how artifacts stay findable).

One deliberate difference from the recon side: **an invalid manifest is loud.**
There, a broken candidate is skipped with a warning, because discovery is racing
many half-built folders. Here, a manifest missing ``postconditions`` describes a
technique that can never be chained, and the failure mode of tolerating it is a
silent wrong answer from a chain query that returned nothing. So the validator
reports it at ERROR level, and ``strict=True`` raises:

``discover()``
    skips invalid folders, logs why — what a long-running engagement wants;
``discover(strict=True)``
    raises :class:`ManifestError` on the first one — what a test and a CI run want.
"""

from __future__ import annotations

import importlib
import logging
from dataclasses import dataclass
from pathlib import Path

from .kernel.manifest import TechniqueManifest
from .kernel.technique import Technique

log = logging.getLogger("vuln_engine.registry")

#: The package all technique folders live in — the only registration point.
TECHNIQUES_PACKAGE = "service.vuln_engine.techniques"


class ManifestError(Exception):
    """A technique's manifest cannot be used, with the reasons attached."""

    def __init__(self, folder: str, problems: list[str]) -> None:
        self.folder = folder
        self.problems = problems
        super().__init__(f"techniques/{folder}: " + "; ".join(problems))


@dataclass
class Registration:
    """A discovered technique, ready to run."""

    name: str
    manifest: TechniqueManifest
    technique: Technique
    module: object

    @property
    def arm(self) -> str:
        """The scheduler's name for this technique (the receipts' operation)."""
        return self.name


class TechniqueRegistry:
    """Discover, order and look up techniques."""

    def __init__(self, registrations: list[Registration], problems: list[str] | None = None) -> None:
        self._registrations = {reg.name: reg for reg in registrations}
        #: Folders that looked like techniques and did not qualify.  Kept so a run
        #: report can say what was in the tree rather than only what ran.
        self.problems = list(problems or [])

    # ------------------------------------------------------------------ #
    # lookups
    # ------------------------------------------------------------------ #

    def names(self) -> list[str]:
        """Every registered technique, sorted — a stable order for a run."""
        return sorted(self._registrations)

    def get(self, name: str) -> Registration:
        if name not in self._registrations:
            known = ", ".join(self.names()) or "(none)"
            raise KeyError(f"unknown technique {name!r}; known: {known}")
        return self._registrations[name]

    def all(self) -> list[Registration]:
        """Registrations in a deterministic order (name), not filesystem order."""
        return [self._registrations[name] for name in self.names()]

    def __len__(self) -> int:
        return len(self._registrations)

    def describe(self) -> list[dict]:
        """The manifest table a run report embeds."""
        return [
            {**registration.manifest.to_dict(), "module": registration.name}
            for registration in self.all()
        ]

    # ------------------------------------------------------------------ #
    # discovery
    # ------------------------------------------------------------------ #

    @classmethod
    def discover(cls, *, strict: bool = False, package: str = TECHNIQUES_PACKAGE) -> "TechniqueRegistry":
        """Scan the techniques package and register every folder that qualifies."""
        try:
            module = importlib.import_module(package)
        except ModuleNotFoundError:
            return cls([])
        package_path = getattr(module, "__path__", None)
        if package_path is None:
            return cls([])

        registrations: list[Registration] = []
        problems: list[str] = []
        for folder in _iter_folders(Path(package_path[0])):
            try:
                registration = _try_register(folder, f"{package}.{folder}")
            except ManifestError as error:
                if strict:
                    raise
                problems.extend(error.problems)
                log.error("techniques/%s: skipped (%s)", folder, error)
                continue
            if registration is None:
                problems.append(f"{folder}: no TECHNIQUE/MANIFEST contract module")
                continue
            registrations.append(registration)
        return cls(registrations, problems)


def _iter_folders(package_path: Path) -> list[str]:
    """Subdirectories of the techniques package, sorted for determinism."""
    try:
        entries = sorted(entry.name for entry in package_path.iterdir())
    except OSError:
        return []
    return [
        entry
        for entry in entries
        if not entry.startswith(("_", ".")) and (package_path / entry).is_dir()
    ]


def _try_register(folder: str, module_name: str) -> Registration | None:
    """Import a candidate; ``None`` when it does not qualify.

    An import failure is reported, never raised, *except* for a manifest that
    validates badly — see the module docstring for why those two are different.
    """
    try:
        module = importlib.import_module(module_name)
    except Exception as exc:  # noqa: BLE001 - one broken folder must not stop discovery
        log.error("techniques/%s: skipped (%s: %s)", folder, type(exc).__name__, exc)
        return None

    manifest = getattr(module, "MANIFEST", None)
    technique = getattr(module, "TECHNIQUE", None)
    if manifest is None or technique is None:
        log.info("techniques/%s: skipped (no MANIFEST/TECHNIQUE)", folder)
        return None
    if manifest.name != folder:
        log.warning(
            "techniques/%s: skipped (manifest name %r disagrees with the folder)",
            folder,
            manifest.name,
        )
        return None
    problems = manifest.validate()
    if problems:
        raise ManifestError(folder, problems)
    return Registration(
        name=folder, manifest=manifest, technique=technique, module=module
    )


__all__ = [
    "ManifestError",
    "Registration",
    "TECHNIQUES_PACKAGE",
    "TechniqueRegistry",
]
