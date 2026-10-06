"""Elicitor discovery — the techniques registry's mirror for ``elicit/`` folders.

Same rules, deliberately: every subdirectory is a candidate, the folder must
expose ``MANIFEST`` and ``ELICITOR``, the manifest's ``name`` must equal the
folder name, and a manifest that validates badly is loud (``strict=True``
raises; otherwise the folder is skipped with a logged reason). Adding an
elicitor means adding a folder; deleting one leaves the engine running with
one fewer measurable claim.
"""

from __future__ import annotations

import importlib
import logging
from dataclasses import dataclass
from pathlib import Path

from ..kernel.manifest import TechniqueManifest
from ..kernel.technique import CAPABILITIES, Surface
from ..registry import ManifestError
from .base import Elicitor

log = logging.getLogger("vuln_engine.elicit.registry")

#: The package all elicitor folders live in.
ELICIT_PACKAGE = "service.vuln_engine.elicit"


@dataclass
class ElicitationRegistration:
    """A discovered elicitor, ready to run."""

    name: str
    manifest: TechniqueManifest
    elicitor: Elicitor

    @property
    def capability(self) -> str:
        """The capability this elicitor establishes — from the manifest's
        ``preconditions`` (the one field reused for the elicitor contract)."""
        return self.manifest.preconditions[0] if self.manifest.preconditions else ""


class ElicitorRegistry:
    """Discover, order and look up elicitors."""

    def __init__(self, registrations: list[ElicitationRegistration]) -> None:
        self._registrations = {reg.name: reg for reg in registrations}

    def names(self) -> list[str]:
        """Every registered elicitor, sorted — a stable order for a run."""
        return sorted(self._registrations)

    def get(self, name: str) -> ElicitationRegistration:
        if name not in self._registrations:
            raise KeyError(f"unknown elicitor {name!r}; known: {', '.join(self.names())}")
        return self._registrations[name]

    def all(self) -> list[ElicitationRegistration]:
        """Registrations in a deterministic order (name), not filesystem order."""
        return [self._registrations[name] for name in self.names()]

    def for_capability(self, capability: str) -> list[ElicitationRegistration]:
        """Every elicitor that can establish *capability*, in registry order."""
        return [
            registration
            for registration in self.all()
            if registration.capability == capability
        ]

    def __len__(self) -> int:
        return len(self._registrations)

    @classmethod
    def discover(
        cls, *, strict: bool = False, package: str = ELICIT_PACKAGE
    ) -> "ElicitorRegistry":
        """Scan the elicit package and register every folder that qualifies."""
        try:
            module = importlib.import_module(package)
        except ModuleNotFoundError:
            return cls([])
        package_path = getattr(module, "__path__", None)
        if package_path is None:
            return cls([])

        registrations: list[ElicitationRegistration] = []
        for folder in _iter_folders(Path(package_path[0])):
            try:
                registration = _try_register(folder, f"{package}.{folder}")
            except ManifestError as error:
                if strict:
                    raise
                log.error("elicit/%s: skipped (%s)", folder, error)
                continue
            if registration is None:
                log.info("elicit/%s: skipped (no MANIFEST/ELICITOR)", folder)
                continue
            registrations.append(registration)
        return cls(registrations)


def _iter_folders(package_path: Path) -> list[str]:
    """Subdirectories of the elicit package, sorted for determinism."""
    try:
        entries = sorted(entry.name for entry in package_path.iterdir())
    except OSError:
        return []
    return [
        entry
        for entry in entries
        if not entry.startswith(("_", ".")) and (package_path / entry).is_dir()
    ]


def _try_register(folder: str, module_name: str) -> ElicitationRegistration | None:
    """Import a candidate; ``None`` when it does not qualify."""
    try:
        module = importlib.import_module(module_name)
    except Exception as exc:  # noqa: BLE001 - one broken folder must not stop discovery
        log.error("elicit/%s: skipped (%s: %s)", folder, type(exc).__name__, exc)
        return None

    manifest = getattr(module, "MANIFEST", None)
    elicitor = getattr(module, "ELICITOR", None)
    if manifest is None or elicitor is None:
        return None
    if manifest.name != folder:
        log.warning(
            "elicit/%s: skipped (manifest name %r disagrees with the folder)",
            folder,
            manifest.name,
        )
        return None
    problems = manifest.validate()
    if problems:
        raise ManifestError(folder, problems)
    capability = manifest.preconditions[0] if manifest.preconditions else ""
    if capability not in CAPABILITIES:
        raise ManifestError(
            folder,
            [f"preconditions[0] {capability!r} is not a capability the kernel speaks"],
        )
    return ElicitationRegistration(
        name=folder, manifest=manifest, elicitor=elicitor
    )


__all__ = [
    "ElicitationRegistration",
    "ElicitorRegistry",
    "ELICIT_PACKAGE",
]
