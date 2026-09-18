"""Pipeline discovery: a folder under ``pipelines/`` that satisfies the
contract *is* the registration.

Discovery rules (deliberately boring):

1. every subdirectory of :data:`contract.PIPELINES_PACKAGE` is a candidate;
2. the registry imports ``<folder>.pipeline`` (falling back to the folder's
   ``__init__``) and looks for module-level ``MANIFEST`` + ``PIPELINE``;
3. a folder missing either is **skipped with a logged reason** — a half-built
   pipeline directory is safe to keep in the tree;
4. a manifest whose ``name`` disagrees with its folder name is skipped too
   (one name, everywhere, is how artifacts stay findable).

Import failures inside a candidate are reported, never raised: one broken
experimental pipeline must not take discovery down.
"""

from __future__ import annotations

import importlib
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .contract import Manifest

log = logging.getLogger("platform.registry")


@dataclass
class Registration:
    """A discovered pipeline, ready to run."""

    name: str
    manifest: "Manifest"  # contract.Manifest at runtime
    pipeline: object  # contract.Pipeline
    module: object


class Registry:
    """Discover, order and look up pipelines."""

    def __init__(self, registrations: list[Registration]) -> None:
        self._registrations = {reg.name: reg for reg in registrations}

    # ------------------------------------------------------------------ #
    # lookups
    # ------------------------------------------------------------------ #

    def names(self) -> list[str]:
        return list(self._registrations)

    def get(self, name: str) -> Registration:
        if name not in self._registrations:
            known = ", ".join(self._registrations) or "(none)"
            raise KeyError(f"unknown pipeline {name!r}; known: {known}")
        return self._registrations[name]

    def all(self) -> list[Registration]:
        return list(self._registrations.values())

    def describe(self) -> list[dict]:
        rows: list[dict] = []
        for name in self._registrations:
            reg = self._registrations[name]
            manifest = reg.manifest
            rows.append(
                {
                    "name": name,
                    "title": manifest.title,
                    "asset_types": ", ".join(manifest.asset_types),
                    "stages": ", ".join(manifest.stage_names()),
                    "passive_only": manifest.passive_only,
                    "description": manifest.description,
                }
            )
        return rows

    # ------------------------------------------------------------------ #
    # ordering (respects `consumes` declarations)
    # ------------------------------------------------------------------ #

    def ordered(self, selected: list[str] | None = None) -> list[Registration]:
        """Pipelines in dependency order (declared `consumes` first).

        Cycles are tolerated by falling back to alphabetical order for the
        cyclic set — a cycle is a manifest bug, not a run killer.
        """
        chosen = [self.get(name) for name in (selected or self.names())]
        chosen_names = {reg.name for reg in chosen}

        ordered: list[Registration] = []
        visited: set[str] = set()
        temp: set[str] = set()

        def visit(name: str) -> None:
            if name in visited or name not in chosen_names:
                return
            if name in temp:  # cycle — bail out of this branch
                return
            temp.add(name)
            reg = self._registrations.get(name)
            if reg is not None:
                for dep in reg.manifest.consumes:
                    dep_owner = dep.split("/")[0]
                    visit(dep_owner)
            temp.discard(name)
            visited.add(name)
            ordered.append(self._registrations[name])

        for name in sorted(chosen_names):
            visit(name)
        return ordered

    # ------------------------------------------------------------------ #
    # discovery
    # ------------------------------------------------------------------ #

    @classmethod
    def discover(cls) -> "Registry":
        """Scan the pipelines package and register every folder that qualifies."""
        from . import contract

        package = importlib.import_module(contract.PIPELINES_PACKAGE)
        package_path = getattr(package, "__path__", None)
        if package_path is None:
            return cls([])

        registrations: list[Registration] = []
        for entry in _iter_folders(package_path[0]):
            module_name = f"{contract.PIPELINES_PACKAGE}.{entry}"
            reg = _try_register(entry, module_name)
            if reg is not None:
                registrations.append(reg)
        return cls(registrations)


def _iter_folders(package_path: str) -> list[str]:
    """Subdirectories of the pipelines package that look like folders at all."""
    import os

    try:
        entries = sorted(os.listdir(package_path))
    except OSError:
        return []
    return [
        entry
        for entry in entries
        if not entry.startswith(("_", "."))
        and os.path.isdir(os.path.join(package_path, entry))
    ]


def _try_register(folder: str, module_name: str) -> Registration | None:
    """Import a candidate; None (with a logged reason) when it does not qualify."""
    from . import contract

    try:
        module = None
        for candidate in (contract.CONTRACT_MODULE, *contract.CONTRACT_MODULE_FALLBACKS):
            try:
                module = importlib.import_module(
                    module_name if candidate == "__init__" else f"{module_name}.{candidate}"
                )
            except ModuleNotFoundError as exc:
                if exc.name and (
                    exc.name.endswith(f".{candidate}") or exc.name == module_name
                ):
                    continue
                raise
            if getattr(module, "MANIFEST", None) is not None and getattr(
                module, "PIPELINE", None
            ) is not None:
                break
        if module is None:
            log.info("pipelines/%s: skipped (no contract module found)", folder)
            return None

        manifest = getattr(module, "MANIFEST", None)
        pipeline = getattr(module, "PIPELINE", None)
        if manifest is None or pipeline is None:
            log.info("pipelines/%s: skipped (no MANIFEST/PIPELINE contract module)", folder)
            return None
        if getattr(manifest, "name", folder) != folder:
            log.warning(
                "pipelines/%s: skipped (manifest name %r disagrees with folder)",
                folder,
                manifest.name,
            )
            return None
        return Registration(name=folder, manifest=manifest, pipeline=pipeline, module=module)
    except Exception as exc:  # one broken candidate must not stop discovery
        log.warning("pipelines/%s: skipped (%s: %s)", folder, type(exc).__name__, exc)
        return None
