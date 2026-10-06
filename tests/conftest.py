"""Shared pytest configuration.

Two jobs:

1. **Importability** — put the project root on ``sys.path`` so tests can use
   the same absolute imports as the application code (``from
   service.recon_pipeline... import ...``), regardless of the directory pytest
   was invoked from.  Without this, pytest only puts the test file's own
   directory on ``sys.path``.

2. **The suite-wide environment guard.** Several production modules call
   ``load_dotenv(..., override=True)`` at import time — the recon side's
   ``platform.common.config`` (imported the moment any recon test module is
   collected) and the repo-root ``config`` (reached via ``shared.db`` when a
   UI test touches the programs database).  Every variable in the repo's
   ``.env`` — including the engine's ``VULN_ENGINE_LLM_API_KEY`` — is copied
   into ``os.environ``, overriding even variables the test process set on
   purpose.  The engine's tests assert the *contract* that a client without a
   key runs degraded and deterministic (the master reference's Invariant 5);
   a key leaked into the environment by an earlier collection or test defeats
   those assertions, and the whole-tree suite fails through no defect of the
   engine's.

   The least invasive fix is at the test boundary, not in production code:
   snapshot the environment when this conftest is imported (before any test
   module is collected) and restore it after collection and around every
   test, so nothing an import or a subprocess loaded outlives the moment it
   happened.  (Patching each module's ``load_dotenv`` call would mean chasing
   every importer; deleting one variable would miss whatever *else* the
   dotenv load mutates.)  Environment changes a child process makes never
   propagate back to the parent anyway; the per-test restore exists for the
   in-process import path.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Taken before pytest collects anything, so it is the process environment as
# the operator launched it — no dotenv override has run yet.
_ENV_BEFORE_COLLECTION = dict(os.environ)


def _restore_env(snapshot: dict[str, str]) -> None:
    current = dict(os.environ)
    for key in current:
        if key not in snapshot:
            os.environ.pop(key, None)
    for key, value in snapshot.items():
        # Restore the *original* value, not just presence: override=True
        # replaces values, and a test that reads the real key must not see
        # the dotenv-clobbered one.
        if current.get(key) != value:
            os.environ[key] = value


def pytest_collection_finish(session) -> None:
    """Undo whatever the collection-time imports loaded from ``.env``."""
    _restore_env(_ENV_BEFORE_COLLECTION)


@pytest.fixture(autouse=True)
def _restore_environ():
    """Snapshot ``os.environ`` around every test; restore it after.

    A test may import a module whose import loads ``.env`` with
    ``override=True``, or start job subprocesses.  Neither may outlive the
    test: the engine's "no key means deterministic" assertions run in the
    same interpreter when the whole tree is tested.
    """
    snapshot = dict(os.environ)
    try:
        yield
    finally:
        _restore_env(snapshot)
