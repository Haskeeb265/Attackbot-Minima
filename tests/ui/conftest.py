"""Shared fixtures for the UI's hermetic tests.

**Suite-isolation note.** Some UI tests reach the database layer
(``service/ui/programs.py`` imports ``shared.db`` lazily inside ``_fetch``).
Importing ``shared.db`` imports the recon side's root ``config``, which calls
``load_dotenv(..., override=True)``: every variable in the repo's ``.env`` —
including the engine's ``VULN_ENGINE_LLM_API_KEY`` — is copied into
``os.environ``, overriding even variables the test process set on purpose.
The engine's tests assert the *contract* that a client without a key runs
degraded and deterministic (the master reference's Invariant 5); a key leaked
into the environment by a UI test that ran first defeats those assertions.

The guard itself lives in the root ``tests/conftest.py`` (snapshot before
collection, restore after collection and around every test) so it covers the
collection-time import path too — recon test modules import
``platform.common.config``, which performs the same override at *collection*
time, before any per-test fixture could snapshot.  See the root conftest for
why the boundary is the test tree and not production code.
"""

from __future__ import annotations
