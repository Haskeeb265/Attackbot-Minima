"""Techniques: one folder per vulnerability class, pure, found by walking the tree.

The folder *is* the registration — the same contract the recon side's pipelines
use (``platform/contract.py``). A folder is registered when it exposes
``MANIFEST`` and ``TECHNIQUE``; a folder missing either is skipped with a logged
reason, so a half-built technique is safe to keep in the tree.

What a folder must not do: import a transport, read a clock, call a model, or
confirm its own candidate. ``tests/vuln_engine/test_invariants.py`` enforces the
first two mechanically; ``kernel/verdict.py`` enforces the last one at the moment a
verdict is built.

The techniques, and why they are different in kind:

``xss_reflected``
    a reflection is *measured*, then a browser confirms it.  A reflected class.
``xss_stored``
    input is *injected* by POST, then a read-back page's reflection is
    measured; confirmed by a two-step verifier (re-inject, then browser).
    The capability claim (``server_stores_input``) separates its territory
    from the reflected lens's.
``oob_fetch``
    a capability is *claimed*, then our own collaborator confirms it.  A blind
    class, and the case with no other evidence strong enough for a finding.

``common.py`` holds the one pure helper both need (parameterised URLs).  Anything
else shared would be a place for technique logic to leak out of its folder.
"""

from __future__ import annotations

__all__: list[str] = []
