"""Safe filesystem-name components from operator-supplied strings.

**Why this module exists.** Several places join an operator-supplied string —
a CLI ``-t`` target, a UI-supplied run name — into a filesystem path:
``run_engine.py`` and ``run_twogate.py`` default their output directory to
``output/vuln_engine/<target>``, and the UI's job launcher forwards a run name
into that same join. A crafted value (``../.env``, ``..\\..\\Windows``, an
absolute path, a name with a separator hiding in it) would walk the run
outside the output root, and an empty one would collapse the join to the root
itself. :func:`safe_component` is the one allowlist every such join goes
through; the CLIs also call it right after ``parse_args``, so a bad ``-t``
fails loudly at option-parse time — before any graph, network or filesystem
work happens.

The shape mirrored here is ``service/ui/artifacts.safe_resolve``, which guards
the *reading* side: that function resolves-then-checks ``relative_to`` so a
crafted request cannot read outside the repo; this one allowlists the *writing*
side so a crafted run name cannot get outside the output root in the first
place. Both exist because a tool that writes and reads files on behalf of an
operator is a file server, and a file server checks its names.
"""

from __future__ import annotations

import string

#: The allowlist: word characters (letters, digits, underscore), the hyphen
#: and the dot — the characters a legitimate run name or target (``acme.test``,
#: ``10_0_0_1``, ``twogate-demo``) already uses. Anything else — separators,
#: whitespace, ``:`` from ``http://`` forms, ``%`` from URL-encoding — is
#: refused, not sanitized: the operator picks the real name, the tool never
#: guesses one.
_SAFE_CHARS = frozenset(string.ascii_letters + string.digits + "._-")

#: A component must exist and must not be longer than this — long enough for
#: any real run name or target, short enough that the joined path cannot butt
#: against filesystem filename limits on its own.
MAX_COMPONENT_LEN = 120

#: Windows reserved device names: a legal-shaped string that cannot be created
#: as a file on the platform the suite runs on. Refused with an extension too
#: (``NUL.txt``): the device part is what precedes the first dot.
_WINDOWS_RESERVED = frozenset(
    {
        "CON", "PRN", "AUX", "NUL",
        *(f"COM{i}" for i in range(1, 10)),
        *(f"LPT{i}" for i in range(1, 10)),
    }
)


def safe_component(name: str) -> str:
    """Return *name* if it is one safe path component; raise ``ValueError`` if not.

    A safe component is non-empty, at most :data:`MAX_COMPONENT_LEN` chars,
    built only from the allowlist above, and never ``.`` or ``..`` — so it
    contains no separators (``/`` or ``\\``), no drive prefixes, and cannot
    traverse.
    """
    if not name:
        raise ValueError("a path component must not be empty")
    if len(name) > MAX_COMPONENT_LEN:
        raise ValueError(f"path component too long ({len(name)} > {MAX_COMPONENT_LEN}): {name!r}")
    if name in (".", ".."):
        raise ValueError(f"refusing traversal component: {name!r}")
    if not set(name) <= _SAFE_CHARS:
        bad = sorted(set(name) - _SAFE_CHARS)
        raise ValueError(
            f"refusing unsafe path component {name!r}: "
            f"characters outside the allowlist {sorted(_SAFE_CHARS)}: {bad}"
        )
    if name.upper().split(".")[0] in _WINDOWS_RESERVED:
        raise ValueError(f"refusing reserved device name: {name!r}")
    return name
