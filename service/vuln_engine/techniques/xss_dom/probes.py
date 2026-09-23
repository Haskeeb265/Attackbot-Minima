"""The probe grammar for DOM-based XSS, as data.

Three families, cheapest first, each gated on the one before it:

**the canary** — one quiet HTTP request carrying the same canary string
``xss_reflected`` uses. Its question is *narrower* than its sibling's: not
"did the server echo it" (that is the other technique's question) but "does the
value survive the server's response path at all" — a value mangled or dropped
before the client's JavaScript sees it can never be rendered, and there is no
point paying for a browser run to learn that.

**the placement probe** — one browser run whose markers are *boolean DOM
questions*: is the canary present in the rendered DOM at all? Is it in a text
node? In an attribute value? A URL-parsed one? Injected as markup? Inside
script state? Each question is an independent predicate the runner evaluates
after the page settles, and the observation layer maps the true answers into
``observation.dom_placement`` rows. This is the family the whole technique
exists for: it is the lens that sees a reflection the wire cannot.

**the payload probe** — one browser run per executable *placement*, gated on
``requires_context`` exactly like ``xss_reflected``'s: a browser is loud, and
it runs only where a placement row established an executable context. The
payload reuses ``xss_reflected``'s breakout table and marker identifier
arithmetic so the two grammars cannot drift apart, plus one DOM-only payload
for the ``dom_url_attribute`` lead (which stays a lead — see ``interpret``).

Notice what is *not* here: confirmation. Every spec carries an oracle and a
declared evidence class, and the loud confirmation belongs to a verifier in a
different class — the same shape as every other technique.
"""

from __future__ import annotations

from ...kernel.observation import (
    CONTEXT_DOM_URL_ATTRIBUTE,
    CONTEXT_JS_CODE,
    CONTEXT_RAW_HTML,
)
from ...kernel.technique import (
    KIND_BROWSER,
    KIND_HTTP,
    ORACLE_CONTEXT,
    ORACLE_REFLECTION,
    ORACLE_SCRIPT_EXECUTION,
    PURPOSE_CONFIRM,
    Hypothesis,
    ProbeSpec,
)
from ..common import (
    DOM_Q_HTML,
    DOM_Q_PRESENT,
    DOM_Q_SCRIPT,
    DOM_Q_TEXT,
    DOM_Q_URLATTR,
    dom_marker,
    with_parameter,
)
from ..xss_reflected import probes as reflected

NAME = "xss_dom"

#: Reuse the sibling grammar's canary and dialog spellings verbatim. Two
#: techniques using *different* canaries against the same surface would double
#: the visibility cost for no information; using different dialog texts would
#: make the two verifiers' bars differ for no reason.
CANARY = reflected.CANARY
MARK = reflected.MARK
DIALOG_TEXT = reflected.DIALOG_TEXT

#: The markup probe: a custom element appended to the canary. A browser only
#: materialises this element if it *parsed our bytes as markup* — the one
#: boolean that separates "the value sits in an attribute or text node" (the
#: string appears in ``innerHTML``, but no element exists) from "the value
#: became markup". The dash keeps it a valid custom-element name, and the name
#: is derived from the shared mark so both lenses can correlate.
MARKUP_PROBE = f"<ve-{MARK}></ve-{MARK}>"
#: The full canary value the DOM lens sends: the sibling's canary (presence and
#: text/script questions) plus the markup probe (the html question).
CANARY_VALUE = f"{CANARY}{MARKUP_PROBE}"


def _browser_spec(
    hypothesis: Hypothesis,
    *,
    probe_id: str,
    url: str,
    markers: dict[str, str],
    oracle: str,
    requires_context: tuple[str, ...] = (),
    purpose: str = "propose",
) -> ProbeSpec:
    """One browser probe: the shared shape, no repeated field lists."""
    return ProbeSpec(
        id=probe_id,
        kind=KIND_BROWSER,
        host=hypothesis.surface.host,
        detail={"url": url, "markers": dict(markers)},
        oracle=oracle,
        canary=CANARY,
        mark=MARK,
        noise={"requests_per_surface": 1, "browser": True},
        requires_context=requires_context,
        produces="execution",
        purpose=purpose,
        payload="",
    )


def _placement_expressions(url: str, param: str) -> dict[str, str]:
    """The DOM questions, as boolean JS expressions.

    Each predicate is independent and side-effect free, and each answer is a
    plain bool — the marker channel coerces, so the questions are built to be
    asked as booleans. ``present`` is deliberately loose (the value anywhere in
    the rendered document, including attribute values): the *absence* of every
    placement row plus a true ``present`` is exactly the ``dom_absent``-shaped
    fact the interpreter records. The ``html`` question is the strict one: it
    looks for the markup probe's custom element, which exists only if the page
    parsed our bytes as markup.
    """
    needle = CANARY.replace('"', '\\"')
    element = f"ve-{MARK}"
    return {
        dom_marker(MARK, DOM_Q_PRESENT): (
            f'document.documentElement.innerHTML.indexOf("{needle}") !== -1'
        ),
        dom_marker(MARK, DOM_Q_TEXT): (
            f'(()=>{{const n=document.createNodeIterator(document.documentElement,'
            f'NodeFilter.SHOW_TEXT);let x;while((x=n.nextNode())){{'
            f'if(x.textContent && x.textContent.indexOf("{needle}")!==-1){{return true}}}}'
            f"return false}})()"
        ),
        dom_marker(MARK, DOM_Q_URLATTR): (
            f'(()=>{{const els=document.querySelectorAll("*");'
            f'for(const el of els){{for(const a of el.attributes){{'
            f'if((a.name==="src"||a.name==="href"||a.name==="action"||'
            f'a.name==="formaction"||a.name==="data") && '
            f'a.value.indexOf("{needle}")!==-1){{return true}}}}}}'
            f"return false}})()"
        ),
        dom_marker(MARK, DOM_Q_HTML): (
            f'document.getElementsByTagName("{element}").length > 0'
        ),
        dom_marker(MARK, DOM_Q_SCRIPT): (
            f'(()=>{{const els=document.getElementsByTagName("script");'
            f'for(const el of els){{'
            f'if(el.textContent.indexOf("{needle}")!==-1){{return true}}}}'
            f"return false}})()"
        ),
    }


def probes(hypothesis: Hypothesis) -> list[ProbeSpec]:
    """The three families, in the order the driver should ask them."""
    surface = hypothesis.surface
    # One URL carries the whole DOM-lens value — plain canary plus markup probe
    # — because both the wire canary and the placement questions read it.
    canary_url = with_parameter(surface.url, surface.param, CANARY_VALUE)

    # Family 1 — the canary: does the value survive to the client at all? The
    # value carries both the plain canary and the markup probe, so one request
    # arms every placement question the browser probe will ask.
    canary_spec = ProbeSpec(
        id=f"{NAME}:{surface.host}:canary:{surface.param}",
        kind=KIND_HTTP,
        host=surface.host,
        detail={"url": canary_url, "method": "GET"},
        oracle=ORACLE_REFLECTION,
        canary=CANARY,
        mark=MARK,
        noise={"requests_per_surface": 1},
        produces="reflection",
        purpose="propose",
        payload=CANARY_VALUE,
    )

    # Family 2 — placement: where does the page put it? Boolean questions only.
    placement = _browser_spec(
        hypothesis,
        probe_id=f"{NAME}:{surface.host}:placement:{surface.param}",
        url=canary_url,
        markers=_placement_expressions(canary_url, surface.param),
        oracle=ORACLE_CONTEXT,
    )

    # Family 3 — payloads: one per executable placement, gated on the placement
    # rows. The DOM-specific payload (a script tag into a URL-parsed attribute
    # is impossible, so the DOM-only family is markup or script-state) uses the
    # sibling grammar's own breakout arithmetic.
    payloads: list[ProbeSpec] = []
    for context in (CONTEXT_RAW_HTML, CONTEXT_JS_CODE, CONTEXT_DOM_URL_ATTRIBUTE):
        payload = _payload_for(hypothesis, context)
        if not payload:
            continue
        payloads.append(
            _browser_spec(
                hypothesis,
                probe_id=f"{NAME}:{surface.host}:payload:{context}:{surface.param}",
                url=with_parameter(surface.url, surface.param, payload),
                markers=_execution_markers(context),
                oracle=ORACLE_SCRIPT_EXECUTION,
                requires_context=(context,),
                purpose=PURPOSE_CONFIRM,
            )
        )
    return [canary_spec, placement, *payloads]


def _payload_for(hypothesis: Hypothesis, context: str) -> str:
    """The payload a *DOM* placement needs: markup where markup is parsed.

    The hypothesis argument is unused by the shared table (the payload depends
    only on the context); it is threaded through so the call is honest about
    the grammar's own signature rather than smuggling a ``None`` past it.

    The markup payload is an event handler, not a ``<script>`` tag: the HTML5
    parser marks script elements inserted via ``innerHTML`` as already-started,
    so a script tag that lands in a sink never runs — an ``onerror`` handler
    does. The marker identifier and dialog text stay the sibling grammar's, so
    the verifier's bar is identical.
    """
    if context == CONTEXT_RAW_HTML:
        ident = reflected.marker_identifier(context)
        return (
            f'<img src=x onerror="{ident}=1;confirm(\'{DIALOG_TEXT}\')">'
        )
    if context == CONTEXT_JS_CODE:
        # Inside script state: no tag to break out of — the payload is the
        # script itself, calling confirm with the shared dialog text.
        return f"confirm('{DIALOG_TEXT}')"
    if context == CONTEXT_DOM_URL_ATTRIBUTE:
        # A javascript: URL into a page-parsed attribute. Execution needs a
        # user interaction the verifier does not simulate — so the grammar
        # still carries the payload (the audit shows what *would* be sent),
        # and interpret() is what keeps the resulting candidate a lead.
        ident = reflected.marker_identifier(CONTEXT_RAW_HTML)
        return f"javascript:{ident}=1;confirm('{DIALOG_TEXT}')"
    return ""


def _execution_markers(context: str) -> dict[str, str]:
    """The marker the payload's script sets, keyed by context."""
    ident = reflected.marker_identifier(context)
    return {f"exec:{ident}": f"window.{ident} === 1"}


def execution_spec_for(hypothesis: Hypothesis, context: str) -> ProbeSpec | None:
    """The payload spec for *context*, or ``None`` when none exists.

    The interpret half's bridge: it answers "can this placement be confirmed
    at all" with the same table ``probes`` builds from, so the two halves
    cannot disagree about which contexts have payloads.
    """
    payload = _payload_for(hypothesis, context)
    if not payload:
        return None
    surface = hypothesis.surface
    return _browser_spec(
        hypothesis,
        probe_id=f"{NAME}:{surface.host}:payload:{context}:{surface.param}",
        url=with_parameter(surface.url, surface.param, payload),
        markers=_execution_markers(context),
        oracle=ORACLE_SCRIPT_EXECUTION,
        requires_context=(context,),
        purpose=PURPOSE_CONFIRM,
    )


__all__ = [
    "CANARY",
    "DIALOG_TEXT",
    "MARK",
    "NAME",
    "execution_spec_for",
    "probes",
]
