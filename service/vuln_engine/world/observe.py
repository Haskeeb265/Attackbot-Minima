"""The observation layer: raw bytes in, typed structure out, bytes discarded.

Pure by construction — no I/O, no clock, no imports from anywhere but the kernel.
This is the module that decides what a response *means* structurally, and its
purity is what lets every technique be tested against recorded pages instead of
against the internet.

The load-bearing piece is :func:`classify_context`. "The parameter reflects" is a
lead; "the parameter reflects inside a double-quoted attribute value" is a fact
that a verifier can act on, a memory layer can generalise over, and a report can
state. It is a small HTML scanner rather than a parser on purpose: it walks the
document up to the reflection offset and answers one question about the state it
is in. A full HTML parser would be more correct in the corners and much harder to
reason about when it disagrees with what a browser actually did — and the browser
is the arbiter in this design, not us (see ``verification/browser_runner.py``).

Two honesty rules the code follows:

* an unparseable document yields :data:`CONTEXT_UNKNOWN`, never "not reflected" —
  a parse failure is our ignorance, not the target's safety;
* a guaranteed-escaped reflection (`&lt;` for `<`) is recorded as *transformed*,
  because "the bytes came back" and "the bytes came back usable" are different
  facts and only the second one is interesting.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..kernel.exchange import RawBrowserRun, RawHttpExchange, RawOobFetch
from ..kernel.observation import (
    CONTEXT_COMMENT,
    CONTEXT_CSS,
    CONTEXT_DOM_ABSENT,
    CONTEXT_DOM_ATTRIBUTE,
    CONTEXT_DOM_TEXT,
    CONTEXT_DOM_UNKNOWN,
    CONTEXT_DOM_URL_ATTRIBUTE,
    CONTEXT_DOUBLE_QUOTED_ATTRIBUTE,
    CONTEXT_IN_TAG,
    CONTEXT_JS_CODE,
    CONTEXT_JS_STRING,
    CONTEXT_RAW_HTML,
    CONTEXT_SINGLE_QUOTED_ATTRIBUTE,
    CONTEXT_UNKNOWN,
    CONTEXT_UNQUOTED_ATTRIBUTE,
    OBS_BROWSER,
    OBS_DIALOG,
    OBS_DOM_PLACEMENT,
    OBS_HTTP_RESPONSE,
    OBS_OOB_INTERACTION,
    OBS_REFLECTION,
    OBS_SCRIPT_EXECUTION,
    Observation,
)
from ..techniques.common import (
    DOM_MARKER_PREFIX,
    DOM_Q_ATTR,
    DOM_Q_HTML,
    DOM_Q_PRESENT,
    DOM_Q_SCRIPT,
    DOM_Q_TEXT,
    DOM_Q_URLATTR,
)

#: Per-character entity maps: what an escaped character looks like.  Two tables
#: because targets disagree about which form they use, and a check that only knew
#: ``&quot;`` would call a target that writes ``&#34;`` unescaped.  Applied one
#: character at a time — replacing whole entities in sequence would re-escape the
#: entities it had just written (``&lt;`` becoming ``&amp;lt;``), which is a bug
#: that looks exactly like a target behaving correctly.
_ENTITY_NAMED: dict[str, str] = {
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
    "&": "&amp;",
}
_ENTITY_NUMERIC: dict[str, str] = {
    "<": "&#60;",
    ">": "&#62;",
    '"': "&#34;",
    "'": "&#39;",
    "&": "&#38;",
}

_TAG_NAME = re.compile(r"[A-Za-z][A-Za-z0-9:-]*")
_END_SCRIPT = re.compile(r"</\s*script", re.IGNORECASE)
_END_STYLE = re.compile(r"</\s*style", re.IGNORECASE)


@dataclass(frozen=True)
class Reflection:
    """The typed answer to "did our input come back, and where did it land?"."""

    reflected: bool = False
    #: Number of times the exact canary appears.
    occurrences: int = 0
    #: Context of the *first* occurrence — the one a payload will be built for.
    context: str = CONTEXT_UNKNOWN
    #: Every distinct context the canary appeared in, in document order.
    contexts: tuple[str, ...] = ()
    #: Byte offsets of each exact occurrence.
    offsets: tuple[int, ...] = ()
    #: A distinctive mark of the canary was found, but not the canary itself: the
    #: target transformed it (escaped, stripped or split).
    transformed: bool = False
    #: Short structural prefix around the first occurrence, for the log — the one
    #: place a *small* amount of surrounding text is kept, because a context with
    #: no neighbourhood is not reviewable by a human.
    prefix: str = ""
    suffix: str = ""

    @property
    def executable_context(self) -> bool:
        from ..kernel.observation import is_executable_context

        return self.reflected and is_executable_context(self.context)

    def to_payload(self) -> dict:
        """The typed fields this becomes as an observation payload."""
        payload: dict = {
            "reflected": self.reflected,
            "occurrences": self.occurrences,
            "context": self.context,
            "contexts": list(self.contexts),
            "transformed": self.transformed,
        }
        if self.offsets:
            payload["offsets"] = list(self.offsets)
        if self.prefix:
            payload["prefix"] = self.prefix
        if self.suffix:
            payload["suffix"] = self.suffix
        return payload


# --------------------------------------------------------------------------- #
# the scanner
# --------------------------------------------------------------------------- #


def classify_context(html: str, index: int) -> str:
    """Where offset *index* of *html* sits, structurally.

    Walks the document from the start and answers one question about the state it
    is in when it arrives. Never raises: a malformed document returns
    :data:`CONTEXT_UNKNOWN`, because our inability to place a reflection is not
    evidence about the target.
    """
    if index < 0 or index > len(html):
        raise ValueError(f"offset {index} is outside the document")
    try:
        return _walk(html, index)
    except Exception:  # noqa: BLE001 - a parse failure is ignorance, not safety
        return CONTEXT_UNKNOWN


def _walk(html: str, index: int) -> str:
    """The scanner behind :func:`classify_context`."""
    text_state = CONTEXT_RAW_HTML
    in_tag = False
    tag_name = ""
    quote = ""
    seen_equals = False
    in_script = False
    in_style = False
    in_comment = False
    js_quote = ""
    js_comment = False

    position = 0
    while position < index:
        char = html[position]

        if in_comment:
            if html.startswith("-->", position):
                in_comment = False
                position += 3
                continue
            position += 1
            continue

        if in_script or in_style:
            if js_comment:
                if html.startswith("*/", position):
                    js_comment = False
                    position += 2
                    continue
                position += 1
                continue
            if in_script and js_quote:
                if char == "\\":
                    position += 2
                    continue
                if char == js_quote:
                    js_quote = ""
                position += 1
                continue
            closing = _END_SCRIPT if in_script else _END_STYLE
            if char == "<" and closing.match(html, position):
                # Skip past the closing tag; the text state resumes after it.
                end = html.find(">", position)
                position = len(html) if end == -1 else end + 1
                in_script = in_style = False
                js_quote = ""
                text_state = CONTEXT_RAW_HTML
                continue
            if in_script:
                if html.startswith("<!--", position):
                    in_comment = True
                    position += 4
                    continue
                if html.startswith("//", position):
                    end = html.find("\n", position)
                    position = len(html) if end == -1 else end
                    continue
                if html.startswith("/*", position):
                    js_comment = True
                    position += 2
                    continue
                if char in "\"'`":
                    js_quote = char
                    position += 1
                    continue
            position += 1
            continue

        if in_tag:
            if quote:
                if char == quote:
                    quote = ""
                position += 1
                continue
            if char in "\"'":
                quote = char
                position += 1
                continue
            if char == "=":
                seen_equals = True
                position += 1
                continue
            if char in " \t\r\n":
                # Whitespace ends an unquoted attribute value and starts a new
                # attribute name, so the `=` we saw no longer describes where we are.
                seen_equals = False
                position += 1
                continue
            if char == ">":
                in_tag = False
                text_state = CONTEXT_RAW_HTML
                if tag_name == "script":
                    in_script = True
                    js_quote = ""
                elif tag_name == "style":
                    in_style = True
                continue
            position += 1
            continue

        # text state
        if html.startswith("<!--", position):
            in_comment = True
            position += 4
            continue
        if char == "<":
            in_tag = True
            quote = ""
            seen_equals = False
            match = _TAG_NAME.match(html, position + 1)
            tag_name = match.group(0).lower() if match else ""
            position += 1
            continue
        position += 1

    if in_comment:
        return CONTEXT_COMMENT
    if in_script:
        return CONTEXT_JS_STRING if js_quote else CONTEXT_JS_CODE
    if in_style:
        return CONTEXT_CSS
    if in_tag:
        if quote == '"':
            return CONTEXT_DOUBLE_QUOTED_ATTRIBUTE
        if quote == "'":
            return CONTEXT_SINGLE_QUOTED_ATTRIBUTE
        if seen_equals:
            return CONTEXT_UNQUOTED_ATTRIBUTE
        return CONTEXT_IN_TAG
    return text_state


# --------------------------------------------------------------------------- #
# reflection
# --------------------------------------------------------------------------- #

#: How much neighbourhood is kept around a reflection.  Small on purpose: a
#: context with no surrounding text is not reviewable, and the whole document is
#: not ours to store.
_NEIGHBOURHOOD = 40


def find_reflection(html: str, canary: str, *, mark: str = "") -> Reflection:
    """Locate *canary* in *html* and place it structurally.

    *mark* is a short distinctive substring of the canary (e.g. a random token
    with no markup characters) used to detect the *transformed* case: the mark is
    present, the canary is not, so the target altered our bytes rather than
    dropping them.
    """
    if not canary:
        return Reflection()
    offsets = tuple(
        match.start() for match in re.finditer(re.escape(canary), html)
    )
    if not offsets:
        transformed = bool(mark) and mark in html
        return Reflection(transformed=transformed)
    contexts: list[str] = []
    for offset in offsets:
        context = classify_context(html, offset)
        if context not in contexts:
            contexts.append(context)
    first = offsets[0]
    return Reflection(
        reflected=True,
        occurrences=len(offsets),
        context=contexts[0],
        contexts=tuple(contexts),
        offsets=offsets,
        prefix=html[max(0, first - _NEIGHBOURHOOD) : first],
        suffix=html[first + len(canary) : first + len(canary) + _NEIGHBOURHOOD],
    )


def is_escaped_verbatim(html: str, canary: str) -> bool:
    """True when the canary is present only in escaped form.

    A separate question from :func:`find_reflection`: a server that HTML-escapes
    its output is *safe* for this vuln class, and recording that as "reflected"
    would be the single most common false lead in the whole engine.
    """
    if canary in html:
        return False
    return any(
        "".join(table.get(char, char) for char in canary) in html
        for table in (_ENTITY_NAMED, _ENTITY_NUMERIC)
    )


# --------------------------------------------------------------------------- #
# exchange -> observations
# --------------------------------------------------------------------------- #


def http_observations(
    exchange: RawHttpExchange,
    *,
    probe: str = "",
    canary: str = "",
    mark: str = "",
    at: float = 0.0,
    timing_class: str = "",
) -> list[Observation]:
    """Parse one HTTP exchange into typed observations.

    The response observation always exists (even a transport failure is a fact
    worth recording); the reflection observation exists only when there is
    something to say about the canary.

    ``timing_class`` labels the response observation with *which population the
    request belonged to* (``baseline`` vs ``injected``) for the timing-differential
    technique. A label rather than a separate observation kind on purpose: timing
    is not a different fact about the world, it is the same response fact with a
    grouping key, and one kind keeps the log's vocabulary small.
    """
    response_payload: dict = {
        "url": exchange.url,
        "method": exchange.method,
        "status": exchange.status,
        "bytes": len(exchange.body),
        "elapsed": round(exchange.elapsed, 4),
        "ok": exchange.ok,
        "transport": exchange.transport,
        **({"final_url": exchange.final_url} if exchange.final_url else {}),
        **({"error": exchange.error} if exchange.error else {}),
    }
    if timing_class:
        response_payload["timing_class"] = timing_class
    observations: list[Observation] = [
        Observation(
            kind=OBS_HTTP_RESPONSE,
            probe=probe,
            at=at,
            payload=response_payload,
        )
    ]
    if not canary or not exchange.ok:
        return observations
    html = exchange.text
    reflection = find_reflection(html, canary, mark=mark)
    if reflection.reflected or reflection.transformed or is_escaped_verbatim(html, canary):
        payload = reflection.to_payload()
        if is_escaped_verbatim(html, canary):
            payload["escaped_verbatim"] = True
        observations.append(
            Observation(kind=OBS_REFLECTION, probe=probe, at=at, payload=payload)
        )
    return observations


def _dom_placement_question_table() -> dict[str, str]:
    """The placement-producing question -> context mapping, as data.

    The technique grammar and this reader share the question names (via
    ``techniques.common``); this table is the reader's half, exposed so the
    invariant test can prove the two sides never drift apart. It holds every
    question *except* ``present`` — which is the gate question, not a
    placement (see :func:`_dom_placement_observations`).
    """
    return {
        DOM_Q_TEXT: CONTEXT_DOM_TEXT,
        DOM_Q_ATTR: CONTEXT_DOM_ATTRIBUTE,
        DOM_Q_URLATTR: CONTEXT_DOM_URL_ATTRIBUTE,
        DOM_Q_HTML: CONTEXT_RAW_HTML,
        DOM_Q_SCRIPT: CONTEXT_JS_CODE,
    }


def _dom_placement_observations(
    run: RawBrowserRun, *, probe: str, at: float
) -> list[Observation]:
    """The ``dom:``-prefixed marker answers, as placement observations.

    A placement marker is named ``dom:<mark>:<question>`` and is a **boolean
    predicate** — the transport's marker channel coerces every answer to bool,
    so a placement is established by *which* questions answered true, never by
    a string the channel would have flattened. The technique's JS asks each
    question independently ("is the canary in a text node?", "in a URL-parsed
    attribute value?", ...) and the mapping below turns each true answer into
    one row. A page can legitimately answer more than one (text *and* markup
    sibling nodes); the rows record what was seen, and the technique's
    interpreter — not this mapping — decides which row a candidate rests on.

    The mapping is total and honest by construction: a ``dom:`` marker the
    grammar never named becomes a ``dom_unknown`` row rather than a context the
    technique invented, a question the page answered *false* produces no row,
    and a true ``present`` with no placement beside it becomes a single
    ``dom_absent`` row — the value landed and the DOM parsed it nowhere live:
    a recorded negative, not a silence.

    This module reads the question names from ``techniques.common`` — the one
    shared spelling — so a renamed question is a breaking change to both sides,
    pinned by the invariant test, rather than a silent disagreement.
    """
    contexts = _dom_placement_question_table()
    rows: list[Observation] = []
    present = False
    for marker in sorted(run.markers):
        if not marker.startswith(DOM_MARKER_PREFIX):
            continue
        question = marker.rsplit(":", 1)[-1]
        if not bool(run.markers[marker]):
            continue
        if question == DOM_Q_PRESENT:
            # The gate question: answered true, it says the value reached the
            # page — but *where* is what the placement questions say. It never
            # produces a row by itself; its one product is the dom_absent row
            # below, when it is true and no placement followed.
            present = True
            continue
        rows.append(
            Observation(
                kind=OBS_DOM_PLACEMENT,
                probe=probe,
                at=at,
                payload={"context": contexts.get(question, CONTEXT_DOM_UNKNOWN), "question": question},
            )
        )
    if present and not rows:
        rows.append(
            Observation(
                kind=OBS_DOM_PLACEMENT,
                probe=probe,
                at=at,
                payload={"context": CONTEXT_DOM_ABSENT, "question": DOM_Q_PRESENT},
            )
        )
    return rows


def browser_observations(run: RawBrowserRun, *, probe: str = "", at: float = 0.0) -> list[Observation]:
    """Parse one browser run into typed observations.

    The run observation is always recorded; a marker only becomes a
    ``script_execution`` observation when its answer is *true*, because "the
    marker did not appear" is the absence of a finding, not a finding.
    """
    observations: list[Observation] = [
        Observation(
            kind=OBS_BROWSER,
            probe=probe,
            at=at,
            payload={
                "url": run.url,
                "driver": run.driver,
                "ok": run.ok,
                "status": run.status,
                "mutations": run.mutations,
                "elapsed": round(run.elapsed, 4),
                **({"final_url": run.final_url} if run.final_url else {}),
                **({"error": run.error} if run.error else {}),
                **({"console_errors": list(run.console_errors)} if run.console_errors else {}),
            },
        )
    ]
    for marker, answer in sorted(run.markers.items()):
        if marker.startswith(DOM_MARKER_PREFIX):
            # A placement answer is not an execution fact: it becomes a
            # ``dom_placement`` row below, never a ``script_execution`` row —
            # otherwise a canary merely *landing* somewhere would be counted
            # by the driver as "the script ran".
            continue
        observations.append(
            Observation(
                kind=OBS_SCRIPT_EXECUTION,
                probe=probe,
                at=at,
                payload={"marker": marker, "executed": bool(answer)},
            )
        )
    for kind, message in run.dialogs:
        observations.append(
            Observation(
                kind=OBS_DIALOG,
                probe=probe,
                at=at,
                payload={"dialog": kind, "message": message},
            )
        )
    observations.extend(_dom_placement_observations(run, probe=probe, at=at))
    return observations


def oob_observations(fetch: RawOobFetch, *, at: float = 0.0) -> list[Observation]:
    """Parse a collaborator lookup into typed observations, one per interaction."""
    return [
        Observation(
            kind=OBS_OOB_INTERACTION,
            probe=interaction.probe or fetch.probe,
            at=at,
            payload={
                "method": interaction.method,
                "path": interaction.path,
                "source_ip": interaction.source_ip,
                "user_agent": interaction.user_agent,
                # The collaborator's own clock is the one time in this engine that
                # is not the caller's — it is somebody else's machine's fact, so it
                # is carried as data rather than used as a timestamp.
                "interaction_seconds": round(interaction.at, 3),
            },
        )
        for interaction in fetch.interactions
    ]


__all__ = [
    "Reflection",
    "browser_observations",
    "classify_context",
    "find_reflection",
    "http_observations",
    "is_escaped_verbatim",
    "oob_observations",
]
