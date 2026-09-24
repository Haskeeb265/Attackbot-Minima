"""Observations: bytes in, structure out, and never a text blob.

The rule this module exists to enforce: *no observation payload is a string*. A
doctor does not hand you a photograph of the swamp the nurse scooped out of your
arm; the lab returns numbers with units and labels. "Script executed in a
double-quoted attribute context after mutation Y" is only expressible if the
observation model has those words — and only *then* can a memory layer generalise
over "double-quoted attribute" instead of over HTML soup.

Consequences that shaped the code:

* every payload is a ``dict`` of named, primitive fields (``str`` values only
  where the field genuinely *is* a label, like a URL or a context name — never a
  response body);
* reflection context is an enum, not a sentence, because a verifier and a
  scheduler both need to compare contexts without parsing English;
* the same vocabulary is used by the proposer and the verifier, so a verdict can
  say "the class differs" without either side re-deriving what the other meant.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# --------------------------------------------------------------------------- #
# Observation kinds — what the world model's rows are labelled with
# --------------------------------------------------------------------------- #

#: A response came back.  Payload: status, bytes, elapsed, final_url, error.
OBS_HTTP_RESPONSE = "observation.http"
#: The response body contained our input, and here is where.
#: Payload: context, occurrences, byte_offsets, prefix/suffix.
OBS_REFLECTION = "observation.reflection"
#: A browser ran the page.  Payload: driver, status, markers, mutation count.
OBS_BROWSER = "observation.browser"
#: A named predicate the runner asked the page for.
OBS_SCRIPT_EXECUTION = "observation.script_execution"
#: A dialog the page opened (``confirm``/``alert``/``prompt``).
OBS_DIALOG = "observation.dialog"
#: Our collaborator saw an inbound interaction.
OBS_OOB_INTERACTION = "observation.oob"
#: The browser placed our value into the page's DOM — placement, not execution.
#: Payload: context, container_tag, attribute (when in an attribute value),
#: sink (when the placement came from a known sink expression).
OBS_DOM_PLACEMENT = "observation.dom_placement"

OBSERVATION_KINDS: tuple[str, ...] = (
    OBS_HTTP_RESPONSE,
    OBS_REFLECTION,
    OBS_BROWSER,
    OBS_SCRIPT_EXECUTION,
    OBS_DIALOG,
    OBS_OOB_INTERACTION,
    OBS_DOM_PLACEMENT,
)

# --------------------------------------------------------------------------- #
# Reflection contexts — where an injected value landed
# --------------------------------------------------------------------------- #

CONTEXT_DOUBLE_QUOTED_ATTRIBUTE = "double_quoted_attribute"
CONTEXT_SINGLE_QUOTED_ATTRIBUTE = "single_quoted_attribute"
CONTEXT_UNQUOTED_ATTRIBUTE = "unquoted_attribute"
#: Inside a tag but not in an attribute value (between attributes, or in the tag
#: name itself).  Only a `>` break-out is available from here — no `<script>`
#: executes — so this context is deliberately *not* in the executable set, and it
#: exists so "between attributes" is never conflated with "in an attribute value".
CONTEXT_IN_TAG = "in_tag"
CONTEXT_JS_STRING = "js_string"
CONTEXT_JS_CODE = "js_code"
CONTEXT_CSS = "css"
CONTEXT_RAW_HTML = "raw_html"
CONTEXT_COMMENT = "comment"
#: The value came back inside a **JSON (or JSON-family) response** — a string
#: value in an API document, not markup. Classified from the response's declared
#: Content-Type, *never* by sniffing bytes: sniffing is how a JSON document that
#: happens to contain ``<script>`` ends up mislabelled. The context is
#: deliberately NOT executable: the wire lens cannot know which client-side sink
#: the value reaches (the DOM lens exists for that question), so claiming
#: ``raw_html`` here was the engine claiming markup parsing it had not observed.
#: The reflection itself stays a fact (an API echo is a real lead for client-side
#: classes); the fiction was only the context name.
CONTEXT_JSON_VALUE = "json_value"
#: Reflected, but the parse could not place it (a broken document, an encoding
#: we do not walk).  Honest, and distinct from "not reflected".
CONTEXT_UNKNOWN = "unknown"
#: The value sits in a DOM attribute value where *any* value the page re-parses
#: as a URL (``src``, ``href``, …) turns ``javascript:`` into execution. A byte-
#: level reflection cannot have this shape (a URL scheme needs no breakout), so
#: it is a DOM-only context — and executable, for the same reason the attribute
#: breakouts are.
CONTEXT_DOM_URL_ATTRIBUTE = "dom_url_attribute"
#: The value sits in some attribute value the lens could not classify as URL-
#: parsed. Serialization re-quotes attributes, so the DOM lens cannot tell a
#: double- from a single-quoted context — and without the quoting, a breakout
#: payload would be guesswork. A lead, never an auto-executable placement.
CONTEXT_DOM_ATTRIBUTE = "dom_attribute"
#: The value reached the page's DOM as *text* — it landed, but escaped or
#: text-node'd, where markup cannot be parsed. A lead-shaped fact (like a
#: reflected comment), never "safe": which sink produced it is what a memory
#: layer generalises over.
CONTEXT_DOM_TEXT = "dom_text"
#: Our value did not reach the page's DOM at all. A *fact* the run records with
#: its reason (encoded away, dropped by the framework, or our instrument could
#: not tell) — never a silent "safe".
CONTEXT_DOM_ABSENT = "dom_absent"
#: The DOM questions could not be answered (the page never settled, the marker
#: expression itself failed). Honest ignorance, distinct from "absent": absent
#: means the instrument looked and the value was not there; unknown means the
#: instrument could not look.
CONTEXT_DOM_UNKNOWN = "dom_unknown"

DOM_ONLY_CONTEXTS: frozenset[str] = frozenset(
    {
        CONTEXT_DOM_TEXT,
        CONTEXT_DOM_ATTRIBUTE,
        CONTEXT_DOM_URL_ATTRIBUTE,
        CONTEXT_DOM_ABSENT,
        CONTEXT_DOM_UNKNOWN,
    }
)

REFLECTION_CONTEXTS: tuple[str, ...] = (
    CONTEXT_DOUBLE_QUOTED_ATTRIBUTE,
    CONTEXT_SINGLE_QUOTED_ATTRIBUTE,
    CONTEXT_UNQUOTED_ATTRIBUTE,
    CONTEXT_IN_TAG,
    CONTEXT_JS_STRING,
    CONTEXT_JS_CODE,
    CONTEXT_CSS,
    CONTEXT_RAW_HTML,
    CONTEXT_COMMENT,
    CONTEXT_JSON_VALUE,
    CONTEXT_UNKNOWN,
)

#: Contexts where a `<script>` payload becomes executable markup.  The set is
#: here (not in the technique) because two techniques and the verifier all need
#: the same answer, and a technique that disagreed with the verifier about what
#: "executable" means would be a bug with no test that could catch it.
#: Deliberately absent: ``dom_url_attribute`` — a ``javascript:`` value in a
#: page-parsed URL attribute executes only *on user interaction*, which the
#: verifier does not simulate, so a payload family for it does not exist yet and
#: the context cannot honestly sit in the auto-executable set.
SCRIPT_EXECUTABLE_CONTEXTS: frozenset[str] = frozenset(
    {
        CONTEXT_DOUBLE_QUOTED_ATTRIBUTE,
        CONTEXT_SINGLE_QUOTED_ATTRIBUTE,
        CONTEXT_UNQUOTED_ATTRIBUTE,
        CONTEXT_RAW_HTML,
    }
)

#: Contexts where a payload lands inside JavaScript already, so executable code
#: needs no tag break-out at all.
JS_EXECUTABLE_CONTEXTS: frozenset[str] = frozenset({CONTEXT_JS_STRING, CONTEXT_JS_CODE})

#: Contexts the observation layer must never claim: an unparsed reflection is
#: reported as this, so "unknown" is never confused with "safe".
DANGEROUS_UNKNOWN = CONTEXT_UNKNOWN


def is_reflection_context(value: str) -> bool:
    """True when *value* is one of the context names this engine recognises."""
    return value in REFLECTION_CONTEXTS


#: Content-Type families. Markup goes to the HTML context classifier; the JSON
#: family to the non-executable ``json_value`` context; everything else is
#: honest ``unknown`` (the lens only understands markup). An absent header is
#: deliberately NOT "other": too many real servers omit it on HTML responses,
#: and refusing to classify those would regress the server-rendered targets
#: for no safety gain.
MARKUP_TYPES = ("text/html", "application/xhtml", "text/xml", "application/xml")
JSON_TYPES = ("application/json", "application/ld+json", "text/json")


def context_for_content_type(content_type: str) -> str | None:
    """The reflection context *content_type* forces, or ``None`` when the HTML
    classifier should decide.

    The gate is **declared type, not sniffed bytes**: a JSON document that
    happens to contain ``<script>`` must stay ``json_value`` because its
    producer promised JSON, and an HTML document with no header must still be
    classified because its producer merely said nothing. ``None`` means "the
    HTML state machine may run"; a string return is the forced context for
    *every* reflection found in the body.
    """
    value = (content_type or "").split(";", 1)[0].strip().lower()
    if not value:
        return None
    if value.startswith(MARKUP_TYPES):
        return None
    if value.startswith(JSON_TYPES):
        return CONTEXT_JSON_VALUE
    return CONTEXT_UNKNOWN


def is_executable_context(value: str) -> bool:
    """True when markup injected at this context can execute script."""
    return value in SCRIPT_EXECUTABLE_CONTEXTS or value in JS_EXECUTABLE_CONTEXTS


# --------------------------------------------------------------------------- #
# The record
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Observation:
    """The observation layer's output: typed fields with labels.

    ``payload`` is a ``dict``, never a ``str``. That is not a style preference —
    the invariant test reads this annotation, and a text blob here would make
    every downstream question ("which context?", "how many bytes?") a parsing
    problem instead of a lookup.
    """

    kind: str
    payload: dict = field(default_factory=dict)
    #: Which probe produced it, when it came from one.
    probe: str = ""
    #: Set by the caller; modules stay clock-free, so a log is replayable.
    at: float = 0.0

    def __post_init__(self) -> None:
        if not isinstance(self.payload, dict):
            raise TypeError(
                "an Observation payload must be a dict of typed fields; the engine "
                "never stores raw text"
            )
        # Taken by value: the log is the record, and an observation that aliased the
        # dict that produced it could be edited after the fact.
        object.__setattr__(self, "payload", dict(self.payload))

    def get(self, key: str, default: object = None) -> object:
        """Read one typed field (convenience for the pure consumers)."""
        return self.payload.get(key, default)

    @property
    def context(self) -> str:
        """The reflection context this observation carries, when it carries one."""
        value = self.payload.get("context", "")
        return str(value) if value else ""

    def to_dict(self) -> dict:
        payload: dict = {
            "kind": self.kind,
            "payload": dict(self.payload),
            "at": round(self.at, 3),
        }
        if self.probe:
            payload["probe"] = self.probe
        return payload

    @classmethod
    def from_dict(cls, row: dict) -> "Observation":
        """Rebuild from a world-log row (the replay path)."""
        return cls(
            kind=str(row.get("kind", "")),
            payload=dict(row.get("payload") or {}),
            probe=str(row.get("probe", "") or ""),
            at=float(row.get("at") or 0.0),
        )


__all__ = [
    "CONTEXT_COMMENT",
    "CONTEXT_CSS",
    "CONTEXT_DOM_ABSENT",
    "CONTEXT_DOM_ATTRIBUTE",
    "CONTEXT_DOM_TEXT",
    "CONTEXT_DOM_UNKNOWN",
    "CONTEXT_DOM_URL_ATTRIBUTE",
    "CONTEXT_DOUBLE_QUOTED_ATTRIBUTE",
    "CONTEXT_IN_TAG",
    "CONTEXT_JS_CODE",
    "CONTEXT_JS_STRING",
    "CONTEXT_RAW_HTML",
    "CONTEXT_SINGLE_QUOTED_ATTRIBUTE",
    "CONTEXT_UNKNOWN",
    "CONTEXT_UNQUOTED_ATTRIBUTE",
    "DANGEROUS_UNKNOWN",
    "JS_EXECUTABLE_CONTEXTS",
    "OBSERVATION_KINDS",
    "OBS_BROWSER",
    "OBS_DIALOG",
    "OBS_DOM_PLACEMENT",
    "OBS_HTTP_RESPONSE",
    "OBS_OOB_INTERACTION",
    "OBS_REFLECTION",
    "OBS_SCRIPT_EXECUTION",
    "Observation",
    "REFLECTION_CONTEXTS",
    "SCRIPT_EXECUTABLE_CONTEXTS",
    "is_executable_context",
    "is_reflection_context",
]
