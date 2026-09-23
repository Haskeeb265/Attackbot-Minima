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

OBSERVATION_KINDS: tuple[str, ...] = (
    OBS_HTTP_RESPONSE,
    OBS_REFLECTION,
    OBS_BROWSER,
    OBS_SCRIPT_EXECUTION,
    OBS_DIALOG,
    OBS_OOB_INTERACTION,
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
#: Reflected, but the parse could not place it (a broken document, an encoding
#: we do not walk).  Honest, and distinct from "not reflected".
CONTEXT_UNKNOWN = "unknown"

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
    CONTEXT_UNKNOWN,
)

#: Contexts where a `<script>` payload becomes executable markup.  The set is
#: here (not in the technique) because two techniques and the verifier all need
#: the same answer, and a technique that disagreed with the verifier about what
#: "executable" means would be a bug with no test that could catch it.
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
