"""The vulnerability-routine corpus: declarative, deterministic, human-curated.

A *routine* is one verifier playbook: a label, the confirm kind it answers, the
payload family it injects, the oracle name that decides, sample counts and a
margin. The verifier agent selects a routine by id; it does **not** invent test
cases.

This is deliberately a small, closed, versioned set — the counterpart of the
hand-authored technique folders. It is the *independent knowledge distribution*
the proposer cannot see: the capability agent says "I suspect SQLi here"; the
verifier agent may only answer with a routine that already existed, so it cannot
tailor the test to make the proposition true.

An added routine is a reviewed code change, never something an agent writes at
run time.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .spec import (
    ORACLE_AUTHZ_DIFFERENTIAL,
    ORACLE_OOB_HIT,
    ORACLE_RESPONSE_DIFFERS,
    ORACLE_SCRIPT_EXECUTED,
    ORACLE_TIMING_DIFFERENTIAL,
)

# --------------------------------------------------------------------------- #
# Capability names — the same spellings the kernel uses
# --------------------------------------------------------------------------- #

CAP_PUBLIC_PARAM = "public_param"
CAP_REFLECTS_INPUT = "http_response_reflects_input"
CAP_INFLUENCE_REMOTE_FETCH = "can_influence_remote_fetch"
CAP_DELAYED_RESPONSE = "delayed_response"
CAP_PERSISTENT_STORAGE = "server_stores_input"
CAP_ACCESS_DIFFERS_BY_SESSION = "access_differs_by_session"


@dataclass(frozen=True)
class Routine:
    """One verifier playbook, before target adaptation."""

    routine_id: str
    label: str
    confirm_kind: str
    oracle: str
    #: The benign population the injected one must differ from.
    baseline_payload: str = "ve-noop0"
    #: A malformed-but-not-target population; strengthens the oracle when present.
    control_payload: str = "ve-control0"
    #: The injected payload family (syntactic families, not one magic string).
    injected_payloads: tuple[str, ...] = ()
    #: How many fresh requests per population.
    samples: int = 3
    #: Timing separation that counts as a difference, in milliseconds.
    margin: float = 1000.0
    #: Body-length change that counts as a response difference, in bytes.
    length_delta: int = 0
    #: Capabilities the surface must have measured before this routine applies.
    preconditions: tuple[str, ...] = ()
    #: Transports the routine needs wired (``http1`` always; others when relevant).
    transports: tuple[str, ...] = ("http1",)
    #: A canary string for reflection/data-extraction oracles.
    canary: str = ""
    #: The marker name a browser oracle asks for.
    marker: str = ""
    vuln_class: str = ""

    def to_dict(self) -> dict:
        return {
            "routine_id": self.routine_id,
            "label": self.label,
            "confirm_kind": self.confirm_kind,
            "oracle": self.oracle,
            "oracle_evidence": _ORACLE_EVIDENCE.get(self.oracle, ""),
            "injected_payloads": list(self.injected_payloads),
            "samples": self.samples,
            "margin": self.margin,
            "preconditions": list(self.preconditions),
            "transports": list(self.transports),
            "vuln_class": self.vuln_class,
        }


# Imported late to avoid a circular import at module load.
from .spec import ORACLE_EVIDENCE as _ORACLE_EVIDENCE  # noqa: E402

# --------------------------------------------------------------------------- #
# The corpus
# --------------------------------------------------------------------------- #

#: The script a reflected-XSS routine injects. Marker assignment + dialog, the
#: same shape the existing browser verifier reads.
_XSS_SCRIPT = (
    "<script>window.__ve=1;document.title='ve-xss';alert('ve-xss')</script>"
)
#: The canary a browser routine asks the page for.
_XSS_MARKER = "ve-xss-exec"

#: Blind SQL injection payloads: a sleep the server executes if the parameter is
#: interpolated into a query. Families, not one string.
_SQLI_PAYLOADS = (
    "1' AND SLEEP(4.0)-- -",
    "1 AND SLEEP(4.0)",
    "1;SELECT SLEEP(4.0)",
)

#: The collaborator marker an SSRF routine injects; the runner replaces the
#: sentinel with a real per-probe URL before sending.
_SSRF_PAYLOAD = "http://ooburlsentinel_ssrf/probe"

ROUTINES: tuple[Routine, ...] = (
    Routine(
        routine_id="xss.browser.v1",
        label="xss",
        vuln_class="xss",
        confirm_kind="browser.run",
        oracle=ORACLE_SCRIPT_EXECUTED,
        injected_payloads=(_XSS_SCRIPT,),
        samples=1,
        marker=_XSS_MARKER,
        preconditions=(CAP_REFLECTS_INPUT,),
        transports=("http1", "browser"),
    ),
    Routine(
        routine_id="sqli.timing.v1",
        label="sqli",
        vuln_class="sqli",
        confirm_kind="timing.differential",
        oracle=ORACLE_TIMING_DIFFERENTIAL,
        injected_payloads=_SQLI_PAYLOADS,
        samples=3,
        margin=1000.0,
        preconditions=(CAP_DELAYED_RESPONSE,),
        transports=("http1",),
    ),
    Routine(
        routine_id="ssrf.oob.v1",
        label="ssrf",
        vuln_class="ssrf",
        confirm_kind="oob.read",
        oracle=ORACLE_OOB_HIT,
        injected_payloads=(_SSRF_PAYLOAD,),
        samples=1,
        preconditions=(CAP_INFLUENCE_REMOTE_FETCH,),
        transports=("http1", "oob"),
    ),
    Routine(
        routine_id="idor.authz.v1",
        label="idor",
        vuln_class="idor",
        confirm_kind="authorization.differential",
        oracle=ORACLE_AUTHZ_DIFFERENTIAL,
        injected_payloads=("",),
        samples=1,
        preconditions=(CAP_ACCESS_DIFFERS_BY_SESSION,),
        transports=("http1",),
    ),
    Routine(
        routine_id="method_confusion.response.v1",
        label="method_confusion",
        vuln_class="method-confusion",
        confirm_kind="differential.response",
        oracle=ORACLE_RESPONSE_DIFFERS,
        baseline_payload="ve-noop0",
        control_payload="ve-control0",
        injected_payloads=("ve-inject0",),
        samples=2,
        length_delta=0,
        preconditions=(CAP_PUBLIC_PARAM,),
        transports=("http1",),
    ),
    Routine(
        routine_id="path_traversal.response.v1",
        label="path_traversal",
        vuln_class="path-traversal",
        confirm_kind="differential.response",
        oracle=ORACLE_RESPONSE_DIFFERS,
        injected_payloads=("../../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd"),
        samples=2,
        preconditions=(CAP_PUBLIC_PARAM,),
        transports=("http1",),
    ),
)

#: label -> routines that answer it. Deterministic order preserved.
_BY_LABEL: dict[str, tuple[Routine, ...]] = {}
_BY_ID: dict[str, Routine] = {}
for _routine in ROUTINES:
    _BY_LABEL.setdefault(_routine.label, ())  # type: ignore[arg-type]
    _BY_LABEL[_routine.label] = (*_BY_LABEL[_routine.label], _routine)
    _BY_ID[_routine.routine_id] = _routine


def routine_ids() -> tuple[str, ...]:
    """Every routine id, sorted — a stable index for prompts and reports."""
    return tuple(sorted(_BY_ID))


def routine_for_id(routine_id: str) -> Routine | None:
    return _BY_ID.get(routine_id)


def routines_for_label(label: str) -> tuple[Routine, ...]:
    """Every routine registered for *label*; empty when none matches."""
    return _BY_LABEL.get(label, ())


def routines_for_kind(confirm_kind: str) -> tuple[Routine, ...]:
    """Every routine that answers *confirm_kind*, in registry order."""
    return tuple(routine for routine in ROUTINES if routine.confirm_kind == confirm_kind)


def select_routine(label: str, confirm_kind: str) -> Routine | None:
    """The single routine for ``(label, confirm_kind)``, or ``None``.

    Deterministic selection: the verifier agent's default (and its no-key
    fallback) is exactly this lookup. When more than one routine matches a pair,
    the first in registry order wins — the corpus is authored so that does not
    happen ambiguously.
    """
    for routine in routines_for_label(label):
        if routine.confirm_kind == confirm_kind:
            return routine
    return None


def index_rows() -> list[dict]:
    """The corpus as compact rows — the read-only index agents may see."""
    return [
        {
            "routine_id": routine.routine_id,
            "label": routine.label,
            "confirm_kind": routine.confirm_kind,
            "vuln_class": routine.vuln_class,
            "preconditions": list(routine.preconditions),
        }
        for routine in ROUTINES
    ]


__all__ = [
    "CAP_ACCESS_DIFFERS_BY_SESSION",
    "CAP_DELAYED_RESPONSE",
    "CAP_INFLUENCE_REMOTE_FETCH",
    "CAP_PERSISTENT_STORAGE",
    "CAP_PUBLIC_PARAM",
    "CAP_REFLECTS_INPUT",
    "ROUTINES",
    "Routine",
    "index_rows",
    "routine_for_id",
    "routine_ids",
    "routines_for_kind",
    "routines_for_label",
    "select_routine",
]
