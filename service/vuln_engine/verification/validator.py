"""The confirm-spec validator: the classic path's planner gate.

The two-gate flow routes every proposal through a ``ConfirmationPlanner``
*before* a verifier agent runs, so a spec that names a different URL or oracle
than its claim is caught at planning time. The classic path used to dispatch
straight from ``candidate.confirm["kind"]`` — techniques are trusted code, but
the dispatch table itself carried no defense in depth: a buggy (or hostile)
technique could hand the timing verifier a URL from another engagement's
surface and get a fresh, honest measurement of the wrong thing, scored
differential.

This module is the same gate, sized for the classic path: one pure function
(:func:`validate_confirm_spec`) that checks *consistency*, not truth —

* the spec's kind must be one the engine speaks (an unknown kind is left to
  the dispatcher's own refusal, so the vocabularies stay in one place);
* every URL the spec names must belong to the surface the candidate declares —
  the verifier may re-measure *this* claim, never a stranger's;
* the fields the answering verifier will read must be present and well-formed
  (a missing margin, oracle or actor is a refusal at dispatch, with the reason
  in the log, instead of a verifier crash or a silent default);
* a claim shape, when present, must be one the engine speaks.

It runs *before* dispatch, so a refused spec costs no measurement and the
refusal lands in the log as a lead with its reason — the same shape as every
other refused confirmation.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from ..kernel.claim import CLAIM_SHAPES

#: The kinds that name target URLs. Every URL a spec of one of these kinds
#: carries must belong to the candidate's declared surface — the host-consistency
#: rule. ``oob.read`` names only our own collaborator's path (the verifier builds
#: the URL itself), so it is deliberately absent here.
_URL_KINDS: frozenset[str] = frozenset(
    {
        "timing.differential",
        "authorization.differential",
        "authorization.state_change",
        "browser.run",
        "xss_stored.execute",
        "differential.response",
    }
)


def _host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _urls_in(spec: dict, kind: str) -> list[str]:
    """Every target URL the spec names, by kind."""
    urls: list[str] = []
    url = str(spec.get("url") or "")
    if url:
        urls.append(url)
    if kind == "authorization.state_change":
        actor = spec.get("actor") or {}
        actor_url = str(actor.get("url") or "") if isinstance(actor, dict) else ""
        victim_url = str(spec.get("victim_url") or "")
        if actor_url:
            urls.append(actor_url)
        if victim_url:
            urls.append(victim_url)
    if kind == "xss_stored.execute":
        inject = spec.get("inject") or {}
        inject_url = str(inject.get("url") or "") if isinstance(inject, dict) else ""
        read_back = str(spec.get("read_back") or "")
        if inject_url:
            urls.append(inject_url)
        if read_back:
            urls.append(read_back)
    return urls


def _required_field_problem(spec: dict, kind: str) -> str:
    """The first missing or malformed field the answering verifier needs."""
    if kind == "timing.differential":
        if not spec.get("url"):
            return "the timing spec names no URL"
        if not spec.get("param"):
            return "the timing spec names no parameter"
        try:
            if float(spec.get("margin") or 0.0) <= 0.0:
                return "the timing spec's margin is not a positive number"
        except (TypeError, ValueError):
            return "the timing spec's margin is not a number"
    elif kind == "authorization.differential":
        if not spec.get("url"):
            return "the authorization spec names no URL"
        if not spec.get("oracle"):
            return "the authorization spec names no oracle"
    elif kind == "authorization.state_change":
        actor = spec.get("actor") or {}
        if not isinstance(actor, dict) or not actor.get("url"):
            return "the state-change spec names no actor change"
        if not spec.get("victim_url"):
            return "the state-change spec names no victim URL"
    elif kind == "browser.run":
        if not spec.get("url"):
            return "the browser spec names no URL"
        if not spec.get("markers"):
            return "the browser spec names no execution markers"
    elif kind == "oob.read":
        if not spec.get("probe") or not spec.get("path"):
            return "the oob spec names no probe path to read"
    elif kind == "differential.response":
        if not spec.get("url"):
            return "the response-differential spec names no URL"
        if not spec.get("param"):
            return "the response-differential spec names no parameter"
        if not spec.get("baseline_payload") or not spec.get("injected_payload"):
            return "the response-differential spec names no baseline or injected population"
    elif kind == "xss_stored.execute":
        inject = spec.get("inject") or {}
        if not isinstance(inject, dict) or not inject.get("url"):
            return "the stored-xss spec names no inject request"
        if not spec.get("read_back"):
            return "the stored-xss spec names no read-back page"
        if not spec.get("markers"):
            return "the stored-xss spec names no execution markers"
    return ""


def validate_confirm_spec(
    spec: dict | None, surface: dict | None
) -> str:
    """``""`` when the spec may be dispatched; otherwise the refusal reason.

    ``spec`` is the candidate's confirmation spec and ``surface`` its declared
    surface dict (``url``/``host``/``param``/``where``). An unknown kind returns
    ``""`` — the dispatcher owns that refusal, and duplicating its vocabulary
    here would be the second copy of a table that drifts.
    """
    confirm = dict(spec or {})
    kind = str(confirm.get("kind") or "")
    if not kind or kind not in _URL_KINDS:
        return ""

    declared_host = str((surface or {}).get("host") or "").lower()
    if not declared_host:
        return "the candidate declares no surface host to hold its confirmation to"
    for url in _urls_in(confirm, kind):
        host = _host_of(url)
        if host != declared_host:
            return (
                f"the confirmation spec names {host or 'a hostless URL'}, but the "
                f"candidate's surface is {declared_host}: a verifier re-measures "
                "the declared claim, never another surface's"
            )

    problem = _required_field_problem(confirm, kind)
    if problem:
        return problem

    claim_shape = str(confirm.get("claim_shape") or "")
    if claim_shape and claim_shape not in CLAIM_SHAPES:
        return (
            f"the confirmation spec's claim_shape {claim_shape!r} is not one the "
            f"engine speaks: {', '.join(CLAIM_SHAPES)}"
        )
    return ""


__all__ = ["validate_confirm_spec"]
