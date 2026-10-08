"""Interpretation: from an echoed answer to a candidate that only a listener can settle.

The proposer's evidence is weak on purpose, and the module says so in its own
summary line: the *response contained the collaborator's answer*, which is
consistent with the server fetching our URL and also consistent with a cached
page, a proxy error, or a reflected parameter. That is a lead.

The candidate travels with a confirmation spec that asks a different question in a
different class: ``oob.read`` for the probe id, satisfied only by an interaction
record on our own collaborator. A verifier that cannot find one refuses the
candidate and the refusal is logged — which is how a claim about a blind class is
tested rather than assumed.

Note the shape of the confirmation spec: it is an ``oob.read``, not a request to
the target. Confirming a blind fetch must not mean asking the target again.
"""

from __future__ import annotations

from ...kernel.evidence import EVIDENCE_HYPOTHESIS, EVIDENCE_REFLECTION, Evidence
from ...kernel.observation import OBS_HTTP_RESPONSE, OBS_REFLECTION, Observation
from ...kernel.technique import Hypothesis, oob_sentinel
from ...kernel.verdict import Candidate
from ..common import surface_id_prefix, with_parameter
from . import probes as probe_grammar

NAME = "oob_fetch"


def _echo(observations: list[Observation], probe: str) -> Observation | None:
    """The last reflection observation *this probe* produced, when there is one.

    Two filters, both cheap: the row must have come from this probe (so another
    surface's echo cannot be mistaken for this one's) and it must be a real
    reflection. No neighbourhood heuristics — the canary is
    ``vuln-engine-collaborator:<probe>``, and the observation layer emits a
    reflection row only when that exact string is in the body.
    """
    found = [
        item
        for item in observations
        if item.kind == OBS_REFLECTION
        and item.probe == probe
        and item.payload.get("reflected")
    ]
    return found[-1] if found else None


def _sent_exchange(observations: list[Observation], probe: str) -> Observation | None:
    """The response observation for *this probe*, when the exchange completed.

    The blind-SSRF shape has no echo: the target fetched our collaborator URL
    and its own response says nothing about it. What this module can still
    honestly claim is *hypothesis* — "the probe was submitted and the server
    answered without a transport failure" — and that claim rests on the
    ``observation.http`` row the driver always records for a sent probe. The
    verifier (``OobVerifier``, ``oob`` grade) still has to prove the fetch
    actually happened from the collaborator's own interaction record; nothing
    here claims it did.
    """
    found = [
        item
        for item in observations
        if item.kind == OBS_HTTP_RESPONSE and item.probe == probe and item.payload.get("ok")
    ]
    return found[-1] if found else None


def candidates(hypothesis: Hypothesis, observations: list[Observation]) -> list[Candidate]:
    """Candidates this hypothesis's observations support.  Usually zero or one."""
    surface = hypothesis.surface
    probe = probe_grammar.probe_id(hypothesis)
    echo = _echo(observations, probe)
    sent = _sent_exchange(observations, probe)
    if echo is None and sent is None:
        return []
    # Two grades of lead, honestly separated:
    #
    # * an echo in the target's own response keeps ``reflection`` — the
    #   response *contained our collaborator's answer*, which is stronger than
    #   "we asked and nothing contradicts a fetch";
    # * no echo (the common blind-SSRF shape) is only ``hypothesis``: the probe
    #   was submitted and the target answered, which is what the proposer
    #   measured, nothing more. Either way the finding-grade proof is the
    #   same ``oob.read`` spec below, settled by OobVerifier from the
    #   collaborator's interaction record — never by this module.
    if echo is not None:
        grade = EVIDENCE_REFLECTION
        evidence_kind = OBS_REFLECTION
        evidence_payload = dict(echo.payload)
        evidence_probe = echo.probe
        evidence_at = echo.at
        summary = (
            f"the response to a caller-supplied {surface.param!r} contained our "
            "collaborator's answer, which a server-side fetch would explain"
        )
    else:
        grade = EVIDENCE_HYPOTHESIS
        evidence_kind = OBS_HTTP_RESPONSE
        evidence_payload = dict(sent.payload) if sent is not None else {}
        evidence_probe = probe
        evidence_at = sent.at if sent is not None else 0.0
        summary = (
            f"a caller-supplied {surface.param!r} was submitted with a collaborator "
            "URL and the target answered without error — consistent with a blind "
            "server-side fetch; only the collaborator's interaction record, which "
            "the confirmation spec reads, can prove it"
        )
    # The URL as it was actually sent, with the placeholder visible: the real
    # collaborator URL is per-probe and only meaningful while the collaborator is
    # up, so showing where it goes is more honest than inventing a working link.
    # A body surface carried the sentinel in the JSON body, not the URL — so the
    # reproducible location is the bare endpoint (the body shape is named in the
    # surface's own ``where`` field on the candidate).
    if surface.where == "body":
        as_sent = surface.url
    else:
        as_sent = with_parameter(surface.url, surface.param, oob_sentinel(probe))
    return [
        Candidate(
            id=f"{surface_id_prefix(NAME, surface)}",
            technique=NAME,
            vuln_class="ssrf",
            surface={
                "url": surface.url,
                "param": surface.param,
                "where": surface.where,
                "host": surface.host,
            },
            summary=summary,
            evidence=Evidence(
                kind=evidence_kind,
                grade=grade,
                payload=evidence_payload,
                probe=evidence_probe,
                at=evidence_at,
            ),
            confirm={
                "kind": "oob.read",
                "probe": probe,
                "path": probe_grammar.collaborator_path(probe),
                "token": probe_grammar.echo_token(probe),
            },
            # No payload: this candidate is not reproducible by hand the way an XSS
            # one is (the collaborator has to be up and reachable), and inventing a
            # URL that cannot work would be worse than admitting the dependency.
            repro_url=as_sent,
        )
    ]


interpret = candidates

__all__ = ["NAME", "candidates", "interpret"]
