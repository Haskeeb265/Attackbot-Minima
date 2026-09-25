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

from ...kernel.evidence import EVIDENCE_REFLECTION, Evidence
from ...kernel.observation import OBS_REFLECTION, Observation
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


def candidates(hypothesis: Hypothesis, observations: list[Observation]) -> list[Candidate]:
    """Candidates this hypothesis's observations support.  Usually zero or one."""
    surface = hypothesis.surface
    probe = probe_grammar.probe_id(hypothesis)
    echo = _echo(observations, probe)
    if echo is None:
        return []
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
            summary=(
                f"the response to a caller-supplied {surface.param!r} contained our "
                "collaborator's answer, which a server-side fetch would explain"
            ),
            evidence=Evidence(
                kind=OBS_REFLECTION,
                grade=EVIDENCE_REFLECTION,
                payload=dict(echo.payload),
                probe=echo.probe,
                at=echo.at,
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
