"""The IDOR probe grammar: two paired requests, one per identity.

Two specs per hypothesis, deliberately symmetric:

* ``...:session-a`` runs under the transport's own default shim — session A,
  the identity the operator declared first (typically the owner/admin);
* ``...:session-b`` marks its detail with ``_session="b"`` — the gate swaps
  in the operator's second cookie jar, refusing the request outright when
  none was declared (that refusal is the receipt-honest "never attempted",
  not an answer about the target).

No payloads exist in this grammar on purpose: the URL under test is the
operator's declared surface verbatim. An authorization probe that mutated
the object reference would test an object nobody declared — a different
engagement. The comparison lives in ``interpret``, from the two responses'
status codes; the probes only collect them, each labeled with the identity
that asked.
"""

from __future__ import annotations

from ...kernel.technique import (
    KIND_HTTP,
    PURPOSE_PROPOSE,
    Hypothesis,
    ProbeSpec,
)

#: Noise declaration shared by both probes: two same-URL requests back to
#: back with different cookies are visible as a pair, and pretending
#: otherwise would flatter the technique's fingerprint.
_NOISE = {
    "requests_per_surface": 2,
    "burstiness": 0.6,
    "fingerprint_distance": 0.6,
    "requires_browser": False,
}


def probes(hypothesis: Hypothesis) -> list[ProbeSpec]:
    surface = hypothesis.surface
    return [
        ProbeSpec(
            id=f"idor:{surface.key}:session-a",
            kind=KIND_HTTP,
            host=surface.host,
            detail={"url": surface.url, "method": "GET"},
            oracle="session_status_comparison",
            noise=dict(_NOISE),
            produces="response",
            purpose=PURPOSE_PROPOSE,
            payload="",
        ),
        ProbeSpec(
            id=f"idor:{surface.key}:session-b",
            kind=KIND_HTTP,
            host=surface.host,
            detail={"url": surface.url, "method": "GET", "_session": "b"},
            oracle="session_status_comparison",
            noise=dict(_NOISE),
            produces="response",
            purpose=PURPOSE_PROPOSE,
            payload="",
        ),
    ]


__all__ = ["probes"]
