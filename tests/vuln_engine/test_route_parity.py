"""Route parity: the two-gate capability routes and the classic techniques, counted.

Batch 2, Phase 3: the master reference states route parity in prose and was
stale about it once already (the reference's §19.2 table said the delayed-response
capability routes only to SQLi until ``command_injection.timing.v1`` landed).
A count over the real corpora is the pin, the same convention as the inventory
pins file — cheap to count, expensive to leave uncounted.

Two directions:

* **classic → twogate**: every classic technique's confirm kind and vuln class
  has a two-gate route (or a named, documented exclusion);
* **twogate → classic**: every CAPABILITY_ROUTES entry maps back to a classic
  technique (or a named, documented exclusion) and to a routine that actually
  answers the (label, confirm kind) pair — a route with no routine is a dead
  arm the capability agent would propose and the planner would always lead on.

The exclusions are *named*, not silent: each one says why it exists, so the day
it closes, the parity test is the thing that fails first.
"""

from __future__ import annotations

import pytest

from service.vuln_engine.kernel.confirm import ConfirmSpec
from service.vuln_engine.kernel.evidence import EVIDENCE_REFLECTION, Evidence
from service.vuln_engine.kernel.observation import OBS_HTTP_RESPONSE
from service.vuln_engine.kernel.verdict import Candidate
from service.vuln_engine.twogate.agents import CAPABILITY_ROUTES
from service.vuln_engine.twogate.routines import ROUTINES, select_routine
from service.vuln_engine.verification import CONFIRM_VERIFIERS, VerificationLayer
from service.vuln_engine.verification.registry import registry
from service.vuln_engine.verification.response_verifier import (
    CONFIRM_KIND as RESPONSE_CONFIRM_KIND,
)
from service.vuln_engine.world.log import WorldLog
from tests.vuln_engine.conftest import FakeHttpEffect

# --------------------------------------------------------------------------- #
# The two corpora, reduced to what parity is about
# --------------------------------------------------------------------------- #

#: Classic technique name -> the confirm kinds its interpret() branches emit.
#: Counted once here, pinned against the live folders by the registry test
#: below; an empty-confirm branch (a deliberate lead) does not count.
CLASSIC_CONFIRM_KINDS: dict[str, frozenset[str]] = {
    "xss_reflected": frozenset({"browser.run"}),
    "xss_dom": frozenset({"browser.run"}),
    "xss_stored": frozenset({"xss_stored.execute"}),
    "sqli_blind_time": frozenset({"timing.differential"}),
    "command_injection": frozenset({"timing.differential"}),
    "oob_fetch": frozenset({"oob.read"}),
    "idor_differential": frozenset({"authorization.differential"}),
    "generic_differential": frozenset(
        {"authorization.state_change", "authorization.differential"}
    ),
}

#: Classic technique name -> the vuln_class its candidates carry.
CLASSIC_VULN_CLASSES: dict[str, str] = {
    "xss_reflected": "xss",
    "xss_dom": "xss",
    "xss_stored": "xss",
    "sqli_blind_time": "sqli",
    "command_injection": "command-injection",
    "oob_fetch": "ssrf",
    "idor_differential": "idor",
    "generic_differential": "method-confusion",
}

#: The two-gate vuln classes, from the routines the routes select.
TWOGATE_VULN_CLASSES: frozenset[str] = frozenset(r.vuln_class for r in ROUTINES)

#: Named, documented exclusions — classic confirm kinds the two-gate flow
#: deliberately does not answer, each with the reason kept honest in one place.
#: * ``xss_stored.execute``: the stored-xss verifier is a two-step
#:   inject-then-read-back experiment; the capability routing models one
#:   measured capability per surface, not a two-step experiment.
#: * ``authorization.state_change``: the state-change verifier re-executes
#:   setup between two victim reads — the same two-step shape.
CLASSIC_TO_TWOGATE_EXCLUSIONS: dict[str, str] = {
    "xss_stored.execute": (
        "documented exclusion: the stored-xss verifier is a two-step "
        "inject-then-read-back experiment the capability routing does not model"
    ),
    "authorization.state_change": (
        "documented exclusion: the state-change verifier re-executes setup "
        "between two victim reads; no twogate routine models a two-step experiment"
    ),
}

#: The twogate label with no classic technique folder. Named, with the reason:
#: a classic path-traversal folder would be NEW vuln-class breadth (out of
#: batch-2 scope); the confirm kind itself is answered on the classic side by
#: the response-differential verifier (batch 2, Phase 3), so a classic
#: candidate could already ride it — the route is no longer a dead arm.
TWOGATE_TO_CLASSIC_EXCLUSIONS: dict[str, str] = {
    "path_traversal": (
        "documented exclusion: no classic path-traversal technique folder exists "
        "— adding one is vuln-class breadth, out of batch-2 scope; the confirm "
        "kind (differential.response) is answered on the classic side by the "
        "response-differential verifier"
    ),
}


# --------------------------------------------------------------------------- #
# the parity counts
# --------------------------------------------------------------------------- #


def test_every_classic_confirm_kind_is_registered_and_dispatched() -> None:
    for name, kinds in CLASSIC_CONFIRM_KINDS.items():
        for kind in kinds:
            assert kind in registry(), f"{name}'s {kind!r} is unregistered"
            assert kind in CONFIRM_VERIFIERS, (
                f"{name}'s {kind!r} is registered but the classic dispatcher "
                "answers nothing for it"
            )


def test_every_classic_confirm_kind_has_a_twogate_route_or_named_exclusion() -> None:
    route_kinds = {route[1] for routes in CAPABILITY_ROUTES.values() for route in routes}
    for name, kinds in CLASSIC_CONFIRM_KINDS.items():
        for kind in kinds:
            assert kind in route_kinds or kind in CLASSIC_TO_TWOGATE_EXCLUSIONS, (
                f"{name} confirms via {kind!r}, but no twogate route answers it "
                "and no exclusion names why"
            )


def test_every_classic_vuln_class_has_a_twogate_route_or_named_exclusion() -> None:
    for name, vuln_class in CLASSIC_VULN_CLASSES.items():
        assert vuln_class in TWOGATE_VULN_CLASSES, (
            f"{name}'s class {vuln_class!r} has no twogate routine"
        )


def test_every_twogate_route_maps_to_a_classic_technique_or_named_exclusion() -> None:
    classic_classes = set(CLASSIC_VULN_CLASSES.values())
    for capability, routes in CAPABILITY_ROUTES.items():
        for label, confirm_kind, vuln_class, _family in routes:
            # The route's (label, kind) pair must have a routine — otherwise
            # the capability agent proposes what the planner always leads on.
            assert select_routine(label, confirm_kind) is not None, (
                f"CAPABILITY_ROUTES[{capability}] proposes {label!r} with "
                f"{confirm_kind!r} but no routine answers the pair"
            )
            assert (
                vuln_class in classic_classes or label in TWOGATE_TO_CLASSIC_EXCLUSIONS
            ), (
                f"twogate label {label!r} (vuln class {vuln_class!r}) has no "
                "classic technique and no exclusion names why"
            )


def test_the_only_runner_only_confirm_kind_is_differential_extraction() -> None:
    # After Phase 3, every registered kind is answered by the classic
    # dispatcher except ``differential.extraction``, which the runner owns
    # (label-indexed routines read the extracted value back). If this set
    # grows, either land a classic verifier or add a named exclusion here.
    route_kinds = {route[1] for routes in CAPABILITY_ROUTES.values() for route in routes}
    assert "differential.extraction" in registry()
    assert "differential.extraction" in route_kinds
    assert "differential.extraction" not in CONFIRM_VERIFIERS
    assert set(registry()) - set(CONFIRM_VERIFIERS) == {"differential.extraction"}


def test_every_routine_names_a_registered_confirm_kind() -> None:
    for routine in ROUTINES:
        assert routine.confirm_kind in registry(), (
            f"{routine.routine_id} answers {routine.confirm_kind!r}, which is "
            "not in the verifier registry"
        )


# --------------------------------------------------------------------------- #
# the response-differential verifier, pinned against the two-gate oracle
# --------------------------------------------------------------------------- #

_BASE = "http://127.0.0.1:8642"
_HOST = "127.0.0.1"


def _target(seen: dict[str, str]):
    """A scripted target whose answers depend only on the ``file`` value."""

    def respond(url: str) -> "RawHttpExchange":
        from urllib.parse import parse_qs, urlsplit

        from service.vuln_engine.kernel.exchange import RawHttpExchange

        params = parse_qs(urlsplit(url).query, keep_blank_values=True)
        value = params.get("file", [""])[0]
        body = seen.get(value, f"default:{value}").encode("utf-8")
        return RawHttpExchange(url=url, status=200, body=body, headers={})

    return respond


def _candidate(confirm: dict) -> Candidate:
    return Candidate(
        id=f"path_traversal:{_HOST}:/download:file",
        technique="path_traversal",
        vuln_class="path-traversal",
        surface={"url": f"{_BASE}/download", "param": "file", "where": "query", "host": _HOST},
        summary="the file parameter reaches the filesystem",
        evidence=Evidence(
            kind=OBS_HTTP_RESPONSE,
            grade=EVIDENCE_REFLECTION,
            probe="p",
            at=1.0,
            payload={},
        ),
        confirm=confirm,
    )


@pytest.fixture
def response_layer(build_gate) -> VerificationLayer:
    # Responses keyed by the injected ``file`` value: baseline and control are
    # distinct from each other and from every traversal answer.
    seen = {
        "ve-noop0": "noop-page",
        "ve-control0": "control-page",
        "../../../../etc/passwd": "root:x:0:0",
        "../payload": "traversal-page",
    }
    gate = build_gate(http=FakeHttpEffect(respond=_target(seen)), log=WorldLog())
    return VerificationLayer(gate)


def test_a_response_that_differs_from_both_populations_is_proven_fresh(
    response_layer,
) -> None:
    verdict = response_layer.verifiers["response_differential"].verify(
        _candidate(
            {
                "kind": RESPONSE_CONFIRM_KIND,
                "url": f"{_BASE}/download",
                "param": "file",
                "baseline_payload": "ve-noop0",
                "control_payload": "ve-control0",
                "injected_payload": "../../../../etc/passwd",
                "where": "query",
            }
        )
    )
    assert verdict.proven, verdict.reason
    assert verdict.evidence is not None
    assert verdict.evidence.grade == "differential"
    payload = verdict.evidence.payload
    assert payload["injected_status"] == 200
    assert payload["baseline_payload"] == "ve-noop0"
    assert payload["control_payload"] == "ve-control0"
    assert payload["injected_body_hash"] not in {
        payload["baseline_body_hash"],
        payload["control_body_hash"],
    }


def test_a_value_that_changes_nothing_is_refused(response_layer) -> None:
    verdict = response_layer.verifiers["response_differential"].verify(
        _candidate(
            {
                "kind": RESPONSE_CONFIRM_KIND,
                "url": f"{_BASE}/download",
                "param": "file",
                "baseline_payload": "ve-noop0",
                "control_payload": "ve-control0",
                "injected_payload": "ve-noop0",
                "where": "query",
            }
        )
    )
    assert not verdict.proven
    assert "matched the baseline" in verdict.reason


def test_a_value_the_control_also_produces_is_refused(response_layer) -> None:
    verdict = response_layer.verifiers["response_differential"].verify(
        _candidate(
            {
                "kind": RESPONSE_CONFIRM_KIND,
                "url": f"{_BASE}/download",
                "param": "file",
                "baseline_payload": "ve-noop0",
                "control_payload": "ve-control0",
                "injected_payload": "ve-control0",
                "where": "query",
            }
        )
    )
    assert not verdict.proven
    assert "matched the control" in verdict.reason


def test_the_confirm_spec_round_trip_carries_the_populations() -> None:
    # The projection the runner's delegation would use carries the same
    # populations the classic dispatcher route does — the two paths measure
    # one experiment, so they must agree on what it is.
    confirm = {
        "kind": RESPONSE_CONFIRM_KIND,
        "url": f"{_BASE}/download",
        "param": "file",
        "baseline_payload": "ve-noop0",
        "control_payload": "ve-control0",
        "injected_payload": "../payload",
        "where": "query",
    }
    spec = ConfirmSpec.from_confirm(confirm)
    assert spec.kind == RESPONSE_CONFIRM_KIND
    assert spec.baseline_payload == "ve-noop0"
    assert spec.control_payload == "ve-control0"
    assert spec.injected_payload == "../payload"
    assert spec.where == "query"
