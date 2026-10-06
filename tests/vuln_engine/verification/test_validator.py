"""The confirm-spec validator: the classic path's planner gate.

The two-gate flow routes every proposal through a planner *before* a verifier
agent runs. The classic path used to dispatch straight from
``confirm["kind"]`` — trusted code, but no defense in depth: a buggy technique
could hand the timing verifier another surface's URL and get an honest
measurement of the wrong thing, scored differential. These tests pin the
sized-down planner gate (:func:`validate_confirm_spec`):

* every URL a spec names must belong to the surface the candidate declares;
* the fields the answering verifier reads must be present and well-formed;
* an unknown kind passes through untouched — the dispatcher owns that refusal,
  and duplicating its vocabulary here would be the second copy of a table
  that drifts.
"""

from __future__ import annotations

from service.vuln_engine.kernel.claim import CLAIM_OBJECT_READ, CLAIM_STATE_CHANGE
from service.vuln_engine.verification.validator import validate_confirm_spec

SURFACE = {
    "url": "http://127.0.0.1:8080/search",
    "host": "127.0.0.1",
    "param": "q",
    "where": "query",
}


# --------------------------------------------------------------------------- #
# host consistency: the verifier re-measures the declared claim, never another's
# --------------------------------------------------------------------------- #


def test_a_spec_consistent_with_its_surface_passes() -> None:
    spec = {
        "kind": "timing.differential",
        "url": "http://127.0.0.1:8080/search",
        "param": "q",
        "margin": 0.5,
    }
    assert validate_confirm_spec(spec, SURFACE) == ""


def test_a_foreign_host_in_the_spec_is_refused() -> None:
    spec = {
        "kind": "timing.differential",
        "url": "http://thirdparty.example.net/search",
        "param": "q",
        "margin": 0.5,
    }
    problem = validate_confirm_spec(spec, SURFACE)
    assert problem
    assert "thirdparty.example.net" in problem
    assert "127.0.0.1" in problem


def test_a_hostless_url_is_refused_by_name() -> None:
    spec = {
        "kind": "timing.differential",
        "url": "not a url",
        "param": "q",
        "margin": 0.5,
    }
    problem = validate_confirm_spec(spec, SURFACE)
    assert problem
    assert "hostless" in problem


def test_a_spec_with_no_declared_surface_host_is_refused() -> None:
    spec = {"kind": "timing.differential", "url": "http://127.0.0.1:8080/search", "margin": 0.5}
    problem = validate_confirm_spec(spec, {"url": SURFACE["url"], "param": "q"})
    assert "declares no surface host" in problem


def test_the_state_change_spec_holds_every_url_to_the_surface() -> None:
    ok = {
        "kind": "authorization.state_change",
        "claim_shape": CLAIM_STATE_CHANGE,
        "actor": {"url": "http://127.0.0.1:8080/api/promote", "method": "POST"},
        "victim_url": "http://127.0.0.1:8080/api/role",
    }
    assert validate_confirm_spec(ok, SURFACE) == ""

    foreign_actor = dict(ok, actor={"url": "http://other.test/api/promote", "method": "POST"})
    assert "other.test" in validate_confirm_spec(foreign_actor, SURFACE)

    foreign_victim = dict(ok, victim_url="http://other.test/api/role")
    assert "other.test" in validate_confirm_spec(foreign_victim, SURFACE)


def test_the_stored_xss_spec_holds_inject_and_read_back_to_the_surface() -> None:
    ok = {
        "kind": "xss_stored.execute",
        "inject": {"url": "http://127.0.0.1:8080/comment", "param": "q"},
        "read_back": "http://127.0.0.1:8080/comments",
        "markers": {"ve-mark": True},
    }
    assert validate_confirm_spec(ok, SURFACE) == ""

    foreign_read_back = dict(ok, read_back="http://other.test/comments")
    assert "other.test" in validate_confirm_spec(foreign_read_back, SURFACE)


# --------------------------------------------------------------------------- #
# required fields: a refusal at dispatch instead of a crash or a silent default
# --------------------------------------------------------------------------- #


def test_a_timing_spec_without_a_positive_margin_is_refused() -> None:
    base = {"kind": "timing.differential", "url": "http://127.0.0.1:8080/search", "param": "q"}
    assert "no parameter" in validate_confirm_spec({**base, "margin": 0.5, "param": ""}, SURFACE)
    problem = validate_confirm_spec(dict(base, margin=0), SURFACE)
    assert "margin" in problem and "positive" in problem
    problem = validate_confirm_spec(dict(base, margin="soon"), SURFACE)
    assert "not a number" in problem
    assert "margin" in validate_confirm_spec(dict(base), SURFACE)


def test_an_authorization_spec_without_an_oracle_is_refused() -> None:
    spec = {"kind": "authorization.differential", "url": "http://127.0.0.1:8080/api/role"}
    assert "no oracle" in validate_confirm_spec(spec, SURFACE)


def test_a_state_change_spec_without_an_actor_or_victim_is_refused() -> None:
    victim_only = {"kind": "authorization.state_change", "victim_url": "http://127.0.0.1:8080/api/role"}
    assert "no actor change" in validate_confirm_spec(victim_only, SURFACE)

    actor_only = {
        "kind": "authorization.state_change",
        "actor": {"url": "http://127.0.0.1:8080/api/promote", "method": "POST"},
    }
    assert "no victim URL" in validate_confirm_spec(actor_only, SURFACE)


def test_a_browser_spec_without_markers_is_refused() -> None:
    spec = {"kind": "browser.run", "url": "http://127.0.0.1:8080/search"}
    assert "no execution markers" in validate_confirm_spec(spec, SURFACE)


# --------------------------------------------------------------------------- #
# the boundary of the gate: unknown kinds and shapes
# --------------------------------------------------------------------------- #


def test_an_unknown_kind_passes_through_for_the_dispatcher_to_refuse() -> None:
    assert validate_confirm_spec({"kind": "oob.read", "probe": "p"}, SURFACE) == ""
    assert validate_confirm_spec({"kind": "something.else"}, SURFACE) == ""
    assert validate_confirm_spec({}, SURFACE) == ""
    assert validate_confirm_spec(None, SURFACE) == ""


def test_an_unrecognized_claim_shape_is_refused_and_a_known_one_passes() -> None:
    spec = {
        "kind": "authorization.state_change",
        "claim_shape": "lateral_move",
        "actor": {"url": "http://127.0.0.1:8080/api/promote", "method": "POST"},
        "victim_url": "http://127.0.0.1:8080/api/role",
    }
    problem = validate_confirm_spec(spec, SURFACE)
    assert "lateral_move" in problem

    for shape in (CLAIM_OBJECT_READ, CLAIM_STATE_CHANGE):
        assert validate_confirm_spec(dict(spec, claim_shape=shape), SURFACE) == ""
