"""The scope boundary: discovered ≠ authorized, hermetically.

The recon pipeline's core safety property is that a *discovered* asset is not
automatically an authorized one. These tests pin the boundary half of that:
assets the program explicitly placed out of scope are honoured as a reference
set — recognized even when a declared in-scope wildcard would otherwise cover
them — and are never turned into targets.
"""

from __future__ import annotations

import json

import pytest

from service.recon_pipeline.platform.programs import (
    ProgramScope,
    ProgramScopeLoader,
    apply_program_scope,
    scope_for_apex,
    scope_from_environment,
    snapshot_json,
)
from service.recon_pipeline.platform.scope import (
    IN_SCOPE,
    OUT_OF_SCOPE,
    ScopeEngine,
)


# --------------------------------------------------------------------------- #
# the engine: an explicit boundary rule is final
# --------------------------------------------------------------------------- #


def test_an_out_of_scope_subdomain_beats_a_declared_wildcard() -> None:
    """Scenario B: in-scope `*.example.com` must not authorise an excluded child."""
    engine = ScopeEngine.from_domain("example.com")
    engine.add_out_of_scope_domain("api.example.com")

    assert engine.check_host("www.example.com").state == IN_SCOPE
    decision = engine.check_host("api.example.com")
    assert decision.state == OUT_OF_SCOPE
    assert "api.example.com" in decision.reason


def test_an_out_of_scope_foreign_host_is_a_boundary_not_needs_review() -> None:
    """Scenario B: the discovered name is explicitly excluded, so say so."""
    engine = ScopeEngine.from_domain("example.com")
    engine.add_out_of_scope_domain("thirdparty.example.net")

    decision = engine.check_host("thirdparty.example.net")

    assert decision.state == OUT_OF_SCOPE
    assert "thirdparty.example.net" in decision.reason


def test_an_unknown_foreign_host_stays_needs_review() -> None:
    """Scenario C: discovered, not declared, not excluded — the operator's call."""
    engine = ScopeEngine.from_domain("example.com")

    assert engine.check_host("thirdparty.example.net").state == "needs_review"


def test_an_out_of_scope_network_refuses_what_is_inside_it() -> None:
    engine = ScopeEngine()
    engine.add_out_of_scope_network("203.0.113.0/24")

    assert engine.check_address("203.0.113.9").state == OUT_OF_SCOPE
    assert engine.check_network("203.0.113.0/24").state == OUT_OF_SCOPE


def test_an_out_of_scope_address_is_refused() -> None:
    engine = ScopeEngine()
    engine.add_out_of_scope_address("198.51.100.7")

    assert engine.check_address("198.51.100.7").state == OUT_OF_SCOPE


def test_the_boundary_is_reported_in_the_summary() -> None:
    engine = ScopeEngine.from_domain("example.com")
    engine.add_out_of_scope_domain("api.example.com")
    engine.add_out_of_scope_network("203.0.113.0/24")

    summary = engine.summary()

    assert summary["out_of_scope_domains"] == 1
    assert summary["out_of_scope_networks"] == 1


# --------------------------------------------------------------------------- #
# the loader: in_scope=False rows become the boundary set
# --------------------------------------------------------------------------- #


def _loader(rows: list[dict]) -> ProgramScopeLoader:
    def fetch_row(query, params):
        return {"id": "m-1", "handle": "acme"}

    def fetch_rows(query, params):
        return rows

    return ProgramScopeLoader(fetch_row=fetch_row, fetch_rows=fetch_rows)


def test_ineligible_rows_land_in_the_boundary_not_the_declared_scope() -> None:
    scope = _loader(
        [
            {"scope_type": "DOMAIN", "scope_identifier": "acme.test", "in_scope": True},
            {"scope_type": "DOMAIN", "scope_identifier": "excluded.acme.test", "in_scope": False},
            {"scope_type": "CIDR", "scope_identifier": "203.0.113.0/24", "in_scope": False},
        ]
    ).load("acme")

    assert scope.domains == ("acme.test",)
    assert scope.out_of_scope_domains == ("excluded.acme.test",)
    assert scope.out_of_scope_networks == ("203.0.113.0/24",)


def test_a_row_without_an_in_scope_flag_is_in_scope() -> None:
    scope = _loader(
        [{"scope_type": "DOMAIN", "scope_identifier": "acme.test"}]
    ).load("acme")

    assert scope.domains == ("acme.test",)
    assert scope.out_of_scope_domains == ()


# --------------------------------------------------------------------------- #
# applying + slicing + snapshot round-trip
# --------------------------------------------------------------------------- #


def test_applying_a_program_installs_the_boundary_on_the_engine() -> None:
    engine = ScopeEngine.from_domain("acme.test")
    scope = ProgramScope(
        handle="acme",
        domains=("acme.test",),
        out_of_scope_domains=("excluded.acme.test",),
    )

    application = apply_program_scope(engine, scope)

    assert application.out_of_scope == 1
    assert engine.check_host("excluded.acme.test").state == OUT_OF_SCOPE


def test_the_boundary_travels_whole_while_in_scope_domains_are_sliced() -> None:
    scope = ProgramScope(
        handle="acme",
        domains=("acme.test", "api.acme.test", "other.net"),
        out_of_scope_domains=("thirdparty.example.net",),
    )

    sliced = scope_for_apex(scope, "acme.test")

    # In-scope: only this engagement's names travel.
    assert sliced.domains == ("acme.test", "api.acme.test")
    # Boundary: the refusal travels whole — hiding it would defeat its purpose.
    assert sliced.out_of_scope_domains == ("thirdparty.example.net",)


def test_the_snapshot_carries_the_boundary_to_a_child_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope = ProgramScope(
        handle="acme",
        domains=("acme.test",),
        out_of_scope_domains=("excluded.acme.test",),
        out_of_scope_networks=("203.0.113.0/24",),
    )
    monkeypatch.setenv("RECON_SCOPE_JSON", json.dumps(snapshot_json(scope)))

    engine = ScopeEngine.from_domain("acme.test")
    program = scope_from_environment(engine)

    assert program is not None
    assert program["out_of_scope"] == 2
    assert engine.check_host("excluded.acme.test").state == OUT_OF_SCOPE
    assert engine.check_address("203.0.113.9").state == OUT_OF_SCOPE
