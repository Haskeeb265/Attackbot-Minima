"""platform/programs.py — S4's recon half, hermetically.

The loader's database boundary is injected (fetch_row/fetch_rows), the
classifier is pure, and the snapshot round-trips through the same JSON the
child-process channel carries — so the whole module is tested without
Postgres, exactly like every other degrade in the platform.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from service.recon_pipeline.platform.programs import (
    ProgramScope,
    ProgramScopeError,
    ProgramScopeLoader,
    apply_program_scope,
    choose_apexes,
    classify_scope_asset,
    engagement_domain_conflicts,
    operator_apexes,
    operator_engagements,
    parse_scope_file,
    resolve_operator_scope,
    scope_for_apex,
    scope_from_environment,
    snapshot_json,
    write_psh_scope_file,
)
from service.recon_pipeline.platform.scope import ScopeEngine


# --------------------------------------------------------------------------- #
# classification — refuse, never guess
# --------------------------------------------------------------------------- #


def test_a_bare_domain_classifies_as_a_domain() -> None:
    kind, value = classify_scope_asset("qbsco.net", "DOMAIN")
    assert (kind, value) == ("domain", "qbsco.net")


def test_a_wildcard_declaration_stores_its_base_domain() -> None:
    kind, value = classify_scope_asset("*.qbsco.net", "WILDCARD")
    assert (kind, value) == ("domain", "qbsco.net")


def test_a_url_declaration_stores_its_host() -> None:
    kind, value = classify_scope_asset("https://qbsco.net/api/v1", "URL")
    assert (kind, value) == ("domain", "qbsco.net")


def test_a_cidr_is_canonicalised() -> None:
    kind, value = classify_scope_asset("45.60.100.7/16", "CIDR")
    assert (kind, value) == ("network", "45.60.0.0/16")


def test_an_address_before_a_network() -> None:
    # A bare IPv4 is also a valid /32 — the address must win.
    kind, value = classify_scope_asset("45.60.10.7", "IP")
    assert (kind, value) == ("address", "45.60.10.7")


def test_an_android_application_id_is_refused_even_though_it_looks_like_a_host() -> None:
    # The row's own type decides: three dotted labels are a mobile id here.
    kind, reason = classify_scope_asset("com.example.app", "ANDROID")
    assert kind is None
    assert "ANDROID" in reason


def test_a_known_non_recon_type_refuses_outright_regardless_of_spelling() -> None:
    # The program said OTHER: the row must not fall back to syntax and
    # accidentally become a target because its id happens to look like a host.
    kind, reason = classify_scope_asset("acme", "OTHER")
    assert kind is None
    assert "OTHER" in reason


def test_an_untyped_single_label_falls_back_to_syntax_and_is_refused() -> None:
    kind, reason = classify_scope_asset("acme", "")
    assert kind is None
    assert "registrable" in reason


def test_an_empty_identifier_is_refused() -> None:
    assert classify_scope_asset("", "DOMAIN")[0] is None
    assert classify_scope_asset("   ", "")[0] is None


def test_a_malformed_declared_address_is_refused_with_the_type_named() -> None:
    kind, reason = classify_scope_asset("not-an-ip", "IP")
    assert kind is None
    assert "IP" in reason


def test_a_malformed_declared_network_is_refused_with_the_type_named() -> None:
    kind, reason = classify_scope_asset("45.60.0.0/99", "CIDR")
    assert kind is None
    assert "CIDR" in reason


# --------------------------------------------------------------------------- #
# loading — the injected database boundary
# --------------------------------------------------------------------------- #


def _loader(rows: list[dict], master: dict | None = None) -> ProgramScopeLoader:
    def fetch_row(query, params):
        assert params == ("acme",)  # the handle is canonicalised before the query
        return master if master is not None else {"id": "m-1", "handle": "acme"}

    def fetch_rows(query, params):
        return rows

    return ProgramScopeLoader(fetch_row=fetch_row, fetch_rows=fetch_rows)


def test_the_loader_classifies_its_rows_into_buckets() -> None:
    scope = _loader(
        [
            {"scope_type": "DOMAIN", "scope_identifier": "qbsco.net"},
            {"scope_type": "WILDCARD", "scope_identifier": "*.qbsco.net"},
            {"scope_type": "CIDR", "scope_identifier": "45.60.0.0/16"},
            {"scope_type": "IP", "scope_identifier": "45.60.10.7"},
            {"scope_type": "ANDROID", "scope_identifier": "com.example.app"},
            {"scope_type": "OTHER", "scope_identifier": "acme", "scope_instructions": "watch this"},
        ]
    ).load("acme")

    assert scope.handle == "acme"
    assert scope.domains == ("qbsco.net",)  # the wildcard folded into its base
    assert scope.networks == ("45.60.0.0/16",)
    assert scope.addresses == ("45.60.10.7",)
    assert len(scope.unsupported) == 2
    # The instruction travels even though its row is unsupported — that is
    # exactly where an operator most needs to read the program's own words.
    assert scope.instructions == ("watch this",)


def test_duplicate_declarations_collapse() -> None:
    scope = _loader(
        [
            {"scope_type": "DOMAIN", "scope_identifier": "qbsco.net"},
            {"scope_type": "WILDCARD", "scope_identifier": "*.qbsco.net"},
            {"scope_type": "DOMAIN", "scope_identifier": "qbsco.net"},
        ]
    ).load("acme")

    assert scope.domains == ("qbsco.net",)


def test_an_unknown_handle_fails_with_the_remedy() -> None:
    def fetch_row(query, params):
        return None

    def fetch_rows(query, params):
        return []

    with pytest.raises(ProgramScopeError, match="unknown program handle"):
        ProgramScopeLoader(fetch_row=fetch_row, fetch_rows=fetch_rows).load("ghost")


def test_the_handle_is_canonicalised_before_the_lookup() -> None:
    seen: list[tuple] = []

    def fetch_row(query, params):
        seen.append(params)
        return {"id": "m-1", "handle": "Acme"}

    def fetch_rows(query, params):
        return []

    ProgramScopeLoader(fetch_row=fetch_row, fetch_rows=fetch_rows).load("@Acme")

    assert seen == [("acme",)]


def test_a_database_failure_is_a_program_scope_error_not_a_traceback() -> None:
    def fetch_row(query, params):
        raise RuntimeError("connection refused")

    with pytest.raises(ProgramScopeError, match="connection refused"):
        ProgramScopeLoader(fetch_row=fetch_row, fetch_rows=lambda q, p: []).load("acme")


def test_an_empty_handle_is_refused_before_touching_the_database() -> None:
    loader = ProgramScopeLoader()  # no injection: touching the DB would fail
    with pytest.raises(ProgramScopeError, match="no program handle"):
        loader.load("   ")


# --------------------------------------------------------------------------- #
# choosing engagements — the fail-fast rules
# --------------------------------------------------------------------------- #


def _scope(**overrides) -> ProgramScope:
    fields = {
        "handle": "acme",
        "domains": ("acme.test", "other.net"),
        "networks": (),
        "addresses": (),
        "unsupported": (),
        "instructions": (),
    }
    fields.update(overrides)
    return ProgramScope(**fields)


def test_no_request_engages_every_declared_domain_in_deterministic_order() -> None:
    assert choose_apexes(_scope(), None) == ["acme.test", "other.net"]


def test_a_program_with_no_engagable_domains_is_an_error_not_an_empty_run() -> None:
    with pytest.raises(ProgramScopeError, match="declares no in-scope domains"):
        choose_apexes(_scope(domains=()), None)


def test_a_requested_domain_must_be_declared() -> None:
    with pytest.raises(ProgramScopeError, match="does not declare") as excinfo:
        choose_apexes(_scope(), "notours.test")
    assert "acme.test, other.net" in str(excinfo.value)


def test_a_subdomain_of_a_declared_domain_is_accepted() -> None:
    assert choose_apexes(_scope(), "api.acme.test") == ["api.acme.test"]


# --------------------------------------------------------------------------- #
# the per-apex slice
# --------------------------------------------------------------------------- #


def test_the_apex_slice_keeps_subdomains_and_drops_foreign_domains() -> None:
    sliced = scope_for_apex(
        _scope(domains=("acme.test", "api.acme.test", "other.net")), "acme.test"
    )

    assert sliced.domains == ("acme.test", "api.acme.test")
    assert sliced.handle == "acme"


def test_networks_and_addresses_travel_whole() -> None:
    sliced = scope_for_apex(
        _scope(networks=("45.60.0.0/16",), addresses=("45.60.10.7",)), "other.net"
    )

    assert sliced.networks == ("45.60.0.0/16",)
    assert sliced.addresses == ("45.60.10.7",)


# --------------------------------------------------------------------------- #
# applying — the scope engine stays the single writer
# --------------------------------------------------------------------------- #


def test_applying_a_program_declares_every_class() -> None:
    engine = ScopeEngine.from_domain("qbsco.net")
    scope = ProgramScope(
        handle="acme",
        domains=("qbsco.net", "extra.test"),
        networks=("45.60.0.0/16",),
        addresses=("45.60.10.7",),
    )

    application = apply_program_scope(engine, scope)

    assert application.domains == 2
    assert application.networks == 1
    assert application.addresses == 1
    assert application.refused == []
    assert engine.check_host("api.qbsco.net").state == "in_scope"
    assert engine.check_host("anything.extra.test").state == "in_scope"
    assert engine.check_address("45.60.10.5").state == "in_scope"
    assert engine.check_address("45.60.10.7").state == "in_scope"


def test_application_refusals_are_recorded_not_swallowed() -> None:
    engine = ScopeEngine.from_domain("qbsco.net")
    scope = ProgramScope(
        handle="acme", domains=(), networks=("not-a-network",), addresses=()
    )

    application = apply_program_scope(engine, scope)

    assert application.networks == 0
    assert application.refused and "not-a-network" in application.refused[0][0]


# --------------------------------------------------------------------------- #
# exports — the PSH file and the snapshot round-trip
# --------------------------------------------------------------------------- #


def test_the_psh_scope_file_carries_networks_addresses_and_domain_comments(
    tmp_path: Path,
) -> None:
    scope = _scope(domains=("qbsco.net",), networks=("45.60.0.0/16",), addresses=("45.60.10.7",))

    path = write_psh_scope_file(scope, tmp_path / "scope.txt")
    text = path.read_text(encoding="utf-8")

    assert path.name == "scope.txt"
    assert "45.60.0.0/16" in text
    assert "45.60.10.7" in text
    assert "# domain: qbsco.net" in text  # a comment, not a token: DNS owns names
    assert "qbsco.net" not in [line for line in text.splitlines() if line and not line.startswith("#")]


def test_the_snapshot_round_trips_through_the_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scope = _scope(
        domains=("qbsco.net",),
        networks=("45.60.0.0/16",),
        addresses=("45.60.10.7",),
        unsupported=(("com.example.app", "ANDROID: not a host"),),
    )
    monkeypatch.setenv("RECON_SCOPE_JSON", json.dumps(snapshot_json(scope)))

    engine = ScopeEngine.from_domain("qbsco.net")
    program = scope_from_environment(engine)

    assert program is not None and program["handle"] == "acme"
    assert program["declared_networks"] == 1
    assert engine.check_host("api.qbsco.net").state == "in_scope"
    assert engine.check_address("45.60.10.5").state == "in_scope"
    assert engine.check_address("45.60.10.7").state == "in_scope"


def test_an_unreadable_snapshot_leaves_the_engine_narrower_and_says_so(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("RECON_SCOPE_JSON", "{not json")

    engine = ScopeEngine.from_domain("qbsco.net")
    program = scope_from_environment(engine)

    assert program is None  # fail-closed: nothing extra applied
    assert engine.check_host("api.qbsco.net").state == "in_scope"  # the apex, from_domain
    assert engine.declared_networks == set()  # the program's CIDR did NOT land


def test_no_snapshot_is_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("RECON_SCOPE_JSON", raising=False)
    assert scope_from_environment(ScopeEngine.from_domain("qbsco.net")) is None


# --------------------------------------------------------------------------- #
# operator-authored scope — the same rules, without a scraper
# --------------------------------------------------------------------------- #


def _write_scope_file(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "scope.txt"
    path.write_text(content, encoding="utf-8")
    return path


def test_a_scope_file_classifies_typed_and_bare_lines(tmp_path: Path) -> None:
    path = _write_scope_file(
        tmp_path,
        "# declared by the operator\n"
        "domain:acme.test\n"
        "wildcard:*.acme.test\n"      # folds into the base domain
        "cidr:45.60.0.0/16\n"
        "ip:45.60.10.7\n"
        "https://api.acme.test/v1\n"  # bare URL line
        "2001:db8::1\n"               # bare IPv6 address
        "\n"
        "   \n",
    )

    scope, refused = parse_scope_file(path)

    assert refused == []
    assert scope.handle == "operator"
    assert scope.domains == ("acme.test", "api.acme.test")
    assert scope.networks == ("45.60.0.0/16",)
    assert scope.addresses == ("45.60.10.7", "2001:db8::1")


def test_refused_lines_come_back_named_not_fatal(tmp_path: Path) -> None:
    # ``com.example.app`` is a syntactically valid three-label host: the
    # untyped fallback accepts it (the classifier's documented limit). An
    # operator who means the mobile id types the refusal themselves.
    path = _write_scope_file(tmp_path, "domain:acme.test\nintranet\n")

    scope, refused = parse_scope_file(path)

    assert scope.domains == ("acme.test",)
    assert refused == ["intranet"]
    # The refusal is recorded in the scope too — the engagement reports it
    # like the loader records unsupported rows.
    assert len(scope.unsupported) == 1


def test_a_type_prefix_can_refuse_what_the_fallback_could_not(tmp_path: Path) -> None:
    # The operator KNOWS it is an Android app id: the prefix makes the
    # classifier refuse outright, exactly as an ANDROID DB row would be.
    path = _write_scope_file(tmp_path, "android:com.example.app\n")

    scope, refused = parse_scope_file(path)

    assert scope.domains == ()
    assert refused == ["android:com.example.app"]


def test_a_cidr_prefix_declares_an_ipv6_network_without_the_fallback(tmp_path: Path) -> None:
    path = _write_scope_file(tmp_path, "cidr:2001:db8::/32\n")

    scope, refused = parse_scope_file(path)

    assert refused == []
    assert scope.networks == ("2001:db8::/32",)


def test_operator_inputs_merge_and_keep_their_refusal_origins(tmp_path: Path) -> None:
    path = _write_scope_file(tmp_path, "domain:acme.test\nbogus-line\n")

    scope, refused = resolve_operator_scope(
        scope_files=[path], assets=["45.60.10.7", "intranet"], target="api.acme.test"
    )

    assert scope.domains == ("acme.test", "api.acme.test")  # -t is declared too
    assert scope.addresses == ("45.60.10.7",)
    assert sorted(refused) == ["--asset: intranet", "scope.txt: bogus-line"]


def test_minimal_engagement_roots_fold_subdomains(tmp_path: Path) -> None:
    scope, _ = resolve_operator_scope(
        assets=["acme.test", "api.acme.test", "other.net"]
    )

    assert operator_apexes(scope) == ["acme.test", "other.net"]


def test_minus_t_engages_the_whole_operator_scope(tmp_path: Path) -> None:
    scope, _ = resolve_operator_scope(
        assets=["acme.test", "other.net", "45.60.0.0/16"], target="other.net"
    )

    engagements = operator_engagements(scope, target="other.net")

    assert [apex for apex, _ in engagements] == ["other.net"]
    # The operator authored the file whole: nothing is sliced away.
    assert engagements[0][1].domains == ("acme.test", "other.net")


def test_a_file_with_several_roots_must_be_named_not_guessed(tmp_path: Path) -> None:
    scope, _ = resolve_operator_scope(assets=["acme.test", "other.net"])

    with pytest.raises(ProgramScopeError, match="engagement roots"):
        operator_engagements(scope)


def test_a_file_with_no_domains_names_the_target_or_refuses(tmp_path: Path) -> None:
    cidrs_only, _ = resolve_operator_scope(assets=["45.60.0.0/16"])

    with pytest.raises(ProgramScopeError, match="no domains"):
        operator_engagements(cidrs_only)
    assert [apex for apex, _ in operator_engagements(cidrs_only, target="acme.test")] == [
        "acme.test"
    ]


def test_minus_t_and_minus_domain_are_alternatives_not_a_pair() -> None:
    scope, _ = resolve_operator_scope(assets=["acme.test"])

    with pytest.raises(ProgramScopeError, match="alternative"):
        operator_engagements(scope, target="acme.test", domain="acme.test")


def test_engagement_conflicts_name_domains_outside_the_apex() -> None:
    scope, _ = resolve_operator_scope(
        assets=["acme.test", "api.acme.test", "other.net"], target="acme.test"
    )

    conflicts = engagement_domain_conflicts(scope, "acme.test")

    assert conflicts == ["other.net"]  # parent, child, and the apex itself are in
