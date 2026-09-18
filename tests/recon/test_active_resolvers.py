"""
Tests for :mod:`active.resolvers` — resolver acquisition and validation.

The resolver pool is the single point where the active stage can go quietly
wrong: a dead pool resolves nothing, and a *lying* pool makes the engines'
wildcard heuristics discard real results.  These tests pin both behaviours with
an injected query function, plus an integrity check on the curated seed files
themselves (a typo'd address there would otherwise only show up as a mysterious
slow run).
"""

from __future__ import annotations

import ipaddress
from pathlib import Path

import pytest

from service.recon_pipeline.pipelines.subdomain_domain_wildcards.active import (
    resolvers,
)
from service.recon_pipeline.pipelines.subdomain_domain_wildcards.active.resolvers import (
    QueryOutcome,
    parse_resolvers,
    prepare_resolvers,
    probe_resolver,
    validate_resolvers,
)
from service.recon_pipeline.pipelines.subdomain_domain_wildcards.active.settings import (
    PUBLIC_RESOLVERS_FILE,
    TRUSTED_RESOLVERS_FILE,
)

HEALTHY = "192.0.2.1"
DEAD = "192.0.2.2"
HIJACKING = "192.0.2.3"
SLOW = "192.0.2.4"


def stub_query(
    *,
    healthy=(HEALTHY,),
    hijacking=(),
    positive_names=("example.com",),
    positive_answers=("93.184.216.34",),
):
    """A query stub with explicit per-address behaviour."""
    healthy_set = set(healthy)
    hijack_set = set(hijacking)

    def query(address: str, name: str, record_type: str = "A", *, timeout: float = 3.0):
        if address in hijack_set:
            return QueryOutcome(answers=frozenset({"203.0.113.9"}))
        if address in healthy_set and name in positive_names:
            return QueryOutcome(answers=frozenset(positive_answers))
        if address in healthy_set and name.endswith(".invalid"):
            return QueryOutcome(error="nxdomain")
        return QueryOutcome(error="timeout")

    return query


# --------------------------------------------------------------------------- #
# File parsing
# --------------------------------------------------------------------------- #


def test_parse_resolvers_ignores_comments_blanks_and_junk() -> None:
    body = """
    # a comment
    1.1.1.1

    8.8.8.8   # trailing comment
    not-an-address
    1.1.1.1    # duplicate
    2606:4700:4700::1111
    """
    assert parse_resolvers(body) == ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"]


def test_load_resolvers_file_missing_is_empty(tmp_path: Path) -> None:
    assert resolvers.load_resolvers_file(tmp_path / "nope.txt") == []


def test_write_resolver_file_is_plain_and_lf_terminated(tmp_path: Path) -> None:
    path = resolvers.write_resolver_file(tmp_path / "out.txt", ["1.1.1.1", "8.8.8.8"])
    assert path.read_bytes() == b"1.1.1.1\n8.8.8.8\n"


# --------------------------------------------------------------------------- #
# Curated seed data
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("path", [PUBLIC_RESOLVERS_FILE, TRUSTED_RESOLVERS_FILE])
def test_seed_files_contain_only_valid_addresses(path: Path) -> None:
    addresses = resolvers.load_resolvers_file(path)
    assert addresses, f"{path.name} is empty"
    for address in addresses:
        ipaddress.ip_address(address)  # raises if the file has a typo
    assert len(addresses) == len(set(addresses)), f"{path.name} has duplicates"


def test_every_trusted_seed_is_also_a_public_candidate() -> None:
    """The trusted pool is a subset of the probed pool, never a separate list.

    puredns validates results against the trusted pool, so a trusted address that
    is never probed could be dead — and poisoning validation against a dead
    resolver silently confirms nothing.
    """
    public = set(resolvers.load_resolvers_file(PUBLIC_RESOLVERS_FILE))
    trusted = set(resolvers.load_resolvers_file(TRUSTED_RESOLVERS_FILE))
    assert trusted <= public
    assert len(trusted) >= 4, "too few trusted resolvers to validate against"


# --------------------------------------------------------------------------- #
# Single-resolver probing
# --------------------------------------------------------------------------- #


def test_healthy_resolver_passes_both_probes() -> None:
    probe = probe_resolver(HEALTHY, query=stub_query())
    assert probe.ok
    assert probe.positive and probe.negative_clean
    assert probe.reason == ""


def test_resolver_that_resolves_nothing_is_rejected() -> None:
    probe = probe_resolver(DEAD, query=stub_query())
    assert not probe.ok
    assert probe.reason == "no answer for any known-good name"


def test_resolver_that_answers_invalid_is_rejected_as_hijacking() -> None:
    """A resolver that invents answers for ``.invalid`` must never be trusted.

    On such a resolver "this zone is a wildcard" and "this resolver fabricates
    answers" are indistinguishable, which is exactly how a wildcard-filtering
    engine ends up discarding real hosts.
    """
    probe = probe_resolver(HIJACKING, query=stub_query(hijacking=(HIJACKING,)))
    assert not probe.ok
    assert "invalid" in probe.reason
    assert probe.positive  # it does answer real names - that is the danger


def test_resolver_is_rejected_when_the_negative_probe_times_out() -> None:
    """A timeout is not a clean NXDOMAIN: the contract is prompt NXDOMAIN."""

    def query(address, name, record_type="A", *, timeout=3.0):
        if name.endswith(".invalid"):
            return QueryOutcome(error="timeout")
        return QueryOutcome(answers=frozenset({"93.184.216.34"}))

    probe = probe_resolver(DEAD, query=query)
    assert not probe.ok
    assert "timeout" in probe.reason


def test_sinkhole_positive_answer_is_not_acceptance() -> None:
    """``0.0.0.0`` means "redirected", not "resolved"."""
    probe = probe_resolver(
        HEALTHY,
        query=stub_query(positive_answers=("0.0.0.0",)),
    )
    assert not probe.ok
    assert probe.reason == "no answer for any known-good name"


def test_negative_label_is_random_per_probe() -> None:
    """A cached NXDOMAIN for a fixed label must not be able to pass the check."""
    seen: list[str] = []

    def query(address, name, record_type="A", *, timeout=3.0):
        if name.endswith(".invalid"):
            seen.append(name)
            return QueryOutcome(error="nxdomain")
        return QueryOutcome(answers=frozenset({"93.184.216.34"}))

    probe_resolver(HEALTHY, query=query)
    probe_resolver(HEALTHY, query=query)
    assert len(seen) == 2
    assert seen[0] != seen[1]


# --------------------------------------------------------------------------- #
# Pool validation
# --------------------------------------------------------------------------- #


def test_validate_resolvers_splits_accepted_and_rejected() -> None:
    query = stub_query(healthy=(HEALTHY,), hijacking=(HIJACKING,))
    validation = validate_resolvers([DEAD, HEALTHY, HIJACKING], query=query)

    assert validation.accepted == [HEALTHY]
    assert validation.probed == 3
    assert {p.address for p in validation.rejected} == {DEAD, HIJACKING}
    assert validation.enough is False  # 1 < RESOLVER_MIN_VALID


def test_validate_resolvers_keeps_candidate_order_and_dedupes() -> None:
    query = stub_query(healthy=("192.0.2.9", "192.0.2.1"))
    validation = validate_resolvers(
        ["192.0.2.9", "192.0.2.1", "192.0.2.9"], query=query
    )
    assert validation.accepted == ["192.0.2.9", "192.0.2.1"]


def test_trusted_set_only_contains_validated_trusted_candidates() -> None:
    """Validation and trust are separate gates: an address must pass both."""
    query = stub_query(healthy=(HEALTHY,))
    validation = validate_resolvers(
        [HEALTHY, DEAD],
        trusted=[HEALTHY, DEAD, "203.0.113.7"],
        query=query,
    )
    assert validation.accepted_trusted == [HEALTHY]


def test_empty_candidate_pool_is_not_enough() -> None:
    validation = validate_resolvers([], query=stub_query())
    assert validation.accepted == []
    assert validation.enough is False


# --------------------------------------------------------------------------- #
# Preparation (the files the tools are pointed at)
# --------------------------------------------------------------------------- #


def test_prepare_resolvers_writes_plain_pool_and_rejections(tmp_path: Path) -> None:
    query = stub_query(healthy=(HEALTHY, "192.0.2.8", "192.0.2.7"), hijacking=(HIJACKING,))
    preparation = prepare_resolvers(
        output_dir=tmp_path,
        resolvers=[HEALTHY, "192.0.2.8", "192.0.2.7", HIJACKING, DEAD],
        trusted=[HEALTHY],
        query=query,
    )

    assert preparation.enough
    pool = (tmp_path / resolvers.OUTPUT_RESOLVERS_FILE).read_text(encoding="utf-8")
    assert pool.splitlines() == [HEALTHY, "192.0.2.8", "192.0.2.7"]
    assert "#" not in pool  # massdns/puredns get a bare address list

    trusted = (tmp_path / resolvers.OUTPUT_TRUSTED_FILE).read_text(encoding="utf-8")
    assert trusted.splitlines() == [HEALTHY]

    rejected = (tmp_path / resolvers.OUTPUT_REJECTED_FILE).read_text(encoding="utf-8")
    assert HIJACKING in rejected and DEAD in rejected
    assert "invalid" in rejected  # the reason, not just the address
    assert preparation.paths["resolvers"].endswith(resolvers.OUTPUT_RESOLVERS_FILE)


def test_prepare_resolvers_uses_seed_files_when_none_are_given(tmp_path: Path) -> None:
    """Without explicit lists, the curated seeds are the candidate pool."""
    seed = resolvers.load_resolvers_file(PUBLIC_RESOLVERS_FILE)
    alive = tuple(seed[:3])

    preparation = prepare_resolvers(
        output_dir=tmp_path,
        public_file=PUBLIC_RESOLVERS_FILE,
        trusted_file=TRUSTED_RESOLVERS_FILE,
        query=stub_query(healthy=alive),
    )

    assert preparation.valid == list(alive)
    # Trusted is derived from the trusted seed intersected with what validated,
    # so a trusted-but-dead address can never end up in the trusted pool.
    trusted_seed = set(resolvers.load_resolvers_file(TRUSTED_RESOLVERS_FILE))
    assert preparation.trusted == [a for a in alive if a in trusted_seed]
    assert len(preparation.rejected) == len(seed) - len(alive)
