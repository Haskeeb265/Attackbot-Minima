"""
Tests for :mod:`passive.wildcard`.

The DNS resolver is injected everywhere, so every case — a genuine wildcard, a
non-existent parent, a real host hiding under a wildcard — is exercised
deterministically and without touching the network.
"""

from __future__ import annotations

import pytest

from service.recon_pipeline.pipelines.subdomain_domain_wildcards.passive import wildcard as wc

APEX = "example.com"

#: A resolver backed by a literal map; anything unlisted does not resolve.
WILDCARD_ANSWER = "203.0.113.10"


def make_resolver(mapping: dict[str, set[str]], default: set[str] | None = None):
    """Build a ``Resolver`` from a name -> answers map.

    ``default`` is returned for names not present in *mapping* — which is how a
    wildcard is modelled: every random label answers identically.
    """

    def resolve(name: str) -> frozenset[str]:
        if name in mapping:
            return frozenset(mapping[name])
        return frozenset(default or ())

    return resolve


# --------------------------------------------------------------------------- #
# candidate_parents
# --------------------------------------------------------------------------- #


def test_candidate_parents_always_includes_apex() -> None:
    assert wc.candidate_parents(["a.example.com"], APEX) == [APEX]


def test_candidate_parents_selects_high_fan_out_parents() -> None:
    names = [
        "a.tcs.example.com",
        "b.tcs.example.com",
        "c.tcs.example.com",
        "d.tcs.example.com",
        "lone.example.com",
    ]
    parents = wc.candidate_parents(names, APEX, min_children=4)
    assert APEX in parents
    assert "tcs.example.com" in parents
    # `lone.example.com` has a single child, so its parent is not probed.
    assert "lone.example.com" not in parents


# --------------------------------------------------------------------------- #
# detect_wildcards
# --------------------------------------------------------------------------- #


def test_detects_wildcard_when_every_sample_answers_identically() -> None:
    # Every random label resolves to the same address => wildcard.
    resolver = make_resolver({}, default={WILDCARD_ANSWER})
    names = ["www.example.com", "a.example.com", "b.example.com", "c.example.com"]

    verdicts = wc.detect_wildcards(APEX, names, resolver=resolver, samples=3, seed=1)

    assert [v.parent for v in verdicts] == [APEX]
    assert verdicts[0].is_wildcard
    assert verdicts[0].pattern == "*.example.com"
    assert verdicts[0].answers == frozenset({WILDCARD_ANSWER})


def test_no_wildcard_when_a_sample_does_not_resolve() -> None:
    calls: list[str] = []

    def resolve(name: str) -> frozenset[str]:
        calls.append(name)
        # Only the first sample answers: not a wildcard.
        return frozenset({WILDCARD_ANSWER}) if len(calls) == 1 else frozenset()

    assert wc.detect_wildcards(APEX, ["www.example.com"], resolver=resolve, samples=3) == []


def test_no_wildcard_when_samples_disagree() -> None:
    counter = {"n": 0}

    def resolve(name: str) -> frozenset[str]:
        counter["n"] += 1
        return frozenset({f"203.0.113.{counter['n']}"})

    assert wc.detect_wildcards(APEX, ["www.example.com"], resolver=resolve, samples=3) == []


def test_probing_is_deterministic_for_a_seed() -> None:
    seen: list[str] = []

    def resolve(name: str) -> frozenset[str]:
        seen.append(name)
        return frozenset()

    wc.detect_wildcards(APEX, ["www.example.com"], resolver=resolve, samples=2, seed=7)
    first = list(seen)
    seen.clear()
    wc.detect_wildcards(APEX, ["www.example.com"], resolver=resolve, samples=2, seed=7)
    assert first == seen


def test_detect_wildcards_returns_empty_for_no_names() -> None:
    assert wc.detect_wildcards(APEX, [], resolver=make_resolver({})) == []


def test_resolver_is_cached_and_capped(monkeypatch) -> None:
    calls = {"n": 0}

    def resolve(name: str) -> frozenset[str]:
        calls["n"] += 1
        return frozenset()

    caching = wc._CachingResolver(resolve, limit=2)
    caching("a.example.com")
    caching("a.example.com")  # cached, no second call
    assert calls["n"] == 1

    caching("b.example.com")
    caching("c.example.com")  # over the cap -> empty, no call
    assert calls["n"] == 2
    assert caching("c.example.com") == frozenset()
    assert caching.queries == 2


# --------------------------------------------------------------------------- #
# filter_wildcard_noise
# --------------------------------------------------------------------------- #


def _wildcard_verdict(parent: str = APEX) -> list[wc.WildcardVerdict]:
    sampled = ((WILDCARD_ANSWER,), (WILDCARD_ANSWER,))
    return [wc.WildcardVerdict(parent=parent, is_wildcard=True, sampled=sampled)]


def test_single_source_name_that_is_just_the_wildcard_is_suppressed() -> None:
    observations = {"noise.example.com": {"crtsh"}}
    resolver = make_resolver({"noise.example.com": {WILDCARD_ANSWER}})

    result = wc.filter_wildcard_noise(observations, _wildcard_verdict(), resolver=resolver)

    assert result.kept == {}
    assert result.suppressed == {"noise.example.com": "*.example.com"}


def test_corroborated_name_survives_a_wildcard() -> None:
    """Two independent sources is evidence the name is real, not wildcard noise."""
    observations = {"real.example.com": {"crtsh", "subfinder"}}
    resolver = make_resolver({"real.example.com": {WILDCARD_ANSWER}})

    result = wc.filter_wildcard_noise(observations, _wildcard_verdict(), resolver=resolver)

    assert result.kept == {"real.example.com": {"crtsh", "subfinder"}}
    assert result.suppressed == {}


def test_name_resolving_elsewhere_survives_a_wildcard() -> None:
    observations = {"real.example.com": {"crtsh"}}
    resolver = make_resolver({"real.example.com": {"198.51.100.7"}})

    result = wc.filter_wildcard_noise(observations, _wildcard_verdict(), resolver=resolver)

    assert "real.example.com" in result.kept
    assert result.suppressed == {}


def test_unresolved_name_survives_a_wildcard() -> None:
    """A name the wildcard does *not* answer for is not wildcard noise."""
    observations = {"dead.example.com": {"crtsh"}}
    resolver = make_resolver({})  # resolves to nothing

    result = wc.filter_wildcard_noise(observations, _wildcard_verdict(), resolver=resolver)

    assert "dead.example.com" in result.kept
    assert result.suppressed == {}


def test_deep_name_under_a_non_immediate_parent_is_kept() -> None:
    """Suppression only applies to immediate children of a confirmed wildcard."""
    observations = {"a.b.example.com": {"crtsh"}}
    resolver = make_resolver({"a.b.example.com": {WILDCARD_ANSWER}})

    result = wc.filter_wildcard_noise(observations, _wildcard_verdict(), resolver=resolver)

    assert "a.b.example.com" in result.kept


def test_no_verdicts_keeps_everything_without_resolving() -> None:
    observations = {"a.example.com": {"crtsh"}, "b.example.com": {"chaos"}}

    def explode(name: str) -> frozenset[str]:  # pragma: no cover
        raise AssertionError("resolver must not be called when there is no wildcard")

    result = wc.filter_wildcard_noise(observations, [], resolver=explode)

    assert result.kept == observations
    assert result.suppressed == {}


def test_nested_wildcard_parent() -> None:
    parent = "tcs.example.com"
    observations = {
        "x.tcs.example.com": {"subfinder"},
        "keep.example.com": {"subfinder"},
    }
    resolver = make_resolver({"x.tcs.example.com": {WILDCARD_ANSWER}})

    result = wc.filter_wildcard_noise(
        observations, _wildcard_verdict(parent), resolver=resolver
    )

    assert result.suppressed == {"x.tcs.example.com": "*.tcs.example.com"}
    assert result.kept == {"keep.example.com": {"subfinder"}}


# --------------------------------------------------------------------------- #
# default resolver degradation
# --------------------------------------------------------------------------- #


def test_dnspython_resolver_returns_empty_when_import_fails(monkeypatch) -> None:
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name.startswith("dns"):
            raise ImportError("no dnspython")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    monkeypatch.setattr(wc, "_dnspython_warned", False)

    assert wc.dnspython_resolver("example.com") == frozenset()


@pytest.mark.parametrize("name", ["example.com", "no-such-host.invalid"])
def test_dnspython_resolver_never_raises(name: str) -> None:
    # Uses the real resolver, but must degrade to an empty set rather than raise
    # whether or not the host exists.
    assert isinstance(wc.dnspython_resolver(name, timeout=2.0), frozenset)
