"""DNS budget tests.

The arithmetic is the feature: ``names / resolvers`` per hourly window is what
published detection analytics count, so these tests pin the numbers, the
keyed-shuffle determinism and the "never silently drop coverage" contract.
"""

from __future__ import annotations

import pytest

from service.recon_pipeline.stealth.dns_budget import (
    DnsBudget,
    batch_delay,
    plan,
    rate_limit_arg,
    rotate,
    shuffle_names,
)

RESOLVERS = [f"10.0.{index // 250}.{index % 250 + 1}" for index in range(40)]


def labels(count: int) -> list[str]:
    return [f"host{index}.example.com" for index in range(count)]


def test_shuffle_is_deterministic_for_a_seed_and_changes_with_it():
    names = labels(200)
    first = shuffle_names(names, seed="target.example")
    assert first == shuffle_names(names, seed="target.example")
    assert first != shuffle_names(names, seed="other.example")
    assert sorted(first) == sorted(names)  # a permutation, nothing lost
    assert first != names  # and not the input order


def test_shuffle_order_is_stable_across_processes():
    """A digest-keyed sort, not ``random``: the same seed means the same order."""
    names = labels(50)
    assert shuffle_names(names, seed="s") == shuffle_names(list(reversed(names)), seed="s")


def test_rotation_moves_the_window_and_wraps():
    for index in range(5):
        window = rotate(RESOLVERS, seed="s", index=index)
        assert sorted(window) == sorted(RESOLVERS)
    starts = {rotate(RESOLVERS, seed="s", index=index)[0] for index in range(8)}
    assert len(starts) > 1
    assert rotate([], seed="s", index=0) == []


def test_small_list_stays_within_budget():
    result = plan(labels(300), RESOLVERS)
    assert result.within_budget
    assert result.hours_needed == 1
    assert sum(result.per_resolver.values()) == 300
    assert result.max_per_resolver <= 60
    assert result.labels == tuple(shuffle_names(labels(300), seed=result.seed))


def test_large_list_reports_exactly_what_it_would_take():
    result = plan(labels(4000), RESOLVERS)
    assert not result.within_budget
    assert result.required_resolvers == pytest.approx(67, abs=1)  # ceil(4000 / 60)
    # hours_needed follows the *worst* resolver, which is what an hourly window
    # actually measures — not the naive total/resolver average.
    assert result.hours_needed == -(-result.max_per_resolver // 60)
    assert result.hours_needed > 1
    assert result.notes and "widen the pool" in result.notes[0]
    payload = result.to_dict()
    assert payload["within_budget"] is False
    assert payload["required_resolvers"] == result.required_resolvers


def test_strict_mode_drops_only_what_does_not_fit():
    result = plan(labels(4000), RESOLVERS, budget=DnsBudget(strict=True))
    assert len(result.labels) == 60 * len(RESOLVERS)
    assert len(result.dropped) == 4000 - len(result.labels)
    assert any("dropped" in note for note in result.notes)


def test_non_strict_mode_never_loses_a_name():
    result = plan(labels(4000), RESOLVERS, budget=DnsBudget(strict=False))
    assert len(result.labels) == 4000
    assert result.dropped == ()


def test_batches_never_exceed_the_window_size():
    result = plan(labels(1200), RESOLVERS, budget=DnsBudget(batch_size=500, strict=False))
    assert [len(batch.labels) for batch in result.batches] == [500, 500, 200]
    assert sum(len(batch.labels) for batch in result.batches) == 1200
    assert {batch.index for batch in result.batches} == {0, 1, 2}


def test_every_batch_gets_a_full_rotated_window():
    result = plan(labels(1200), RESOLVERS, budget=DnsBudget(batch_size=500))
    assert all(len(batch.resolvers) >= 4 for batch in result.batches)


def test_empty_inputs_are_handled_honestly():
    assert plan([], RESOLVERS).batches == ()
    no_pool = plan(labels(10), [])
    assert not no_pool.within_budget
    assert "no resolvers" in no_pool.notes[0]


def test_duplicates_are_removed_before_budgeting():
    result = plan(["a.example.com"] * 5, RESOLVERS)
    assert result.labels == ("a.example.com",)
    assert sum(result.per_resolver.values()) == 1


def test_batch_delay_is_jittered_and_zero_for_the_first_batch():
    budget = DnsBudget(batch_spacing=20.0, jitter=0.35)
    assert batch_delay(0, budget=budget) == 0.0
    assert batch_delay(1, budget=budget, random_value=0.5) == pytest.approx(20.0)
    assert batch_delay(1, budget=budget, random_value=0.0) == pytest.approx(13.0)
    assert batch_delay(1, budget=budget, random_value=1.0) == pytest.approx(27.0)
    assert batch_delay(1, budget=DnsBudget(batch_spacing=0)) == 0.0


def test_rate_limit_is_capped_by_the_volume_budget():
    assert rate_limit_arg(budget=DnsBudget(qps=0), resolver_count=40) == 0
    assert rate_limit_arg(budget=DnsBudget(qps=100), resolver_count=40) == 40
    assert rate_limit_arg(budget=DnsBudget(qps=100)) == 100
    assert rate_limit_arg(budget=DnsBudget(qps=100, names_per_resolver_hour=1), resolver_count=2) >= 1


def test_invalid_budget_is_rejected():
    with pytest.raises(ValueError):
        DnsBudget(names_per_resolver_hour=0)
    with pytest.raises(ValueError):
        DnsBudget(batch_size=0)
