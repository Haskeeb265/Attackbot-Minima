"""Item 4.2 — the model channel says what it costs.

Three stamps ride every live junction call — tokens (from the provider's
``usage`` block), wall-clock latency (measured around the transport), and USD
cost (from the static ``MODEL_PRICES`` table, a policy statement pinned by
test). They travel onto the ``llm.junction`` row, are restored unchanged on a
cached replay (a replay did not pay again), stay zero on the degraded path (a
call the model never answered bought nothing), and aggregate into the report
through the pure ``views.llm_cost_summary`` view.
"""

from __future__ import annotations

import pytest

from service.vuln_engine.llm.client import (
    EVENT_LLM_JUNCTION,
    LLMClient,
    MODEL_PRICES,
    junction_cost,
)
from service.vuln_engine.world.views import LLM_JUNCTION_EVENT, llm_cost_summary


class _FakeLog:
    """The sliver of WorldLog the client and the views touch."""

    def __init__(self) -> None:
        self.rows: list[dict] = []

    def append(self, event_type: str, **fields: object) -> dict:
        row = {"type": event_type, **fields}
        self.rows.append(row)
        return row

    def events(self, *types: str) -> list[dict]:
        return [row for row in self.rows if row["type"] in types]

    def __len__(self) -> int:
        return len(self.rows)

    def summary(self) -> dict:
        return {}


def _client(answer: str = '{"ok": true}', usage: dict | None = None) -> LLMClient:
    return LLMClient(
        api_key="test-key",
        model=next(iter(MODEL_PRICES)),  # a priced model, so cost is computable
        caller=lambda prompt, system: (
            (answer, usage) if usage is not None else answer
        ),
    )


def _validate(_answer: dict) -> str:
    return "accepted"


_JUNCTION = dict(
    junction="test.junction",
    input={"q": "x"},
    prompt="p",
    system="s",
    validate=_validate,
)


# --------------------------------------------------------------------------- #
# the stamps
# --------------------------------------------------------------------------- #


def test_a_live_call_stamps_tokens_latency_and_cost() -> None:
    client = _client(usage={"prompt_tokens": 1000, "completion_tokens": 200})
    opinion = client.ask(**_JUNCTION)
    assert opinion.validated
    assert opinion.prompt_tokens == 1000
    assert opinion.completion_tokens == 200
    assert opinion.latency >= 0.0
    assert opinion.cost_usd == pytest.approx(junction_cost(opinion.model, 1000, 200))
    assert opinion.cost_usd > 0.0


def test_the_stamps_ride_the_llm_junction_row() -> None:
    world = _FakeLog()
    opinion = _client(usage={"prompt_tokens": 10, "completion_tokens": 5}).ask(
        **_JUNCTION, world=world, now=1.0
    )
    (row,) = world.events(EVENT_LLM_JUNCTION)
    assert row["prompt_tokens"] == 10
    assert row["completion_tokens"] == 5
    assert row["latency"] == opinion.latency
    assert row["cost_usd"] == pytest.approx(opinion.cost_usd)


def test_a_caller_returning_the_old_contract_still_works() -> None:
    # Backward compatibility: a caller that returns bare text reports a call
    # with unknown usage — zeros, not a crash.
    opinion = _client().ask(**_JUNCTION)
    assert opinion.validated
    assert opinion.prompt_tokens == 0
    assert opinion.completion_tokens == 0
    assert opinion.cost_usd == 0.0


def test_a_cached_replay_restores_the_stamps_unchanged() -> None:
    world = _FakeLog()
    client = _client(usage={"prompt_tokens": 40, "completion_tokens": 8})
    first = client.ask(**_JUNCTION, world=world, now=1.0)
    # A second client with a caller that would fail if asked: the answer must
    # come from the log, and the cost facts with it.
    def _must_not_call(prompt: str, system: str) -> str:
        raise AssertionError("a cached replay must not reach the network")

    replay_client = LLMClient(
        api_key="test-key",
        model=next(iter(MODEL_PRICES)),
        caller=_must_not_call,
    )
    second = replay_client.ask(**_JUNCTION, world=world, now=2.0)
    assert second.source == "cached"
    assert second.prompt_tokens == first.prompt_tokens == 40
    assert second.completion_tokens == first.completion_tokens == 8
    assert second.latency == first.latency
    assert second.cost_usd == pytest.approx(first.cost_usd)


def test_a_degraded_opinion_buys_nothing() -> None:
    keyless = LLMClient(api_key="")
    opinion = keyless.ask(**_JUNCTION)
    assert opinion.degraded
    assert opinion.prompt_tokens == 0
    assert opinion.completion_tokens == 0
    assert opinion.latency == 0.0
    assert opinion.cost_usd == 0.0


# --------------------------------------------------------------------------- #
# the price table is a policy statement, pinned
# --------------------------------------------------------------------------- #


def test_the_price_table_covers_the_default_model_and_prices_are_positive() -> None:
    from service.vuln_engine.llm.client import DEFAULT_MODEL

    # Matching strips a provider/ prefix, then prefix-matches the model name.
    bare = DEFAULT_MODEL.split("/", 1)[1]
    assert any(bare.startswith(name) for name in MODEL_PRICES)
    for input_price, output_price in MODEL_PRICES.values():
        assert input_price > 0.0
        assert output_price > 0.0


def test_an_unlisted_model_costs_nothing() -> None:
    assert junction_cost("totally-unknown-model", 1000, 1000) == 0.0


def test_a_price_prefix_matches_variants() -> None:
    name = next(iter(MODEL_PRICES))
    assert junction_cost(f"{name}-2026-09-preview", 1_000_000, 0) == MODEL_PRICES[name][0]


# --------------------------------------------------------------------------- #
# the report aggregate (pure view)
# --------------------------------------------------------------------------- #


def test_llm_cost_summary_aggregates_the_rows() -> None:
    world = _FakeLog()
    # Two *different* inputs — the same digest would be served from the cache
    # and priced once, which the replay test above pins separately.
    _client(usage={"prompt_tokens": 100, "completion_tokens": 50}).ask(
        **_JUNCTION, world=world, now=1.0
    )
    _client(usage={"prompt_tokens": 30, "completion_tokens": 10}).ask(
        **{**_JUNCTION, "input": {"q": "y"}}, world=world, now=2.0
    )
    summary = llm_cost_summary(world)
    assert summary["calls"] == 2
    assert summary["degraded"] == 0
    assert summary["prompt_tokens"] == 130
    assert summary["completion_tokens"] == 60
    assert summary["cost_usd"] == pytest.approx(
        sum(
            junction_cost(next(iter(MODEL_PRICES)), p, c)
            for p, c in ((100, 50), (30, 10))
        )
    )
    assert summary["worst_latency"] >= 0.0


def test_llm_cost_summary_of_a_keyless_run_is_all_zeros() -> None:
    class _EmptyLog(_FakeLog):
        def events(self, *types: str) -> list[dict]:
            return []

    summary = llm_cost_summary(_EmptyLog())
    assert summary == {
        "calls": 0,
        "degraded": 0,
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "worst_latency": 0.0,
        "cost_usd": 0.0,
    }


def test_the_views_event_literal_is_pinned_to_the_client_constant() -> None:
    # views cannot import llm (one-way import graph), so the row type is
    # spelled as a literal there — this pin is what stops the two drifting.
    assert LLM_JUNCTION_EVENT == EVENT_LLM_JUNCTION
