"""
Tests for :mod:`active.wordlist` — word normalisation, provider assembly, and the
integrity of the bundled list.

A wordlist is hostile input in a practical sense: real lists contain full
hostnames, URLs, wildcard-escaped cert names, and stray CSV columns.  Anything
that is not a single valid DNS label reaching a DNS tool is either a wasted query
or a malformed name, so the normalisation rules are pinned here — including a
data-file check on ``generic.txt`` so a bad edit fails a test instead of a run.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from service.recon_pipeline.asset_pipelines.subdomain_domain_wildcards.active import (
    wordlist,
)
from service.recon_pipeline.asset_pipelines.subdomain_domain_wildcards.active.settings import (
    GENERIC_WORDLIST,
)
from service.recon_pipeline.asset_pipelines.subdomain_domain_wildcards.active.wordlist import (
    WordlistProvider,
    build_wordlist,
    load_wordlist_file,
    normalize_word,
    parse_words,
    register_provider,
)


# --------------------------------------------------------------------------- #
# Normalisation
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("api", "api"),
        ("  API  ", "api"),
        ("api-v2", "api-v2"),
        ("s3", "s3"),
        ("node01", "node01"),
        ("api.example.com", None),  # a hostname, not a word
        ("-api", None),  # leading hyphen is not a valid label
        ("api-", None),  # trailing hyphen is not a valid label
        ("api_v2", None),  # underscore is not valid in a hostname
        ("", None),
        ("# a comment", None),
        ("*.example.com", None),  # wildcard cert name
        ("api/path", "api"),  # URL-ish evidence: keep the host part
        ("api:8443", "api"),  # host:port evidence
        ("api.example.com", None),
        ("ünicode", None),
        ("a" * 64, None),  # label longer than 63 octets
    ],
)
def test_normalize_word(raw: str, expected: str | None) -> None:
    assert normalize_word(raw) == expected


def test_normalize_word_keeps_wildcard_label_evidence() -> None:
    """``*.api`` carries the useful label even though the wildcard does not."""
    assert normalize_word("*.api") == "api"


def test_parse_words_preserves_order_and_dedupes() -> None:
    body = "api\nwww\napi\n\n# comment\ndev\n"
    assert parse_words(body) == ["api", "www", "dev"]


def test_load_wordlist_file_missing_is_empty(tmp_path: Path) -> None:
    assert load_wordlist_file(tmp_path / "nope.txt") == []


# --------------------------------------------------------------------------- #
# Bundled list integrity
# --------------------------------------------------------------------------- #


def test_bundled_wordlist_is_large_enough_to_be_useful() -> None:
    words = load_wordlist_file(GENERIC_WORDLIST)
    assert len(words) >= 500, "the built-in list should cover real targets"
    assert len(words) < 10_000, "the built-in list should stay a fast default"


def test_bundled_wordlist_contains_only_valid_single_labels() -> None:
    words = load_wordlist_file(GENERIC_WORDLIST)
    for word in words:
        assert word == word.lower(), f"{word!r} should be lowercase"
        assert "." not in word, f"{word!r} is a hostname, not a label"
        assert wordlist.LABEL_RE.match(word), f"{word!r} is not a valid DNS label"


def test_bundled_wordlist_has_no_duplicate_entries() -> None:
    raw = [line.strip() for line in GENERIC_WORDLIST.read_text(encoding="utf-8").splitlines()]
    entries = [line.lower() for line in raw if line and not line.startswith("#")]
    assert len(entries) == len(set(entries))


# --------------------------------------------------------------------------- #
# Assembly
# --------------------------------------------------------------------------- #


def test_build_wordlist_defaults_to_the_builtin_list() -> None:
    result = build_wordlist()
    assert len(result) == len(load_wordlist_file(GENERIC_WORDLIST))
    assert result.sources == [f"builtin({len(result)})"]


def test_operator_words_come_first_so_a_limit_keeps_them(tmp_path: Path) -> None:
    custom = tmp_path / "custom.txt"
    custom.write_text("staging\nqa\napi\n", encoding="utf-8")

    result = build_wordlist(files=[custom], limit=2)

    assert result.words == ["staging", "qa"]
    assert result.sources[0].startswith("file:custom.txt")


def test_builtin_can_be_disabled(tmp_path: Path) -> None:
    custom = tmp_path / "custom.txt"
    custom.write_text("only-this\n", encoding="utf-8")

    result = build_wordlist(files=[custom], builtin=False)

    assert result.words == ["only-this"]
    assert all(not source.startswith("builtin") for source in result.sources)


def test_duplicate_words_across_sources_are_collapsed(tmp_path: Path) -> None:
    first = tmp_path / "first.txt"
    second = tmp_path / "second.txt"
    first.write_text("api\napi2\n", encoding="utf-8")
    second.write_text("api\napi3\n", encoding="utf-8")

    result = build_wordlist(files=[first, second], builtin=False)

    assert result.words == ["api", "api2", "api3"]


def test_empty_wordlist_warns_and_is_still_usable(caplog, monkeypatch) -> None:
    """No words must degrade to a warning, not an exception."""
    monkeypatch.setattr(wordlist, "PROVIDERS", dict(wordlist.PROVIDERS))
    result = build_wordlist(builtin=False)
    assert result.words == []


# --------------------------------------------------------------------------- #
# Pluggable providers (the v2 plan's extensibility hook)
# --------------------------------------------------------------------------- #


def test_registered_provider_contributes_words() -> None:
    register_provider(
        WordlistProvider(
            name="test-wayback",
            load=lambda **_: ["from-wayback", "another"],
            description="test fixture",
        ),
        replace=True,
    )
    try:
        result = build_wordlist(builtin=False, providers=["test-wayback"])
        assert result.words == ["from-wayback", "another"]
        assert result.sources == ["test-wayback(2)"]
    finally:
        wordlist.PROVIDERS.pop("test-wayback", None)


def test_provider_receives_call_context() -> None:
    seen: dict[str, object] = {}

    def load(**context):
        seen.update(context)
        return []

    register_provider(WordlistProvider(name="test-context", load=load), replace=True)
    try:
        build_wordlist(
            builtin=False, providers=["test-context"], context={"apex": "example.com"}
        )
    finally:
        wordlist.PROVIDERS.pop("test-context", None)

    assert seen == {"apex": "example.com"}


def test_duplicate_provider_registration_is_refused() -> None:
    register_provider(WordlistProvider(name="test-dup", load=lambda **_: []), replace=True)
    try:
        with pytest.raises(ValueError, match="already registered"):
            register_provider(WordlistProvider(name="test-dup", load=lambda **_: []))
    finally:
        wordlist.PROVIDERS.pop("test-dup", None)


def test_unknown_provider_is_ignored_not_fatal(caplog) -> None:
    """A provider named by a caller that is not installed must not break a run."""
    result = build_wordlist(builtin=False, providers=["does-not-exist"])
    assert result.words == []
