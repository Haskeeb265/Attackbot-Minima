"""
Wordlist sourcing for the active stage.

The bruteforce engine is only one half of bruteforce; the other half is the list
of labels.  This module owns that half, and follows the v2 plan's decision to
make sourcing **pluggable** so later stages can contribute words without the
bruteforce loop ever changing::

    IMPLEMENTATION_PLAN_V2 S16 - "Combine a small built-in generic wordlist with
    dynamically-derived terms ... implemented as a pluggable wordlist-provider
    function so later stages can register more sources without changing the core
    loop."

Two provider kinds ship today:

* ``builtin`` — :data:`..settings.GENERIC_WORDLIST`, always available offline;
* ``file`` — any list passed by the operator (SecLists, Assetnote, a stage's own
  output), repeatable.

A provider is just a name plus a callable returning strings, so a future Wayback
or code-analysis stage registers one function and nothing else changes::

    register_provider(WordlistProvider("wayback", wayback_words, "..."))

Words are normalised and validated here rather than in the engine.  A wordlist
is hostile input in a very practical sense — real lists contain full hostnames,
URLs, wildcard-escaped cert names (``*.example.com``), stray CSV columns and
UTF-8 junk, and any of those reaching a DNS tool becomes either a wasted query or
a malformed name.  So every word must be a single, syntactically valid DNS label
and nothing else.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

from .settings import GENERIC_WORDLIST

log = logging.getLogger("active.wordlist")

#: A single DNS label: alphanumeric, optional *interior* hyphens, <= 63 chars.
#: Anchored and hyphen-safe, so "api", "api-v2" and "s3" pass while
#: "-api", "api-", "api.example.com", "*.api" and "api_v2" do not.
LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

#: Labels that are pure digits sometimes appear in lists as noise ("1234").
#: They are legal DNS labels, so they are kept — a numbered host like
#: ``node01`` is real, and ``1`` costs one query.
_MAX_WORDS = 5_000_000


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class WordlistProvider:
    """A named source of candidate labels.

    ``load`` receives whatever keyword context the caller supplies (``apex``,
    ``output_dir``, ...) and returns an iterable of raw words, which are then
    normalised.  Returning junk is therefore cheap and safe — it is dropped.
    """

    name: str
    load: Callable[..., Iterable[str]]
    description: str = ""


#: Provider registry, keyed by name.  ``builtin`` guarantees a list is always
#: available, so a run cannot fail merely because no ``--wordlist`` was provided.
PROVIDERS: dict[str, WordlistProvider] = {}


def register_provider(provider: WordlistProvider, *, replace: bool = False) -> None:
    """Register *provider* so it can be selected by name.

    Raises
    ------
    ValueError
        If the name is already taken and *replace* is false — silently
        shadowing a provider would make one stage's words disappear based on
        import order.
    """
    if provider.name in PROVIDERS and not replace:
        raise ValueError(
            f"wordlist provider {provider.name!r} is already registered "
            "(pass replace=True to override)"
        )
    PROVIDERS[provider.name] = provider


# --------------------------------------------------------------------------- #
# Normalisation
# --------------------------------------------------------------------------- #


def normalize_word(value: str) -> str | None:
    """Return *value* as a valid single DNS label, or ``None`` to drop it."""
    word = value.strip().lower().lstrip(".").rstrip(".")
    if not word or word.startswith("#"):
        return None
    # Cert-transparency and URL-derived lists are full of these.
    word = word.removeprefix("*.")
    if "/" in word:
        word = word.split("/", 1)[0]
    if ":" in word:
        word = word.split(":", 1)[0]
    if not word or "." in word:
        return None
    if not LABEL_RE.match(word):
        return None
    return word


def parse_words(text: str) -> list[str]:
    """Normalise a wordlist body, preserving order and dropping duplicates."""
    words: list[str] = []
    seen: set[str] = set()
    for raw in text.splitlines():
        word = normalize_word(raw)
        if word is None or word in seen:
            continue
        seen.add(word)
        words.append(word)
    return words


def load_wordlist_file(path: Path | str) -> list[str]:
    """Read a wordlist file; ``[]`` when it does not exist."""
    path = Path(path)
    try:
        return parse_words(path.read_text(encoding="utf-8", errors="replace"))
    except FileNotFoundError:
        log.warning("wordlist %s not found - ignored", path)
        return []
    except OSError as exc:
        log.warning("wordlist %s unreadable (%s) - ignored", path, exc)
        return []


# --------------------------------------------------------------------------- #
# Built-in + file providers
# --------------------------------------------------------------------------- #


def builtin_words(**_: object) -> list[str]:
    """Labels from the bundled wordlist."""
    return load_wordlist_file(GENERIC_WORDLIST)


def file_words(path: Path | str, **_: object) -> list[str]:
    """Labels from one operator-supplied list."""
    return load_wordlist_file(path)


register_provider(
    WordlistProvider(
        name="builtin",
        load=builtin_words,
        description="bundled generic list (wordlists/generic.txt)",
    )
)


# --------------------------------------------------------------------------- #
# Assembly
# --------------------------------------------------------------------------- #


@dataclass
class Wordlist:
    """The assembled label set for one bruteforce run."""

    words: list[str] = field(default_factory=list)
    #: Provider/file labels that contributed, in order.
    sources: list[str] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.words)

    def __iter__(self):
        return iter(self.words)

    def to_dict(self) -> dict[str, object]:
        return {"words": len(self.words), "sources": list(self.sources)}


def build_wordlist(
    *,
    files: Iterable[Path | str] = (),
    builtin: bool = True,
    limit: int | None = None,
    providers: Iterable[str] = (),
    context: Mapping[str, object] | None = None,
) -> Wordlist:
    """Assemble the label set from the built-in list, files, and providers.

    Parameters
    ----------
    files:
        Operator-supplied wordlists (``--wordlist``), combined in order.
    builtin:
        Include the bundled generic list (last, so it never displaces operator
        words in a shortlist).  On by default so a bare run still bruteforces
        something meaningful; ``--no-builtin-wordlist`` turns it off when the
        operator wants *only* their list.
    limit:
        Keep at most this many words, after combining.  Used by recursive
        bruteforce, which deliberately runs a shortlist.
    providers:
        Names of registered providers to consult (the extensibility hook).
    context:
        Keyword arguments forwarded to each provider (e.g. ``apex``).

    Order matters, because two callers take a *prefix* of the result: ``limit``
    here, and recursive bruteforce's word shortlist.  Operator-supplied words are
    therefore absorbed **before** the built-in list, so a shortlist is the
    operator's own words first and the bundled defaults fill the remainder.
    Duplicates are removed on first sight.
    """
    context = dict(context or {})
    combined: list[str] = []
    sources: list[str] = []
    seen: set[str] = set()

    def absorb(label: str, words: Iterable[str]) -> None:
        added = 0
        for word in words:
            if word in seen:
                continue
            seen.add(word)
            combined.append(word)
            added += 1
            if len(combined) >= _MAX_WORDS:  # pragma: no cover - sanity guard
                break
        sources.append(f"{label}({added})")

    for path in files:
        absorb(f"file:{Path(path).name}", file_words(path, **context))

    for name in providers:
        provider = PROVIDERS.get(name)
        if provider is None:
            log.warning("unknown wordlist provider %r - ignored", name)
            continue
        absorb(provider.name, provider.load(**context))

    # The bundled list is the fallback, absorbed last: it is the broad default,
    # not the operator's stated priority.
    if builtin:
        absorb("builtin", PROVIDERS["builtin"].load(**context))

    if limit is not None and limit > 0:
        combined = combined[:limit]

    if not combined:
        log.warning(
            "wordlist is empty - bruteforce would query nothing; check --wordlist "
            "paths and the built-in list at %s",
            GENERIC_WORDLIST,
        )
    else:
        log.info("wordlist: %d label(s) from %s", len(combined), ", ".join(sources))

    if sources and sources[-1].startswith("builtin") and len(sources) > 1:
        # Worth stating explicitly: the bundled list is a fallback, so the
        # operator's words are what a recursion shortlist will spend its budget
        # on.  Without this line a thin recursive pass looks like a bug in
        # recursion rather than a wordlist ordering surprise.
        log.debug("bundled list absorbed last: %s", ", ".join(sources))

    return Wordlist(words=combined, sources=sources)
