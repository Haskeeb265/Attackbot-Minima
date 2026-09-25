"""The LLM client: one door to the model, with the same discipline as the gate.

The design's contract for every LLM junction, kept exact (``engine_view.md`` §3):

* **advisory** — an opinion is data a pure consumer may read; it never decides
  anything on its own. The selector still picks, the verifier still confirms,
  and the report's canonical lines are still derived views of the log;
* **no key means deterministic behaviour, never silence** — the available=False
  health object is the answer, and every junction returns its degraded result
  without touching the network or raising;
* **logged and replayable** — every call is appended to the world log as an
  ``llm.junction`` row keyed by *content digest*, not by count: a replay of a
  run that once consulted the model finds the cached opinion in the log and
  reproduces the engagement offline with the key removed. That is what makes
  the model auditable the way the gate is: every opinion's input and answer
  are on the record.

R&D grounding (``RnD_2026-09.md`` §C8, OWASP LLM cheat sheets): the model here
is the *quarantined* LLM of the OWASP pattern — it reads typed structural
fields (contexts, counts, names), never target response bodies, and it holds
no tools. Untrusted content cannot instruct it because untrusted content is
never sent to it; what it returns is validated against a fixed shape, and an
answer that drifts from the shape is a degraded opinion, not an exception.

The transport is deliberately the same idiom the recon side's
``platform/enrich.py`` set: a plain POST, hard timeout, no SDK. ``ENV_KEY``
(``VULN_ENGINE_LLM_API_KEY``) plus ``VULN_ENGINE_LLM_API_URL`` gates the
network path; an injectable ``caller`` replaces it in tests. The URL has a
default (Groq's OpenAI-shaped endpoint — every junction question is a small
structured ask, so the default model is the fast/cheap one); setting
``VULN_ENGINE_LLM_API_URL`` / ``VULN_ENGINE_LLM_MODEL`` overrides it without
 touching this file.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

log = logging.getLogger("vuln_engine.llm")

#: Environment names.  Distinct from the recon side's ``LLM_API_KEY`` on
#: purpose: a key an operator set for recon classification should not silently
#: become a key the exploit engine spends against targets.
ENV_KEY = "VULN_ENGINE_LLM_API_KEY"
ENV_URL = "VULN_ENGINE_LLM_API_URL"
ENV_MODEL = "VULN_ENGINE_LLM_MODEL"
ENV_MAX_COMPLETION_TOKENS = "VULN_ENGINE_LLM_MAX_COMPLETION_TOKENS"
DEFAULT_TIMEOUT = 20.0
#: Completion-token headroom per call. The default models are reasoning models:
#: their chain-of-thought spends completion tokens before the answer's first
#: character, and at the provider's default cap (2048) a long question can spend
#: the entire budget thinking and answer with *nothing* — observed live as
#: ``finish_reason: length`` with an empty ``content``. The cap is generous
#: because every junction's question is small and temperature-0: an answer stops
#: at its own end, the cap only bounds the reasoning, never shapes the answer.
DEFAULT_MAX_COMPLETION_TOKENS = 8192
#: The default endpoint: Groq's OpenAI-shaped chat completions. The caller's
#: wire format is exactly this shape, so the default and the override differ
#: only in the URL string. Override with ``VULN_ENGINE_LLM_API_URL``.
DEFAULT_API_URL = "https://api.groq.com/openai/v1/chat/completions"
#: The default model: the junctions ask small, structured, temperature-0
#: questions (a ranking over four techniques; three multiple-choice payload
#: questions), so the fast/cheap tier is the right default, and the questions
#: are engineered so a weaker model degrades into a *refused* opinion rather
#: than a wrong one — validation is the bar, not eloquence. Chosen from the
#: live roster (2026-09-24): the older llama-instant ids are retired, and
#: ``openai/gpt-oss-20b`` is the small end of the text-capable chat models.
DEFAULT_MODEL = "openai/gpt-oss-20b"

#: The world-log row type every junction call is recorded as.
EVENT_LLM_JUNCTION = "llm.junction"

#: Health reasons that mean "this is design, not breakage".
NO_KEY_REASON = f"{ENV_KEY} not set: the junction runs degraded (deterministic), by design"


class LLMJunction(Protocol):
    """What a junction implementation offers, beyond its own typed method."""

    @property
    def name(self) -> str: ...


def opinion_digest(input: Mapping[str, Any]) -> str:
    """A stable content digest of a junction's *input*.

    The cache key. Content-addressed rather than counted so a replay finds the
    opinion for *this* question regardless of how many other calls the
    original run made — and so a different question never reuses an answer it
    did not ask for. Canonical-JSON (sorted keys) so dict order cannot change
    the digest.
    """
    canonical = json.dumps(input, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Health:
    """Whether the model path exists, and why not when it does not."""

    available: bool
    reason: str = ""
    model: str = ""

    def to_dict(self) -> dict:
        return {"available": self.available, "reason": self.reason, "model": self.model}


@dataclass(frozen=True)
class Opinion:
    """One junction's answer, or the degraded no-opinion.

    ``degraded=True`` means the model had no say — unavailable, refused, or an
    answer that failed validation. A consumer that treats a degraded opinion
    as a real one is the bug this shape exists to expose: the reason is right
    there, and ``validated=False`` is the parse story.
    """

    junction: str
    digest: str
    #: The validated answer payload (a dict of typed fields), or ``{}``.
    answer: dict = field(default_factory=dict)
    #: Which rule accepted it, when it was accepted.
    validation: str = ""
    #: True when the answer passed this junction's contract validation.
    validated: bool = False
    #: True when the model had no say at all (unavailable/refused/unparseable).
    degraded: bool = False
    #: Why: the health reason, an HTTP failure, or the validation complaint.
    reason: str = ""
    model: str = ""
    #: ``live`` (asked just now), ``cached`` (replayed from the log), ``degraded``.
    source: str = "live"

    def to_dict(self) -> dict:
        return {
            "junction": self.junction,
            "digest": self.digest,
            "answer": dict(self.answer),
            "validation": self.validation,
            "validated": self.validated,
            "degraded": self.degraded,
            "reason": self.reason,
            "model": self.model,
            "source": self.source,
        }


#: The callable that performs one model call. Injectable so tests never need a
#: key or a socket; the default performs a plain POST, no SDK.
ModelCaller = Callable[[str, str], str]


def _default_caller(
    url: str,
    api_key: str,
    model: str,
    timeout: float,
    max_completion_tokens: int,
) -> ModelCaller:
    """Build the plain-POST caller.  OpenAI-shaped because the recon side's
    ``enrich.py`` already speaks that shape and one idiom is one review."""

    def call(prompt: str, system: str) -> str:
        import time  # call time: the degraded path must not need it either
        import requests  # imported at call time: the degraded path must not need it

        #: Three attempts: a rate-limited (429) call backs off per the server's
        #: ``Retry-After`` (or an escalating wait), an intermittent 413 is
        #: retried as-is (Groq's edge returns it sporadically for payloads well
        #: under its documented limit — observed live, same body succeeding on
        #: the next attempt), and a 200 whose content is empty is retried too —
        #: the observed failure is a reasoning model spending its completion
        #: budget on chain-of-thought (``finish_reason: length``, empty
        #: ``content``), which is server-side variance rather than an answer. A
        #: persistent 429 still raises (the caller degrades with the status),
        #: as does any other HTTP error.
        content = ""
        delay = 2.0
        for attempt in range(3):
            response = requests.post(
                url,
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": model,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": prompt},
                    ],
                    "temperature": 0,
                    "max_completion_tokens": max_completion_tokens,
                },
                timeout=timeout,
            )
            if response.status_code in (429, 413) and attempt < 2:
                retry_after = response.headers.get("retry-after", "")
                try:
                    time.sleep(min(float(retry_after), 8.0))
                except ValueError:
                    time.sleep(delay)
                    delay *= 2
                continue
            response.raise_for_status()
            body = response.json()
            content = str(body["choices"][0]["message"]["content"] or "")
            if content.strip() or attempt == 2:
                return content
            time.sleep(delay)
            delay *= 2
        return content

    return call


class LLMClient:
    """Key-gated access to one model, through one logged, cache-checking door."""

    def __init__(
        self,
        *,
        api_key: str | None = None,
        api_url: str | None = None,
        model: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        max_completion_tokens: int = DEFAULT_MAX_COMPLETION_TOKENS,
        caller: ModelCaller | None = None,
    ) -> None:
        self._api_key = (
            api_key if api_key is not None else os.getenv(ENV_KEY, "")
        ).strip()
        self._api_url = (
            api_url if api_url is not None else os.getenv(ENV_URL, "")
        ).strip() or DEFAULT_API_URL
        self._model = (
            (model if model is not None else os.getenv(ENV_MODEL, "")).strip()
            or DEFAULT_MODEL
        )
        self._timeout = timeout
        raw_max = os.getenv(ENV_MAX_COMPLETION_TOKENS, "").strip()
        try:
            self._max_completion_tokens = int(raw_max) if raw_max else max_completion_tokens
        except ValueError:
            self._max_completion_tokens = max_completion_tokens
        self._caller = caller
        if self._caller is not None:
            self._health = Health(available=True, model="injected")
        elif self._api_key:
            self._health = Health(available=True, model=self._model)
        else:
            self._health = Health(available=False, reason=NO_KEY_REASON)

    @property
    def health(self) -> Health:
        return self._health

    @property
    def available(self) -> bool:
        return self._health.available

    def to_dict(self) -> dict:
        return {"llm": self._health.to_dict()}

    # ------------------------------------------------------------------ #
    # the one door
    # ------------------------------------------------------------------ #

    def ask(
        self,
        *,
        junction: str,
        input: Mapping[str, Any],
        prompt: str,
        system: str,
        validate: Callable[[dict], str],
        world: Any = None,
        now: float = 0.0,
    ) -> Opinion:
        """Ask the junction's question, or replay the cached answer.

        *validate* receives the parsed answer and returns an acceptance label,
        or raises ``ValueError`` with the reason it refused. Refusal is the
        contract working, not a crash: the opinion comes back degraded with
        the complaint as its reason.

        *world* is the world log; when given, the call and its answer are
        appended as an ``llm.junction`` row, and a row with the same digest is
        consulted before the network is. That row is what makes a replay
        reproduce the model's influence with the key removed.
        """
        digest = opinion_digest(input)
        if world is not None:
            cached = self._cached(world, junction, digest)
            if cached is not None:
                return cached

        if not self._health.available:
            return Opinion(
                junction=junction,
                digest=digest,
                degraded=True,
                reason=self._health.reason,
                model=self._health.model,
                source="degraded",
            )

        try:
            text = self._perform(prompt, system)
            answer = _extract_json(text)
            validation = validate(answer)
            opinion = Opinion(
                junction=junction,
                digest=digest,
                answer=dict(answer),
                validation=validation,
                validated=True,
                model=self._health.model,
                source="live",
            )
        except Exception as exc:  # noqa: BLE001 - advisory failure must not stop the run
            if world is not None:
                world.append(
                    EVENT_LLM_JUNCTION,
                    at=now,
                    junction=junction,
                    digest=digest,
                    degraded=True,
                    validated=False,
                    reason=f"{type(exc).__name__}: {exc}"[:300],
                    model=self._health.model,
                )
            log.warning("llm junction %s degraded: %s", junction, exc)
            return Opinion(
                junction=junction,
                digest=digest,
                degraded=True,
                reason=f"{type(exc).__name__}: {exc}"[:300],
                model=self._health.model,
                source="degraded",
            )

        if world is not None:
            world.append(
                EVENT_LLM_JUNCTION,
                at=now,
                junction=junction,
                digest=digest,
                junction_input=dict(input),
                answer=dict(opinion.answer),
                validation=opinion.validation,
                degraded=False,
                validated=True,
                reason="",
                model=opinion.model,
            )
        return opinion

    def _perform(self, prompt: str, system: str) -> str:
        if self._caller is not None:
            return self._caller(prompt, system)
        if not self._api_url:
            raise RuntimeError("no API URL configured")
        return _default_caller(
            self._api_url,
            self._api_key,
            self._model,
            self._timeout,
            self._max_completion_tokens,
        )(prompt, system)

    def _cached(self, log: Any, junction: str, digest: str) -> Opinion | None:
        """The replayed opinion for *digest*, from the log's ``llm.junction`` rows.

        A *degraded* row is skipped rather than replayed: a failure is a fact
        about that call, not an answer to the question — the same rule that
        keeps ``failed`` out of the receipts ledger's conclusive outcomes. A
        keyed re-run therefore re-asks what once failed (and pays for it); a
        keyless replay never reaches here anyway, because health gates first.
        """
        for row in log.events(EVENT_LLM_JUNCTION):

            if row.get("digest") != digest or row.get("junction") != junction:
                continue
            if row.get("degraded"):
                continue
            return Opinion(
                junction=junction,
                digest=digest,
                answer=dict(row.get("answer") or {}),
                validation=str(row.get("validation", "")),
                validated=bool(row.get("validated")),
                model=str(row.get("model", "")),
                source="cached",
            )
        return None


def _extract_json(text: str) -> dict:
    """The answer's outermost JSON object, or raise.

    One brace-scan rather than a regex, and *outermost* on purpose: the model
    may wrap its answer in prose (the 2026 structured-output literature's
    first failure mode), and an inner object would be a fragment of an answer,
    not an answer.
    """
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        raise ValueError(f"no JSON object in the answer ({len(text)} chars of prose)")
    payload = json.loads(text[start : end + 1])
    if not isinstance(payload, dict):
        raise ValueError("the answer's JSON is not an object")
    return payload


__all__ = [
    "DEFAULT_MAX_COMPLETION_TOKENS",
    "DEFAULT_MODEL",
    "DEFAULT_TIMEOUT",
    "ENV_KEY",
    "ENV_MAX_COMPLETION_TOKENS",
    "ENV_MODEL",
    "ENV_URL",
    "EVENT_LLM_JUNCTION",
    "Health",
    "LLMClient",
    "LLMJunction",
    "ModelCaller",
    "NO_KEY_REASON",
    "Opinion",
    "opinion_digest",
]
