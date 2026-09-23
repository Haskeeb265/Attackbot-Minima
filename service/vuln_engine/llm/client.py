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
network path; an injectable ``caller`` replaces it in tests.
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
DEFAULT_TIMEOUT = 20.0
DEFAULT_MODEL = "general"

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


def _default_caller(url: str, api_key: str, model: str, timeout: float) -> ModelCaller:
    """Build the plain-POST caller.  OpenAI-shaped because the recon side's
    ``enrich.py`` already speaks that shape and one idiom is one review."""

    def call(prompt: str, system: str) -> str:
        import requests  # imported at call time: the degraded path must not need it

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
            },
            timeout=timeout,
        )
        response.raise_for_status()
        body = response.json()
        return str(body["choices"][0]["message"]["content"])

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
        caller: ModelCaller | None = None,
    ) -> None:
        self._api_key = (
            api_key if api_key is not None else os.getenv(ENV_KEY, "")
        ).strip()
        self._api_url = (
            api_url if api_url is not None else os.getenv(ENV_URL, "")
        ).strip()
        self._model = (
            (model if model is not None else os.getenv(ENV_MODEL, "")).strip()
            or DEFAULT_MODEL
        )
        self._timeout = timeout
        self._caller = caller
        if self._caller is not None:
            self._health = Health(available=True, model="injected")
        elif self._api_key and self._api_url:
            self._health = Health(available=True, model=self._model)
        elif not self._api_key:
            self._health = Health(available=False, reason=NO_KEY_REASON)
        else:
            self._health = Health(
                available=False, reason=f"{ENV_URL} not set (key present, url missing)"
            )

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
            self._api_url, self._api_key, self._model, self._timeout
        )(prompt, system)

    def _cached(self, log: Any, junction: str, digest: str) -> Opinion | None:
        """The replayed opinion for *digest*, from the log's ``llm.junction`` rows."""
        for row in log.events(EVENT_LLM_JUNCTION):
            if row.get("digest") != digest or row.get("junction") != junction:
                continue
            if row.get("degraded"):
                return Opinion(
                    junction=junction,
                    digest=digest,
                    degraded=True,
                    reason=str(row.get("reason", "degraded call on record")),
                    model=str(row.get("model", "")),
                    source="cached",
                )
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
    "DEFAULT_MODEL",
    "DEFAULT_TIMEOUT",
    "ENV_KEY",
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
