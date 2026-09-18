"""S13 — LLM classification: advisory labels, gate-checked, key-optional.

The plan's contract for LLM enrichment, kept exact:

* **advisory only** — labels never change scope or authorization; every active
  decision reads the scope engine and dispatcher, not an LLM;
* **gate-checked** — the dispatcher/gate sees the enrichment as a score
  *signal* at most, and the §5.4 scope rule still applies to it;
* **key-optional** — no provider SDK, endpoint or key exists in this tree
  (CONCERNS #7); the module degrades to ``available=False`` and every method
  returns "no opinion" instead of raising.  When a key appears (env), the
  HTTP call is a plain POST with a hard timeout — no new SDK dependency.

Labels are deliberately taxonomy-shaped (the §4 classification vocabulary):
``infra`` (hosting/CDN edge), ``app`` (a real application), ``admin`` (an
administrative surface), ``api``, ``junk`` (debris/parked).  The consumer
decides what to do with them; this module only reports.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field

log = logging.getLogger("platform.enrich")

ENV_KEY = "LLM_API_KEY"
ENV_URL = "LLM_API_URL"
ENV_MODEL = "LLM_MODEL"
DEFAULT_TIMEOUT = 20.0

#: The taxonomy the report speaks (§4 classification vocabulary).
LABEL_INFRA = "infra"
LABEL_APP = "app"
LABEL_ADMIN = "admin"
LABEL_API = "api"
LABEL_JUNK = "junk"
LABELS = (LABEL_INFRA, LABEL_APP, LABEL_ADMIN, LABEL_API, LABEL_JUNK)

NO_OPINION = "no-opinion"


@dataclass
class Enrichment:
    """One asset's advisory labels (or the no-opinion answer)."""

    asset_type: str
    canonical_value: str
    label: str = NO_OPINION
    confidence: float = 0.0
    reason: str = ""
    model: str = ""

    @property
    def has_opinion(self) -> bool:
        return self.label != NO_OPINION and self.confidence > 0

    def to_dict(self) -> dict:
        return {
            "asset_type": self.asset_type,
            "canonical_value": self.canonical_value,
            "label": self.label,
            "confidence": self.confidence,
            "reason": self.reason,
            "model": self.model,
        }


@dataclass
class EnrichHealth:
    available: bool
    reason: str = ""
    provider: str = ""

    def to_dict(self) -> dict:
        return {"available": self.available, "reason": self.reason, "provider": self.provider}


class LLMEnricher:
    """Key-gated, advisory-only classification.  Degrades to no-opinion."""

    def __init__(
        self,
        *,
        api_key: str | None = None,
        api_url: str | None = None,
        model: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self._api_key = (api_key if api_key is not None else os.getenv(ENV_KEY, "")).strip()
        self._api_url = (api_url if api_url is not None else os.getenv(ENV_URL, "")).strip()
        self._model = (model if model is not None else os.getenv(ENV_MODEL, "")).strip() or "general"
        self._timeout = timeout
        if self._api_key and self._api_url:
            self._health = EnrichHealth(available=True, provider=self._model)
        elif not self._api_key:
            self._health = EnrichHealth(available=False, reason=f"{ENV_KEY} not set")
        else:
            self._health = EnrichHealth(available=False, reason=f"{ENV_URL} not set")

    @property
    def health(self) -> EnrichHealth:
        return self._health

    @property
    def available(self) -> bool:
        return self._health.available

    # ------------------------------------------------------------------ #
    # classification
    # ------------------------------------------------------------------ #

    def classify(
        self,
        asset_type: str,
        canonical_value: str,
        *,
        context: str = "",
    ) -> Enrichment:
        """Advisory label for one asset; never raises, never decides scope."""
        if not self.available:
            return Enrichment(
                asset_type=asset_type,
                canonical_value=canonical_value,
                reason=self._health.reason,
                model=self._model,
            )

        prompt = self._prompt(asset_type, canonical_value, context)
        try:
            import requests

            response = requests.post(
                self._api_url,
                headers={
                    "Authorization": f"Bearer {self._api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self._model,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0,
                },
                timeout=self._timeout,
            )
            response.raise_for_status()
            body = response.json()
            text = body["choices"][0]["message"]["content"]
            return self._parse(asset_type, canonical_value, text)
        except Exception as exc:
            log.warning("enrichment degraded for %s: %s", canonical_value, exc)
            return Enrichment(
                asset_type=asset_type,
                canonical_value=canonical_value,
                reason=f"{type(exc).__name__}: {exc}",
                model=self._model,
            )

    def _prompt(self, asset_type: str, value: str, context: str) -> str:
        labels = ", ".join(LABELS)
        return (
            f"Classify this recon asset in one line.\n"
            f"type: {asset_type}\nvalue: {value}\n"
            f"{f'context: {context}\n' if context else ''}"
            f"Answer with JSON only: {{\"label\": one of [{labels}], "
            f"\"confidence\": 0.0-1.0, \"reason\": \"<= 15 words\"}}\n"
            f"Admin surfaces (login panels, dashboards) are {LABEL_ADMIN}; "
            f"parked or placeholder pages are {LABEL_JUNK}."
        )

    def _parse(self, asset_type: str, value: str, text: str) -> Enrichment:
        """Parse the model's answer; any drift from the taxonomy is no-opinion."""
        try:
            start, end = text.find("{"), text.rfind("}")
            payload = json.loads(text[start : end + 1])
            label = str(payload.get("label", "")).strip().lower()
            confidence = float(payload.get("confidence", 0.0))
            reason = str(payload.get("reason", ""))[:200]
            if label not in LABELS or not 0.0 <= confidence <= 1.0:
                raise ValueError(f"label/confidence out of contract: {label!r}")
            return Enrichment(
                asset_type=asset_type,
                canonical_value=value,
                label=label,
                confidence=confidence,
                reason=reason,
                model=self._model,
            )
        except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            return Enrichment(
                asset_type=asset_type,
                canonical_value=value,
                reason=f"unparseable answer ({exc})",
                model=self._model,
            )

    def to_dict(self) -> dict:
        return {"enrichment": self._health.to_dict()}
