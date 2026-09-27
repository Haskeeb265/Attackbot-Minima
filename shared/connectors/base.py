"""
Platform-agnostic connector (source) base class.

A connector is a *source* of bug bounty program data — HackerOne today,
Bugcrowd and other platforms later. The scraper service depends only on
this interface and never on platform-specific URLs, auth, or JSON
envelopes. Adding a new platform means adding a new connector subclass
(plus a mapper for its response shape), not touching the scraper.

Each abstract method returns the fully-paginated, *raw* platform items
(the ``data`` arrays of the platform's API response). The scraper
orchestrates those items; per-platform response-shape adaptation to the
internal DB format lives in the mappers under ``db/mapper/``.
"""

from abc import ABC, abstractmethod

import requests


class BaseConnector(ABC):
    """
    Abstract source of bug bounty program data.

    Concrete connectors provide:
      - platform credentials / auth,
      - endpoint paths,
      - pagination behaviour (the default ``_paginate`` follows a
        HackerOne-style ``links.next`` envelope; override for platforms
        that paginate differently).
    """

    def __init__(self, base_url: str, auth: tuple | None = None):
        self.base_url = base_url.rstrip("/") + "/"
        self.auth = auth

    # ------------------------------------------------------------------
    # HTTP plumbing (shared by all connectors)
    # ------------------------------------------------------------------

    def _get(self, path: str) -> dict:
        """GET an endpoint (relative to the base URL) and return parsed JSON.

        Raises on HTTP errors so callers never silently proceed with an
        empty/unauthenticated response.
        """
        response = requests.get(
            f"{self.base_url}{path.lstrip('/')}",
            auth=self.auth,
            timeout=30,
        )
        response.raise_for_status()
        return response.json()

    def _paginate(
        self,
        path: str,
        page_size: int,
        max_pages: int,
    ) -> list[dict]:
        """
        Fetch every page of an endpoint and return the concatenated items.

        Follows a HackerOne-style envelope: ``page[number]`` /
        ``page[size]`` query params, with pagination continuing while
        ``links.next`` is present. Returns the raw ``data`` items.
        """
        items: list[dict] = []
        page = 1

        while True:
            data = self._get(f"{path}?page[number]={page}&page[size]={page_size}")

            if not data or "data" not in data or not data["data"]:
                break

            items.extend(data["data"])

            if not data.get("links", {}).get("next"):
                break

            page += 1
            if page > max_pages:
                break

        return items

    # ------------------------------------------------------------------
    # Source contract — every platform connector implements these
    # ------------------------------------------------------------------

    def fetch_program_detail(self, handle: str) -> dict:
        """Raw attributes for one program — status, policy, disclosure, etc.

        Optional, and deliberately **not** abstract: a connector that has no
        per-program endpoint, or whose response shape has not been adapted yet,
        returns ``{}`` and the mapper persists NULLs instead of inventing
        program-level facts. The scraper calls this best-effort; a platform that
        cannot answer must degrade to "no program intelligence", never fail the
        whole program's ingestion.
        """
        return {}

    @abstractmethod
    def fetch_programs(
        self,
        page_size: int = 100,
        max_pages: int = 100,
    ) -> list[dict]:
        """All bounty programs (raw items)."""
        raise NotImplementedError

    @abstractmethod
    def fetch_program_scopes(
        self,
        handle: str,
        page_size: int = 100,
        max_pages: int = 100,
    ) -> list[dict]:
        """All structured scopes for one program (raw items)."""
        raise NotImplementedError

    @abstractmethod
    def fetch_program_weaknesses(
        self,
        handle: str,
        page_size: int = 100,
        max_pages: int = 100,
    ) -> list[dict]:
        """All weakness rulesets for one program (raw items)."""
        raise NotImplementedError

    @abstractmethod
    def fetch_program_scope_exclusions(self, handle: str) -> list[dict]:
        """All scope exclusions for one program (raw items)."""
        raise NotImplementedError
