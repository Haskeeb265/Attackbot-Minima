"""
HackerOne Hacker API v1 connector.

Concrete ``BaseConnector`` implementation for HackerOne. The scraper
service talks to this connector (or any other ``BaseConnector``) instead
of issuing HackerOne-specific HTTP calls itself.
"""

from config import HACKERONE_AUTH, HACKERONE_BASE_URL

from shared.connectors.base import BaseConnector


class HackerOneConnector(BaseConnector):
    """HackerOne implementation of :class:`BaseConnector` (Hacker API v1)."""

    def __init__(self):
        super().__init__(base_url=HACKERONE_BASE_URL, auth=HACKERONE_AUTH)

    def fetch_programs(
        self,
        page_size: int = 100,
        max_pages: int = 100,
    ) -> list[dict]:
        return self._paginate("hackers/programs", page_size, max_pages)

    def fetch_program_detail(self, handle: str) -> dict:
        """``hackers/programs/{handle}`` -> the program's own attributes.

        Best-effort by contract: the program-detail endpoint is not needed for
        the identity/scope half of ingestion, so a transport error, a 404 for a
        retired program, or an unexpected envelope returns ``{}`` and the run
        proceeds. The alternative — letting one optional endpoint abort an
        otherwise-good program — is the failure this tolerance exists to avoid.
        """
        try:
            payload = self._get(f"hackers/programs/{handle}")
        except Exception:  # noqa: BLE001 - optional enrichment, never fatal
            return {}
        if not isinstance(payload, dict):
            return {}
        item = payload.get("data")
        if not isinstance(item, dict):
            return {}
        attributes = item.get("attributes")
        return attributes if isinstance(attributes, dict) else {}

    def fetch_program_scopes(
        self,
        handle: str,
        page_size: int = 100,
        max_pages: int = 100,
    ) -> list[dict]:
        return self._paginate(
            f"hackers/programs/{handle}/structured_scopes",
            page_size,
            max_pages,
        )

    def fetch_program_weaknesses(
        self,
        handle: str,
        page_size: int = 100,
        max_pages: int = 100,
    ) -> list[dict]:
        return self._paginate(
            f"hackers/programs/{handle}/weaknesses",
            page_size,
            max_pages,
        )

    def fetch_program_scope_exclusions(self, handle: str) -> list[dict]:
        data = self._get(f"hackers/programs/{handle}/scope_exclusions")
        if not data or "data" not in data:
            return []
        return data["data"]
