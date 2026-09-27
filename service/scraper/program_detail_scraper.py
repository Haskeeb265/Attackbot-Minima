import json

from shared.colorlog import log
from shared.connectors.base import BaseConnector
from shared.connectors.hackerone_client import HackerOneConnector

from .program_scraper import ProgramScraper


class ProgramDetailScraper:
    """
    Fetches full detail for one program handle at a time.

    All data comes from a :class:`BaseConnector` source (HackerOne today);
    this class never issues platform-specific HTTP calls itself.
    """

    MAX_PAGES = 100
    PAGE_SIZE = 100

    def __init__(self, connector: BaseConnector | None = None):
        self.connector = connector or HackerOneConnector()

    def _flatten_scope(self, scope):
        attrs = scope.get('attributes', {})
        return {
            'id': scope.get('id'),
            'asset_type': attrs.get('asset_type'),
            'asset_identifier': attrs.get('asset_identifier'),
            'eligible_for_bounty': attrs.get('eligible_for_bounty'),
            'eligible_for_submission': attrs.get('eligible_for_submission'),
            'max_severity': attrs.get('max_severity'),
            'instruction': attrs.get('instruction'),
            'confidentiality_requirement': attrs.get('confidentiality_requirement'),
            'integrity_requirement': attrs.get('integrity_requirement'),
            'availability_requirement': attrs.get('availability_requirement'),
            'created_at': attrs.get('created_at'),
            'updated_at': attrs.get('updated_at'),
        }

    def _fetch_handle_scopes(self, handle):
        log.process(f"[{handle}] Fetching structured scopes...")
        all_scopes = self.connector.fetch_program_scopes(
            handle,
            page_size=self.PAGE_SIZE,
            max_pages=self.MAX_PAGES,
        )
        log.success(f"[{handle}] {len(all_scopes)} total scopes fetched")

        return {
            'handle': handle,
            'scope_count': len(all_scopes),
            'scopes': [self._flatten_scope(scope) for scope in all_scopes]
        }

    def get_scope_exclusions(self, handle: str) -> list[dict]:
        log.process(f"[{handle}] Fetching scope exclusions...")
        exclusions = self.connector.fetch_program_scope_exclusions(handle)
        log.success(f"[{handle}] {len(exclusions)} scope exclusions fetched")
        return exclusions

    def get_weaknesses(self, handle: str) -> list[dict]:
        log.process(f"[{handle}] Fetching weaknesses...")
        all_weaknesses = self.connector.fetch_program_weaknesses(
            handle,
            page_size=self.PAGE_SIZE,
            max_pages=self.MAX_PAGES,
        )
        log.success(f"[{handle}] {len(all_weaknesses)} total weaknesses fetched")
        return all_weaknesses

    def high_priority_handle_detail_scraping(self):
        log.process("Starting HIGH priority handle detail scraping...")
        scraper = ProgramScraper(self.connector)
        handles = scraper.high_priority_handle_scraping()
        results = [self.fetch_program(handle) for handle in handles]
        log.success(f"Finished HIGH priority scraping — {len(results)} programs")
        return results

    def low_priority_handle_detail_scraping(self):
        log.process("Starting LOW priority handle detail scraping...")
        scraper = ProgramScraper(self.connector)
        handles = scraper.low_priority_handle_scraping()
        results = [self.fetch_program(handle) for handle in handles]
        log.success(f"Finished LOW priority scraping — {len(results)} programs")
        return results
    
    
    def fetch_program(self, handle: str) -> dict:
        """Everything one program publishes: identity, scope, policy, exclusions.

        ``program`` carries the program-level attributes (status, policy,
        disclosure, safe harbour) the mapper now persists; it is the source's own
        dict and is best-effort — an empty dict means the source did not answer,
        which the mapper records as NULLs rather than as invented facts.
        """
        return {
            **self._fetch_handle_scopes(handle),
            "program": self.connector.fetch_program_detail(handle),
            "scope_exclusions": self.get_scope_exclusions(handle),
            "weaknesses": self.get_weaknesses(handle),
        }


# ============================================================
# MAIN
# ============================================================
if __name__ == "__main__":
    try:
        detail_scraper = ProgramDetailScraper()
        high_function = detail_scraper.high_priority_handle_detail_scraping()
        low_function = detail_scraper.low_priority_handle_detail_scraping()

        with open("high_priority_details.json", "w") as f:
            json.dump(high_function, f, indent=4)

        with open("low_priority_details.json", "w") as f:
            json.dump(low_function, f, indent=4)

        log.success(f"High priority details saved: {len(high_function)} programs")
        log.success(f"Low priority details saved: {len(low_function)} programs")

    except Exception as e:
        log.failed(f"Scraping run aborted: {e}")
        raise