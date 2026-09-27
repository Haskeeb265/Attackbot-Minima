class HackerOneMapper:
    #: The program-level attributes the mapper will persist, in the order the
    #: repository's column whitelist uses. Absent keys map to ``None`` ("the
    #: source did not say"), never to an invented default.
    MASTER_FIELDS = (
        "platform",
        "program_url",
        "program_name",
        "program_status",
        "description",
        "policy",
        "disclosure_policy",
        "safe_harbor",
        "offers_bounties",
        "open_scope",
        "gold_standard_safe_harbor",
    )

    @staticmethod
    def map_program(program: dict) -> dict:
        return {
            "master": HackerOneMapper._map_master(program),
            "scopes": HackerOneMapper._map_scopes(program.get("scopes", [])),
            "weaknesses": HackerOneMapper._map_weaknesses(program.get("weaknesses", [])),
            "exclusions": HackerOneMapper._map_exclusions(
                program.get("scope_exclusions", [])
            ),
        }

    @staticmethod
    def _map_master(program: dict) -> dict:
        """Program identity plus the program-level intelligence, where present.

        ``program`` is the raw attributes dict the connector returned (empty
        when the source could not answer). Key names here are the *source's*
        own, mapped once so the rest of the codebase never speaks HackerOne's
        envelope: ``submission_state`` becomes ``program_status`` because
        "status" is the bug-bounty concept and HackerOne's spelling is not.
        """
        attrs = program.get("program") or {}
        return {
            "handle": program["handle"],
            "scope_count": program["scope_count"],
            "platform": attrs.get("platform") or "hackerone",
            "program_url": attrs.get("url"),
            "program_name": attrs.get("name"),
            "program_status": attrs.get("submission_state") or attrs.get("state"),
            "description": attrs.get("description"),
            "policy": attrs.get("policy"),
            "disclosure_policy": attrs.get("disclosure_policy"),
            "safe_harbor": attrs.get("safe_harbor"),
            "offers_bounties": attrs.get("offers_bounties"),
            "open_scope": attrs.get("open_scope"),
            "gold_standard_safe_harbor": attrs.get("gold_standard_safe_harbor"),
        }

    @staticmethod
    def is_in_scope(eligible_for_submission) -> bool:
        """The boundary flag: an asset is out of scope only when told so.

        HackerOne's structured scopes carry ``eligible_for_submission``. When it
        is **explicitly False** the program lists the asset but does not accept
        reports on it — an out-of-scope boundary. ``True`` and ``None`` both mean
        in scope: an absent flag is the source not saying, and treating "not
        said" as "excluded" would silently drop real assets from scope.
        """
        return eligible_for_submission is not False

    @staticmethod
    def _map_scopes(scopes: list[dict]) -> list[dict]:
        """Every declared scope asset, with its boundary and eligibility kept.

        This used to keep only four fields, which is why out-of-scope assets and
        per-asset bounty eligibility never reached the database.
        """
        mapped = []
        for scope in scopes:
            eligible_for_submission = scope.get("eligible_for_submission")
            mapped.append(
                {
                    "scope_type": scope.get("asset_type"),
                    "scope_identifier": scope.get("asset_identifier"),
                    "max_severity": scope.get("max_severity"),
                    "scope_instructions": scope.get("instruction"),
                    "asset_id": scope.get("id"),
                    "in_scope": HackerOneMapper.is_in_scope(eligible_for_submission),
                    "eligible_for_bounty": scope.get("eligible_for_bounty"),
                    "eligible_for_submission": eligible_for_submission,
                    "confidentiality_requirement": scope.get("confidentiality_requirement"),
                    "integrity_requirement": scope.get("integrity_requirement"),
                    "availability_requirement": scope.get("availability_requirement"),
                }
            )
        return mapped

    @staticmethod
    def _map_weaknesses(weaknesses: list[dict]) -> list[dict]:
        mapped = []

        for weakness in weaknesses:
            attrs = weakness.get("attributes", {})

            mapped.append(
                {
                    "weakness_id": weakness.get("id"),
                    "hackerone_weakness_id": attrs.get("weakness_id"),
                    "weakness_name": attrs.get("name"),
                    "weakness_description": attrs.get("description"),
                }
            )

        return mapped

    @staticmethod
    def _map_exclusions(exclusions: list[dict]) -> list[dict]:
        mapped = []

        for exclusion in exclusions:
            attrs = exclusion.get("attributes", {})

            mapped.append(
                {
                    "exclusion_category": attrs.get("category"),
                    "exclusion_details": attrs.get("details"),
                }
            )

        return mapped