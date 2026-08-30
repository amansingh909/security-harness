"""Import HackerOne scope data and convert to in-scope/out-of-scope lists.

This module reads a HackerOne scope export (JSON format) and extracts
in-scope and out-of-scope patterns for use with the ScopeGuard.
"""
from __future__ import annotations

import json
import logging
from typing import List, Tuple, TypedDict

log = logging.getLogger(__name__)


class HackerOneAsset(TypedDict, total=False):
    """Represents a single asset in HackerOne scope data."""
    identifier: str
    asset_type: str
    eligible_for_bounty: bool
    # Optional fields we might ignore for scope purposes
    max_severity: str
    confidence: str


def parse_hackerone_scope(
    scope_file: str,
) -> Tuple[List[str], List[str]]:
    """Parse a HackerOne scope JSON file and return (in_scope, out_of_scope) lists.

    Args:
        scope_file: Path to the HackerOne scope JSON file.

    Returns:
        A tuple of (in_scope_list, out_of_scope_list) where each list contains
        strings suitable for passing to ScopeGuard (e.g., "example.com", "*.example.com",
        "192.168.1.0/24").

    Expected JSON format:
        {
            "assets": [
                {
                    "identifier": "example.com",
                    "asset_type": "URL",
                    "eligible_for_bounty": true,
                    "max_severity": "critical"
                },
                ...
            ]
        }
    """
    in_scope: List[str] = []
    out_of_scope: List[str] = []

    try:
        with open(scope_file, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        log.error("HackerOne scope file not found: %s", scope_file)
        return in_scope, out_of_scope
    except json.JSONDecodeError as exc:
        log.error("Invalid JSON in HackerOne scope file %s: %s", scope_file, exc)
        return in_scope, out_of_scope

    # Handle both direct list and nested under "assets" key
    assets = data.get("assets", data if isinstance(data, list) else [])
    if not isinstance(assets, list):
        log.error("Expected a list of assets in HackerOne scope data")
        return in_scope, out_of_scope

    for asset in assets:
        if not isinstance(asset, dict):
            log.warning("Skipping non-dict asset in HackerOne scope: %s", asset)
            continue

        identifier = asset.get("identifier")
        asset_type = asset.get("asset_type")
        eligible = asset.get("eligible_for_bounty")

        # Skip if we don't have the minimum required fields
        if identifier is None or asset_type is None or eligible is None:
            log.warning(
                "Skipping asset missing required fields: identifier=%s, asset_type=%s, eligible_for_bounty=%s",
                identifier,
                asset_type,
                eligible,
            )
            continue

        # We only handle URL assets for now; other types (NETWORK, etc.) can be added later
        if asset_type.upper() != "URL":
            log.debug("Skipping non-URL asset type: %s (identifier: %s)", asset_type, identifier)
            continue

        # Clean the identifier: strip whitespace and convert to lowercase
        identifier = str(identifier).strip().lower()
        if not identifier:
            continue

        # Add to appropriate list
        if eligible:
            in_scope.append(identifier)
        else:
            out_of_scope.append(identifier)

    log.info(
        "Parsed HackerOne scope: %d in-scope, %d out-of-scope URL assets",
        len(in_scope),
        len(out_of_scope),
    )

    return in_scope, out_of_scope