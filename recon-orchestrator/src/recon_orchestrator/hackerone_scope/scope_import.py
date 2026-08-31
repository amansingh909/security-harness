"""Import HackerOne structured scopes into ScopeGuard patterns.

Scopes can come from a JSON file you exported by hand, or straight from the
HackerOne API. Both paths land in :func:`parse_structured_scopes`, which is
written against the real API schema:

    asset_identifier          the host, wildcard, or URL
    asset_type                URL | WILDCARD | OTHER | SOURCE_CODE | ...
    eligible_for_submission   whether the asset is IN SCOPE
    eligible_for_bounty       whether it PAYS - not the same thing

An asset can be in scope and pay nothing, so scope is decided by
``eligible_for_submission`` alone.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Iterable, List, Tuple, TypedDict

log = logging.getLogger(__name__)

#: Asset types that name something we can resolve and probe over HTTP. Types
#: like SOURCE_CODE ("https://gitlab.com/org/repo"), APPLE_STORE_APP_ID or
#: CIDR are in scope for a human but are not hosts a web prober can sweep.
HOST_ASSET_TYPES = frozenset({"URL", "WILDCARD", "DOMAIN", "OTHER"})


class HackerOneAsset(TypedDict, total=False):
    """One entry in a HackerOne structured-scopes response."""

    asset_identifier: str
    asset_type: str
    eligible_for_submission: bool
    eligible_for_bounty: bool
    max_severity: str
    instruction: str


def to_host_pattern(identifier: str) -> str | None:
    """Reduce a scope identifier to a host pattern ScopeGuard understands.

    Strips scheme, port and trailing dots, and keeps a leading ``*.``. Returns
    None for anything that is not a whole host, so the caller can skip it.

    A path is disqualifying, not something to strip. HackerOne's "security"
    program scopes ``https://github.com/Hacker0x01/react-datepicker`` — one
    repository. Reducing that to ``github.com`` would authorize scanning all
    of GitHub. Under-including a target costs one manual edit; over-including
    one means testing something the program never put in scope.
    """
    if not identifier:
        return None
    value = str(identifier).strip().lower()
    if not value:
        return None

    if "://" in value:
        value = value.split("://", 1)[1]

    # A path means this names a resource on a host, not the host itself.
    host, slash, remainder = value.partition("/")
    if slash and remainder.strip():
        return None
    value = host

    # Credentials and port.
    value = value.rsplit("@", 1)[-1]
    if value.count(":") == 1:
        value = value.split(":", 1)[0]
    value = value.strip().rstrip(".")

    if not value or "." not in value or " " in value:
        return None
    return value


def parse_structured_scopes(
    assets: Iterable[dict[str, Any]] | dict[str, Any],
    skipped: List[str] | None = None,
) -> Tuple[List[str], List[str]]:
    """Split structured scopes into (in_scope, out_of_scope) host patterns.

    Accepts the raw API response, a ``{"assets": [...]}`` export, or a bare
    list. Entries are de-duplicated with their first-seen order preserved.

    Pass a list as ``skipped`` to collect the identifiers that were dropped
    for not being whole hosts — repositories, mobile app ids, path-scoped
    URLs. They are real scope entries a human should still look at.
    """
    items = _coerce_assets(assets)

    in_scope: List[str] = []
    out_of_scope: List[str] = []
    dropped = skipped if skipped is not None else []

    for asset in items:
        if not isinstance(asset, dict):
            continue
        # API responses nest the fields under "attributes".
        attributes = asset.get("attributes") if isinstance(asset.get("attributes"), dict) else asset

        identifier = attributes.get("asset_identifier") or attributes.get("identifier")
        asset_type = (attributes.get("asset_type") or "").upper()
        # Absent eligible_for_submission means the export predates the field;
        # treat the asset as in scope rather than silently dropping a target.
        eligible = attributes.get("eligible_for_submission")
        if eligible is None:
            eligible = True

        if asset_type and asset_type not in HOST_ASSET_TYPES:
            log.debug("skipping non-host asset type %s (%s)", asset_type, identifier)
            if identifier:
                dropped.append(f"{identifier} ({asset_type})")
            continue

        pattern = to_host_pattern(identifier)
        if pattern is None:
            log.debug("skipping non-host identifier %r", identifier)
            if identifier:
                dropped.append(f"{identifier} ({asset_type or 'unknown'})")
            continue

        target = in_scope if eligible else out_of_scope
        if pattern not in target:
            target.append(pattern)

    log.info(
        "parsed HackerOne scope: %d in scope, %d out of scope, %d skipped",
        len(in_scope), len(out_of_scope), len(dropped),
    )
    return in_scope, out_of_scope


def parse_hackerone_scope(
    scope_file: str, skipped: List[str] | None = None
) -> Tuple[List[str], List[str]]:
    """Parse a HackerOne scope JSON file exported by hand."""
    try:
        with open(scope_file, encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        log.error("HackerOne scope file not found: %s", scope_file)
        return [], []
    except json.JSONDecodeError as exc:
        log.error("invalid JSON in HackerOne scope file %s: %s", scope_file, exc)
        return [], []
    return parse_structured_scopes(data, skipped)


async def fetch_structured_scopes(
    handle: str,
    identifier: str,
    api_token: str,
    timeout: float = 30.0,
    skipped: List[str] | None = None,
) -> Tuple[List[str], List[str]]:
    """Fetch a program's scope from the HackerOne API.

    ``identifier`` is the API identifier (the username half of the credential);
    HackerOne authenticates with HTTP Basic ``identifier:token``. Paginates
    until the API stops offering a next link.
    """
    import base64

    import httpx

    if not handle:
        raise ValueError("a program handle is required, e.g. 'security'")
    if not identifier or not api_token:
        raise ValueError(
            "HackerOne needs both an API identifier and a token "
            "(Settings -> API Tokens)."
        )

    credential = base64.b64encode(f"{identifier}:{api_token}".encode()).decode()
    headers = {"Authorization": f"Basic {credential}", "Accept": "application/json"}
    url = (
        f"https://api.hackerone.com/v1/hackers/programs/{handle}/structured_scopes"
    )

    collected: List[dict[str, Any]] = []
    async with httpx.AsyncClient(timeout=timeout) as client:
        while url:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 401:
                raise PermissionError(
                    "HackerOne rejected the credential (401). Check H1_IDENTIFIER "
                    "and H1_API_KEY."
                )
            if resp.status_code == 404:
                raise LookupError(
                    f"no program with handle {handle!r}, or it is not visible to you."
                )
            resp.raise_for_status()
            body = resp.json()
            collected.extend(body.get("data", []))
            url = (body.get("links") or {}).get("next")

    return parse_structured_scopes(collected, skipped)


def _coerce_assets(payload: Any) -> list:
    """Pull the asset list out of whichever shape the caller supplied."""
    if isinstance(payload, dict):
        for key in ("data", "assets"):
            value = payload.get(key)
            if isinstance(value, list):
                return value
        return []
    if isinstance(payload, list):
        return payload
    log.error("expected a list of assets, got %s", type(payload).__name__)
    return []
