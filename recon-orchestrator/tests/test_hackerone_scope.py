"""Tests for HackerOne scope import.

The original module was unreachable (it sat outside the package root) and had
three defects that only real API data exposes: it read ``identifier`` where the
API sends ``asset_identifier``, it decided scope from ``eligible_for_bounty``
instead of ``eligible_for_submission``, and it dropped every WILDCARD asset.
"""
from __future__ import annotations

import json

import pytest

from recon_orchestrator.hackerone_scope import (
    parse_hackerone_scope,
    parse_structured_scopes,
    to_host_pattern,
)


def _asset(identifier, asset_type="URL", submission=True, bounty=True):
    return {"attributes": {
        "asset_identifier": identifier,
        "asset_type": asset_type,
        "eligible_for_submission": submission,
        "eligible_for_bounty": bounty,
    }}


# --- host normalisation ------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("example.com", "example.com"),
    ("  Example.COM  ", "example.com"),
    ("https://example.com", "example.com"),
    ("https://example.com/", "example.com"),
    ("*.example.com", "*.example.com"),
    ("example.com:8443", "example.com"),
    ("example.com.", "example.com"),
])
def test_host_patterns_are_normalised(raw, expected):
    assert to_host_pattern(raw) == expected


@pytest.mark.parametrize("raw", [
    "https://github.com/Hacker0x01/react-datepicker",  # a single repository
    "https://hackerone.com/mcp",                       # a path on a host
    "example.com/app/login",                           # path without a scheme
    "",
    None,
])
def test_path_scoped_identifiers_are_rejected(raw):
    """Reducing a path-scoped asset to its host would turn one repository into
    all of github.com. Under-include rather than over-include."""
    assert to_host_pattern(raw) is None


def test_app_ids_are_excluded_by_type_not_by_shape():
    """`com.example.app` is shape-indistinguishable from a hostname, so the
    asset_type filter is what keeps it out — guessing from the string would
    need a TLD list and would eventually reject a real host."""
    assert to_host_pattern("com.example.app") == "com.example.app"

    skipped: list[str] = []
    in_scope, _ = parse_structured_scopes(
        [_asset("com.example.app", "GOOGLE_PLAY_APP_ID")], skipped
    )
    assert in_scope == []
    assert skipped == ["com.example.app (GOOGLE_PLAY_APP_ID)"]


# --- scope splitting ---------------------------------------------------------

def test_scope_is_decided_by_submission_not_bounty():
    """An asset can be in scope and pay nothing; the old code called that
    out of scope and would have blocked a legitimate target."""
    assets = [
        _asset("paid.example.com", submission=True, bounty=True),
        _asset("unpaid.example.com", submission=True, bounty=False),
        _asset("excluded.example.com", submission=False, bounty=False),
    ]
    in_scope, out_of_scope = parse_structured_scopes(assets)

    assert in_scope == ["paid.example.com", "unpaid.example.com"]
    assert out_of_scope == ["excluded.example.com"]


def test_wildcard_assets_are_kept():
    """WILDCARD is the most valuable scope entry and was dropped entirely."""
    in_scope, _ = parse_structured_scopes([_asset("*.example.com", "WILDCARD")])
    assert in_scope == ["*.example.com"]


def test_non_host_asset_types_are_skipped_and_reported():
    skipped: list[str] = []
    assets = [
        _asset("example.com", "URL"),
        _asset("https://gitlab.com/org/repo", "SOURCE_CODE"),
        _asset("com.example.app", "GOOGLE_PLAY_APP_ID"),
    ]
    in_scope, out_of_scope = parse_structured_scopes(assets, skipped)

    assert in_scope == ["example.com"]
    assert out_of_scope == []
    assert len(skipped) == 2


def test_duplicates_collapse_preserving_order():
    assets = [_asset("b.example.com"), _asset("a.example.com"), _asset("b.example.com")]
    in_scope, _ = parse_structured_scopes(assets)
    assert in_scope == ["b.example.com", "a.example.com"]


def test_missing_eligibility_defaults_to_in_scope():
    """An older export without the field should not silently lose targets."""
    in_scope, out_of_scope = parse_structured_scopes(
        [{"asset_identifier": "example.com", "asset_type": "URL"}]
    )
    assert in_scope == ["example.com"]
    assert out_of_scope == []


def test_legacy_identifier_key_still_works():
    in_scope, _ = parse_structured_scopes(
        [{"identifier": "example.com", "asset_type": "URL",
          "eligible_for_submission": True}]
    )
    assert in_scope == ["example.com"]


@pytest.mark.parametrize("payload", [
    {"data": [_asset("example.com")]},      # raw API response
    {"assets": [_asset("example.com")]},    # hand-made export
    [_asset("example.com")],                # bare list
])
def test_accepts_every_payload_shape(payload):
    in_scope, _ = parse_structured_scopes(payload)
    assert in_scope == ["example.com"]


# --- file entry point --------------------------------------------------------

def test_parse_file(tmp_path):
    path = tmp_path / "scope.json"
    path.write_text(json.dumps({"data": [
        _asset("example.com"),
        _asset("*.example.com", "WILDCARD"),
        _asset("gone.example.com", submission=False),
    ]}))

    in_scope, out_of_scope = parse_hackerone_scope(str(path))

    assert in_scope == ["example.com", "*.example.com"]
    assert out_of_scope == ["gone.example.com"]


def test_missing_file_returns_empty(tmp_path):
    assert parse_hackerone_scope(str(tmp_path / "nope.json")) == ([], [])


def test_malformed_file_returns_empty(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not json")
    assert parse_hackerone_scope(str(path)) == ([], [])


def test_imported_scope_round_trips_through_scopeguard():
    """The whole point: the output must be usable as ScopeGuard patterns."""
    from recon_orchestrator.scope import ScopeGuard

    in_scope, out_of_scope = parse_structured_scopes([
        _asset("*.example.com", "WILDCARD"),
        _asset("example.com"),
        _asset("blocked.example.com", submission=False),
    ])
    guard = ScopeGuard(in_scope, out_of_scope, True)

    assert guard.is_authorized("api.example.com")
    assert guard.is_authorized("example.com")
    assert not guard.is_authorized("blocked.example.com")
    assert not guard.is_authorized("evil.com")
