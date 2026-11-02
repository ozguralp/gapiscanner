"""Tests for origin scope."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import google_api_scanner as gas  # noqa: E402

SENTINEL_KEY_A = "AIzaSyAA" + "A" * 31
SENTINEL_KEY_B = "AIzaSyBB" + "B" * 31
SENTINEL_KEY_C = "AIzaSyCC" + "C" * 31


# 1. `_partition_keys_by_origin_scope` — pure-function correctness

class TestPartitionKeysByOriginScope:
    @pytest.mark.unit
    def test_single_in_scope_source_passes(self):
        chk = gas._build_direct_discovery_in_scope_check(
            "url", "https://www.victim.com/")
        keys = {SENTINEL_KEY_A}
        sources = {SENTINEL_KEY_A: {"https://www.victim.com/app.js"}}
        in_scope, oos, reasons = gas._partition_keys_by_origin_scope(
            keys, sources, chk)
        assert in_scope == {SENTINEL_KEY_A}
        assert oos == set()
        assert reasons == {}

    @pytest.mark.unit
    def test_all_oos_keys_get_skipped(self):
        chk = gas._build_direct_discovery_in_scope_check(
            "url", "https://www.victim.com/")
        keys = {SENTINEL_KEY_A, SENTINEL_KEY_B}
        sources = {
            SENTINEL_KEY_A: {"https://cdn.example.net/lib.js"},
            SENTINEL_KEY_B: {"https://gtm.example.org/p.js",
                             "https://stats.tracker.com/x.js"},
        }
        in_scope, oos, reasons = gas._partition_keys_by_origin_scope(
            keys, sources, chk)
        assert in_scope == set()
        assert oos == {SENTINEL_KEY_A, SENTINEL_KEY_B}
        assert reasons[SENTINEL_KEY_A] == ["https://cdn.example.net/lib.js"]
        assert "https://gtm.example.org/p.js" in reasons[SENTINEL_KEY_B]
        assert "https://stats.tracker.com/x.js" in reasons[SENTINEL_KEY_B]

    @pytest.mark.unit
    def test_mixed_sources_at_least_one_in_scope_passes(self):
        chk = gas._build_direct_discovery_in_scope_check(
            "url", "https://www.victim.com/")
        keys = {SENTINEL_KEY_A}
        # One in-scope + many OOS — should land in in_scope bucket.
        sources = {SENTINEL_KEY_A: {
            "https://www.victim.com/app.js",
            "https://cdn.example.net/lib.js",
            "https://gtm.example.org/p.js",
        }}
        in_scope, oos, reasons = gas._partition_keys_by_origin_scope(
            keys, sources, chk)
        assert in_scope == {SENTINEL_KEY_A}
        assert oos == set()

    @pytest.mark.unit
    def test_empty_source_set_fails_closed(self):
        """A key with NO recorded source URL is treated as out-of-scope —
        we have no way to attribute it to the operator's target."""
        chk = gas._build_direct_discovery_in_scope_check(
            "url", "https://www.victim.com/")
        keys = {SENTINEL_KEY_A}
        sources = {SENTINEL_KEY_A: set()}
        in_scope, oos, reasons = gas._partition_keys_by_origin_scope(
            keys, sources, chk)
        assert in_scope == set()
        assert oos == {SENTINEL_KEY_A}
        assert reasons[SENTINEL_KEY_A] == []

    @pytest.mark.unit
    def test_missing_source_key_fails_closed(self):
        """`sources` dict missing the key entirely → treated as empty → OOS."""
        chk = gas._build_direct_discovery_in_scope_check(
            "url", "https://www.victim.com/")
        keys = {SENTINEL_KEY_A}
        sources = {}  # nothing recorded for this key
        in_scope, oos, reasons = gas._partition_keys_by_origin_scope(
            keys, sources, chk)
        assert in_scope == set()
        assert oos == {SENTINEL_KEY_A}

    @pytest.mark.unit
    def test_none_sources_handled(self):
        chk = gas._build_direct_discovery_in_scope_check(
            "url", "https://www.victim.com/")
        in_scope, oos, reasons = gas._partition_keys_by_origin_scope(
            {SENTINEL_KEY_A}, None, chk)
        assert in_scope == set()
        assert oos == {SENTINEL_KEY_A}

    @pytest.mark.unit
    def test_empty_keys_returns_empty(self):
        chk = gas._build_direct_discovery_in_scope_check(
            "url", "https://www.victim.com/")
        in_scope, oos, reasons = gas._partition_keys_by_origin_scope(
            set(), {}, chk)
        assert in_scope == set()
        assert oos == set()
        assert reasons == {}

    @pytest.mark.unit
    def test_host_list_entrypoint_oos_third_party(self):
        chk = gas._build_direct_discovery_in_scope_check(
            "host_list", {"1.2.3.4"})
        keys = {SENTINEL_KEY_A}
        sources = {SENTINEL_KEY_A: {"https://cdn.thirdparty.com/v1/x.js"}}
        in_scope, oos, _ = gas._partition_keys_by_origin_scope(
            keys, sources, chk)
        assert in_scope == set()
        assert oos == {SENTINEL_KEY_A}

    @pytest.mark.unit
    def test_host_list_entrypoint_matching_host(self):
        chk = gas._build_direct_discovery_in_scope_check(
            "host_list", {"1.2.3.4"})
        keys = {SENTINEL_KEY_A}
        sources = {SENTINEL_KEY_A: {"http://1.2.3.4:8080/dist/app.js"}}
        in_scope, oos, _ = gas._partition_keys_by_origin_scope(
            keys, sources, chk)
        assert in_scope == {SENTINEL_KEY_A}
        assert oos == set()

    @pytest.mark.unit
    def test_mobile_entrypoint_all_sources_in_scope(self):
        """Mobile bundle sources (archive-internal paths) are by-construction
        in-scope because the operator handed us the bundle."""
        chk = gas._build_direct_discovery_in_scope_check("mobile", None)
        keys = {SENTINEL_KEY_A, SENTINEL_KEY_B}
        sources = {
            SENTINEL_KEY_A: {"classes.dex"},
            SENTINEL_KEY_B: {"META-INF/google-services.json"},
        }
        in_scope, oos, _ = gas._partition_keys_by_origin_scope(
            keys, sources, chk)
        assert in_scope == {SENTINEL_KEY_A, SENTINEL_KEY_B}
        assert oos == set()


class _FakeBundle:
    """Minimal stand-in for `ScopeBundle.oos` consumers."""
    def __init__(self, oos):
        self.oos = oos


class TestBundleOriginScope:
    @pytest.mark.unit
    def test_http_in_scope_when_oos_empty(self):
        b = _FakeBundle(oos=[])
        assert gas._is_source_in_scope_for_auth_read(
            "https://www.victim.com/app.js", bundle=b) is True

    @pytest.mark.unit
    def test_http_oos_matches_regex(self):
        b = _FakeBundle(oos=[r"cdn\.example\.net"])
        assert gas._is_source_in_scope_for_auth_read(
            "https://cdn.example.net/lib.js", bundle=b) is False
        # Still in scope for the same-bundle target host
        assert gas._is_source_in_scope_for_auth_read(
            "https://www.victim.com/app.js", bundle=b) is True

    @pytest.mark.unit
    def test_mobile_label_always_in_scope(self):
        b = _FakeBundle(oos=[r".*"])
        assert gas._is_source_in_scope_for_auth_read(
            "mobile:ios:com.victim.app", bundle=b) is True

    @pytest.mark.unit
    def test_unknown_label_fails_closed(self):
        b = _FakeBundle(oos=[])
        assert gas._is_source_in_scope_for_auth_read(
            "rescan-kb", bundle=b) is False
        assert gas._is_source_in_scope_for_auth_read(
            None, bundle=b) is False
        assert gas._is_source_in_scope_for_auth_read(
            "", bundle=b) is False
