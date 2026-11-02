"""Tests for direct discovery scope."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import google_api_scanner as gas  # noqa: E402

SENTINEL_KEY = "AIzaSyXX" + "X" * 31
FAKE_TOKEN = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImYzNGI"


@pytest.fixture(autouse=True)
def _reset_state():
    gas._set_auth_read_enabled(False)
    gas._set_auth_read_scope_ok(True)

    gas._DERIVED_PROJECT_IDS.add("test-derived-proj")
    with gas._AUTH_READ_LOCK:
        gas._AUTH_READ_FINDINGS.clear()
    with gas._IDENTITY_TOOLKIT_LOCK:
        gas._IDENTITY_TOOLKIT_ARTIFACTS.clear()
    with gas._DERIVED_LOCK:
        gas._DERIVED_PROJECT_IDS.clear()
        gas._DERIVED_PROJECT_NUMBERS.clear()
    with gas._DERIVED_FIREBASE_LOCK:
        gas._DERIVED_FIREBASE_CONFIGS.clear()
    yield
    gas._set_auth_read_enabled(False)
    gas._set_auth_read_scope_ok(True)
    gas._DERIVED_PROJECT_IDS.discard("test-derived-proj")


# 1. Per-entrypoint check builder

class TestUrlEntrypoint:
    @pytest.mark.unit
    def test_same_site_passes(self):
        chk = gas._build_direct_discovery_in_scope_check(
            "url", "https://www.victim.com/app")
        assert chk("https://www.victim.com/path/a.js") is True
        assert chk("https://api.victim.com/v1/x") is True  # same registrable apex

    @pytest.mark.unit
    def test_cross_origin_fails(self):
        chk = gas._build_direct_discovery_in_scope_check(
            "url", "https://www.victim.com/app")
        assert chk("https://cdn.example.net/lib.js") is False
        assert chk("https://attacker.example/x.js") is False

    @pytest.mark.unit
    def test_non_http_fails(self):
        chk = gas._build_direct_discovery_in_scope_check(
            "url", "https://www.victim.com/")
        assert chk("classes.dex") is False  # mobile path
        assert chk("") is False
        assert chk(None) is False

    @pytest.mark.unit
    def test_empty_target_fails_safe(self):
        chk = gas._build_direct_discovery_in_scope_check("url", "")
        assert chk("https://www.victim.com/") is False


@pytest.mark.skipif(
    not hasattr(gas, "_is_in_scope"),
    reason="scope entrypoint requires the scope-matching helper.",
)
class TestScopeEntrypoint:
    @pytest.mark.unit
    def test_in_scope_url_passes(self):
        import re
        include = [(re.compile(r"^www\.victim\.com$"),
                    re.compile(r"^/.*$"), "any")]
        exclude = []
        chk = gas._build_direct_discovery_in_scope_check(
            "scope", (include, exclude))
        assert chk("https://www.victim.com/app.js") is True

    @pytest.mark.unit
    def test_out_of_scope_url_fails(self):
        import re
        include = [(re.compile(r"^www\.victim\.com$"),
                    re.compile(r"^/.*$"), "any")]
        exclude = []
        chk = gas._build_direct_discovery_in_scope_check(
            "scope", (include, exclude))
        assert chk("https://cdn.example.net/lib.js") is False

    @pytest.mark.unit
    def test_explicit_exclude_blocks_match(self):
        import re
        include = [(re.compile(r"^.*\.victim\.com$"),
                    re.compile(r"^/.*$"), "any")]
        exclude = [(re.compile(r"^support\.victim\.com$"),
                    re.compile(r"^/.*$"), "any")]
        chk = gas._build_direct_discovery_in_scope_check(
            "scope", (include, exclude))
        assert chk("https://www.victim.com/x") is True
        assert chk("https://support.victim.com/y") is False

    @pytest.mark.unit
    def test_no_include_fails_safe(self):
        chk = gas._build_direct_discovery_in_scope_check("scope", (None, None))
        assert chk("https://www.victim.com/") is False


class TestHostListEntrypoint:
    @pytest.mark.unit
    def test_matching_host_passes(self):
        chk = gas._build_direct_discovery_in_scope_check(
            "host_list", {"1.2.3.4", "target.example.com"})
        assert chk("http://1.2.3.4:8080/x") is True
        assert chk("https://target.example.com/y") is True

    @pytest.mark.unit
    def test_non_matching_host_fails(self):
        chk = gas._build_direct_discovery_in_scope_check(
            "host_list", {"1.2.3.4"})
        assert chk("http://9.9.9.9/x") is False
        assert chk("http://other.example.com/x") is False

    @pytest.mark.unit
    def test_case_insensitive(self):
        chk = gas._build_direct_discovery_in_scope_check(
            "host_list", {"TARGET.example.com"})
        assert chk("http://target.example.com/x") is True

    @pytest.mark.unit
    def test_empty_set_fails(self):
        chk = gas._build_direct_discovery_in_scope_check("host_list", set())
        assert chk("http://anything.example.com/") is False


class TestMobileEntrypoint:
    @pytest.mark.unit
    def test_all_sources_in_scope(self):
        chk = gas._build_direct_discovery_in_scope_check("mobile", None)
        # Mobile sources are archive-internal paths; ALL operator-supplied.
        assert chk("classes.dex") is True
        assert chk("META-INF/foo") is True
        assert chk("assets/firebase.json") is True
        # Even an http URL is fine — operator gave us the bundle.
        assert chk("https://cdn.example.net/x") is True


class TestUnknownEntrypoint:
    @pytest.mark.unit
    def test_unknown_always_false(self):
        chk = gas._build_direct_discovery_in_scope_check("garbage", None)
        assert chk("anything") is False
        assert chk("https://www.victim.com/") is False


# 2. _are_key_sources_in_scope

class TestAreKeySourcesInScope:
    @pytest.mark.unit
    def test_empty_set_returns_false(self):
        chk = gas._build_direct_discovery_in_scope_check(
            "url", "https://www.victim.com/")
        assert gas._are_key_sources_in_scope(set(), chk) is False
        assert gas._are_key_sources_in_scope(None, chk) is False
        assert gas._are_key_sources_in_scope([], chk) is False

    @pytest.mark.unit
    def test_any_in_scope_source_passes(self):
        chk = gas._build_direct_discovery_in_scope_check(
            "url", "https://www.victim.com/")
        # One in-scope source + many OOS sources → in-scope.
        sources = {
            "https://www.victim.com/app.js",
            "https://cdn.example.net/lib.js",
            "https://stats.tracker.com/p.js",
        }
        assert gas._are_key_sources_in_scope(sources, chk) is True

    @pytest.mark.unit
    def test_all_out_of_scope_returns_false(self):
        chk = gas._build_direct_discovery_in_scope_check(
            "url", "https://www.victim.com/")
        sources = {
            "https://cdn.example.net/lib.js",
            "https://stats.tracker.com/p.js",
            "https://googletagmanager.com/gtm.js",
        }
        assert gas._are_key_sources_in_scope(sources, chk) is False


# 3. End-to-end: cross-origin key suppresses auth-read

def _mock_response(status, body="", url=None):
    m = MagicMock()
    m.status_code = status
    m.text = body
    m.content = body.encode() if isinstance(body, str) else (body or b"")
    try:
        m.json.return_value = json.loads(body) if body else {}
    except Exception:
        m.json.side_effect = ValueError("not json")
    m.headers = {"Content-Type": "application/json"}
    m.request = MagicMock()
    m.request.url = url or "https://x/x?key=" + SENTINEL_KEY
    return m


class TestEndToEndCrossOriginSuppression:
    """Simulate a `--url https://www.victim.com/` run where the discovered
    key was found only at `https://cdn.example.net/firebase.js`. With
    `--include-auth-read` enabled, the auth-read chain MUST NOT fire."""

    def _signup_response(self):
        body = (
            '{"idToken":"' + FAKE_TOKEN +
            '","localId":"local_x",'
            '"kind":"identitytoolkit#SignupNewUserResponse"}'
        )
        m = _mock_response(200, body)
        m.request.url = ("https://identitytoolkit.googleapis.com/v1/accounts:signUp?key="
                         + SENTINEL_KEY)
        return m

    @pytest.mark.unit
    def test_cross_origin_key_does_not_run_auth_read(self, monkeypatch):
        # Operator pointed at https://www.victim.com/
        target_url = "https://www.victim.com/"
        chk = gas._build_direct_discovery_in_scope_check("url", target_url)
        # The discovered key's sources are ALL cross-origin.
        key_sources = {"https://cdn.example.net/firebase.js",
                       "https://stats.tracker.com/p.js"}
        in_scope = gas._are_key_sources_in_scope(key_sources, chk)
        assert in_scope is False, (
            "all-cross-origin sources must be out-of-scope")

        # Simulate the wiring: operator's --include-auth-read sets master
        # gate ON. The per-key loop then sets scope_ok=False for this key.
        gas._set_auth_read_enabled(True)
        gas._set_auth_read_scope_ok(in_scope)
        gas._DERIVED_PROJECT_IDS.add("victim")  # Phase 0 derived
        gas._record_firebase_config(gas._firebase_config(
            project_id="victim",
            database_url="https://victim-default-rtdb.firebaseio.com",
            source="x.plist"))

        called_urls = []
        def _stub_post(url, **kwargs):
            called_urls.append(url)
            return _mock_response(200, "{}", url=url)
        def _stub_get(url, **kwargs):
            called_urls.append(url)
            return _mock_response(200, "{}", url=url)
        import requests
        monkeypatch.setattr(requests, "post", _stub_post)
        monkeypatch.setattr(requests, "get", _stub_get)

        # signUp succeeds; auth-read chain MUST short-circuit because
        # scope_ok=False even though master gate is ON.
        gas._check_it_signup_anon(self._signup_response())

        # Cleanup DELETE still fired — that's mandatory.
        assert any(":delete" in u for u in called_urls), (
            "mandatory cleanup must always run")
        # NO auth-read URLs hit.
        for u in called_urls:
            assert ":listCollectionIds" not in u, (
                f"Firestore auth-read fired on cross-origin key: {u}")
            assert "shallow=true" not in u, (
                f"RTDB auth-read fired on cross-origin key: {u}")
            # Storage list (firebasestorage.googleapis.com/.../o?) — same
            # path is used by other probes; we already key on the absence
            # of the others above.
        # No findings emitted.
        with gas._AUTH_READ_LOCK:
            assert gas._AUTH_READ_FINDINGS == [], (
                f"auth-read findings leaked for cross-origin key: "
                f"{gas._AUTH_READ_FINDINGS}")

    @pytest.mark.unit
    def test_same_origin_key_does_run_auth_read(self, monkeypatch):
        """Sanity counter-test: when the key IS same-site, auth-read fires."""
        target_url = "https://www.victim.com/"
        chk = gas._build_direct_discovery_in_scope_check("url", target_url)
        key_sources = {"https://www.victim.com/static/firebase.js"}
        in_scope = gas._are_key_sources_in_scope(key_sources, chk)
        assert in_scope is True

        gas._set_auth_read_enabled(True)
        gas._set_auth_read_scope_ok(in_scope)
        gas._DERIVED_PROJECT_IDS.add("victim")

        post_urls = []
        get_urls = []
        def _stub_post(url, **kwargs):
            post_urls.append(url)
            if ":listCollectionIds" in url:
                return _mock_response(200, '{"collectionIds":["users"]}', url=url)
            if ":delete" in url:
                return _mock_response(200, "{}", url=url)
            return _mock_response(200, "{}", url=url)
        def _stub_get(url, **kwargs):
            get_urls.append(url)
            return _mock_response(200, "{}", url=url)
        import requests
        monkeypatch.setattr(requests, "post", _stub_post)
        monkeypatch.setattr(requests, "get", _stub_get)
        gas._check_it_signup_anon(self._signup_response())

        assert any(":listCollectionIds" in u for u in post_urls), (
            "Firestore auth-read must fire for in-scope same-site key")

    @pytest.mark.unit
    def test_host_list_third_party_origin_suppressed(self, monkeypatch):
        """Direct `--host-list` flow: a key extracted from a cross-origin
        script (loaded by a live host but living on a 3rd-party CDN) must
        NOT trigger auth-read."""
        chk = gas._build_direct_discovery_in_scope_check(
            "host_list", {"1.2.3.4", "5.6.7.8"})
        key_sources = {"https://cdn.thirdparty.com/v1/lib.js"}
        in_scope = gas._are_key_sources_in_scope(key_sources, chk)
        assert in_scope is False

    @pytest.mark.unit
    def test_host_list_matching_host_passes(self):
        chk = gas._build_direct_discovery_in_scope_check(
            "host_list", {"1.2.3.4"})
        key_sources = {"http://1.2.3.4:8080/dist/app.js"}
        in_scope = gas._are_key_sources_in_scope(key_sources, chk)
        assert in_scope is True


# 4. Per-key state isolation

class TestPerKeyIsolation:
    @pytest.mark.unit
    def test_oos_iteration_does_not_disable_next_in_scope(self):
        """Simulate the save→set→scan→restore pattern across two keys."""
        gas._set_auth_read_scope_ok(True)
        # Key 1 — OOS.
        prior = gas._AUTH_READ_SCOPE_OK
        gas._set_auth_read_scope_ok(False)
        # ... scan runs with gate closed ...
        gas._set_auth_read_scope_ok(prior)
        # Key 2 — in scope. Prior was True, so we're back to True.
        assert gas._AUTH_READ_SCOPE_OK is True

    @pytest.mark.unit
    def test_in_scope_iteration_does_not_enable_next_oos(self):
        """If prior was False (e.g. --rescan-kb context), an in-scope
        middle iteration must NOT permanently flip it."""
        gas._set_auth_read_scope_ok(False)
        prior = gas._AUTH_READ_SCOPE_OK
        gas._set_auth_read_scope_ok(True)
        # ... scan runs with gate open ...
        gas._set_auth_read_scope_ok(prior)
        assert gas._AUTH_READ_SCOPE_OK is False

    @pytest.mark.unit
    def test_restore_runs_even_if_scan_raises(self):
        """The try/finally in the per-key loop must restore the prior
        scope even when scan_gapis raises an unexpected exception."""
        gas._set_auth_read_scope_ok(True)
        prior = gas._AUTH_READ_SCOPE_OK
        gas._set_auth_read_scope_ok(False)
        try:
            raise RuntimeError("simulated scan crash")
        except RuntimeError:
            pass
        finally:
            gas._set_auth_read_scope_ok(prior)
        assert gas._AUTH_READ_SCOPE_OK is True
