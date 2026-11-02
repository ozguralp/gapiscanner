"""Tests for auth read isolation."""
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
FAKE_TOKEN = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImYzNGI"  # ~JWT-looking, never real


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
    m.request.url = url or "https://identitytoolkit.googleapis.com/v1/x?key=" + SENTINEL_KEY
    return m


class TestScopeHelper:
    @pytest.mark.unit
    def test_mobile_source_label_is_in_scope(self):
        assert gas._is_source_in_scope_for_auth_read("mobile:ios:com.victim.app") is True
        assert gas._is_source_in_scope_for_auth_read("mobile:android:com.victim.app:AB:CD") is True

    @pytest.mark.unit
    def test_http_source_no_bundle_is_in_scope(self):
        # Direct --url / --scope flows pass bundle=None.
        assert gas._is_source_in_scope_for_auth_read(
            "https://www.victim.com/app.js") is True

    @pytest.mark.unit
    def test_http_source_matching_oos_regex_is_out_of_scope(self):
        class B:
            oos = [r"^.*\.cdn\.example\.com$"]
        assert gas._is_source_in_scope_for_auth_read(
            "https://target.cdn.example.com/lib.js", B()) is False

    @pytest.mark.unit
    def test_http_source_matching_third_party_saas_oos(self):
        # Zendesk / lever / statuspage style OOS that applications use.
        class B:
            oos = [r"^.*\.zendesk\.com$"]
        assert gas._is_source_in_scope_for_auth_read(
            "https://target.zendesk.com/x.js", B()) is False

    @pytest.mark.unit
    def test_http_source_passing_bundle_oos_is_in_scope(self):
        class B:
            oos = [r"^.*\.cdn\.example\.com$"]
        assert gas._is_source_in_scope_for_auth_read(
            "https://www.victim.com/app.js", B()) is True

    @pytest.mark.unit
    def test_unknown_label_is_out_of_scope(self):
        # Defensive: anything that isn't mobile:* or http(s):// is OOS.
        assert gas._is_source_in_scope_for_auth_read("rescan-kb") is False
        assert gas._is_source_in_scope_for_auth_read("") is False
        assert gas._is_source_in_scope_for_auth_read(None) is False

    @pytest.mark.unit
    def test_invalid_regex_falls_back_to_substring(self):
        class B:
            oos = ["[invalid(regex"]
        # Substring match — won't trigger.
        assert gas._is_source_in_scope_for_auth_read(
            "https://www.victim.com/", B()) is True
        # Substring match — WILL trigger.
        class C:
            oos = ["[invalid(regex"]
        assert gas._is_source_in_scope_for_auth_read(
            "https://[invalid(regex.victim.com/", C()) is False


class TestOutOfScopeSuppressesAuthRead:
    """Drives a signUp-success response through `_check_it_signup_anon` AND
    asserts the auth-read chain's HTTP calls are NEVER issued when the
    scope gate is closed. Uses requests-level mocks so any leak would
    register as an HTTP call we can count."""

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
    def test_scope_closed_skips_all_auth_read_calls(self, monkeypatch):
        """Master gate ON, scope gate CLOSED → no listCollectionIds /
        no RTDB shallow / no Storage list HTTP."""
        gas._set_auth_read_enabled(True)
        gas._set_auth_read_scope_ok(False)
        gas._DERIVED_PROJECT_IDS.add("victim")
        # Pre-populate a config with bucket + DB URL so we'd otherwise probe them.
        gas._record_firebase_config(gas._firebase_config(
            project_id="victim",
            database_url="https://victim-default-rtdb.firebaseio.com",
            storage_bucket="victim.appspot.com",
            source="x.plist"))

        called_urls = []
        def _stub_post(url, **kwargs):
            called_urls.append(("POST", url))
            return _mock_response(200, "{}", url=url)
        def _stub_get(url, **kwargs):
            called_urls.append(("GET", url))
            return _mock_response(200, "{}", url=url)
        import requests
        monkeypatch.setattr(requests, "post", _stub_post)
        monkeypatch.setattr(requests, "get",  _stub_get)

        gas._check_it_signup_anon(self._signup_response())

        # The mandatory `accounts:delete` cleanup MUST still fire.
        assert any(":delete" in u for _, u in called_urls), (
            "cleanup DELETE must fire even when auth-read is gated off")
        # Every auth-read endpoint must be ABSENT.
        for method, u in called_urls:
            assert ":listCollectionIds" not in u, (
                f"Firestore auth-read fired with scope gate closed: {u}")
            assert "shallow=true" not in u, (
                f"RTDB auth-read fired with scope gate closed: {u}")

        with gas._AUTH_READ_LOCK:
            assert gas._AUTH_READ_FINDINGS == [], (
                f"findings leaked: {gas._AUTH_READ_FINDINGS}")

    @pytest.mark.unit
    def test_scope_open_runs_auth_read(self, monkeypatch):
        """Master gate ON, scope gate OPEN → chain runs as designed."""
        gas._set_auth_read_enabled(True)
        gas._set_auth_read_scope_ok(True)
        gas._DERIVED_PROJECT_IDS.add("victim")
        gas._record_firebase_config(gas._firebase_config(
            project_id="victim",
            database_url="https://victim-default-rtdb.firebaseio.com",
            source="x.plist"))

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
        monkeypatch.setattr(requests, "get",  _stub_get)
        gas._check_it_signup_anon(self._signup_response())

        # listCollectionIds DID fire.
        assert any(":listCollectionIds" in u for u in post_urls)
        # RTDB shallow DID fire.
        assert any("shallow=true" in u for u in get_urls)


class TestPerKeyScopeIsolation:
    @pytest.mark.unit
    def test_oos_key_does_not_disable_next_in_scope_key(self, monkeypatch):
        """Simulate the discovery loop pattern: save→set→scan→restore.
        After a closed-gate iteration, the prior state is restored so the
        next key's iteration starts with the same scope status it began."""
        gas._set_auth_read_scope_ok(True)

        # Iteration 1 — OOS key (gate temporarily closes).
        prior = gas._AUTH_READ_SCOPE_OK
        gas._set_auth_read_scope_ok(False)
        # ... scan_gapis would run here with gate closed ...
        gas._set_auth_read_scope_ok(prior)

        # Iteration 2 — in-scope key. Gate must be back to True.
        assert gas._AUTH_READ_SCOPE_OK is True

    @pytest.mark.unit
    def test_in_scope_key_does_not_enable_next_oos_key(self, monkeypatch):
        """If the prior state was False (e.g. --rescan-kb context), an
        in-scope iteration in the middle must NOT permanently flip it."""
        gas._set_auth_read_scope_ok(False)

        prior = gas._AUTH_READ_SCOPE_OK
        gas._set_auth_read_scope_ok(True)
        # ... scan runs with gate open for one in-scope key ...
        gas._set_auth_read_scope_ok(prior)

        # Next iteration sees False (restored).
        assert gas._AUTH_READ_SCOPE_OK is False


class TestRTDBTokenRedaction:
    """For each RTDB response branch, assert:
      * the LIVE request URL contained the raw token (auth still works)
      * the RETURNED result dict has `auth=<redacted>` in `url`
      * no string field in the result contains the raw token
    """

    def _capture_request(self, monkeypatch, body, status=200):
        seen_urls = []
        def _stub_get(url, **kwargs):
            seen_urls.append(url)
            return _mock_response(status, body, url=url)
        import requests
        monkeypatch.setattr(requests, "get", _stub_get)
        return seen_urls

    def _assert_no_token_leak(self, result):
        for k, v in result.items():
            if isinstance(v, str):
                assert FAKE_TOKEN not in v, (
                    f"RTDB result leaked raw token in field {k!r}: {v!r}")
        assert "<redacted>" in result["url"]
        assert FAKE_TOKEN not in result["url"]

    @pytest.mark.unit
    def test_denied_branch_does_not_leak(self, monkeypatch):
        seen = self._capture_request(monkeypatch, "Permission denied", status=401)
        result = gas._authenticated_rtdb_read(
            "https://victim-default-rtdb.firebaseio.com", FAKE_TOKEN)
        assert result is not None
        # Live request URL DID carry the token.
        assert any(FAKE_TOKEN in u for u in seen), (
            "auth-read must send the real token in the live request")
        self._assert_no_token_leak(result)
        assert result["severity"] == "INFO"
        assert result["error_class"] == "PERMISSION_DENIED"

    @pytest.mark.unit
    def test_empty_branch_does_not_leak(self, monkeypatch):
        seen = self._capture_request(monkeypatch, "null", status=200)
        result = gas._authenticated_rtdb_read(
            "https://victim-default-rtdb.firebaseio.com", FAKE_TOKEN)
        assert result is not None
        assert any(FAKE_TOKEN in u for u in seen)
        self._assert_no_token_leak(result)
        assert result["severity"] == "INFO"

    @pytest.mark.unit
    def test_non_empty_branch_does_not_leak(self, monkeypatch):
        seen = self._capture_request(
            monkeypatch, '{"users":true,"orders":true}', status=200)
        result = gas._authenticated_rtdb_read(
            "https://victim-default-rtdb.firebaseio.com", FAKE_TOKEN)
        assert result is not None
        assert any(FAKE_TOKEN in u for u in seen)
        self._assert_no_token_leak(result)
        assert result["severity"] == "HIGH"
        assert "auth_read_rtdb_keys=2" in result["manual_note"]

    @pytest.mark.unit
    def test_non_json_body_does_not_leak(self, monkeypatch):
        self._capture_request(monkeypatch, "not json at all", status=200)
        gas._reset_transport_errors()
        result = gas._authenticated_rtdb_read(
            "https://victim-default-rtdb.firebaseio.com", FAKE_TOKEN)
        assert result is None
        assert gas._transport_error_total() == 1

    @pytest.mark.unit
    def test_server_echoes_token_in_reason_gets_scrubbed(self, monkeypatch):
        """Defense-in-depth — if Google's error body ever echoes the token
        back (extremely unlikely but possible with debug responses), the
        scrub MUST replace it."""
        body = (
            'Permission denied for token ' + FAKE_TOKEN + ' on /users')
        self._capture_request(monkeypatch, body, status=401)
        result = gas._authenticated_rtdb_read(
            "https://victim-default-rtdb.firebaseio.com", FAKE_TOKEN)
        assert result is not None
        self._assert_no_token_leak(result)
        # The scrubbed version should still surface "Permission denied".
        assert "Permission denied" in result["reason"]
        # Token in the reason is replaced.
        assert "<redacted>" in result["reason"]


class TestScrubTokenHelper:
    @pytest.mark.unit
    def test_scrub_replaces_token_in_every_string_field(self):
        finding = {
            "name": "auth-read",
            "url":  "https://x?auth=" + FAKE_TOKEN,
            "reason": "rejected token " + FAKE_TOKEN,
            "manual_note": FAKE_TOKEN + " was rejected",
            "snippet": None,
            "status_code": 200,
            "vulnerable": True,
        }
        scrubbed = gas._scrub_token_from_finding(finding, FAKE_TOKEN)
        # Non-string fields untouched.
        assert scrubbed["status_code"] == 200
        assert scrubbed["vulnerable"] is True
        # String fields scrubbed.
        assert FAKE_TOKEN not in scrubbed["url"]
        assert FAKE_TOKEN not in scrubbed["reason"]
        assert FAKE_TOKEN not in scrubbed["manual_note"]
        # None-valued fields stay None.
        assert scrubbed["snippet"] is None

    @pytest.mark.unit
    def test_scrub_is_noop_when_token_falsy(self):
        finding = {"url": "https://x?auth=ABC"}
        assert gas._scrub_token_from_finding(finding, "") == {"url": "https://x?auth=ABC"}
        assert gas._scrub_token_from_finding(finding, None) == {"url": "https://x?auth=ABC"}

    @pytest.mark.unit
    def test_chain_runner_scrubs_findings(self, monkeypatch):
        """End-to-end: the chain runner applies the scrub even when an
        individual reader fails to (e.g. a future regression)."""
        gas._set_auth_read_enabled(True)
        gas._set_auth_read_scope_ok(True)
        gas._DERIVED_PROJECT_IDS.add("victim")

        # Stub a reader that ACCIDENTALLY leaks the token.
        def _leaky_firestore_read(project_id, apikey, id_token):
            return {
                "name": "leaky firestore",
                "category": "destructive",
                "url": "https://leak?token=" + id_token,
                "impact": "leak",
                "vulnerable": True,
                "manual_note": None, "referer_blocked": False,
                "error_class": None, "services_seen": set(),
                "reason": "echoed " + id_token,
                "gemini_disabled": False, "status_code": 200, "snippet": None,
                "tier": "CONFIRMED", "impact_type": "data_read",
                "confirmation": "confirmed_data",
                "data_sensitivity": "customer_data", "severity": "HIGH",
            }
        monkeypatch.setattr(gas, "_authenticated_firestore_read", _leaky_firestore_read)
        # Stub the others to return None so they don't add noise.
        monkeypatch.setattr(gas, "_authenticated_rtdb_read",
                            lambda *a, **kw: None)
        monkeypatch.setattr(gas, "_authenticated_storage_list",
                            lambda *a, **kw: None)
        findings = gas._run_authenticated_read_chain(SENTINEL_KEY, FAKE_TOKEN)
        assert findings, "leaky reader should still have produced a finding"
        for f in findings:
            for k, v in f.items():
                if isinstance(v, str):
                    assert FAKE_TOKEN not in v, (
                        f"chain runner failed to scrub token from {k!r}: {v!r}")


class TestTokenAbsentFromOutputs:
    @pytest.mark.unit
    def test_token_absent_from_AUTH_READ_FINDINGS(self, monkeypatch):
        """End-to-end: drive the RTDB reader into _AUTH_READ_FINDINGS and
        verify the appended finding has no token anywhere."""
        gas._set_auth_read_enabled(True)
        gas._set_auth_read_scope_ok(True)
        gas._record_firebase_config(gas._firebase_config(
            project_id="victim",
            database_url="https://victim-default-rtdb.firebaseio.com",
            source="x.plist"))

        def _stub_get(url, **kwargs):
            return _mock_response(200, '{"users":true}', url=url)
        # Suppress the other auth-read readers so the test focuses on RTDB.
        monkeypatch.setattr(gas, "_authenticated_firestore_read",
                            lambda *a, **kw: None)
        monkeypatch.setattr(gas, "_authenticated_storage_list",
                            lambda *a, **kw: None)
        import requests
        monkeypatch.setattr(requests, "get", _stub_get)
        gas._run_authenticated_read_chain(SENTINEL_KEY, FAKE_TOKEN)
        with gas._AUTH_READ_LOCK:
            findings = list(gas._AUTH_READ_FINDINGS)
        assert findings, "RTDB finding should have been recorded"
        for f in findings:
            for k, v in f.items():
                if isinstance(v, str):
                    assert FAKE_TOKEN not in v, (
                        f"token in _AUTH_READ_FINDINGS field {k!r}: {v!r}")

    @pytest.mark.unit
    def test_token_absent_from_json_output(self, monkeypatch):
        """The _build_json_output JSON shape must not carry the token in
        any field. Drive a finding into the results list and verify."""
        # Construct a synthetic auth-read result with the sanitized URL
        # (what the reader actually emits).
        results = [{
            "name": "signUp + authenticated RTDB shallow read",
            "category": "destructive",
            "url": "https://victim-default-rtdb.firebaseio.com/.json?shallow=true&auth=<redacted>",
            "impact": "RTDB authenticated read confirmed — 2 top-level key(s)",
            "vulnerable": True,
            "manual_note": "auth_read_rtdb_keys=2",
            "referer_blocked": False, "error_class": None,
            "services_seen": set(),
            "reason": "", "gemini_disabled": False,
            "status_code": 200, "snippet": None,
            "tier": "CONFIRMED",
            "impact_type": "data_read", "confirmation": "confirmed_data",
            "data_sensitivity": "customer_data", "severity": "HIGH",
        }]
        out = gas._build_json_output(results, tested_count=1, options={})
        text = json.dumps(out)
        assert FAKE_TOKEN not in text, (
            f"raw token leaked into JSON output: {text}")
        # And the sanitized URL IS present.
        assert "<redacted>" in text


class TestPriorInvariantsPreserved:
    @pytest.mark.unit
    def test_chain_still_short_circuits_when_master_gate_off(self, monkeypatch):
        gas._set_auth_read_enabled(False)
        gas._set_auth_read_scope_ok(True)
        called = [False]
        def _stub(*a, **kw):
            called[0] = True
            return _mock_response(200, "{}")
        import requests
        monkeypatch.setattr(requests, "get",  _stub)
        monkeypatch.setattr(requests, "post", _stub)
        out = gas._run_authenticated_read_chain(SENTINEL_KEY, FAKE_TOKEN)
        assert out == []
        assert called[0] is False
