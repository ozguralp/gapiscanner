"""Tests for authenticated reads."""
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


@pytest.fixture(autouse=True)
def _reset_auth_read_state():
    gas._set_auth_read_enabled(False)
    gas._set_auth_read_scope_ok(True)
    with gas._AUTH_READ_LOCK:
        gas._AUTH_READ_FINDINGS.clear()
    with gas._IDENTITY_TOOLKIT_LOCK:
        gas._IDENTITY_TOOLKIT_ARTIFACTS.clear()
    with gas._DERIVED_LOCK:
        gas._DERIVED_PROJECT_IDS.clear()
        gas._DERIVED_PROJECT_NUMBERS.clear()

        gas._DERIVED_PROJECT_IDS.add("test-derived-proj")
    with gas._DERIVED_FIREBASE_LOCK:
        gas._DERIVED_FIREBASE_CONFIGS.clear()
    yield
    # Same on the way out so other test files start clean.
    gas._set_auth_read_enabled(False)
    gas._set_auth_read_scope_ok(True)
    gas._DERIVED_PROJECT_IDS.discard("test-derived-proj")
    with gas._AUTH_READ_LOCK:
        gas._AUTH_READ_FINDINGS.clear()


# 1. Sign-in probes are DIAGNOSTIC ONLY

DIAGNOSTIC_PROBE_NAMES = (
    "Identity Toolkit signInWithCustomToken (diagnostic)",
    "Identity Toolkit signInWithIdp (diagnostic)",
    "Identity Toolkit signInWithEmailLink (diagnostic)",
    "Identity Toolkit signInWithPassword (diagnostic)",
    "Identity Toolkit v3 getAccountInfo (diagnostic)",
)


def _find_probe(name):
    for p in list(gas.ALL_PROBES) + list(gas.FIREBASE_CHAIN_PROBES):
        if p[0] == name:
            return p
    return None


class TestDiagnosticReclassification:
    @pytest.mark.unit
    def test_old_names_are_gone(self):
        for old in ("Identity Toolkit signInWithCustomToken (key acceptance)",
                    "Identity Toolkit signInWithIdp (key acceptance)",
                    "Identity Toolkit signInWithEmailLink (key acceptance)",
                    "Identity Toolkit signInWithPassword (enum)",
                    "Identity Toolkit v3 getAccountInfo (key acceptance)"):
            assert _find_probe(old) is None, (
                f"Obsolete probe name {old!r} should be gone")

    @pytest.mark.unit
    def test_diagnostic_probes_removed(self):

        for name in DIAGNOSTIC_PROBE_NAMES:
            assert _find_probe(name) is None, (
                f"{name!r} should have been removed")

    @pytest.mark.unit
    def test_none_in_potential_probes(self):
        for name in DIAGNOSTIC_PROBE_NAMES:
            assert name not in gas.POTENTIAL_PROBES, (
                f"{name} must not be in POTENTIAL_PROBES")

    @pytest.mark.unit
    def test_none_in_probe_impact_defaults(self):
        for name in DIAGNOSTIC_PROBE_NAMES:
            assert name not in gas._PROBE_IMPACT_DEFAULTS, (
                f"{name} should have no _PROBE_IMPACT_DEFAULTS entry")

    @pytest.mark.unit
    def test_impact_text_no_longer_claims_exploit(self):
        # No diagnostic probes remain to check; the affirmative-exploit
        # phrases below must not appear on ANY surviving probe's impact text.
        forbidden_phrases = (
            "federated takeover possible",
            "idp token replay possible",
            "account-info disclosure if idtoken",
            "email_not_found vs invalid_password",
            "enumeration possible",
            "real branded phishing",
        )
        for p in gas.ALL_PROBES:
            name = p[0]
            impact_lower = (p[6] or "").lower()
            for ph in forbidden_phrases:
                assert ph.lower() not in impact_lower, (
                    f"{name}: impact text still claims {ph!r}: {p[6]!r}")


# 2. _check_it_diagnostic_only behavior

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


class TestDiagnosticOnlyCheckFn:
    @pytest.mark.unit
    def test_returns_false_on_200_with_kind(self):
        r = _mock_response(200, '{"kind":"identitytoolkit#X"}')
        out = gas._check_it_diagnostic_only(r)
        assert out == (False, "diagnostic_key_accepted")

    @pytest.mark.unit
    def test_returns_false_on_400_invalid_token(self):
        r = _mock_response(400, '{"error":{"message":"INVALID_CUSTOM_TOKEN"}}')
        out = gas._check_it_diagnostic_only(r)
        assert out == (False, "diagnostic_key_accepted")

    @pytest.mark.unit
    def test_returns_false_none_on_api_key_invalid(self):
        r = _mock_response(400, '{"error":{"message":"API_KEY_INVALID"}}')
        vulnerable, note = gas._check_it_diagnostic_only(r)
        assert vulnerable is False
        assert note != "diagnostic_key_accepted"

    @pytest.mark.unit
    def test_returns_false_none_on_403(self):
        r = _mock_response(403, '{"error":"PERMISSION_DENIED"}')
        vulnerable, _ = gas._check_it_diagnostic_only(r)
        assert vulnerable is False


# 3. Gating: chain is OFF by default + scope gate

class TestAuthReadGating:
    @pytest.mark.unit
    def test_disabled_by_default(self):
        assert gas._AUTH_READ_ENABLED is False

    @pytest.mark.unit
    def test_chain_returns_empty_when_disabled(self, monkeypatch):
        called = [False]
        def _stub(*a, **kw): called[0] = True; return _mock_response(200, "{}")
        import requests
        monkeypatch.setattr(requests, "get",  _stub)
        monkeypatch.setattr(requests, "post", _stub)
        gas._DERIVED_PROJECT_IDS.add("victim")
        out = gas._run_authenticated_read_chain(SENTINEL_KEY, "fake_token")
        assert out == []
        assert called[0] is False, "chain must not issue HTTP when disabled"

    @pytest.mark.unit
    def test_chain_short_circuits_when_scope_denied(self, monkeypatch):
        gas._set_auth_read_enabled(True)
        gas._set_auth_read_scope_ok(False)
        called = [False]
        def _stub(*a, **kw): called[0] = True; return _mock_response(200, "{}")
        import requests
        monkeypatch.setattr(requests, "get",  _stub)
        monkeypatch.setattr(requests, "post", _stub)
        gas._DERIVED_PROJECT_IDS.add("victim")
        out = gas._run_authenticated_read_chain(SENTINEL_KEY, "fake_token")
        assert out == []
        assert called[0] is False, (
            "scope-denied chain must not issue any HTTP request")


# 4. _authenticated_firestore_read

class TestAuthenticatedFirestoreRead:
    @pytest.mark.unit
    def test_url_is_listCollectionIds(self, monkeypatch):
        seen = {}
        def _stub_post(url, **kwargs):
            seen["url"] = url
            seen["headers"] = kwargs.get("headers") or {}
            return _mock_response(200, '{"collectionIds":["users","orders"]}',
                                  url=url)
        import requests
        monkeypatch.setattr(requests, "post", _stub_post)
        gas._authenticated_firestore_read("victim-app", SENTINEL_KEY, "tok123")
        assert ":listCollectionIds" in seen["url"], (
            "Firestore auth-read must use :listCollectionIds (collection NAMES "
            "only, never document field values)")
        assert seen["headers"].get("Authorization") == "Bearer tok123"

    @pytest.mark.unit
    def test_records_collection_count_not_contents(self, monkeypatch):
        def _stub_post(url, **kwargs):
            return _mock_response(200, '{"collectionIds":["users","orders","secrets"]}',
                                  url=url)
        import requests
        monkeypatch.setattr(requests, "post", _stub_post)
        res = gas._authenticated_firestore_read("victim", SENTINEL_KEY, "tok")
        assert res is not None
        assert res["severity"] == "HIGH"
        assert res["impact_type"] == "data_read"
        assert res["confirmation"] == "confirmed_data"
        assert res["data_sensitivity"] == "customer_data"
        # The note records COUNT, not values.
        assert "auth_read_collections=3" in res["manual_note"]
        # The impact text MUST disclaim that values were read.
        assert "NOT read" in res["impact"]

    @pytest.mark.unit
    def test_empty_collections_is_INFO_no_data(self, monkeypatch):
        def _stub_post(url, **kwargs):
            return _mock_response(200, '{}', url=url)
        import requests
        monkeypatch.setattr(requests, "post", _stub_post)
        res = gas._authenticated_firestore_read("victim", SENTINEL_KEY, "tok")
        assert res is not None
        assert res["severity"] == "INFO"
        assert res["data_sensitivity"] == "none"

    @pytest.mark.unit
    @pytest.mark.parametrize("status, body", [
        (400, '{"error":{"status":"FAILED_PRECONDITION"}}'),
        (404, '{"error":{"status":"NOT_FOUND"}}'),
    ])
    def test_non_200_firestore_error_is_not_empty_read(
            self, monkeypatch, status, body):
        def _stub_post(url, **kwargs):
            return _mock_response(status, body, url=url)
        import requests
        monkeypatch.setattr(requests, "post", _stub_post)
        res = gas._authenticated_firestore_read("victim", SENTINEL_KEY, "tok")
        assert res is None

    @pytest.mark.unit
    def test_403_denies_returns_INFO_not_vulnerable(self, monkeypatch):
        def _stub_post(url, **kwargs):
            return _mock_response(403, '{"error":"PERMISSION_DENIED"}', url=url)
        import requests
        monkeypatch.setattr(requests, "post", _stub_post)
        res = gas._authenticated_firestore_read("victim", SENTINEL_KEY, "tok")
        assert res is not None
        assert res["vulnerable"] is False
        assert res["severity"] == "INFO"
        assert res["error_class"] == "PERMISSION_DENIED"


# 5. _authenticated_rtdb_read

class TestAuthenticatedRTDBRead:
    @pytest.mark.unit
    def test_url_uses_shallow_and_auth(self, monkeypatch):
        seen = {}
        def _stub_get(url, **kwargs):
            seen["url"] = url
            return _mock_response(200, '{"users":true,"orders":true}', url=url)
        import requests
        monkeypatch.setattr(requests, "get", _stub_get)
        gas._authenticated_rtdb_read(
            "https://victim-default-rtdb.firebaseio.com", "tok456")
        assert "shallow=true" in seen["url"]
        assert "auth=tok456" in seen["url"]
        # MUST NOT request the full DB.
        assert "shallow=false" not in seen["url"]

    @pytest.mark.unit
    def test_non_empty_shallow_is_HIGH(self, monkeypatch):
        def _stub_get(url, **kwargs):
            return _mock_response(200, '{"users":true,"orders":true}', url=url)
        import requests
        monkeypatch.setattr(requests, "get", _stub_get)
        res = gas._authenticated_rtdb_read(
            "https://victim-default-rtdb.firebaseio.com", "tok")
        assert res["severity"] == "HIGH"
        assert "auth_read_rtdb_keys=2" in res["manual_note"]
        assert "values not retrieved" in res["impact"]

    @pytest.mark.unit
    def test_empty_rtdb_is_INFO(self, monkeypatch):
        def _stub_get(url, **kwargs):
            return _mock_response(200, 'null', url=url)
        import requests
        monkeypatch.setattr(requests, "get", _stub_get)
        res = gas._authenticated_rtdb_read(
            "https://victim-default-rtdb.firebaseio.com", "tok")
        assert res["severity"] == "INFO"
        assert res["data_sensitivity"] == "none"

    @pytest.mark.unit
    def test_permission_denied_is_INFO_not_vulnerable(self, monkeypatch):
        def _stub_get(url, **kwargs):
            return _mock_response(401, 'Permission denied', url=url)
        import requests
        monkeypatch.setattr(requests, "get", _stub_get)
        res = gas._authenticated_rtdb_read(
            "https://victim-default-rtdb.firebaseio.com", "tok")
        assert res["vulnerable"] is False
        assert res["severity"] == "INFO"


# 6. _authenticated_storage_list — list only, no downloads

class TestAuthenticatedStorageList:
    @pytest.mark.unit
    def test_list_only_no_object_download(self, monkeypatch):
        get_calls = []
        def _stub_get(url, **kwargs):
            get_calls.append(url)
            return _mock_response(200, '{"items":[{"name":"a.bin"},{"name":"b.bin"}]}',
                                  url=url)
        import requests
        monkeypatch.setattr(requests, "get", _stub_get)
        res = gas._authenticated_storage_list(
            "victim.appspot.com", SENTINEL_KEY, "tok")

        assert len(get_calls) == 1
        # The list URL ends in /o (Firebase Storage list), NOT /o/<name>?alt=media.
        assert "/o?" in get_calls[0]
        assert "alt=media" not in get_calls[0]
        assert res["severity"] == "HIGH"
        assert "object bytes NOT downloaded" in res["impact"]

    @pytest.mark.unit
    def test_empty_bucket_is_INFO(self, monkeypatch):
        def _stub_get(url, **kwargs):
            return _mock_response(200, '{}', url=url)
        import requests
        monkeypatch.setattr(requests, "get", _stub_get)
        res = gas._authenticated_storage_list("victim.appspot.com", SENTINEL_KEY, "tok")
        assert res["severity"] == "INFO"
        assert res["data_sensitivity"] == "none"


# 7. signUp → auth-read → cleanup

class TestSignUpAuthReadCleanup:
    def _signup_success_response(self):
        body = '{"idToken":"signup_token_x","localId":"local_x","kind":"identitytoolkit#SignupNewUserResponse"}'
        m = _mock_response(200, body)
        # The check fn parses key out of request.url
        m.request.url = ("https://identitytoolkit.googleapis.com/v1/accounts:signUp?key="
                         + SENTINEL_KEY)
        return m

    @pytest.mark.unit
    def test_signup_invokes_auth_read_chain_when_enabled(self, monkeypatch):
        """When --include-auth-read is on and scope is OK, the chain fires
        and findings end up in _AUTH_READ_FINDINGS."""
        gas._set_auth_read_enabled(True)
        gas._set_auth_read_scope_ok(True)
        gas._DERIVED_PROJECT_IDS.add("victim")

        post_calls = []
        def _stub_post(url, **kwargs):
            post_calls.append(url)
            if ":listCollectionIds" in url:
                return _mock_response(
                    200, '{"collectionIds":["users","orders"]}', url=url)
            if ":delete" in url:
                # cleanup ok
                return _mock_response(200, "{}", url=url)
            return _mock_response(200, "{}", url=url)
        def _stub_get(url, **kwargs):
            post_calls.append(url)
            return _mock_response(200, '{}', url=url)
        import requests
        monkeypatch.setattr(requests, "post", _stub_post)
        monkeypatch.setattr(requests, "get",  _stub_get)

        out = gas._check_it_signup_anon(self._signup_success_response())
        assert out == (True, None), f"signUp probe should succeed cleanly; got {out}"
        # Auth-read findings recorded.
        with gas._AUTH_READ_LOCK:
            findings = list(gas._AUTH_READ_FINDINGS)
        assert any(f["name"].startswith("signUp + authenticated Firestore read")
                   for f in findings), (
            f"Firestore auth-read finding missing: {findings}")
        # listCollectionIds URL was actually requested.
        assert any(":listCollectionIds" in u for u in post_calls)
        # Cleanup DELETE was also called (must come AFTER auth-read).
        assert any(":delete" in u for u in post_calls)

    @pytest.mark.unit
    def test_signup_skips_auth_read_when_disabled(self, monkeypatch):
        """Default off — no listCollectionIds / RTDB / Storage requests."""
        gas._set_auth_read_enabled(False)
        gas._DERIVED_PROJECT_IDS.add("victim")
        post_urls = []
        def _stub_post(url, **kwargs):
            post_urls.append(url)
            return _mock_response(200, "{}", url=url)
        import requests
        monkeypatch.setattr(requests, "post", _stub_post)
        monkeypatch.setattr(requests, "get",  lambda *a, **kw: _mock_response(200, "{}"))
        gas._check_it_signup_anon(self._signup_success_response())
        # No auth-read URLs hit.
        assert not any(":listCollectionIds" in u for u in post_urls), (
            "auth-read fired even though _AUTH_READ_ENABLED is False")
        # But the cleanup DELETE still ran.
        assert any(":delete" in u for u in post_urls), (
            "mandatory cleanup must always fire")
        # And no findings recorded.
        with gas._AUTH_READ_LOCK:
            assert gas._AUTH_READ_FINDINGS == []

    @pytest.mark.unit
    def test_signup_skips_auth_read_when_scope_denied(self, monkeypatch):
        """Discovery flow may set scope=False; auth-read must not run."""
        gas._set_auth_read_enabled(True)
        gas._set_auth_read_scope_ok(False)
        gas._DERIVED_PROJECT_IDS.add("victim")
        post_urls = []
        def _stub_post(url, **kwargs):
            post_urls.append(url)
            return _mock_response(200, "{}", url=url)
        import requests
        monkeypatch.setattr(requests, "post", _stub_post)
        monkeypatch.setattr(requests, "get",  lambda *a, **kw: _mock_response(200, "{}"))
        gas._check_it_signup_anon(self._signup_success_response())
        assert not any(":listCollectionIds" in u for u in post_urls)
        assert any(":delete" in u for u in post_urls)

    @pytest.mark.unit
    def test_cleanup_runs_even_if_auth_read_raises(self, monkeypatch):
        """If the auth-read chain raises, the mandatory DELETE cleanup must
        still execute. No token is left behind."""
        gas._set_auth_read_enabled(True)
        gas._set_auth_read_scope_ok(True)
        gas._DERIVED_PROJECT_IDS.add("victim")

        def _exploding_chain(*a, **kw):
            raise RuntimeError("simulated auth-read crash")
        monkeypatch.setattr(gas, "_run_authenticated_read_chain",
                            _exploding_chain)
        delete_called = [False]
        def _stub_post(url, **kwargs):
            if ":delete" in url:
                delete_called[0] = True
            return _mock_response(200, "{}", url=url)
        import requests
        monkeypatch.setattr(requests, "post", _stub_post)
        out = gas._check_it_signup_anon(self._signup_success_response())
        assert out == (True, None), (
            "signUp must still report vulnerable=True (account was created); "
            f"got {out}")
        assert delete_called[0] is True, (
            "cleanup DELETE must fire even when auth-read crashed")

    @pytest.mark.unit
    def test_idtoken_never_appears_in_findings(self, monkeypatch):
        """ROE — the auth-read findings must NOT carry the raw idToken in
        any field that a user might paste into a report."""
        gas._set_auth_read_enabled(True)
        gas._set_auth_read_scope_ok(True)
        gas._DERIVED_PROJECT_IDS.add("victim")
        def _stub_post(url, **kwargs):
            if ":listCollectionIds" in url:
                return _mock_response(200, '{"collectionIds":["x"]}', url=url)
            if ":delete" in url:
                return _mock_response(200, "{}", url=url)
            return _mock_response(200, "{}", url=url)
        import requests
        monkeypatch.setattr(requests, "post", _stub_post)
        monkeypatch.setattr(requests, "get",  lambda *a, **kw: _mock_response(200, "{}"))
        gas._check_it_signup_anon(self._signup_success_response())
        with gas._AUTH_READ_LOCK:
            findings = list(gas._AUTH_READ_FINDINGS)
        for f in findings:
            for k, v in f.items():
                if not isinstance(v, str):
                    continue
                assert "signup_token_x" not in v, (
                    f"raw idToken leaked in finding[{k!r}]: {v!r}")


# 8. scan_gapis end-to-end: diagnostic probes don't fire as findings

class TestScanGapisEndToEnd:
    @pytest.mark.unit
    def test_valid_key_no_finding_from_diagnostic_signin_probes(self, monkeypatch):
        def _stub(*args, **kwargs):
            url = args[0] if args else kwargs.get("url", "")
            # Sign-in endpoints return INVALID_X_TOKEN (key accepted, body wrong)
            if "signInWith" in url or "getAccountInfo" in url:
                return _mock_response(
                    400, '{"error":{"message":"INVALID_CUSTOM_TOKEN"}}', url=url)
            # Everything else returns API_KEY_INVALID (default rejection).
            return _mock_response(
                400, '{"error":{"details":[{"reason":"API_KEY_INVALID"}]}}',
                url=url)
        import requests
        for fn in ("get", "post", "put", "delete"):
            monkeypatch.setattr(requests, fn, _stub)
        confirmed = gas.scan_gapis(SENTINEL_KEY, quiet=True, skip_jsapi=True,
                                    threads=4)
        # No sign-in diagnostic probe should appear in confirmed.
        for name in DIAGNOSTIC_PROBE_NAMES:
            assert name not in confirmed, (
                f"diagnostic-only probe leaked into CONFIRMED: {name}")
        # And ZERO confirmed overall (sentinel-style regression).
        assert confirmed == []


class TestSentinelRegressionPreserved:
    @pytest.mark.unit
    def test_sentinel_still_zero_confirmed(self, monkeypatch):
        def _garbage(*args, **kwargs):
            return _mock_response(
                400, '{"error":{"code":400,"status":"INVALID_ARGUMENT",'
                     '"details":[{"reason":"API_KEY_INVALID"}]}}',
                url=(args[0] if args else ""))
        import requests
        for fn in ("get", "post", "put", "delete"):
            monkeypatch.setattr(requests, fn, _garbage)
        confirmed = gas.scan_gapis(SENTINEL_KEY, quiet=True, skip_jsapi=True,
                                    threads=4)
        assert confirmed == []
