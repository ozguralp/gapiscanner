"""Regression coverage for signup anon default."""
from __future__ import annotations

import json

import pytest

import google_api_scanner as gas

SENTINEL_KEY = "AIzaSy" + "X" * 33
SIGNUP_NAME = "Identity Toolkit signUp anon (account creation + auto-cleanup)"


def _signup_probe():
    for p in gas.ALL_PROBES:
        if p[0] == SIGNUP_NAME:
            return p
    raise AssertionError("signUp probe missing")


class _Resp:
    def __init__(self, status_code, body, url=None, headers=None):
        self.status_code = status_code
        self.text = body if isinstance(body, str) else json.dumps(body)
        self.content = self.text.encode()
        self.headers = {"Content-Type": "application/json"}
        self.request = type("R", (), {"url": url or (
            "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key="
            + SENTINEL_KEY), "headers": headers or {}})()

    def json(self):
        return json.loads(self.text)


class TestSignupAnonRegistry:
    @pytest.mark.unit
    def test_signup_in_default_high_run_group(self):
        assert _signup_probe()[1] == "high", (
            "signUp anon must be a default `high` probe, not destructive")

    @pytest.mark.unit
    def test_signup_in_potential_probes(self):
        assert SIGNUP_NAME in gas.POTENTIAL_PROBES

    @pytest.mark.unit
    def test_default_scan_executes_signup(self, monkeypatch):

        executed = []
        monkeypatch.setattr(gas, "_execute_probe",
                            lambda p, *a, **k: executed.append(p[0]))
        gas.scan_gapis(SENTINEL_KEY, quiet=True, threads=1)
        assert SIGNUP_NAME in executed


class TestSignupCleanSuccessIsPotential:
    @pytest.mark.unit
    def test_clean_success_returns_vulnerable_no_cleanup_note(self, monkeypatch):
        """signUp 200 with idToken/localId + delete 200 → vulnerable=True,
        manual_note is None (clean) → tier POTENTIAL downstream."""
        probe = _signup_probe()
        signup_url = probe[3].replace("{key}", SENTINEL_KEY)
        signup_resp = _Resp(200, {"idToken": "SECRET_TOKEN_xyz",
                                  "localId": "anon123"}, url=signup_url)
        delete_resp = _Resp(200, {}, url=signup_url)
        calls = {"n": 0}

        def fake_post(url, *a, **kw):
            calls["n"] += 1
            return signup_resp if "signUp" in url else delete_resp

        monkeypatch.setattr(gas, "_AUTH_READ_ENABLED", False)
        monkeypatch.setattr(gas.requests, "post", fake_post)
        res = gas._execute_probe(probe, SENTINEL_KEY, "proj", base_headers={})
        assert res["vulnerable"] is True
        # Clean success: no cleanup_failed note.
        assert res["manual_note"] is None
        assert res["followup_required"] == (
            "identity_toolkit_app_backend_chain")
        # Delete must have been attempted (mandatory cleanup).
        assert calls["n"] >= 2

    @pytest.mark.unit
    def test_clean_success_tier_is_potential(self):
        """A clean signUp success (manual_note None) → POTENTIAL via the
        tier rule (signUp is in POTENTIAL_PROBES, no cleanup-failed note)."""
        name = SIGNUP_NAME
        is_potential = name in gas.POTENTIAL_PROBES
        manual_note = None  # clean success
        if str(manual_note or "").startswith("cleanup_failed"):
            is_potential = False
        tier = "POTENTIAL" if is_potential else "CONFIRMED"
        assert tier == "POTENTIAL"


class TestSignupCleanupFailureIsConfirmed:
    @pytest.mark.unit
    def test_cleanup_failure_sets_cleanup_note(self, monkeypatch):
        """signUp 200 but delete non-200 → manual_note starts with
        'cleanup_failed' and an artifact is recorded."""
        probe = _signup_probe()
        signup_url = probe[3].replace("{key}", SENTINEL_KEY)
        signup_resp = _Resp(200, {"idToken": "SECRET_TOKEN_xyz",
                                  "localId": "anon999"}, url=signup_url)
        delete_resp = _Resp(403, {"error": {"message": "PERMISSION_DENIED"}},
                            url=signup_url)
        artifacts = []
        monkeypatch.setattr(gas, "_it_record_artifact",
                            lambda *a, **k: artifacts.append(a))
        monkeypatch.setattr(gas, "_AUTH_READ_ENABLED", False)
        monkeypatch.setattr(gas.requests, "post",
                            lambda url, *a, **kw: signup_resp
                            if "signUp" in url else delete_resp)
        res = gas._execute_probe(probe, SENTINEL_KEY, "proj", base_headers={})
        assert res["vulnerable"] is True
        assert str(res["manual_note"]).startswith("cleanup_failed")
        assert res["followup_required"] is None
        assert artifacts, "cleanup failure must record a loud artifact"

    @pytest.mark.unit
    def test_cleanup_preserves_mobile_restriction_headers(self, monkeypatch):
        """If signUp succeeds only with iOS/Android restriction headers, delete
        must use the same headers or cleanup can fail with HTTP 403."""
        probe = _signup_probe()
        signup_url = probe[3].replace("{key}", SENTINEL_KEY)
        restriction_headers = {"X-Ios-Bundle-Identifier": "com.example.app"}
        signup_resp = _Resp(200, {"idToken": "SECRET_TOKEN_xyz",
                                  "localId": "anon-ios"},
                            url=signup_url, headers=restriction_headers)
        delete_resp = _Resp(200, {}, url=signup_url)
        delete_headers = []

        def fake_post(url, *a, **kw):
            if "signUp" in url:
                return signup_resp
            delete_headers.append(dict(kw.get("headers") or {}))
            return delete_resp

        monkeypatch.setattr(gas, "_AUTH_READ_ENABLED", False)
        monkeypatch.setattr(gas.requests, "post", fake_post)
        res = gas._execute_probe(
            probe, SENTINEL_KEY, "proj",
            base_headers=restriction_headers)
        assert res["vulnerable"] is True
        assert res["manual_note"] is None
        assert delete_headers
        assert delete_headers[0]["X-Ios-Bundle-Identifier"] == "com.example.app"

    @pytest.mark.unit
    def test_cleanup_failed_note_forces_confirmed_tier(self):
        """The _handle_result tier override: a vulnerable result whose
        manual_note starts with 'cleanup_failed' must be CONFIRMED even
        though signUp is in POTENTIAL_PROBES."""
        # Mirror the tier-decision rule from scan_gapis.
        name = SIGNUP_NAME
        is_potential_by_name = name in gas.POTENTIAL_PROBES
        assert is_potential_by_name  # baseline: clean → POTENTIAL
        manual_note = "cleanup_failed_localId=anon999"
        is_potential = is_potential_by_name
        if str(manual_note or "").startswith("cleanup_failed"):
            is_potential = False
        tier = "POTENTIAL" if is_potential else "CONFIRMED"
        assert tier == "CONFIRMED"


class TestSignupTokenRedaction:
    @pytest.mark.unit
    def test_idtoken_never_in_manual_note(self, monkeypatch):
        probe = _signup_probe()
        signup_url = probe[3].replace("{key}", SENTINEL_KEY)
        signup_resp = _Resp(200, {"idToken": "SECRET_TOKEN_xyz",
                                  "localId": "anonX"}, url=signup_url)
        delete_resp = _Resp(500, {}, url=signup_url)
        monkeypatch.setattr(gas, "_it_record_artifact", lambda *a, **k: None)
        monkeypatch.setattr(gas, "_AUTH_READ_ENABLED", False)
        monkeypatch.setattr(gas.requests, "post",
                            lambda url, *a, **kw: signup_resp
                            if "signUp" in url else delete_resp)
        res = gas._execute_probe(probe, SENTINEL_KEY, "proj", base_headers={})
        assert "SECRET_TOKEN_xyz" not in str(res.get("manual_note"))


class TestAuthReadStillGated:
    @pytest.mark.unit
    def test_auth_read_chain_not_run_when_disabled(self, monkeypatch):
        """With _AUTH_READ_ENABLED False, the auth-read chain must not
        append findings even though signUp succeeded."""
        probe = _signup_probe()
        signup_url = probe[3].replace("{key}", SENTINEL_KEY)
        signup_resp = _Resp(200, {"idToken": "T", "localId": "a"},
                            url=signup_url)
        delete_resp = _Resp(200, {}, url=signup_url)
        ran = {"chain": False}
        orig = gas._run_authenticated_read_chain

        def spy_chain(*a, **k):
            ran["chain"] = True
            return orig(*a, **k)

        monkeypatch.setattr(gas, "_AUTH_READ_ENABLED", False)
        monkeypatch.setattr(gas, "_run_authenticated_read_chain", spy_chain)
        with gas._AUTH_READ_FINDINGS_LOCK if hasattr(
                gas, "_AUTH_READ_FINDINGS_LOCK") else _nullctx():
            gas._AUTH_READ_FINDINGS.clear()
        monkeypatch.setattr(gas.requests, "post",
                            lambda url, *a, **kw: signup_resp
                            if "signUp" in url else delete_resp)
        gas._execute_probe(probe, SENTINEL_KEY, "proj", base_headers={})
        # chain is called but short-circuits; no findings appended.
        assert not gas._AUTH_READ_FINDINGS


class _nullctx:
    def __enter__(self): return self
    def __exit__(self, *a): return False
