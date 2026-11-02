"""Regression coverage for credential isolation."""
from __future__ import annotations

import json

import pytest

import google_api_scanner as gas

SENTINEL_KEY = "AIzaSy" + "X" * 33


class _FakeResponse:
    def __init__(self, status_code=200, body="", url=None):
        self.status_code = status_code
        self.text = body if isinstance(body, str) else json.dumps(body)
        self.content = self.text.encode()
        self.headers = {"Content-Type": "application/json"}
        self.request = type("R", (), {"url": url or "https://x/?key=" + SENTINEL_KEY})()

    def json(self):
        return json.loads(self.text) if self.text else {}


@pytest.fixture(autouse=True)
def _clean_derived_state():
    with gas._DERIVED_LOCK:
        gas._DERIVED_PROJECT_IDS.clear()
        gas._DERIVED_PROJECT_NUMBERS.clear()
    with gas._DERIVED_FIREBASE_LOCK:
        gas._DERIVED_FIREBASE_CONFIGS.clear()
    yield
    with gas._DERIVED_LOCK:
        gas._DERIVED_PROJECT_IDS.clear()
        gas._DERIVED_PROJECT_NUMBERS.clear()
    with gas._DERIVED_FIREBASE_LOCK:
        gas._DERIVED_FIREBASE_CONFIGS.clear()


def _probe_by_name(name):
    for p in gas.ALL_PROBES:
        if p[0] == name:
            return p
    raise AssertionError("probe not found: " + name)


# Removed-symbol guarantees

class TestAllowProjectFullyRemoved:
    @pytest.mark.unit
    @pytest.mark.parametrize("sym", [
        "_ALLOW_PROJECTS", "_ALLOW_PROJECTS_UNSET", "_normalize_allow_projects",
        "_set_allow_projects", "_is_allow_any", "_is_project_allowlisted",
        "_allow_project_skip_reason"])
    def test_symbol_gone(self, sym):
        assert not hasattr(gas, sym), (
            f"{sym} must be removed (--allow-project is unsupported)")

    @pytest.mark.unit
    def test_new_guard_exists(self):
        assert hasattr(gas, "_dangerous_probe_skip_reason")

    @pytest.mark.unit
    def test_scan_gapis_has_no_allow_projects_kwarg(self):
        assert "allow_projects" not in gas.scan_gapis.__code__.co_varnames


# Project resolvers (still used by auth-read target filtering)

class TestProjectResolvers:
    @pytest.mark.unit
    @pytest.mark.parametrize("url,expected", [
        ("https://x.googleapis.com/v1/projects/abc/things?key=K", "abc"),
        ("https://x.googleapis.com/v1/projects/abc:method?key=K", "abc"),
        ("https://x.googleapis.com/v1/things?key=K", None),
    ])
    def test_resolve_from_url(self, url, expected):
        assert gas._resolve_target_project_from_url(url) == expected

    @pytest.mark.unit
    @pytest.mark.parametrize("db_url,expected", [
        ("https://my-proj-default-rtdb.firebaseio.com/.json", "my-proj"),
        ("https://my-proj.firebaseio.com/.json", "my-proj"),
        ("https://my-proj.us-central1.firebasedatabase.app/.json", "my-proj"),
        ("https://example.com/", None),
    ])
    def test_resolve_from_db_url(self, db_url, expected):
        assert gas._resolve_target_project_from_db_url(db_url) == expected

    @pytest.mark.unit
    @pytest.mark.parametrize("bucket,expected", [
        ("my-proj.appspot.com", "my-proj"),
        ("my-proj.firebasestorage.app", "my-proj"),
        ("not-a-bucket", None),
    ])
    def test_resolve_from_bucket(self, bucket, expected):
        assert gas._resolve_target_project_from_bucket(bucket) == expected


# _dangerous_probe_skip_reason — the new guard

_PROJ_PROBE = ("Some Destructive Write", "destructive", "POST",
               "https://x.googleapis.com/v1/projects/{project}/things?key={key}",
               None, "200", "x")
_KEYOWN_PROBE = ("Gemini File Upload (write)", "destructive", "POST",
                 "https://generativelanguage.googleapis.com/v1beta/files?key={key}",
                 "{}", "not_auth", "x")
_HIGH_PROBE = ("Pub/Sub Topics", "high", "GET",
               "https://pubsub.googleapis.com/v1/projects/{project}/topics?key={key}",
               None, "x", "x")


class TestDangerousProbeSkipReason:
    @pytest.mark.unit
    def test_non_dangerous_never_skipped(self):
        url = "https://pubsub.googleapis.com/v1/projects/test-project-123/topics?key=K"
        assert gas._dangerous_probe_skip_reason(_HIGH_PROBE, url, []) is None

    @pytest.mark.unit
    def test_project_targeted_placeholder_skips(self):
        url = "https://x.googleapis.com/v1/projects/test-project-123/things?key=K"
        reason = gas._dangerous_probe_skip_reason(_PROJ_PROBE, url, [])
        assert reason is not None and "placeholder" in reason

    @pytest.mark.unit
    def test_project_targeted_derived_runs(self):
        url = "https://x.googleapis.com/v1/projects/real-proj/things?key=K"
        assert gas._dangerous_probe_skip_reason(
            _PROJ_PROBE, url, ["real-proj"]) is None

    @pytest.mark.unit
    def test_project_targeted_not_derived_skips(self):
        url = "https://x.googleapis.com/v1/projects/real-proj/things?key=K"
        reason = gas._dangerous_probe_skip_reason(_PROJ_PROBE, url, ["other"])
        assert reason is not None and "not derived" in reason

    @pytest.mark.unit
    def test_key_own_always_runs(self):
        url = "https://generativelanguage.googleapis.com/v1beta/files?key=K"
        assert gas._dangerous_probe_skip_reason(_KEYOWN_PROBE, url, []) is None


# _execute_probe integration

class TestExecuteProbeGuard:
    @pytest.mark.unit
    def test_project_targeted_destructive_skipped_on_placeholder(self):
        """A real destructive {project} probe with only the placeholder
        project available must NOT issue any HTTP request."""
        probe = None
        for p in gas.ALL_PROBES:
            if p[1] == "destructive" and "{project}" in (p[3] or ""):
                probe = p
                break
        if probe is None:
            pytest.skip("no project-targeted destructive probe in registry")
        from unittest.mock import patch
        with patch.object(gas.requests, "post") as mp:
            res = gas._execute_probe(probe, SENTINEL_KEY, None, base_headers={})
        assert res is None
        mp.assert_not_called()

    @pytest.mark.unit
    def test_key_own_destructive_runs_without_project(self, monkeypatch):
        """A key-own destructive probe (no {project}) issues its request
        even with no derived project."""
        probe = _probe_by_name("Gemini File Upload (write)")
        called = {"n": 0}

        def fake_post(url, *a, **kw):
            called["n"] += 1
            return _FakeResponse(403, '{"error":{"message":"PERMISSION_DENIED"}}',
                                url=url)

        monkeypatch.setattr(gas.requests, "post", fake_post)
        gas._execute_probe(probe, SENTINEL_KEY, None, base_headers={})
        assert called["n"] >= 1

    @pytest.mark.unit
    def test_project_targeted_destructive_runs_with_derived(self, monkeypatch):
        probe = None
        for p in gas.ALL_PROBES:
            if p[1] == "destructive" and "{project}" in (p[3] or ""):
                probe = p
                break
        if probe is None:
            pytest.skip("no project-targeted destructive probe in registry")
        with gas._DERIVED_LOCK:
            gas._DERIVED_PROJECT_IDS.add("derived-proj")
        called = {"n": 0}
        monkeypatch.setattr(gas.requests, "post",
                            lambda url, *a, **kw: called.__setitem__("n", called["n"] + 1)
                            or _FakeResponse(403, "{}", url=url))
        gas._execute_probe(probe, SENTINEL_KEY, "derived-proj", base_headers={})
        assert called["n"] >= 1


# Auth-read chain never targets the placeholder

class TestAuthReadChainDerivedOnly:
    @pytest.mark.unit
    def test_chain_returns_empty_when_disabled(self):
        gas._set_auth_read_enabled(False)
        out = gas._run_authenticated_read_chain(SENTINEL_KEY, "tok", "lid")
        assert out == []

    @pytest.mark.unit
    def test_chain_never_reads_placeholder_project(self, monkeypatch):
        """With auth-read enabled but only the placeholder in derived
        state, the chain must not issue a read against test-project-123."""
        gas._set_auth_read_enabled(True)
        gas._set_auth_read_scope_ok(True)
        with gas._DERIVED_LOCK:
            gas._DERIVED_PROJECT_IDS.clear()
            gas._DERIVED_PROJECT_IDS.add("test-project-123")
        reads = []
        monkeypatch.setattr(gas, "_authenticated_firestore_read",
                            lambda pid, *a, **k: reads.append(pid))
        monkeypatch.setattr(gas, "_authenticated_rtdb_read",
                            lambda *a, **k: None)
        monkeypatch.setattr(gas, "_authenticated_storage_list",
                            lambda *a, **k: None)
        try:
            gas._run_authenticated_read_chain(SENTINEL_KEY, "tok", "lid")
        finally:
            gas._set_auth_read_enabled(False)
        assert "test-project-123" not in reads
