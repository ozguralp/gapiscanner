"""Tests for firebase config lifecycle."""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import google_api_scanner as gas  # noqa: E402

SENTINEL_KEY = "AIzaSyXX" + "X" * 31


@pytest.fixture(autouse=True)
def _reset_firebase_store():
    """Clear before and after every test in this module so we don't leak
    extracted configs into other test modules."""
    with gas._DERIVED_FIREBASE_LOCK:
        gas._DERIVED_FIREBASE_CONFIGS.clear()
    yield
    with gas._DERIVED_FIREBASE_LOCK:
        gas._DERIVED_FIREBASE_CONFIGS.clear()


# session hygiene

class TestSessionHygiene:
    @pytest.mark.unit
    def test_begin_session_clears_store(self):
        gas._record_firebase_config(gas._firebase_config(
            project_id="leftover", source="stale.plist"))
        with gas._DERIVED_FIREBASE_LOCK:
            assert len(gas._DERIVED_FIREBASE_CONFIGS) == 1
        gas._begin_discovery_session()
        with gas._DERIVED_FIREBASE_LOCK:
            assert gas._DERIVED_FIREBASE_CONFIGS == []

    @pytest.mark.unit
    def test_begin_session_idempotent_on_empty(self):
        with gas._DERIVED_FIREBASE_LOCK:
            assert gas._DERIVED_FIREBASE_CONFIGS == []
        gas._begin_discovery_session()
        gas._begin_discovery_session()
        with gas._DERIVED_FIREBASE_LOCK:
            assert gas._DERIVED_FIREBASE_CONFIGS == []

    @pytest.mark.unit
    def test_configs_persist_across_keys_in_same_session(self, monkeypatch):
        """Two scan_gapis calls in a row (simulating two keys discovered in
        the same bundle) must both see the configs populated BEFORE the
        first call. scan_gapis does NOT clear the store."""
        gas._record_firebase_config(gas._firebase_config(
            project_id="shared", source="shared.plist"))
        monkeypatch.setattr(gas, "ALL_PROBES", [])
        monkeypatch.setattr(gas, "FIREBASE_CHAIN_PROBES", [])
        monkeypatch.setattr(gas, "PHASE_0_PROBE_NAMES", ())
        gas.scan_gapis(SENTINEL_KEY, quiet=True, skip_jsapi=True)
        gas.scan_gapis(SENTINEL_KEY, quiet=True, skip_jsapi=True)
        with gas._DERIVED_FIREBASE_LOCK:
            project_ids = {c.get("project_id")
                           for c in gas._DERIVED_FIREBASE_CONFIGS}
            assert "shared" in project_ids, (
                "scan_gapis must NOT clear configs; the same "
                "bundle's configs must remain available for every key.")

    @pytest.mark.unit
    def test_session_boundary_does_not_leak(self):
        """Between sessions, configs from session 1 must not leak into
        session 2."""
        # Session 1
        gas._begin_discovery_session()
        gas._record_firebase_config(gas._firebase_config(
            project_id="session1-app", source="s1.plist"))
        with gas._DERIVED_FIREBASE_LOCK:
            assert any(c.get("project_id") == "session1-app"
                       for c in gas._DERIVED_FIREBASE_CONFIGS)
        # Session 2 begins
        gas._begin_discovery_session()
        gas._record_firebase_config(gas._firebase_config(
            project_id="session2-app", source="s2.plist"))
        with gas._DERIVED_FIREBASE_LOCK:
            project_ids = {c.get("project_id")
                           for c in gas._DERIVED_FIREBASE_CONFIGS}
            assert "session2-app" in project_ids
            assert "session1-app" not in project_ids, (
                "Configs from a prior session must not leak across "
                "_begin_discovery_session() boundary.")

    @pytest.mark.unit
    def test_run_bundle_calls_begin_session(self, monkeypatch, tmp_path):
        if not hasattr(gas, "_run_bundle"):
            pytest.skip("This frontend does not expose scope-bundle execution")
        # Pre-populate the store with a config from a prior session.
        gas._record_firebase_config(gas._firebase_config(
            project_id="prior-session", source="prior.plist"))
        bundle = SimpleNamespace(program="example", platform="example", raw_source={},
                                 web_assets=[], mobile_apps=[], api_assets=[],
                                 executable_assets=[], oos=[])
        gas._run_bundle(bundle, dry_run=True, quiet=True, output_dir=str(tmp_path))
        with gas._DERIVED_FIREBASE_LOCK:
            project_ids = {c.get("project_id")
                           for c in gas._DERIVED_FIREBASE_CONFIGS}
            assert "prior-session" not in project_ids, (
                "_run_bundle must call _begin_discovery_session at entry "
                "to clear configs from prior sessions.")


# projectless configs

class TestProjectIdDerivation:
    @pytest.mark.unit
    def test_derive_from_legacy_rtdb_url(self):
        assert gas._derive_project_id_from_config({
            "database_url": "https://my-app.firebaseio.com"
        }) == "my-app"

    @pytest.mark.unit
    def test_derive_from_us_default_rtdb_url(self):
        assert gas._derive_project_id_from_config({
            "database_url": "https://my-app-default-rtdb.firebaseio.com"
        }) == "my-app"

    @pytest.mark.unit
    def test_derive_from_regional_rtdb_url(self):
        # The critical case: the regex would have greedily swallowed
        # `-default-rtdb` if we'd used `[a-z0-9-]+` for the project label.
        assert gas._derive_project_id_from_config({
            "database_url": "https://my-app-default-rtdb.europe-west1.firebasedatabase.app"
        }) == "my-app"

    @pytest.mark.unit
    def test_derive_from_legacy_storage_bucket(self):
        assert gas._derive_project_id_from_config({
            "storage_bucket": "my-app.appspot.com"
        }) == "my-app"

    @pytest.mark.unit
    def test_derive_from_new_storage_bucket(self):
        assert gas._derive_project_id_from_config({
            "storage_bucket": "my-app.firebasestorage.app"
        }) == "my-app"

    @pytest.mark.unit
    def test_lowercases_result(self):
        # Firebase project IDs must be lowercase; derivation should normalize.
        assert gas._derive_project_id_from_config({
            "database_url": "https://My-App.firebaseio.com"
        }) == "my-app"

    @pytest.mark.unit
    def test_returns_none_for_unknown_host(self):
        assert gas._derive_project_id_from_config({
            "database_url": "https://attacker.example/db"
        }) is None

    @pytest.mark.unit
    def test_returns_none_for_no_url_or_bucket(self):
        assert gas._derive_project_id_from_config({
            "google_app_id": "1:1:web:x"
        }) is None


class TestRecordConfigDerivesProjectId:
    @pytest.mark.unit
    def test_strings_xml_with_url_only_gets_project_id(self):
        """An Android strings.xml might define only `firebase_database_url`
        without `project_id`. _record_firebase_config must derive the id so
        the config doesn't get dropped from Phase 3."""
        cfg = gas._firebase_config(
            database_url="https://victim-app.firebaseio.com",
            source="res/values/strings.xml")
        gas._record_firebase_config(cfg)
        with gas._DERIVED_FIREBASE_LOCK:
            stored = gas._DERIVED_FIREBASE_CONFIGS[0]
            assert stored.get("project_id") == "victim-app"

    @pytest.mark.unit
    def test_js_with_bucket_only_gets_project_id(self):
        cfg = gas._firebase_config(
            storage_bucket="victim-app.appspot.com",
            source="app.js")
        gas._record_firebase_config(cfg)
        with gas._DERIVED_FIREBASE_LOCK:
            stored = gas._DERIVED_FIREBASE_CONFIGS[0]
            assert stored.get("project_id") == "victim-app"

    @pytest.mark.unit
    def test_truly_projectless_config_still_stored(self):
        """If derivation fails, the config is still recorded — Phase 3's
        projectless branch will run its extras."""
        cfg = gas._firebase_config(
            google_app_id="1:1:web:abc",
            source="weird.js")
        gas._record_firebase_config(cfg)
        with gas._DERIVED_FIREBASE_LOCK:
            assert len(gas._DERIVED_FIREBASE_CONFIGS) == 1
            assert gas._DERIVED_FIREBASE_CONFIGS[0].get("project_id") is None


class TestPhase3ProjectlessBranch:
    @pytest.mark.unit
    def test_projectless_config_with_database_url_runs_probe(self, monkeypatch):
        """A config with no project_id (and no derivable id) but a usable
        database_url must still have its URL probed in Phase 3."""
        # Use a URL host shape that won't trip the derivation regex.
        cfg = gas._firebase_config(
            database_url="https://db.firebaseio.com",
            source="weird.js")
        # Bypass derivation so the config stays projectless even after
        # _record_firebase_config (the URL host won't match either pattern).
        gas._record_firebase_config(cfg)
        with gas._DERIVED_FIREBASE_LOCK:
            assert gas._DERIVED_FIREBASE_CONFIGS[0].get("project_id") is None
        # Capture URLs issued.
        seen_urls = []
        def _stub(*args, **kwargs):
            seen_urls.append(args[0] if args else kwargs.get("url"))
            m = MagicMock()
            m.status_code = 403
            m.text = '{"error":"PERMISSION_DENIED"}'
            m.json.return_value = {"error": "PERMISSION_DENIED"}
            m.content = m.text.encode()
            m.headers = {"Content-Type": "application/json"}
            m.request = MagicMock()
            m.request.url = args[0] if args else ""
            return m
        import requests
        monkeypatch.setattr(requests, "get",  _stub)
        monkeypatch.setattr(requests, "post", _stub)
        monkeypatch.setattr(gas, "ALL_PROBES", [])
        monkeypatch.setattr(gas, "PHASE_0_PROBE_NAMES", ())
        # No --project-id either. Phase 3's main per-pid loop will skip
        # (no derived project IDs); only the projectless branch should fire.
        gas.scan_gapis(SENTINEL_KEY, quiet=True, skip_jsapi=True)
        assert any("db.firebaseio.com" in (u or "")
                   for u in seen_urls), (
            "projectless config's database_url was not probed; seen URLs:\n"
            + "\n".join(str(u) for u in seen_urls[:20]))


# RTDB regional fallback

class TestRegionalRTDBFallback:
    @pytest.mark.unit
    def test_europe_west1_probe_exists(self):
        names = {p[0] for p in gas.FIREBASE_CHAIN_PROBES}
        assert "Firebase RTDB root (europe-west1)" in names

    @pytest.mark.unit
    def test_asia_southeast1_probe_exists(self):
        names = {p[0] for p in gas.FIREBASE_CHAIN_PROBES}
        assert "Firebase RTDB root (asia-southeast1)" in names

    @pytest.mark.unit
    def test_regional_urls_use_firebasedatabase_app(self):
        for p in gas.FIREBASE_CHAIN_PROBES:
            if "europe-west1" in p[0] or "asia-southeast1" in p[0]:
                assert ".firebasedatabase.app" in p[3], (
                    f"{p[0]} must use .firebasedatabase.app pattern; got {p[3]}")

    @pytest.mark.unit
    def test_regional_fallback_budget_is_conservative(self):
        """Sanity guard: don't let the regional list grow into a 30-region
        brute-force sweep without explicit review. Cap at 4 regional
        probes total (europe-west1 root + asia-southeast1 root, plus
        any future explicit-region addition)."""
        regional = [p for p in gas.FIREBASE_CHAIN_PROBES
                    if ".firebasedatabase.app" in p[3]
                    and "europe-west1" in p[3] or "asia-southeast1" in p[3]]
        assert len(regional) <= 4, (
            f"too many .firebasedatabase.app regional probes ({len(regional)}); "
            "review the regional fallback budget before expanding")


# storage object read cap (Range + stream cap)

class TestStorageObjectReadCap:
    def _list_response(self, items):
        import json as _j
        m = MagicMock()
        m.status_code = 200
        m.text = _j.dumps({"items": items})
        m.json.return_value = {"items": items}
        m.content = m.text.encode()
        m.headers = {"Content-Type": "application/json"}
        m.request = MagicMock()
        m.request.url = ("https://firebasestorage.googleapis.com/v0/b/"
                         "victim-app.appspot.com/o?key=" + SENTINEL_KEY)
        return m

    @pytest.mark.unit
    def test_range_header_is_set(self, monkeypatch):
        """The bounded read MUST send a Range header. Without it, the server
        can stream the full file — violating the ROE byte cap."""
        items = [{"name": "small.txt", "bucket": "victim-app.appspot.com",
                  "size": "500"}]
        list_resp = self._list_response(items)
        captured_headers = []
        def _stub_get(url, **kwargs):
            captured_headers.append(kwargs.get("headers") or {})
            stream_resp = MagicMock()
            stream_resp.status_code = 206
            stream_resp.iter_content = lambda chunk_size=4096, decode_unicode=False: iter([b"X" * 500])
            stream_resp.close = lambda: None
            return stream_resp
        import requests
        monkeypatch.setattr(requests, "get", _stub_get)
        gas._try_firebase_storage_object_read(list_resp, items)
        assert captured_headers, "no GET issued by read-confirmation"
        assert "Range" in captured_headers[0], (
            f"Range header missing; headers were {captured_headers[0]}")
        # Range must request at most 10 KB - 1 (0-indexed).
        cap = gas._STORAGE_OBJECT_READ_CAP_BYTES
        assert captured_headers[0]["Range"] == ("bytes=0-%d" % (cap - 1))

    @pytest.mark.unit
    def test_stream_is_used(self, monkeypatch):
        """Defense in depth: even if the server ignores Range, the request
        must use `stream=True` so the client can stop reading at the cap."""
        items = [{"name": "x.txt", "bucket": "victim-app.appspot.com",
                  "size": "100"}]
        list_resp = self._list_response(items)
        captured_kwargs = []
        def _stub_get(url, **kwargs):
            captured_kwargs.append(kwargs)
            r = MagicMock()
            r.status_code = 200
            r.iter_content = lambda chunk_size=4096, decode_unicode=False: iter([b"hi"])
            r.close = lambda: None
            return r
        import requests
        monkeypatch.setattr(requests, "get", _stub_get)
        gas._try_firebase_storage_object_read(list_resp, items)
        assert captured_kwargs and captured_kwargs[0].get("stream") is True

    @pytest.mark.unit
    def test_client_caps_oversized_server_response(self, monkeypatch):
        """If the server ignores the Range header and streams a 1 MB file,
        the client must stop reading at _STORAGE_OBJECT_READ_CAP_BYTES."""
        cap = gas._STORAGE_OBJECT_READ_CAP_BYTES
        items = [{"name": "leaky.bin", "bucket": "victim-app.appspot.com",
                  "size": str(cap // 2)}]
        list_resp = self._list_response(items)
        # Server emits 200 chunks of 8 KB each = 1.6 MB total. Client must
        # consume at most `cap` bytes (10 KB) — meaning at most 2 chunks
        # plus some of a third before breaking out of the loop.
        chunks_yielded = [0]
        def _generator(chunk_size=4096, decode_unicode=False):
            for _ in range(200):
                chunks_yielded[0] += 1
                yield b"A" * 8192
        def _stub_get(url, **kwargs):
            r = MagicMock()
            r.status_code = 200       # server ignored Range
            r.iter_content = _generator
            r.close = lambda: None
            return r
        import requests
        monkeypatch.setattr(requests, "get", _stub_get)
        result = gas._try_firebase_storage_object_read(list_resp, items)
        assert result is True
        # 10 KB cap / 8 KB chunk = the loop must break after at most 2
        # chunks (16 KB total read). It must NOT consume all 200 chunks.
        assert chunks_yielded[0] <= 3, (
            f"client cap failed: consumed {chunks_yielded[0]} chunks "
            f"({chunks_yielded[0] * 8192} bytes) for a {cap}-byte cap")

    @pytest.mark.unit
    def test_oversized_item_not_attempted(self, monkeypatch):
        """If the LISTED size already exceeds the cap, no download attempt
        is made at all."""
        items = [{"name": "huge.bin", "bucket": "victim-app.appspot.com",
                  "size": str(gas._STORAGE_OBJECT_READ_CAP_BYTES * 100)}]
        list_resp = self._list_response(items)
        called = [False]
        def _stub_get(*a, **kw):
            called[0] = True
            return MagicMock()
        import requests
        monkeypatch.setattr(requests, "get", _stub_get)
        result = gas._try_firebase_storage_object_read(list_resp, items)
        assert result is False
        assert called[0] is False, (
            "oversized listed object must short-circuit before any HTTP")


class TestPriorInvariantsPreserved:
    @pytest.mark.unit
    def test_sentinel_still_zero_confirmed(self, monkeypatch):
        def _garbage(*args, **kwargs):
            m = MagicMock()
            m.status_code = 400
            m.text = ('{"error":{"code":400,"status":"INVALID_ARGUMENT",'
                      '"message":"API key not valid. Please pass a valid API key.",'
                      '"details":[{"reason":"API_KEY_INVALID"}]}}')
            m.json.return_value = {
                "error": {"code": 400, "status": "INVALID_ARGUMENT",
                          "message": "API key not valid.",
                          "details": [{"reason": "API_KEY_INVALID"}]},
            }
            m.content = m.text.encode()
            m.headers = {"Content-Type": "application/json"}
            m.request = MagicMock()
            m.request.url = args[0] if args else ""
            return m
        import requests
        monkeypatch.setattr(requests, "get",    _garbage)
        monkeypatch.setattr(requests, "post",   _garbage)
        monkeypatch.setattr(requests, "put",    _garbage)
        monkeypatch.setattr(requests, "delete", _garbage)
        confirmed = gas.scan_gapis(SENTINEL_KEY, quiet=True, skip_jsapi=True,
                                   threads=4)
        assert confirmed == [], (
            f"Synthetic key produced a confirmed result: CONFIRMED={confirmed}")

    @pytest.mark.unit
    def test_scan_gapis_still_does_not_clear_configs(self, monkeypatch):
        gas._record_firebase_config(gas._firebase_config(
            project_id="multi-key", source="x.plist"))
        monkeypatch.setattr(gas, "ALL_PROBES", [])
        monkeypatch.setattr(gas, "FIREBASE_CHAIN_PROBES", [])
        monkeypatch.setattr(gas, "PHASE_0_PROBE_NAMES", ())
        for _ in range(3):
            gas.scan_gapis(SENTINEL_KEY, quiet=True, skip_jsapi=True)
        with gas._DERIVED_FIREBASE_LOCK:
            assert any(c.get("project_id") == "multi-key"
                       for c in gas._DERIVED_FIREBASE_CONFIGS)
