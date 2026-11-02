"""Tests for firebase chain."""
from __future__ import annotations

import sys
import json
import plistlib
import zipfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import google_api_scanner as gas  # noqa: E402

SENTINEL_KEY = "AIzaSyXX" + "X" * 31


@pytest.fixture(autouse=True)
def _reset_firebase_store():
    with gas._DERIVED_FIREBASE_LOCK:
        gas._DERIVED_FIREBASE_CONFIGS.clear()
    yield
    with gas._DERIVED_FIREBASE_LOCK:
        gas._DERIVED_FIREBASE_CONFIGS.clear()


# Firestore documents check

def _mk_response(status_code, body_text):
    m = MagicMock()
    m.status_code = status_code
    m.text = body_text
    try:
        m.json.return_value = json.loads(body_text) if body_text else {}
    except Exception:
        m.json.side_effect = ValueError("not json")
    m.content = (body_text or "").encode()
    m.headers = {"Content-Type": "application/json"}
    m.request = MagicMock()
    m.request.url = ("https://firestore.googleapis.com/v1/projects/"
                     "victim/databases/(default)/documents?key=" + SENTINEL_KEY)
    return m


class TestCheckFirestoreDocuments:
    @pytest.mark.unit
    def test_denied_returns_not_vulnerable(self):
        r = _mk_response(403, '{"error":{"status":"PERMISSION_DENIED"}}')
        out = gas._check_firestore_documents(r)
        assert out == (False, None)

    @pytest.mark.unit
    def test_api_key_invalid_is_not_vulnerable(self):

        body = ('{"error":{"code":400,"status":"INVALID_ARGUMENT",'
                '"message":"API key not valid. Please pass a valid API key.",'
                '"details":[{"reason":"API_KEY_INVALID"}]}}')
        r = _mk_response(400, body)
        out = gas._check_firestore_documents(r)
        assert out == (False, None)

    @pytest.mark.unit
    def test_empty_documents_is_INFO(self):
        r = _mk_response(200, '{}')
        out = gas._check_firestore_documents(r)
        assert len(out) == 3, "empty Firestore must return 3-tuple override"
        vulnerable, note, overrides = out
        assert vulnerable is True
        assert overrides.get("data_sensitivity") == "none"
        assert overrides.get("confirmation") == "key_accepted_only"

        it, c, ds = gas._resolve_response_fields(
            overrides.get("name", "Firestore"), overrides.get("category", "high"),
            check_overrides=overrides)
        assert gas._derive_severity(it, c, ds) == "INFO"

    @pytest.mark.unit
    def test_empty_documents_array_is_INFO(self):
        r = _mk_response(200, '{"documents":[]}')
        out = gas._check_firestore_documents(r)
        assert len(out) == 3
        vulnerable, _, overrides = out
        assert vulnerable is True
        assert overrides.get("data_sensitivity") == "none"

    @pytest.mark.unit
    def test_documents_present_is_HIGH(self):
        body = ('{"documents":[{"name":"projects/victim/databases/(default)/'
                'documents/users/u1","fields":{"email":{"stringValue":"a@b.c"}}}]}')
        r = _mk_response(200, body)
        out = gas._check_firestore_documents(r)
        assert len(out) == 3
        vulnerable, note, overrides = out
        assert vulnerable is True
        assert overrides["data_sensitivity"] == "customer_data"
        assert overrides["confirmation"]     == "confirmed_data"
        assert overrides["impact_type"]      == "data_read"
        # Severity:
        it, c, ds = gas._resolve_response_fields(
            "Firestore documents (default DB)", "high",
            check_overrides=overrides)
        assert gas._derive_severity(it, c, ds) == "HIGH"


# Firebase Storage list — empty vs items

class TestCheckFirebaseStorageList:
    @pytest.mark.unit
    def test_api_key_invalid_returns_false(self):
        body = '{"error":{"details":[{"reason":"API_KEY_INVALID"}]}}'
        r = _mk_response(400, body)
        assert gas._check_firebase_storage_list(r) == (False, None)

    @pytest.mark.unit
    def test_open_but_empty_is_INFO(self):
        r = _mk_response(200, '{"kind":"storage#objects"}')
        out = gas._check_firebase_storage_list(r)
        assert len(out) == 3
        vulnerable, note, overrides = out
        assert vulnerable is True
        assert overrides.get("data_sensitivity") == "none"
        assert "Storage bucket open but empty" in overrides.get("name", "")

    @pytest.mark.unit
    def test_items_present_is_HIGH_no_download(self, monkeypatch):
        """When items[] is populated but the object-download check returns
        False (object too large or download error), the probe still reports
        HIGH (the list metadata itself proves customer-data exposure)."""
        # Force the download attempt to fail by stubbing requests.get inside
        # the helper.
        body = '{"items":[{"name":"big.bin","bucket":"victim-app.appspot.com","size":"99999999"}]}'
        r = _mk_response(200, body)
        out = gas._check_firebase_storage_list(r)
        assert len(out) == 3
        vulnerable, note, overrides = out
        assert vulnerable is True
        assert overrides["data_sensitivity"] == "customer_data"
        assert overrides["confirmation"]     == "confirmed_data"
        assert "object_read_confirmed" not in note  # too big for read

    @pytest.mark.unit
    def test_object_download_confirmation_path(self, monkeypatch):
        """When a small object is listed, _try_firebase_storage_object_read
        is invoked. We stub requests.get to return a small body; the note
        must include 'object_read_confirmed'."""
        body = ('{"items":[{"name":"public/readme.txt",'
                '"bucket":"victim-app.appspot.com","size":"512"}]}')
        r = _mk_response(200, body)

        small_body = b"a" * 512
        dl_resp = MagicMock()
        dl_resp.status_code = 206  # Partial Content (Range honored)
        dl_resp.iter_content = lambda chunk_size=4096, decode_unicode=False: iter([small_body])
        dl_resp.close = lambda: None
        import requests
        monkeypatch.setattr(requests, "get", lambda *a, **kw: dl_resp)
        out = gas._check_firebase_storage_list(r)
        assert len(out) == 3
        vulnerable, note, overrides = out
        assert vulnerable is True
        assert "object_read_confirmed" in note

    @pytest.mark.unit
    def test_object_download_is_read_only(self, monkeypatch):
        """The bounded download must use ONLY HTTP GET, never POST/PUT/DELETE."""
        body = ('{"items":[{"name":"public/x.txt",'
                '"bucket":"victim-app.appspot.com","size":"100"}]}')
        r = _mk_response(200, body)
        seen_methods = []
        def _record_get(*a, **kw):
            seen_methods.append("get")
            m = MagicMock(); m.status_code = 200
            m.iter_content = lambda chunk_size=4096, decode_unicode=False: iter([b"hi"])
            m.close = lambda: None
            return m
        def _fail_others(*a, **kw):
            seen_methods.append("OTHER"); pytest.fail("non-GET in storage read path")
        import requests
        monkeypatch.setattr(requests, "get",    _record_get)
        monkeypatch.setattr(requests, "post",   _fail_others)
        monkeypatch.setattr(requests, "put",    _fail_others)
        monkeypatch.setattr(requests, "delete", _fail_others)
        gas._check_firebase_storage_list(r)
        assert seen_methods == ["get"]


# Regional RTDB probes exist in FIREBASE_CHAIN_PROBES

class TestFirebaseChainProbes:
    @pytest.mark.unit
    def test_regional_rtdb_probes_present(self):
        names = {p[0] for p in gas.FIREBASE_CHAIN_PROBES}
        assert "Firebase RTDB root (regional default)" in names
        assert "Firebase RTDB shallow keys (regional default)" in names

    @pytest.mark.unit
    def test_regional_rtdb_uses_default_rtdb_format(self):
        for p in gas.FIREBASE_CHAIN_PROBES:
            if p[0] == "Firebase RTDB root (regional default)":
                assert "{project}-default-rtdb.firebaseio.com" in p[3]
                return
        pytest.fail("Firebase RTDB root (regional default) probe not found")

    @pytest.mark.unit
    def test_firestore_documents_probe_present(self):
        names = {p[0] for p in gas.FIREBASE_CHAIN_PROBES}
        assert "Firestore documents (default DB)" in names
        for p in gas.FIREBASE_CHAIN_PROBES:
            if p[0] == "Firestore documents (default DB)":
                # Honors Firestore default-DB documents endpoint
                assert (
                    "firestore.googleapis.com/v1/projects/{project}/"
                    "databases/(default)/documents") in p[3]
                # Read-only (GET)
                assert p[2] == "GET"
                return


# FirebaseConfig store + state hygiene

class TestFirebaseConfigStore:
    def setup_method(self):
        # Tests run in any order — start each with a clean store.
        with gas._DERIVED_FIREBASE_LOCK:
            gas._DERIVED_FIREBASE_CONFIGS.clear()

    @pytest.mark.unit
    def test_record_config_dedupes_by_project_id(self):
        gas._record_firebase_config(gas._firebase_config(
            project_id="vp", source="a.plist"))
        gas._record_firebase_config(gas._firebase_config(
            project_id="vp", database_url="https://vp.firebaseio.com",
            source="b.xml"))
        with gas._DERIVED_FIREBASE_LOCK:
            assert len(gas._DERIVED_FIREBASE_CONFIGS) == 1
            cfg = gas._DERIVED_FIREBASE_CONFIGS[0]
            assert cfg["project_id"] == "vp"
            assert cfg["database_url"] == "https://vp.firebaseio.com"
            assert set(cfg["sources"]) == {"a.plist", "b.xml"}

    @pytest.mark.unit
    def test_scan_gapis_preserves_firebase_configs(self, monkeypatch):
        gas._record_firebase_config(gas._firebase_config(
            project_id="shared", source="discovered.plist"))
        with gas._DERIVED_FIREBASE_LOCK:
            assert len(gas._DERIVED_FIREBASE_CONFIGS) == 1
        monkeypatch.setattr(gas, "ALL_PROBES", [])
        monkeypatch.setattr(gas, "FIREBASE_CHAIN_PROBES", [])
        monkeypatch.setattr(gas, "PHASE_0_PROBE_NAMES", ())
        gas.scan_gapis(SENTINEL_KEY, quiet=True, skip_jsapi=True)
        with gas._DERIVED_FIREBASE_LOCK:
            # Must STILL be present so the next key's scan can use it.
            project_ids = {c.get("project_id")
                           for c in gas._DERIVED_FIREBASE_CONFIGS}
            assert "shared" in project_ids, (
                "configs are session-scoped (discovery clears at "
                "session start), not per-key — scan_gapis must not clear them.")


class TestProbeSeverityFields:
    @pytest.mark.unit
    def test_firestore_records_response_yields_HIGH(self, monkeypatch):
        body = '{"documents":[{"name":"projects/v/databases/(default)/documents/users/u1"}]}'
        m = _mk_response(200, body)
        import requests
        monkeypatch.setattr(requests, "get",    lambda *a, **kw: m)
        monkeypatch.setattr(requests, "post",   lambda *a, **kw: m)
        for probe in gas.FIREBASE_CHAIN_PROBES:
            if probe[0] != "Firestore documents (default DB)":
                continue
            res = gas._execute_probe(probe, SENTINEL_KEY, "victim", {})
            assert res["vulnerable"] is True
            assert res["severity"]         == "HIGH"
            assert res["impact_type"]      == "data_read"
            assert res["confirmation"]     == "confirmed_data"
            assert res["data_sensitivity"] == "customer_data"
            return
        pytest.fail("Firestore probe not iterated")

    @pytest.mark.unit
    def test_firestore_empty_response_yields_INFO(self, monkeypatch):
        m = _mk_response(200, '{"documents":[]}')
        import requests
        monkeypatch.setattr(requests, "get",    lambda *a, **kw: m)
        for probe in gas.FIREBASE_CHAIN_PROBES:
            if probe[0] != "Firestore documents (default DB)":
                continue
            res = gas._execute_probe(probe, SENTINEL_KEY, "victim", {})
            assert res["vulnerable"] is True
            assert res["severity"]         == "INFO"
            assert res["data_sensitivity"] == "none"
            return
        pytest.fail("Firestore probe not iterated")


# Phase 3 expansion uses extracted DATABASE_URL / STORAGE_BUCKET

class TestPhase3UsesExtractedConfig:
    def setup_method(self):
        with gas._DERIVED_FIREBASE_LOCK:
            gas._DERIVED_FIREBASE_CONFIGS.clear()
        with gas._DERIVED_LOCK:
            gas._DERIVED_PROJECT_IDS.clear()
            gas._DERIVED_PROJECT_NUMBERS.clear()

    @pytest.mark.unit
    def test_extracted_database_url_runs_in_chain(self, monkeypatch):
        # Pre-populate the store with one config carrying a regional URL.
        gas._record_firebase_config(gas._firebase_config(
            project_id="victim-app",
            database_url="https://victim-app-default-rtdb.europe-west1.firebasedatabase.app",
            storage_bucket="victim-app-bucket",
            source="GoogleService-Info.plist"))
        # Capture URLs that scan_gapis sends through requests.get.
        seen_urls = []
        def _stub_get(*args, **kwargs):
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
        monkeypatch.setattr(requests, "get",    _stub_get)
        monkeypatch.setattr(requests, "post",   _stub_get)
        # Reduce ALL_PROBES to nothing so only Phase 3 fires.
        monkeypatch.setattr(gas, "ALL_PROBES", [])
        monkeypatch.setattr(gas, "PHASE_0_PROBE_NAMES", ())
        # Pin project so Phase 3 runs without Phase 0 derivation.
        gas.scan_gapis(SENTINEL_KEY, quiet=True, skip_jsapi=True,
                       project_id="victim-app")
        # The extracted DATABASE_URL must appear in some probe's request URL.
        assert any(
            "victim-app-default-rtdb.europe-west1.firebasedatabase.app" in u
            for u in seen_urls
        ), ("extracted DATABASE_URL was not used in Phase 3 chain; seen URLs:\n"
            + "\n".join(seen_urls[:20]))
        # And the extracted STORAGE_BUCKET must appear too.
        assert any("victim-app-bucket" in u for u in seen_urls), (
            "extracted STORAGE_BUCKET was not used; seen URLs:\n"
            + "\n".join(seen_urls[:20]))

    @pytest.mark.unit
    def test_placeholder_project_id_does_not_run_phase3(self, monkeypatch):
        gas._record_firebase_config(gas._firebase_config(
            project_id="$(GOOGLE_PROJECT_ID)",
            database_url="https://$(GOOGLE_PROJECT_ID).firebaseio.com",
            storage_bucket="$(GOOGLE_PROJECT_ID).appspot.com",
            source="GoogleService-Info.plist"))
        seen_urls = []

        def _stub_get(*args, **kwargs):
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
        monkeypatch.setattr(requests, "get", _stub_get)
        monkeypatch.setattr(requests, "post", _stub_get)
        monkeypatch.setattr(gas, "ALL_PROBES", [])
        monkeypatch.setattr(gas, "PHASE_0_PROBE_NAMES", ())
        gas.scan_gapis(SENTINEL_KEY, quiet=True, skip_jsapi=True)
        assert not seen_urls

    @pytest.mark.unit
    def test_domain_scoped_project_skips_hostname_probes(self, monkeypatch):
        scoped = "priceline.com:api-project-97269564947"
        gas._record_firebase_config(gas._firebase_config(
            project_id=scoped, source="GoogleService-Info.plist"))
        seen_urls = []

        def _stub_get(*args, **kwargs):
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
        monkeypatch.setattr(requests, "get", _stub_get)
        monkeypatch.setattr(requests, "post", _stub_get)
        monkeypatch.setattr(gas, "ALL_PROBES", [])
        monkeypatch.setattr(gas, "PHASE_0_PROBE_NAMES", ())
        gas.scan_gapis(SENTINEL_KEY, quiet=True, skip_jsapi=True)
        assert any("/projects/%s/" % scoped in u for u in seen_urls)
        assert not any("firebaseio.com" in u for u in seen_urls)
        assert not any("%s.appspot.com" % scoped in u for u in seen_urls)
        assert not any("%s.firebasestorage.app" % scoped in u for u in seen_urls)


class TestSentinelRegression:
    @pytest.mark.unit
    def test_sentinel_yields_zero_confirmed(self, monkeypatch):
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


HAS_EXTRACTORS = (
    hasattr(gas, "_extract_firebase_configs_from_plist") and
    hasattr(gas, "_extract_firebase_configs_from_google_services_json") and
    hasattr(gas, "_extract_firebase_configs_from_strings_xml") and
    hasattr(gas, "_extract_firebase_configs_from_js")
)


@pytest.mark.skipif(not HAS_EXTRACTORS,
                    reason="Config extractors are unavailable in this frontend")
class TestPlistExtractor:
    @pytest.mark.unit
    def test_extract_full_plist(self):
        data = plistlib.dumps({
            "PROJECT_ID":     "my-victim-project",
            "GCM_SENDER_ID":  "123456789012",
            "DATABASE_URL":   "https://my-victim-project.firebaseio.com",
            "STORAGE_BUCKET": "my-victim-project.appspot.com",
            "GOOGLE_APP_ID":  "1:123456789012:ios:abc123",
            "BUNDLE_ID":      "com.victim.app",
            "API_KEY":        "AIzaSyDummyTestKey1234567890123456789",
        })
        cfgs = gas._extract_firebase_configs_from_plist(data, source="x.plist")
        assert len(cfgs) == 1
        cfg = cfgs[0]
        assert cfg["project_id"]      == "my-victim-project"
        assert cfg["project_number"]  == "123456789012"
        assert cfg["database_url"]    == "https://my-victim-project.firebaseio.com"
        assert cfg["storage_bucket"]  == "my-victim-project.appspot.com"
        assert cfg["google_app_id"]   == "1:123456789012:ios:abc123"
        assert cfg["sources"]         == ["x.plist"]

    @pytest.mark.unit
    def test_extract_empty_plist_returns_empty(self):
        data = plistlib.dumps({"unrelated": "stuff"})
        assert gas._extract_firebase_configs_from_plist(data) == []

    @pytest.mark.unit
    def test_malformed_plist_returns_empty(self):
        assert gas._extract_firebase_configs_from_plist(b"not a plist") == []


@pytest.mark.skipif(not HAS_EXTRACTORS, reason="Config extractors are unavailable in this frontend")
class TestGoogleServicesJsonExtractor:
    @pytest.mark.unit
    def test_extract_full_json(self):
        body = json.dumps({
            "project_info": {
                "project_id":     "my-victim-proj-2",
                "project_number": "999888",
                "firebase_url":   "https://my-victim-proj-2.firebaseio.com",
                "storage_bucket": "my-victim-proj-2.appspot.com",
            },
            "client": [{
                "client_info": {
                    "mobilesdk_app_id": "1:999888:android:xyz789",
                },
            }],
        }).encode()
        cfgs = gas._extract_firebase_configs_from_google_services_json(body, "gs.json")
        assert len(cfgs) == 1
        cfg = cfgs[0]
        assert cfg["project_id"]     == "my-victim-proj-2"
        assert cfg["project_number"] == "999888"
        assert cfg["database_url"]   == "https://my-victim-proj-2.firebaseio.com"
        assert cfg["storage_bucket"] == "my-victim-proj-2.appspot.com"
        assert cfg["google_app_id"]  == "1:999888:android:xyz789"

    @pytest.mark.unit
    def test_multiple_clients_emit_multiple_configs(self):
        body = json.dumps({
            "project_info": {"project_id": "vp", "project_number": "1"},
            "client": [
                {"client_info": {"mobilesdk_app_id": "1:1:android:a"}},
                {"client_info": {"mobilesdk_app_id": "1:1:android:b"}},
            ],
        }).encode()
        cfgs = gas._extract_firebase_configs_from_google_services_json(body)
        assert len(cfgs) == 2
        assert {c["google_app_id"] for c in cfgs} == {"1:1:android:a", "1:1:android:b"}

    @pytest.mark.unit
    def test_invalid_json_returns_empty(self):
        assert gas._extract_firebase_configs_from_google_services_json(b"{not json") == []


@pytest.mark.skipif(not HAS_EXTRACTORS, reason="Config extractors are unavailable in this frontend")
class TestStringsXmlExtractor:
    @pytest.mark.unit
    def test_extract_firebase_fields(self):
        xml = (b'<?xml version="1.0" encoding="utf-8"?>'
               b'<resources>'
               b'<string name="firebase_database_url">https://x.firebaseio.com</string>'
               b'<string name="google_storage_bucket">x.appspot.com</string>'
               b'<string name="google_app_id">1:1:android:zzz</string>'
               b'<string name="gcm_defaultSenderId">123456</string>'
               b'<string name="project_id">x</string>'
               b'<string name="unrelated">noise</string>'
               b'</resources>')
        cfgs = gas._extract_firebase_configs_from_strings_xml(xml, "strings.xml")
        assert len(cfgs) == 1
        cfg = cfgs[0]
        assert cfg["database_url"]   == "https://x.firebaseio.com"
        assert cfg["storage_bucket"] == "x.appspot.com"
        assert cfg["google_app_id"]  == "1:1:android:zzz"
        assert cfg["project_number"] == "123456"
        assert cfg["project_id"]     == "x"

    @pytest.mark.unit
    def test_no_firebase_fields_returns_empty(self):
        xml = b'<?xml version="1.0"?><resources><string name="other">x</string></resources>'
        assert gas._extract_firebase_configs_from_strings_xml(xml) == []

    @pytest.mark.unit
    def test_invalid_xml_returns_empty(self):
        assert gas._extract_firebase_configs_from_strings_xml(b"<not xml>") == []

    @pytest.mark.unit
    def test_size_cap_drops_huge_xml(self):
        huge = b"<resources>" + (b"<string name=\"x\">y</string>" * 100000) + b"</resources>"
        # Over 1 MB → must drop without OOM.
        assert gas._extract_firebase_configs_from_strings_xml(huge) == []


@pytest.mark.skipif(not HAS_EXTRACTORS, reason="Config extractors are unavailable in this frontend")
class TestInlineJsExtractor:
    @pytest.mark.unit
    def test_modular_firebase_config_assignment(self):
        body = ('const firebaseConfig = {'
                '  apiKey: "AIzaSyXX",'
                '  projectId: "site-v",'
                '  databaseURL: "https://site-v-default-rtdb.us-central1.firebasedatabase.app",'
                '  storageBucket: "site-v.appspot.com",'
                '  appId: "1:111:web:zzz",'
                '};')
        cfgs = gas._extract_firebase_configs_from_js(body, "app.js")
        assert len(cfgs) == 1
        cfg = cfgs[0]
        assert cfg["project_id"]     == "site-v"
        assert cfg["database_url"]   == "https://site-v-default-rtdb.us-central1.firebasedatabase.app"
        assert cfg["storage_bucket"] == "site-v.appspot.com"
        assert cfg["google_app_id"]  == "1:111:web:zzz"

    @pytest.mark.unit
    def test_initializeApp_inline_object(self):
        body = ('firebase.initializeApp({apiKey: "AIzaSyXX",'
                'projectId: "site-w", appId: "1:222:web:abc"});')
        cfgs = gas._extract_firebase_configs_from_js(body)
        assert len(cfgs) == 1
        assert cfgs[0]["project_id"]    == "site-w"
        assert cfgs[0]["google_app_id"] == "1:222:web:abc"

    @pytest.mark.unit
    def test_unrelated_js_object_not_extracted(self):
        body = 'const otherConfig = {host: "x", port: 8080, debug: true};'
        # No projectId/appId/apiKey field — must be rejected.
        assert gas._extract_firebase_configs_from_js(body) == []

    @pytest.mark.unit
    def test_url_with_double_slash_does_not_break_parser(self):
        # Regression — the `://` substring in databaseURL must survive
        # the JS line-comment stripper.
        body = ('const firebaseConfig = {apiKey: "AIzaSyXX", '
                'projectId: "x", databaseURL: "https://x.firebaseio.com"};')
        cfgs = gas._extract_firebase_configs_from_js(body)
        assert len(cfgs) == 1
        assert cfgs[0]["database_url"] == "https://x.firebaseio.com"


HAS_ARCHIVE_WALKER = hasattr(gas, "_extract_firebase_configs_from_archive")


@pytest.mark.skipif(not HAS_ARCHIVE_WALKER,
                    reason="Archive extraction is unavailable in this frontend")
class TestArchiveWalker:
    @pytest.mark.unit
    def test_apk_with_google_services_and_strings(self, tmp_path):
        gs = json.dumps({
            "project_info": {
                "project_id": "ap", "project_number": "1",
                "firebase_url": "https://ap.firebaseio.com",
                "storage_bucket": "ap.appspot.com",
            },
            "client": [{"client_info": {"mobilesdk_app_id": "1:1:android:a"}}],
        }).encode()
        strings = (b'<?xml version="1.0"?><resources>'
                   b'<string name="firebase_database_url">https://ap-extra.firebaseio.com</string>'
                   b'</resources>')
        apk_path = tmp_path / "victim.apk"
        with zipfile.ZipFile(apk_path, "w") as zf:
            zf.writestr("google-services.json", gs)
            zf.writestr("res/values/strings.xml", strings)
        cfgs = gas._extract_firebase_configs_from_archive(str(apk_path))
        # At least one config from JSON, plus one from XML.
        assert len(cfgs) >= 2
        project_ids = {c.get("project_id") for c in cfgs}
        assert "ap" in project_ids

    @pytest.mark.unit
    def test_ipa_with_plist(self, tmp_path):
        plist = plistlib.dumps({
            "PROJECT_ID": "ip", "GCM_SENDER_ID": "9",
            "DATABASE_URL": "https://ip.firebaseio.com",
            "STORAGE_BUCKET": "ip.appspot.com",
            "GOOGLE_APP_ID": "1:9:ios:p",
        })
        ipa_path = tmp_path / "victim.ipa"
        with zipfile.ZipFile(ipa_path, "w") as zf:
            zf.writestr("Payload/Victim.app/GoogleService-Info.plist", plist)
        cfgs = gas._extract_firebase_configs_from_archive(str(ipa_path))
        assert len(cfgs) == 1
        assert cfgs[0]["project_id"]   == "ip"
        assert cfgs[0]["database_url"] == "https://ip.firebaseio.com"

    @pytest.mark.unit
    def test_malformed_archive_returns_empty(self, tmp_path):
        bad = tmp_path / "garbage.apk"
        bad.write_bytes(b"not a zip")
        assert gas._extract_firebase_configs_from_archive(str(bad)) == []
