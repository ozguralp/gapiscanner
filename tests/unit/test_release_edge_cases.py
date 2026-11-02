"""Regression coverage for persistence, redirects and malformed API responses."""
import json
import sys
from types import SimpleNamespace

import pytest
import requests

import google_api_scanner as scanner
from gapiscanner_core.authorization import check_vertex_authorization_count_tokens
from gapiscanner_core.mobile_kb import mobile_restrictions_from_kb_entry
from gapiscanner_core.url_budget import load_url_queue_completed_urls


@pytest.fixture(autouse=True)
def isolated_kb_location(monkeypatch, tmp_path):
    monkeypatch.setattr(scanner, "_kb_path", lambda output_dir=None: str(tmp_path / "key_kb.json"))


def response(payload, status=200, url="https://example.googleapis.com/v1/list"):
    result = requests.Response()
    result.status_code = status
    result._content = json.dumps(payload).encode()
    result.url = url
    result.request = requests.Request("GET", url).prepare()
    return result


@pytest.mark.parametrize("value", [None, 7, "https://example.com", {}])
def test_malformed_completed_queue_is_ignored(tmp_path, value):
    path = tmp_path / "queue.json"
    path.write_text(json.dumps({"completed": value}))
    assert load_url_queue_completed_urls(path) == set()


@pytest.mark.parametrize("body", ['{', '[]', '{"key":null}', '{"key":{"sources":2}}'])
def test_corrupt_kb_is_preserved_on_write(tmp_path, body):
    path = tmp_path / "key_kb.json"
    path.write_text(body)
    with pytest.raises(ValueError, match="file preserved"):
        scanner._kb_record_discovery("synthetic", "https://example.com", "example", "url", "now", output_dir=str(tmp_path))
    assert path.read_text() == body


def test_legacy_kb_sources_export_without_data_loss(tmp_path):
    path = tmp_path / "key_kb.json"
    path.write_text(json.dumps({"synthetic": {"sources": ["mobile:ios:com.example.app"]}}))
    output = tmp_path / "keys.csv"
    assert scanner._kb_export_csv(str(output), output_dir=str(tmp_path)) == 1
    assert "mobile:ios:com.example.app" in output.read_text()


def test_legacy_scalar_mobile_restriction_is_preserved():
    label = "mobile:ios:com.example.app"
    assert mobile_restrictions_from_kb_entry({"mobile_restrictions": label, "sources": 7}) == [label]


@pytest.mark.parametrize("value", [float("nan"), float("inf"), 1.5, True, -1])
def test_authorization_count_requires_nonnegative_integer(value):
    assert check_vertex_authorization_count_tokens(response({"totalTokens": value}))[0] is False


@pytest.mark.parametrize("payload", [False, 0, "", "example", {"error": True}])
def test_rtdb_shallow_valid_values_are_supported(monkeypatch, payload):
    monkeypatch.setattr(scanner.requests, "get", lambda *a, **k: response(payload))
    row = scanner._authenticated_rtdb_read("https://example-project.firebaseio.com", "token")
    assert row["vulnerable"] is True
    assert row["manual_note"] != "auth_read_rtdb_empty"
    assert row["snippet"] is None


@pytest.mark.parametrize("payload", [[], False, {"error": "denied"}, {"collectionIds": 7}, {"collectionIds": [None]}])
def test_authenticated_firestore_rejects_invalid_payload(monkeypatch, payload):
    scanner._reset_transport_errors()
    monkeypatch.setattr(scanner.requests, "post", lambda *a, **k: response(payload))
    assert scanner._authenticated_firestore_read("example-project", "key", "token") is None
    assert scanner._transport_error_total() == 1


@pytest.mark.parametrize("status", [429, 503])
def test_authenticated_storage_temporary_errors_are_incomplete(monkeypatch, status):
    scanner._reset_transport_errors()
    monkeypatch.setattr(scanner.requests, "get", lambda *a, **k: response({}, status))
    assert scanner._authenticated_storage_list("example.appspot.com", "key", "token") is None
    assert scanner._transport_error_total() == 1


def test_collection_check_rejects_error_envelope():
    assert scanner._check_non_empty_list(response({"error": "denied", "items": [1]}))[0] is False
    assert scanner._check_non_empty_operations_list(response({"operations": [None]}))[0] is False
    assert scanner._check_firestore_documents(response({"error": "denied"}))[0] is False


@pytest.mark.parametrize("provider", ["_dns_enum_crtsh", "_dns_enum_certspotter", "_dns_enum_wayback", "_dns_enum_otx"])
def test_malformed_passive_dns_data_does_not_crash(monkeypatch, provider):
    monkeypatch.setattr(scanner.requests, "get", lambda *a, **k: response({"error": "unavailable"}))
    assert getattr(scanner, provider)("example.com") == set()


def test_redirected_keys_keep_final_source_on_resume(monkeypatch, tmp_path):
    key = "AIza" + "R" * 35
    original = "https://example.com/app.js"
    final = "https://cdn.example.net/app.js"
    calls = []
    def fetch(url, **kwargs):
        calls.append(url)
        return SimpleNamespace(status_code=200, text=key, url=final, headers={})
    monkeypatch.setattr(scanner.requests, "get", fetch)
    for resume in (False, True):
        keys, sources = scanner._fetch_and_extract_keys({original}, seed_url=original, cache_dir=str(tmp_path), resume=resume)
        assert keys == {key}
        assert sources[key] == {final}
    assert calls == [original]


def test_redirected_relative_script_uses_final_directory(monkeypatch):
    original = "https://example.com/start"
    final = "https://example.com/app/"
    monkeypatch.setattr(scanner.requests, "get", lambda *a, **k: SimpleNamespace(text='<script src="main.js"></script>', url=final, status_code=200, headers={}))
    assert "https://example.com/app/main.js" in scanner._crawl_with_python(original, max_pages=1)


def test_rtdb_write_uses_unique_node_each_time(monkeypatch):
    urls = []
    def put(url, **kwargs):
        urls.append(url)
        return response("probe", url=url)
    monkeypatch.setattr(scanner.requests, "put", put)
    monkeypatch.setattr(scanner, "_dangerous_probe_skip_reason", lambda *a: None)
    probe = next(p for p in scanner.FIREBASE_CHAIN_PROBES if p[0] == "Firebase RTDB write probe")
    for _ in range(2):
        result = scanner._execute_probe(probe, "key", "example-project", {})
        assert result["url"] == urls[-1]
    assert len(set(urls)) == 2
    assert all("{probe_path}" not in url and "__gapiscanner_probe__.json" not in url for url in urls)


@pytest.mark.skipif(getattr(scanner, "_OVERLAY_FILENAME", None) is not None, reason="Public CLI contract")
def test_mobile_passes_keep_their_own_project_and_cleanup_metadata(monkeypatch, tmp_path):
    monkeypatch.setenv("GAPISCANNER_DATA_DIR", str(tmp_path / "data"))
    key = "AIza" + "K" * 35
    archive = tmp_path / "app.ipa"
    archive.touch()
    monkeypatch.setattr(scanner, "_run_mobile_batch", lambda *a, **k: ({key}, {key: {"mobile:ios:com.example.app"}}, {}))
    def scan(*args, **kwargs):
        mode = kwargs.get("restriction_mode") or "unrestricted"
        scanner._DERIVED_PROJECT_IDS.clear()
        scanner._DERIVED_PROJECT_IDS.add(mode + "-project")
        scanner._IDENTITY_TOOLKIT_ARTIFACTS.clear()
        scanner._it_record_artifact("signUp", mode + "-account", None, "cleanup failed")
        scanner._reset_transport_errors()
        scanner._capture_last_transport_errors()
        scanner._capture_last_scan_result_snapshot([])
        scanner._capture_last_scan_diagnostic_snapshot([])
        scanner._capture_last_confirmed_severity_counts({})
        return []
    monkeypatch.setattr(scanner, "scan_gapis", scan)
    monkeypatch.setattr(sys, "argv", ["gapiscanner", "--mobile", str(archive)])
    with pytest.raises(SystemExit) as result:
        scanner.main()
    assert result.value.code == 0
    history = scanner._kb_load()[key]["scan_history"]
    assert [row["project_id"] for row in history] == ["unrestricted-project", "ios-project"]
    assert [row["identity_toolkit_cleanup_failures"][0]["local_id"] for row in history] == ["unrestricted-account", "ios-account"]


@pytest.mark.parametrize("check", ["_check_it_sms_delivery", "_check_it_oob_email_delivery"])
@pytest.mark.parametrize("payload", [{}, [], {"error": "denied"}])
def test_oob_delivery_requires_documented_success_fields(check, payload):
    assert getattr(scanner, check)(response(payload))[0] is False


def test_authenticated_reads_preserve_client_context_and_replace_credentials(monkeypatch):
    calls = []
    def send(url, **kwargs):
        calls.append(kwargs["headers"])
        return response({})
    monkeypatch.setattr(scanner.requests, "post", send)
    monkeypatch.setattr(scanner.requests, "get", send)
    headers = {"X-Ios-Bundle-Identifier": "com.example.app", "Cookie": "private", "Authorization": "ambient"}
    scanner._authenticated_firestore_read("example-project", "key", "identity", restriction_headers=headers)
    scanner._authenticated_storage_list("example.appspot.com", "key", "identity", restriction_headers=headers)
    assert len(calls) == 2
    for sent in calls:
        assert sent["X-Ios-Bundle-Identifier"] == "com.example.app"
        assert sent["Authorization"] == "Bearer identity"
        assert "Cookie" not in sent
