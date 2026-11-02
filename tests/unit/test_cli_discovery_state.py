"""Discovery transport, attribution and persistence contracts."""
import sys

import pytest

import google_api_scanner as scanner

pytestmark = pytest.mark.skipif(
    getattr(scanner, "_OVERLAY_FILENAME", None) is not None,
    reason="This suite exercises the public CLI",
)
KEY_A = "AIza" + "A" * 35
KEY_B = "AIza" + "B" * 35


@pytest.fixture
def scan_calls(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setenv("GAPISCANNER_DATA_DIR", str(tmp_path / "state"))
    scanner._reset_transport_errors()
    scanner._capture_last_transport_errors()
    scanner._capture_last_confirmed_severity_counts({})
    scanner._capture_last_scan_result_snapshot([])
    scanner._capture_last_scan_diagnostic_snapshot([])
    def scan(key, **kwargs):
        calls.append((key, kwargs))
        return []
    monkeypatch.setattr(scanner, "scan_gapis", scan)
    return calls


def run_cli(monkeypatch, args):
    monkeypatch.setattr(sys, "argv", ["gapiscanner", *args])
    with pytest.raises(SystemExit) as result:
        scanner.main()
    assert result.value.code == 0


def test_url_discovery_preserves_selected_proxy(monkeypatch, scan_calls):
    url = "https://example.com/app.js"
    monkeypatch.setattr(scanner, "discover_keys_from_url", lambda *a, **kw: ({KEY_A}, {KEY_A: {url}}))
    run_cli(monkeypatch, ["--url", url, "--proxy", "http://localhost:8080"])
    assert scan_calls
    assert all(options["proxy"] == "http://localhost:8080" for _, options in scan_calls)


def test_url_discovery_records_key_and_source(monkeypatch, scan_calls):
    url = "https://example.com/app.js"
    monkeypatch.setattr(scanner, "discover_keys_from_url", lambda *a, **kw: ({KEY_A}, {KEY_A: {url}}))
    run_cli(monkeypatch, ["--url", url])
    kb = scanner._kb_load()
    assert KEY_A in kb
    assert any(source.get("url") == url for source in kb[KEY_A]["sources"])


def test_mobile_key_does_not_inherit_another_archive_restriction(monkeypatch, tmp_path, scan_calls):
    first = tmp_path / "first.apk"
    second = tmp_path / "second.apk"
    first.touch()
    second.touch()
    cert = "AA" * 20
    label = "mobile:android:com.example.first:" + cert
    monkeypatch.setattr(scanner, "_run_mobile_batch", lambda *a, **kw: (
        {KEY_A, KEY_B},
        {KEY_A: {"archive:first.apk", label}, KEY_B: {"archive:second.apk"}},
        {},
    ))
    monkeypatch.setattr(scanner, "_extract_android_package_and_sha1", lambda path, **kw: (
        ("com.example.first", cert) if path == str(first) else (None, None)))
    run_cli(monkeypatch, ["--mobile", str(first), "--mobile", str(second)])
    key_b_modes = [options.get("restriction_mode") for key, options in scan_calls if key == KEY_B]
    assert key_b_modes == [None]
