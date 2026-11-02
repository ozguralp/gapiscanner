"""Discovery-mode --output aggregate JSON regression.

The URL/mobile discovery loop scans each key with per-call output disabled, then
must write one redacted aggregate artifact after all passes complete.
"""
from __future__ import annotations

import json
import sys

import pytest

import google_api_scanner as gas


@pytest.mark.unit
def test_mobile_discovery_output_is_written_and_redacts_raw_key(
        tmp_path, monkeypatch):
    mobile_path = tmp_path / "sample.apk"
    mobile_path.write_bytes(b"placeholder")
    output_path = tmp_path / "results.json"
    raw_key = "AIza" + "x" * 35

    def fake_mobile_batch(paths, **kwargs):
        assert paths == [str(mobile_path)]
        return (
            {raw_key},
            {raw_key: {"mobile:%s" % mobile_path}},
            {},
        )

    def fake_scan(key, **kwargs):
        assert key == raw_key
        gas._capture_last_scan_result_snapshot(
            [], restriction_mode=kwargs.get("restriction_mode"),
            restriction_value=kwargs.get("restriction_value"))
        gas._capture_last_scan_diagnostic_snapshot([])
        gas._capture_last_confirmed_severity_counts(
            {"HIGH": 0, "MED": 0, "LOW_INFO": 0})
        gas._reset_transport_errors()
        gas._capture_last_transport_errors()
        return []

    monkeypatch.setattr(gas, "_run_mobile_batch", fake_mobile_batch)
    monkeypatch.setattr(gas, "scan_gapis", fake_scan)
    monkeypatch.setattr(
        gas, "_extract_android_package_and_sha1",
        lambda *args, **kwargs: (None, None))
    monkeypatch.setattr(gas, "_kb_record_scan", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        sys, "argv",
        [
            "google_api_scanner.py",
            "--mobile", str(mobile_path),
            "--output", str(output_path),
            "--output-dir", str(tmp_path / "state"),
            "--quiet",
        ],
    )

    with pytest.raises(SystemExit) as exc_info:
        gas.main()

    assert exc_info.value.code == 0
    data = json.loads(output_path.read_text(encoding="utf-8"))
    serialized = json.dumps(data, sort_keys=True)
    assert data["mode"] == "mobile"
    assert data["in_scope_key_count"] == 1
    assert data["out_of_scope_key_count"] == 0
    assert data["transport_incomplete"] is False
    assert data["keys"][0]["key"] == gas._redact_key_display(raw_key)
    assert data["keys"][0]["pass1"]["restriction_mode"] == "unrestricted"
    assert raw_key not in serialized
