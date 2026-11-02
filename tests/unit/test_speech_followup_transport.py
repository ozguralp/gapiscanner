"""Speech follow-up failures must preserve the scan completeness signal."""
import json

import pytest
import requests

import google_api_scanner as scanner


def response(status, payload):
    item = requests.Response()
    item.status_code = status
    item._content = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    return item


@pytest.mark.parametrize("status,body", [
    (429, {"error": {"code": 429}}),
    (503, {"error": {"code": 503}}),
    (200, b"<html>maintenance</html>"),
    (200, []),
    (200, None),
])
def test_speech_detail_failure_marks_scan_incomplete(monkeypatch, status, body):
    scanner._reset_transport_errors()
    responses = iter([
        response(200, {"operations": [{"name": "123", "done": True}]}),
        response(status, body),
    ])
    monkeypatch.setattr(scanner.requests, "get", lambda *a, **kw: next(responses))
    probe = next(p for p in scanner.ALL_PROBES if p[0] == "Speech Operations")
    result = scanner._execute_probe(probe, "AIza" + "x" * 35, None, {})
    assert result["severity"] == "LOW"
    assert result["operation_evidence"]["detail_incomplete"] is True
    assert scanner._transport_error_total() == 1


@pytest.mark.parametrize("status", [401, 403, 404])
def test_speech_detail_denial_is_complete_metadata_only(monkeypatch, status):
    scanner._reset_transport_errors()
    replies = iter([
        response(200, {"operations": [{"name": "123", "done": True}]}),
        response(status, {"error": {"code": status}}),
    ])
    monkeypatch.setattr(scanner.requests, "get", lambda *a, **kw: next(replies))
    probe = next(p for p in scanner.ALL_PROBES if p[0] == "Speech Operations")
    result = scanner._execute_probe(probe, "AIza" + "x" * 35, None, {})
    assert result["severity"] == "LOW"
    assert result["operation_evidence"]["detail_incomplete"] is False
    assert scanner._transport_error_total() == 0


def test_speech_detail_budget_exhaustion_marks_scan_incomplete(monkeypatch):
    scanner._reset_transport_errors()
    monkeypatch.setattr(scanner.requests, "get", lambda *a, **kw: response(200, {"done": False}))
    listed = response(200, {"operations": [{"name": str(i)} for i in range(2)]})
    evidence = scanner._inspect_speech_operations(
        listed, "https://speech.googleapis.com/v1/operations", "synthetic", {}, {}, max_details=1)
    assert evidence["detail_attempted"] == 1
    assert evidence["detail_incomplete"] is True
    assert scanner._transport_error_total() == 1
