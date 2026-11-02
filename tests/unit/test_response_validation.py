import json

import pytest
import requests

import google_api_scanner as scanner


def response(body, status=200, content_type="application/json"):
    result = requests.Response()
    result.status_code = status
    result._content = body if isinstance(body, bytes) else body.encode()
    result.headers["Content-Type"] = content_type
    result.request = requests.Request("GET", "https://example.googleapis.com/v1/list?key=synthetic").prepare()
    return result


@pytest.mark.parametrize("payload", [None, 7, True, "unexpected", [None]])
def test_unexpected_json_error_body_does_not_crash_probe(monkeypatch, payload):
    monkeypatch.setattr(scanner.requests, "get", lambda *a, **kw: response(json.dumps(payload), 400))
    probe = ("Response validation", "low", "GET", "https://example.googleapis.com/v1/list?key={key}", None, "200+kw:items", "Test")
    result = scanner._execute_probe(probe, "synthetic", None, {})
    assert result["vulnerable"] is False
    assert result["status_code"] == 400


@pytest.mark.parametrize("body", [b'<html>Maintenance</html>', b'{"error":{"message":"denied"}}', b''])
def test_image_probe_rejects_non_image_success_body(body):
    assert scanner._parse_check("image")(response(body))[0] is False


def test_image_probe_accepts_png_signature():
    assert scanner._parse_check("image")(response(b'\x89PNG\r\n\x1a\n', content_type="image/png"))[0] is True


@pytest.mark.parametrize("check,body", [
    ("200", '<html>Maintenance</html>'),
    ("200+kw:models", '{"message":"models unavailable"}'),
    ("200+kw:candidates", '{"error":{"message":"candidates unavailable"}}'),
])
def test_json_probe_rejects_invalid_success_shape(check, body):
    assert scanner._parse_check(check)(response(body))[0] is False


@pytest.mark.parametrize("status", [429, 500, 503])
def test_temporary_api_failure_marks_scan_incomplete(monkeypatch, status):
    scanner._reset_transport_errors()
    monkeypatch.setattr(scanner.requests, "get", lambda *a, **kw: response('{"error":{"message":"retry later"}}', status))
    probe = ("Response validation", "low", "GET", "https://example.googleapis.com/v1/list?key={key}", None, "200+kw:items", "Test")
    scanner._execute_probe(probe, "synthetic", None, {})
    assert scanner._transport_error_total() == 1


@pytest.mark.parametrize("body", ['<html>Maintenance</html>', '[]', '{"error":"denied"}'])
def test_authenticated_rtdb_rejects_invalid_shallow_response(monkeypatch, body):
    monkeypatch.setattr(scanner.requests, "get", lambda *a, **kw: response(body))
    result = scanner._authenticated_rtdb_read("https://example-project.firebaseio.com", "synthetic-token")
    assert result is None or result["vulnerable"] is False


def test_authenticated_rtdb_empty_object_is_not_customer_data(monkeypatch):
    monkeypatch.setattr(scanner.requests, "get", lambda *a, **kw: response('{}'))
    result = scanner._authenticated_rtdb_read("https://example-project.firebaseio.com", "synthetic-token")
    assert result["severity"] == "INFO"
    assert result["data_sensitivity"] == "none"
