"""Tests for response checks."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import google_api_scanner as gas  # noqa: E402

SENTINEL_KEY = "AIzaSyXX" + "X" * 31


class FakeResponse:
    def __init__(self, status_code, body, url="https://example.googleapis.com/v1/x"):
        self.status_code = status_code
        self.text = body
        self.content = body.encode("utf-8")
        self.headers = {"Content-Type": "application/json"}
        self.request = SimpleNamespace(url=url)

    def json(self):
        return json.loads(self.text)


def _run_get_probe(monkeypatch, probe, response):
    def fake_get(url, *args, **kwargs):
        response.request.url = url
        return response

    monkeypatch.setattr(gas.requests, "get", fake_get)
    return gas._execute_probe(probe, SENTINEL_KEY, "test-project-123", {}, verbose=True)


class TestRtdbResponseEval:
    @pytest.mark.unit
    def test_empty_rtdb_is_low_info_not_data_dump(self, monkeypatch):
        probe = (
            "Firebase RTDB root (.json)", "high", "GET",
            "https://{project}.firebaseio.com/.json?auth={key}",
            None, gas._check_firebase_rtdb_root,
            "Data leak - Firebase RTDB root",
        )
        result = _run_get_probe(monkeypatch, probe, FakeResponse(200, "{}"))

        assert result["vulnerable"] is True
        assert result["manual_note"] == "open_empty"
        assert result["name"] == "Firebase RTDB open but empty"
        assert result["category"] == "low"
        assert result["abuse_class"] == "Recon"
        assert "empty" in result["impact"].lower()

    @pytest.mark.unit
    def test_denied_rtdb_is_not_vulnerable_and_classified(self, monkeypatch):
        probe = (
            "Firebase RTDB root (.json)", "high", "GET",
            "https://{project}.firebaseio.com/.json?auth={key}",
            None, gas._check_firebase_rtdb_root,
            "Data leak - Firebase RTDB root",
        )
        result = _run_get_probe(
            monkeypatch,
            probe,
            FakeResponse(401, '{"error":"Permission denied"}'),
        )

        assert result["vulnerable"] is False
        assert result["error_class"] == "PERMISSION_DENIED"


class TestStructuralDsl:
    @pytest.mark.unit
    def test_generic_dsl_tokens_use_json_structure(self):
        check = gas._parse_check("200+kw:items+ne:error")
        ok = FakeResponse(200, '{"items":[{"name":"error budget"}]}')
        denied = FakeResponse(
            200,
            '{"items":[],"error":{"status":"PERMISSION_DENIED","message":"nope"}}',
        )

        assert check(ok) == (True, None)
        assert check(denied) == (False, None)

    @pytest.mark.unit
    def test_maps_request_denied_not_authorized_maps_to_service_blocked(self, monkeypatch):
        probe = (
            "Directions", "maps", "GET",
            "https://maps.googleapis.com/maps/api/directions/json?origin=A&destination=B&key={key}",
            None, "ne:error_message",
            "$5 per 1000 requests",
        )
        response = FakeResponse(
            200,
            json.dumps({
                "status": "REQUEST_DENIED",
                "error_message": "This API project is not authorized to use this API.",
            }),
        )

        assert gas._parse_check("ne:error_message")(response) == (False, None)
        result = _run_get_probe(monkeypatch, probe, response)
        assert result["vulnerable"] is False
        assert result["error_class"] == "SERVICE_BLOCKED"
