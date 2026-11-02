"""Regression coverage for recon invalid argument."""
from __future__ import annotations

import io
from contextlib import redirect_stdout

import pytest

import google_api_scanner as gas


def _invalid_arg_result(name="Some Probe", service="pubsub.googleapis.com",
                        url=None):
    """A non-vulnerable INVALID_ARGUMENT (400) result — key accepted,
    body malformed."""
    return {
        "name": name,
        "category": "high",
        "abuse_class": None,
        "url": url or ("https://%s/v1/x?key=AIzaSyRAWSECRET01234567890abcdefgh"
                       % service),
        "impact": "n/a",
        "vulnerable": False,
        "manual_note": None,
        "referer_blocked": False,
        "error_class": "INVALID_ARGUMENT",
        "services_seen": {service},
        "reason": "INVALID_ARGUMENT: Request contains an invalid argument.",
        "gemini_disabled": False,
        "status_code": 400,
        "snippet": '{"error":{"code":400,"status":"INVALID_ARGUMENT",'
                   '"details":[{"metadata":{"service":"%s",'
                   '"method":"google.pubsub.v1.Publisher.CreateTopic"}}]}}' % service,
        "impact_type": "info_disclosure",
        "confirmation": "key_accepted_only",
        "data_sensitivity": "none",
        "severity": "INFO",
        "check_signature": "fake_check",
    }


def _vuln_result(name="Pub/Sub Topics"):
    return {
        "name": name, "category": "high", "abuse_class": "DataExfil",
        "url": "https://pubsub.googleapis.com/v1/x?key=AIzaX",
        "impact": "exfil", "vulnerable": True, "manual_note": None,
        "referer_blocked": False, "error_class": None, "services_seen": set(),
        "reason": "", "gemini_disabled": False, "status_code": 200,
        "snippet": None, "impact_type": "data_read",
        "confirmation": "confirmed_data", "data_sensitivity": "customer_data",
        "severity": "HIGH", "tier": "CONFIRMED", "check_signature": "fake",
    }


# Predicate / record / collector


class TestReconPredicate:
    @pytest.mark.unit
    def test_invalid_argument_nonvuln_is_recon(self):
        assert gas._is_malformed_body_accepted(_invalid_arg_result()) is True

    @pytest.mark.unit
    def test_vulnerable_invalid_argument_is_not_recon(self):
        r = _invalid_arg_result()
        r["vulnerable"] = True
        assert gas._is_malformed_body_accepted(r) is False

    @pytest.mark.unit
    def test_other_error_class_is_not_recon(self):
        r = _invalid_arg_result()
        r["error_class"] = "NOT_FOUND"
        assert gas._is_malformed_body_accepted(r) is False

    @pytest.mark.unit
    def test_record_shape(self):
        rec = gas._build_recon_record(_invalid_arg_result(name="My Probe"))

        assert set(rec.keys()) == {
            "name", "url", "status_code", "error_class",
            "service", "method", "check_signature"}
        assert rec["name"] == "My Probe"
        assert rec["status_code"] == 400
        assert rec["error_class"] == "INVALID_ARGUMENT"
        assert rec["service"] == "pubsub.googleapis.com"
        assert rec["method"] == "google.pubsub.v1.Publisher.CreateTopic"

    @pytest.mark.unit
    def test_record_url_redacted(self):
        rec = gas._build_recon_record(_invalid_arg_result())
        assert "AIzaSyRAWSECRET01234567890abcdefgh" not in rec["url"]
        assert "<redacted>" in rec["url"]

    @pytest.mark.unit
    def test_collector_filters_only_recon_rows(self):
        results = [
            _invalid_arg_result(name="A"),
            _vuln_result(),
            _invalid_arg_result(name="B"),
            {"name": "C", "vulnerable": False, "error_class": "NOT_FOUND"},
        ]
        recon = gas._collect_malformed_body_accepted(results)
        assert {r["name"] for r in recon} == {"A", "B"}


# JSON output: recon field present, never affects counts


class TestReconJsonOutput:
    @pytest.mark.unit
    def test_json_has_recon_field(self):
        out = gas._build_json_output(
            [_invalid_arg_result(name="A"), _invalid_arg_result(name="B")],
            tested_count=2, options={})
        assert "recon" in out
        assert "malformed_body_accepted" in out["recon"]
        assert len(out["recon"]["malformed_body_accepted"]) == 2

    @pytest.mark.unit
    def test_recon_does_not_inflate_counts(self):
        out = gas._build_json_output(
            [_invalid_arg_result(name="A"), _invalid_arg_result(name="B")],
            tested_count=2, options={})
        assert out["confirmed_count"] == 0
        assert out["confirmed_high_count"] == 0
        assert out["confirmed_med_count"] == 0
        assert out["potential_count"] == 0

    @pytest.mark.unit
    def test_recon_coexists_with_real_finding(self):
        out = gas._build_json_output(
            [_vuln_result(), _invalid_arg_result(name="A")],
            tested_count=2, options={})
        assert out["confirmed_count"] == 1
        assert out["confirmed_high_count"] == 1
        assert len(out["recon"]["malformed_body_accepted"]) == 1

    @pytest.mark.unit
    def test_no_raw_key_in_recon_json(self):
        import json
        out = gas._build_json_output(
            [_invalid_arg_result()], tested_count=1, options={})
        blob = json.dumps(out)
        assert "AIzaSyRAWSECRET01234567890abcdefgh" not in blob


# End-to-end: SUMMARY line + exit-code invariant via scan_gapis


class TestReconEndToEnd:
    def _run(self, monkeypatch, result_factory):
        def fake_execute(probe_tuple, apikey, project_id, base_headers,
                         verbose=False):
            r = result_factory()
            r["name"] = probe_tuple[0]
            r["category"] = probe_tuple[1]
            return r

        monkeypatch.setattr(gas, "_execute_probe", fake_execute)
        monkeypatch.setattr(gas, "ALL_PROBES",
                            [("Some Probe", "high", "GET",
                              "https://pubsub.googleapis.com/v1/x?key={key}",
                              None, "200", "fake")])
        monkeypatch.setattr(gas, "PHASE_0_PROBE_NAMES", ())
        monkeypatch.setattr(gas, "FIREBASE_CHAIN_PROBES", [])
        with gas._DERIVED_FIREBASE_LOCK:
            gas._DERIVED_FIREBASE_CONFIGS.clear()
        with gas._DERIVED_LOCK:
            gas._DERIVED_PROJECT_IDS.clear()
            gas._DERIVED_PROJECT_NUMBERS.clear()
        buf = io.StringIO()
        with redirect_stdout(buf):
            ret = gas.scan_gapis("AIzaSyTEST" + "x" * 27, quiet=False,
                                 skip_jsapi=True, threads=1, no_color=True)
        return buf.getvalue(), ret

    @pytest.mark.unit
    def test_summary_prints_recon_line(self, monkeypatch):
        out, ret = self._run(monkeypatch, _invalid_arg_result)
        assert "Recon: 1 malformed-body accepted endpoint(s)" in out

    @pytest.mark.unit
    def test_recon_only_scan_returns_no_confirmed(self, monkeypatch):
        out, ret = self._run(monkeypatch, _invalid_arg_result)
        # scan_gapis returns CONFIRMED names only — recon is not one.
        assert ret == []
        # The severity snapshot must show zero HIGH (no reportable finding).
        assert gas._last_confirmed_high_total() == 0
        assert gas._classify_scan_vulnerable(ret, False) is False

    @pytest.mark.unit
    def test_no_recon_line_when_no_invalid_argument(self, monkeypatch):
        def clean_result():
            r = _invalid_arg_result()
            r["error_class"] = None  # not INVALID_ARGUMENT
            return r
        out, ret = self._run(monkeypatch, clean_result)
        assert "Recon:" not in out
