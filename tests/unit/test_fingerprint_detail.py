"""Regression coverage for fingerprint detail."""
from __future__ import annotations

import io
from contextlib import redirect_stdout

import pytest

import google_api_scanner as gas


def _result(name, category, error_class, service, vulnerable=False):
    return {
        "name": name, "category": category, "abuse_class": None,
        "url": "https://%s/v1/x?key=AIzaX" % service, "impact": "n/a",
        "vulnerable": vulnerable, "manual_note": None,
        "referer_blocked": False, "error_class": error_class,
        "services_seen": {service}, "reason": error_class or "",
        "gemini_disabled": False, "status_code": 403, "snippet": None,
        "impact_type": "info_disclosure", "confirmation": "key_accepted_only",
        "data_sensitivity": "none", "severity": "INFO",
        "tier": "CONFIRMED" if vulnerable else None,
        "check_signature": "fake",
    }


def _run_scan(monkeypatch, probe_results, fingerprint_detail="concise"):
    """Drive scan_gapis with a synthetic ALL_PROBES whose _execute_probe
    returns the supplied per-probe results, and capture stdout."""
    by_name = {r["name"]: r for r in probe_results}

    def fake_execute(probe_tuple, apikey, project_id, base_headers,
                     verbose=False):
        r = dict(by_name[probe_tuple[0]])
        return r

    probes = [(r["name"], r["category"], "GET",
               "https://%s/v1/x?key={key}" % next(iter(r["services_seen"])),
               None, "200", "fake") for r in probe_results]
    monkeypatch.setattr(gas, "_execute_probe", fake_execute)
    monkeypatch.setattr(gas, "ALL_PROBES", probes)
    monkeypatch.setattr(gas, "PHASE_0_PROBE_NAMES", ())
    monkeypatch.setattr(gas, "FIREBASE_CHAIN_PROBES", [])
    with gas._DERIVED_FIREBASE_LOCK:
        gas._DERIVED_FIREBASE_CONFIGS.clear()
    with gas._DERIVED_LOCK:
        gas._DERIVED_PROJECT_IDS.clear()
        gas._DERIVED_PROJECT_NUMBERS.clear()
    buf = io.StringIO()
    with redirect_stdout(buf):
        gas.scan_gapis("AIzaSyTEST" + "x" * 27, quiet=False, skip_jsapi=True,
                       threads=1, no_color=True,
                       fingerprint_detail=fingerprint_detail)
    return buf.getvalue()


# 12 distinct services all in the does-not-accept-api-keys (capped) bucket.
def _many_unsupported(n=12):
    return [_result("P%02d" % i, "high", "API_KEY_UNSUPPORTED",
                    "svc%02d.googleapis.com" % i) for i in range(n)]


class TestConciseCapping:
    @pytest.mark.unit
    def test_concise_caps_noisy_bucket(self, monkeypatch):
        out = _run_scan(monkeypatch, _many_unsupported(12),
                        fingerprint_detail="concise")
        assert "does-not-accept-api-keys (12)" in out
        assert "re-run with --fingerprint-detail full" in out
        # Only 8 services + the "... more" line are shown.
        assert "svc07.googleapis.com" in out
        assert "svc11.googleapis.com" not in out

    @pytest.mark.unit
    def test_full_lists_every_service(self, monkeypatch):
        out = _run_scan(monkeypatch, _many_unsupported(12),
                        fingerprint_detail="full")
        assert "does-not-accept-api-keys (12)" in out
        assert "re-run with --fingerprint-detail full" not in out
        # Every service appears, including the ones concise would cap.
        for i in range(12):
            assert "svc%02d.googleapis.com" % i in out


class TestBlockedBucketsShown:
    @pytest.mark.unit
    def test_android_blocked_service_listed(self, monkeypatch):
        out = _run_scan(monkeypatch, [
            _result("AndroidProbe", "high", "ANDROID_BLOCKED",
                    "maps.googleapis.com"),
        ])
        assert "android-blocked (1)" in out
        assert "maps.googleapis.com" in out

    @pytest.mark.unit
    def test_ios_blocked_service_listed(self, monkeypatch):
        out = _run_scan(monkeypatch, [
            _result("IosProbe", "high", "IOS_BLOCKED",
                    "firebaseio.googleapis.com"),
        ])
        assert "ios-blocked (1)" in out
        assert "firebaseio.googleapis.com" in out

    @pytest.mark.unit
    def test_ip_blocked_service_listed(self, monkeypatch):
        out = _run_scan(monkeypatch, [
            _result("IpProbe", "high", "IP_BLOCKED", "spanner.googleapis.com"),
        ])
        assert "ip-blocked (1)" in out
        assert "spanner.googleapis.com" in out


class TestClarifyingWording:
    @pytest.mark.unit
    def test_api_disabled_wording(self, monkeypatch):
        out = _run_scan(monkeypatch, [
            _result("DisProbe", "high", "API_DISABLED", "pubsub.googleapis.com"),
        ])
        assert "api-disabled-in-project (1)" in out
        # Clear "per-project, not a key vulnerability" wording.
        assert "per-project" in out
        assert "not a key vulnerability" in out

    @pytest.mark.unit
    def test_unauthenticated_wording(self, monkeypatch):
        out = _run_scan(monkeypatch, [
            _result("UnauthProbe", "high", "UNAUTHENTICATED",
                    "iam.googleapis.com"),
        ])
        assert "unauthenticated (1)" in out
        assert "generic 401 auth failure" in out

    @pytest.mark.unit
    def test_does_not_accept_wording(self, monkeypatch):
        out = _run_scan(monkeypatch, _many_unsupported(2))
        assert "protocol-rejects API-key auth" in out


class TestJsonAlwaysFull:
    @pytest.mark.unit
    def test_json_allowlist_uncapped(self):
        """Even in concise textual mode, the JSON output lists every
        service in every bucket (machine-readable diagnostics are full)."""
        results = _many_unsupported(20)
        out = gas._build_json_output(results, tested_count=20,
                                     options={"fingerprint_detail": "concise"})
        bucket = out["service_allowlist_inference"].get(
            "does-not-accept-api-keys", [])
        assert len(bucket) == 20

    @pytest.mark.unit
    def test_json_carries_blocked_services(self):
        results = [
            _result("A", "high", "ANDROID_BLOCKED", "maps.googleapis.com"),
            _result("B", "high", "IOS_BLOCKED", "fcm.googleapis.com"),
        ]
        out = gas._build_json_output(results, tested_count=2, options={})
        allowlist = out["service_allowlist_inference"]
        assert "maps.googleapis.com" in allowlist.get("android-blocked", [])
        assert "fcm.googleapis.com" in allowlist.get("ios-blocked", [])
