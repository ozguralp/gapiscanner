"""Tests for transport security."""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import google_api_scanner as gas  # noqa: E402


# 1. TLS split — `_should_verify_tls` + `_request_kwargs_for_url`

class TestShouldVerifyTLS:
    @pytest.mark.unit
    @pytest.mark.parametrize("url", [
        "https://identitytoolkit.googleapis.com/v1/accounts:signUp",
        "https://firestore.googleapis.com/v1/projects/x/databases/(default)/documents",
        "https://firebasestorage.googleapis.com/v0/b/x/o",
        "https://maps.googleapis.com/maps/api/geocode/json",
        "https://generativelanguage.googleapis.com/v1beta/models",
        "https://my-app-default-rtdb.firebaseio.com/.json",
        "https://my-app.firebaseapp.com/",
        "https://my-app.firebasedatabase.app/.json",
        "https://oauth2.google.com/token",
        "https://www.google.com/",
        "https://my-proj.appspot.com/",
        "https://my-fn.cloudfunctions.net/",
    ])
    def test_google_endpoints_verify_tls(self, url):
        assert gas._should_verify_tls(url) is True

    @pytest.mark.unit
    @pytest.mark.parametrize("url", [
        "https://www.victim.com/",
        "https://api.example.com/v1",
        "http://1.2.3.4:8080/",
        "https://cdn.thirdparty.net/lib.js",
        "https://attacker.example/x",
    ])
    def test_non_google_endpoints_do_not_force_verify(self, url):
        assert gas._should_verify_tls(url) is False

    @pytest.mark.unit
    @pytest.mark.parametrize("garbage", [None, "", "not-a-url", 1234, []])
    def test_bad_input_returns_false(self, garbage):
        assert gas._should_verify_tls(garbage) is False


class TestRequestKwargsForURL:
    @pytest.mark.unit
    def test_google_url_gets_verify_true(self):
        kw = gas._request_kwargs_for_url(
            "https://identitytoolkit.googleapis.com/v1/accounts:signUp")
        assert kw["verify"] is True

    @pytest.mark.unit
    def test_unrelated_url_default_verify_true(self):
        kw = gas._request_kwargs_for_url("https://attacker.example/x")
        assert kw["verify"] is True

    @pytest.mark.unit
    def test_target_crawl_keeps_verify_false_for_unrelated(self):
        kw = gas._request_kwargs_for_url(
            "https://www.victim.com/", target_crawl=True)
        assert kw["verify"] is False

    @pytest.mark.unit
    def test_target_crawl_does_not_override_google(self):
        """Even if a probe site mistakenly passes target_crawl=True, Google
        URLs MUST verify TLS — never punch through for googleapis.com."""
        kw = gas._request_kwargs_for_url(
            "https://identitytoolkit.googleapis.com/v1/accounts:signUp",
            target_crawl=True)
        assert kw["verify"] is True

    @pytest.mark.unit
    def test_kwargs_copy_not_global_reference(self):
        kw = gas._request_kwargs_for_url(
            "https://identitytoolkit.googleapis.com/v1/accounts:signUp")
        kw["verify"] = False  # mutate local
        # Global _REQUEST_KWARGS unchanged.
        assert gas._REQUEST_KWARGS.get("verify") is False  # legacy default

    @pytest.mark.unit
    def test_proxies_preserved_through_helper(self):
        prior = gas._REQUEST_KWARGS.copy()
        try:
            gas._REQUEST_KWARGS["proxies"] = {"https": "http://proxy.local:8080"}
            kw = gas._request_kwargs_for_url(
                "https://firestore.googleapis.com/v1/x")
            assert kw["verify"] is True
            assert kw["proxies"] == {"https": "http://proxy.local:8080"}
        finally:
            gas._REQUEST_KWARGS.clear()
            gas._REQUEST_KWARGS.update(prior)


# 2. `_execute_probe` end-to-end TLS verification check

class TestExecuteProbeUsesVerifiedTLS:
    @pytest.mark.unit
    def test_probe_call_passes_verify_true_for_googleapis(self):
        """When `_execute_probe` is invoked against a *.googleapis.com URL,
        the requests.get call MUST receive verify=True."""
        probe_tuple = (
            "Test Probe", "high", "GET",
            "https://identitytoolkit.googleapis.com/v1/accounts:lookup?key={key}",
            None, "200", "Test impact",
        )
        captured_kwargs = {}

        class _FakeResp:
            status_code = 200
            text = ""
            content = b""
            headers = {"Content-Type": "application/json"}
            request = None
            def json(self): return {}

        def _stub_get(url, **kwargs):
            captured_kwargs.update(kwargs)
            r = _FakeResp()
            r.request = type("R", (), {"url": url})()
            return r

        with patch.object(gas.requests, "get", _stub_get):
            gas._execute_probe(probe_tuple,
                               "AIzaSyTEST" + "X" * 31,
                               "test-project", base_headers={})

        assert captured_kwargs.get("verify") is True, (
            f"googleapis.com probe must verify TLS; got {captured_kwargs}")


# 3. Cost-amp cap helper

class TestCapCostAmpDrain:
    @pytest.mark.unit
    def test_below_cap_passes_through(self):
        v, capped = gas._cap_cost_amp_drain(500.0)
        assert v == 500.0
        assert capped is False

    @pytest.mark.unit
    def test_above_cap_clamps(self):
        v, capped = gas._cap_cost_amp_drain(99999.99)
        assert v == gas._COST_AMP_DISPLAY_CAP_USD_PER_HR
        assert capped is True

    @pytest.mark.unit
    def test_equal_cap_not_marked_capped(self):
        v, capped = gas._cap_cost_amp_drain(
            gas._COST_AMP_DISPLAY_CAP_USD_PER_HR)
        assert v == gas._COST_AMP_DISPLAY_CAP_USD_PER_HR
        assert capped is False

    @pytest.mark.unit
    def test_garbage_returns_zero(self):
        for bad in (None, "abc", object()):
            v, capped = gas._cap_cost_amp_drain(bad)
            assert v == 0.0
            assert capped is False


# 4. Cost-amp wording — theoretical label + reachability separation

class TestCostAmpWording:
    @pytest.mark.unit
    def test_theoretical_label_text(self):
        assert "theoretical max" in gas._COST_AMP_THEORETICAL_LABEL
        assert "per-project quotas" in gas._COST_AMP_THEORETICAL_LABEL


# 5. Maps extras inferred provenance

class TestMapsExtrasInferred:
    @pytest.mark.unit
    def test_inferred_note_constant_present(self):
        assert gas._MAPS_EXTRAS_INFERRED_NOTE == (
            "inferred_not_independently_confirmed")
        assert "inferred, not independently confirmed" in (
            gas._MAPS_EXTRAS_INFERRED_IMPACT_SUFFIX)

    @pytest.mark.unit
    def test_build_json_output_marks_inferred_extras(self):
        """A maps-extras dict with tier=POTENTIAL + manual_note=inferred_*
        must appear in `potential` (not `confirmed`) in JSON output and
        carry the marker on the output record."""
        results = [
            # The trigger probe — confirmed
            {
                "name": "Directions", "category": "maps", "url": "x",
                "impact": "Directions billing impact",
                "vulnerable": True, "referer_blocked": False,
                "manual_note": None, "reason": "",
                "tier": "CONFIRMED",
                "severity": "MED",
                "impact_type": "quota_cost",
                "confirmation": "confirmed_data",
                "data_sensitivity": "billing_reachable",
            },
            # The inferred extra
            {
                "name": "Directions (Advanced)", "category": "maps",
                "url": "(included with Directions)",
                "impact": "$10 per 1000 elements"
                          + gas._MAPS_EXTRAS_INFERRED_IMPACT_SUFFIX,
                "vulnerable": True, "referer_blocked": False,
                "manual_note": gas._MAPS_EXTRAS_INFERRED_NOTE,
                "reason": "",
                "tier": "POTENTIAL",
                "severity": "INFO",
                "impact_type": "quota_cost",
                "confirmation": "key_accepted_only",
                "data_sensitivity": "billing_reachable",
            },
        ]
        out = gas._build_json_output(results, tested_count=2, options={})
        # CONFIRMED headline only counts the trigger probe.
        assert out["confirmed_count"] == 1
        assert out["potential_count"] == 1
        confirmed_names = {r["api"] for r in out["confirmed"]}
        potential_names = {r["api"] for r in out["potential"]}
        assert "Directions" in confirmed_names
        assert "Directions (Advanced)" in potential_names
        # Find the inferred record and verify provenance fields propagate.
        adv = next(r for r in out["potential"]
                   if r["api"] == "Directions (Advanced)")
        assert adv["manual_note"] == gas._MAPS_EXTRAS_INFERRED_NOTE
        assert adv["confirmation"] == "key_accepted_only"
        assert "inferred, not independently confirmed" in adv["impact"]
