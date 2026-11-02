"""Tests for severity model."""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import google_api_scanner as gas  # noqa: E402

SENTINEL_KEY = "AIzaSyXX" + "X" * 31


# Constant tables exist with expected vocabulary

class TestVocabulary:
    @pytest.mark.unit
    def test_impact_types_vocabulary(self):
        assert gas._IMPACT_TYPES == frozenset({
            "data_read", "data_write", "data_delete", "account",
            "quota_cost", "info_disclosure",

            "user_enumeration",
        })

    @pytest.mark.unit
    def test_confirmation_levels_vocabulary(self):
        assert gas._CONFIRMATION_LEVELS == frozenset({
            "confirmed_data", "key_accepted_only",
        })

    @pytest.mark.unit
    def test_data_sensitivities_vocabulary(self):
        assert gas._DATA_SENSITIVITIES == frozenset({
            "none", "static_catalog", "metadata",
            "customer_data", "secret_material", "billing_reachable",
        })

    @pytest.mark.unit
    def test_severities_ordered(self):
        assert gas._SEVERITIES == ("INFO", "LOW", "MED", "HIGH", "CRITICAL")

    @pytest.mark.unit
    def test_category_defaults_present(self):

        for cat in ("high", "maps", "low", "destructive", "cost-amp"):
            assert cat in gas._CATEGORY_IMPACT_DEFAULTS, (
                f"_CATEGORY_IMPACT_DEFAULTS missing {cat!r}")
            d = gas._CATEGORY_IMPACT_DEFAULTS[cat]
            assert d["impact_type"]      in gas._IMPACT_TYPES
            assert d["confirmation"]     in gas._CONFIRMATION_LEVELS
            assert d["data_sensitivity"] in gas._DATA_SENSITIVITIES


# _derive_severity matrix

class TestDeriveSeverity:
    # --- Top-of-matrix rules (dominate everything else) ---

    @pytest.mark.unit
    def test_data_sensitivity_none_is_INFO(self):
        # No exposure regardless of impact_type or confirmation.
        for it in gas._IMPACT_TYPES:
            for c in gas._CONFIRMATION_LEVELS:
                assert gas._derive_severity(it, c, "none") == "INFO"

    @pytest.mark.unit
    def test_data_sensitivity_static_catalog_is_INFO(self):
        # Region lists / public catalogs / static service metadata.
        for it in gas._IMPACT_TYPES:
            for c in gas._CONFIRMATION_LEVELS:
                assert gas._derive_severity(it, c, "static_catalog") == "INFO"

    @pytest.mark.unit
    def test_secret_material_confirmed_is_CRITICAL(self):
        # The only CRITICAL bucket. Requires confirmation=confirmed_data.
        for it in ("data_read", "data_write", "account"):
            assert gas._derive_severity(it, "confirmed_data",
                                        "secret_material") == "CRITICAL"

    @pytest.mark.unit
    def test_secret_material_key_accepted_only_is_INFO(self):
        # Even secret-material probes don't escalate if we only proved key acceptance.
        assert gas._derive_severity("data_read", "key_accepted_only",
                                    "secret_material") == "INFO"

    # --- key_accepted_only column ---

    @pytest.mark.unit
    def test_key_accepted_only_quota_cost_is_LOW(self):
        assert gas._derive_severity("quota_cost", "key_accepted_only",
                                    "billing_reachable") == "LOW"

    @pytest.mark.unit
    def test_key_accepted_only_anything_else_is_INFO(self):
        # Account / data_read / etc. with key_accepted_only and metadata or
        # customer_data sensitivity is still just INFO — acceptance is not
        # exfiltration.
        for ds in ("metadata", "customer_data"):
            for it in ("data_read", "data_write", "data_delete",
                       "account", "info_disclosure"):
                assert gas._derive_severity(it, "key_accepted_only", ds) == "INFO", (
                    f"({it}, key_accepted_only, {ds}) should be INFO")

    # --- confirmed_data column ---

    @pytest.mark.unit
    def test_confirmed_customer_data_read_is_HIGH(self):
        assert gas._derive_severity("data_read", "confirmed_data",
                                    "customer_data") == "HIGH"

    @pytest.mark.unit
    def test_confirmed_customer_data_account_actions_are_HIGH(self):
        for it in ("account", "data_write", "data_delete"):
            assert gas._derive_severity(it, "confirmed_data",
                                        "customer_data") == "HIGH"

    @pytest.mark.unit
    def test_confirmed_billing_reachable_quota_cost_is_MED(self):
        assert gas._derive_severity("quota_cost", "confirmed_data",
                                    "billing_reachable") == "MED"

    @pytest.mark.unit
    def test_confirmed_metadata_is_LOW(self):
        # Project ID leak via error envelope, etc. Confirmed but small impact.
        assert gas._derive_severity("info_disclosure", "confirmed_data",
                                    "metadata") == "LOW"


# _resolve_response_fields precedence

class TestResolveResponseFields:
    @pytest.mark.unit
    def test_category_default_high(self):
        it, c, ds = gas._resolve_response_fields("Unknown Probe", "high")
        assert (it, c, ds) == ("data_read", "confirmed_data", "customer_data")

    @pytest.mark.unit
    def test_category_default_low(self):
        it, c, ds = gas._resolve_response_fields("Unknown Probe", "low")
        assert (it, c, ds) == ("quota_cost", "key_accepted_only", "billing_reachable")

    @pytest.mark.unit
    def test_static_catalog_derives_info(self):

        sev = gas._derive_severity("info_disclosure", "key_accepted_only",
                                    "static_catalog")
        assert sev == "INFO", f"static_catalog must derive INFO, got {sev}"

    @pytest.mark.unit
    def test_no_probe_uses_static_catalog_override(self):
        """After the Cloud KMS removal, no _PROBE_IMPACT_DEFAULTS entry
        should still carry data_sensitivity=static_catalog."""
        leftovers = [n for n, e in gas._PROBE_IMPACT_DEFAULTS.items()
                     if isinstance(e, dict)
                     and e.get("data_sensitivity") == "static_catalog"]
        assert leftovers == [], (
            f"no static_catalog override should remain; found {leftovers}")

    @pytest.mark.unit
    def test_per_probe_override_metadata(self):

        for name in ("Firebase Installations create (enum)",
                     "Gemini Models List"):
            it, c, ds = gas._resolve_response_fields(name, "high")
            assert ds == "metadata", f"{name} must be metadata"
            sev = gas._derive_severity(it, c, ds)
            # confirmation=confirmed_data + metadata → LOW
            assert sev == "LOW", f"{name} should derive LOW, got {sev}"

    @pytest.mark.unit
    def test_check_override_wins_over_per_probe(self):

        it, c, ds = gas._resolve_response_fields(
            "Pub/Sub Topics", "high",
            check_overrides={"data_sensitivity": "customer_data",
                             "confirmation": "confirmed_data"},
        )
        # check override flipped both fields:
        assert ds == "customer_data"
        assert c == "confirmed_data"


class TestRTDBEmptyDoesNotEscalate:
    @pytest.mark.unit
    def test_empty_rtdb_override_yields_INFO(self):
        # _check_firebase_rtdb_root returns a 3-tuple with category=low and
        # data_sensitivity=none for the empty branch.
        r = MagicMock()
        r.status_code = 200
        r.text = "null"
        result = gas._check_firebase_rtdb_root(r)
        assert len(result) == 3, "empty RTDB must return 3-tuple override"
        vulnerable, note, overrides = result
        assert vulnerable is True
        assert overrides.get("data_sensitivity") == "none"
        # Then severity must be INFO regardless of any "200 readable" framing.
        it, c, ds = gas._resolve_response_fields(
            overrides.get("name", "Firebase RTDB"),
            overrides.get("category", "high"),
            check_overrides=overrides,
        )
        assert gas._derive_severity(it, c, ds) == "INFO"

    @pytest.mark.unit
    def test_empty_dict_rtdb_also_INFO(self):
        r = MagicMock()
        r.status_code = 200
        r.text = "{}"
        r.json.return_value = {}
        result = gas._check_firebase_rtdb_root(r)
        assert len(result) == 3
        vulnerable, note, overrides = result
        assert vulnerable is True
        assert overrides.get("data_sensitivity") == "none"


# Existing override compatibility: 2-tuple vs 3-tuple check functions

class TestOverrideTupleCompatibility:
    """The override mechanism in _execute_probe must accept both 2-tuple
    (`vulnerable, note`) and 3-tuple (`vulnerable, note, overrides`) check
    returns. Existing two-tuple check fns must keep working."""

    def _mock_response(self, status=200, body='{"items":[1,2,3]}'):
        m = MagicMock()
        m.status_code = status
        m.text = body
        m.json.return_value = {"items": [1, 2, 3]}
        m.content = body.encode()
        m.headers = {"Content-Type": "application/json"}
        m.request = MagicMock()
        m.request.url = "https://example.googleapis.com/v1/x?key=" + SENTINEL_KEY
        return m

    @pytest.mark.unit
    def test_two_tuple_check_fn_still_works(self, monkeypatch):
        def two_tuple_check(r):
            return True, None
        probe = ("Two Tuple Probe", "high", "GET",
                 "https://example.googleapis.com/v1/x?key={key}",
                 None, two_tuple_check, "synthetic impact")

        import requests
        monkeypatch.setattr(requests, "get",
                            lambda *a, **kw: self._mock_response())
        result = gas._execute_probe(probe, SENTINEL_KEY, None, {})
        assert result is not None
        assert result["vulnerable"] is True

        assert result["impact_type"]      == "data_read"
        assert result["confirmation"]     == "confirmed_data"
        assert result["data_sensitivity"] == "customer_data"
        assert result["severity"]         == "HIGH"

    @pytest.mark.unit
    def test_three_tuple_override_applies(self, monkeypatch):
        def three_tuple_check(r):
            return True, "downgraded", {
                "data_sensitivity": "static_catalog",
                "confirmation": "key_accepted_only",
            }
        probe = ("Three Tuple Probe", "high", "GET",
                 "https://example.googleapis.com/v1/x?key={key}",
                 None, three_tuple_check, "synthetic impact")
        import requests
        monkeypatch.setattr(requests, "get",
                            lambda *a, **kw: self._mock_response())
        result = gas._execute_probe(probe, SENTINEL_KEY, None, {})
        assert result is not None
        assert result["data_sensitivity"] == "static_catalog"
        assert result["confirmation"]     == "key_accepted_only"
        assert result["severity"]         == "INFO"

    @pytest.mark.unit
    def test_severity_escape_hatch_override(self, monkeypatch):
        """An override may pin `severity` directly, bypassing the matrix."""
        def custom_severity_check(r):
            return True, None, {"severity": "CRITICAL"}
        probe = ("Pinned Severity Probe", "low", "GET",
                 "https://example.googleapis.com/v1/x?key={key}",
                 None, custom_severity_check, "synthetic impact")
        import requests
        monkeypatch.setattr(requests, "get",
                            lambda *a, **kw: self._mock_response())
        result = gas._execute_probe(probe, SENTINEL_KEY, None, {})
        assert result["severity"] == "CRITICAL"


# JSON output shape

def _mk_result(name, vulnerable, tier=None, **kwargs):
    r = {
        "name": name,
        "category": kwargs.get("category", "high"),
        "abuse_class": "Recon",
        "url": "https://example.googleapis.com/v1/x?key=" + SENTINEL_KEY,
        "impact": "synthetic",
        "vulnerable": vulnerable,
        "tier": tier,
        "manual_note": None,
        "referer_blocked": False,
        "error_class": kwargs.get("error_class"),
        "services_seen": set(),
        "reason": "",
        "gemini_disabled": False,
        "status_code": 200 if vulnerable else 403,
        "snippet": None,
    }
    for k in ("impact_type", "confirmation", "data_sensitivity", "severity"):
        if k in kwargs:
            r[k] = kwargs[k]
    return r


class TestJSONOutputShape:
    @pytest.mark.unit
    def test_confirmed_entries_carry_severity_fields(self):
        results = [
            _mk_result("Customer Data Probe", True, tier="CONFIRMED",
                       impact_type="data_read", confirmation="confirmed_data",
                       data_sensitivity="customer_data", severity="HIGH"),
            _mk_result("Static Catalog Probe", True, tier="CONFIRMED",
                       impact_type="info_disclosure",
                       confirmation="key_accepted_only",
                       data_sensitivity="static_catalog", severity="INFO"),
        ]
        out = gas._build_json_output(results, tested_count=2, options={})
        assert out["confirmed_count"] == 2
        assert out["potential_count"] == 0

        assert "confirmed" in out
        assert "potential" in out

        for entry in out["confirmed"]:
            for k in ("severity", "impact_type", "confirmation",
                      "data_sensitivity", "tier"):
                assert k in entry, f"confirmed entry missing {k!r}"
        # Specifically: static-catalog probe should be INFO
        cust = next(v for v in out["confirmed"]
                    if v["api"] == "Customer Data Probe")
        stat = next(v for v in out["confirmed"]
                    if v["api"] == "Static Catalog Probe")
        assert cust["severity"] == "HIGH"
        assert stat["severity"] == "INFO"

    @pytest.mark.unit
    def test_missing_severity_fields_default_conservatively(self):
        r = _mk_result("Bare Probe", True, tier="CONFIRMED")
        out = gas._build_json_output([r], tested_count=1, options={})
        entry = out["confirmed"][0]
        assert entry["severity"]         == "INFO"
        assert entry["impact_type"]      == "info_disclosure"
        assert entry["confirmation"]     == "key_accepted_only"
        assert entry["data_sensitivity"] == "metadata"


class TestPreservedInvariants:

    @pytest.fixture(autouse=True)
    def _mock_garbage_api(self, monkeypatch):
        def _garbage_resp(*args, **kwargs):
            m = MagicMock()
            m.status_code = 400
            m.text = (
                '{"error":{"code":400,"status":"INVALID_ARGUMENT","message":'
                '"API key not valid. Please pass a valid API key.","details":'
                '[{"reason":"API_KEY_INVALID"}]}}'
            )
            m.json.return_value = {
                "error": {
                    "code": 400, "status": "INVALID_ARGUMENT",
                    "message": "API key not valid. Please pass a valid API key.",
                    "details": [{"reason": "API_KEY_INVALID"}],
                },
            }
            m.content = m.text.encode()
            m.headers = {"Content-Type": "application/json"}
            m.request = MagicMock()
            m.request.url = args[0] if args else ""
            return m
        import requests
        monkeypatch.setattr(requests, "get",    _garbage_resp)
        monkeypatch.setattr(requests, "post",   _garbage_resp)
        monkeypatch.setattr(requests, "put",    _garbage_resp)
        monkeypatch.setattr(requests, "delete", _garbage_resp)

    @pytest.mark.unit
    def test_sentinel_yields_zero_confirmed(self):
        confirmed = gas.scan_gapis(
            SENTINEL_KEY,
            include_maps=False, include_low=False,
            include_destructive=False, include_cost_amp=False,

            quiet=True, skip_jsapi=True, threads=4,
        )
        assert confirmed == [], (
            f"Synthetic key produced a confirmed result: CONFIRMED={confirmed}")

    @pytest.mark.unit
    def test_potential_still_excluded_from_return(self, monkeypatch):
        # Restore mocks but make the response look "successful enough" for a
        # POTENTIAL probe — Identity Toolkit key-acceptance pattern.
        def ok_resp(*args, **kwargs):
            m = MagicMock()

            url = args[0] if args else ""
            if "accounts:signUp" in url:
                m.status_code = 200
                m.text = '{"idToken":"T","localId":"anon-1"}'
                m.json.return_value = {"idToken": "T", "localId": "anon-1"}
            else:  # accounts:delete cleanup
                m.status_code = 200
                m.text = "{}"
                m.json.return_value = {}
            m.content = m.text.encode()
            m.headers = {"Content-Type": "application/json"}
            m.request = MagicMock()
            m.request.url = url
            return m
        import requests
        monkeypatch.setattr(requests, "post", ok_resp)
        # Restrict the probe set so only the POTENTIAL probe runs. signUp anon
        # is a default `high` probe in POTENTIAL_PROBES; auth-read stays OFF.
        gas._set_auth_read_enabled(False)
        target_name = "Identity Toolkit signUp anon (account creation + auto-cleanup)"
        only = [p for p in gas.ALL_PROBES if p[0] == target_name]
        assert only, f"target POTENTIAL probe {target_name!r} not in ALL_PROBES"
        monkeypatch.setattr(gas, "ALL_PROBES", only)
        monkeypatch.setattr(gas, "PHASE_0_PROBE_NAMES", ())
        monkeypatch.setattr(gas, "FIREBASE_CHAIN_PROBES", [])
        ret = gas.scan_gapis(SENTINEL_KEY, quiet=True, skip_jsapi=True,
                             threads=1)
        # The probe is in POTENTIAL_PROBES so even though it "fired"
        # (vulnerable=True), it must NOT appear in the CONFIRMED-only return.
        assert ret == [], (
            f"POTENTIAL probe leaked into CONFIRMED return: {ret}")
