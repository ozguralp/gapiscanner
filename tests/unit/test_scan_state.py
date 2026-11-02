"""Tests for scan state."""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import google_api_scanner as gas  # noqa: E402

SENTINEL_KEY = "AIzaSyXX" + "X" * 31  # 39 chars, AIza-shaped, never a real key


# IID dead-code resolution

class TestIIDDeadCodeRemoved:
    @pytest.mark.unit
    def test_iid_derived_symbol_removed(self):
        assert not hasattr(gas, "_IID_DERIVED")
        assert not hasattr(gas, "_IID_LOCK")

    @pytest.mark.unit
    def test_check_iid_info_still_reports_leak(self):
        """The IID probe must still surface leaked fields as a finding even
        though the shared store is gone — project numbers in the body are now
        harvested through _extract_project_ids by _execute_probe."""
        r = MagicMock()
        r.status_code = 200
        r.json.return_value = {
            "application": "com.victim.app",
            "platform": "ANDROID",
            "appSigner": "AB:CD:EF",
        }
        vulnerable, note = gas._check_iid_info(r)
        assert vulnerable is True
        # leaked fields are sorted alphabetically
        assert note == "iid_leaked=appSigner,application,platform"

    @pytest.mark.unit
    def test_check_iid_info_no_leak_returns_false(self):
        r = MagicMock()
        r.status_code = 200
        r.json.return_value = {"unrelated": "field"}
        vulnerable, note = gas._check_iid_info(r)
        assert vulnerable is False
        assert note is None

    @pytest.mark.unit
    def test_check_iid_info_non_200_returns_false(self):
        r = MagicMock()
        r.status_code = 403
        r.json.return_value = {}
        vulnerable, note = gas._check_iid_info(r)
        assert vulnerable is False
        assert note is None


# State clearing at scan_gapis entry

class TestScanEntryClearsState:
    """scan_gapis must clear _DERIVED_PROJECT_IDS, _DERIVED_PROJECT_NUMBERS,
    AND _IDENTITY_TOOLKIT_ARTIFACTS at the top of every invocation — without
    this, the discovery loop misattributes artifacts to whichever key is being
    scanned next."""

    @pytest.fixture
    def no_op_probes(self, monkeypatch):
        """Empty probe set so scan_gapis runs the state-clear + summary path
        without making any network calls."""
        monkeypatch.setattr(gas, "ALL_PROBES", [])
        monkeypatch.setattr(gas, "FIREBASE_CHAIN_PROBES", [])
        monkeypatch.setattr(gas, "PHASE_0_PROBE_NAMES", ())
        yield

    @pytest.mark.unit
    def test_clears_derived_project_ids(self, no_op_probes):
        gas._DERIVED_PROJECT_IDS.add("stale-from-prior-scan")
        gas._DERIVED_PROJECT_NUMBERS.add("999999999999")
        gas.scan_gapis(SENTINEL_KEY, quiet=True, skip_jsapi=True)
        assert gas._DERIVED_PROJECT_IDS == set()
        assert gas._DERIVED_PROJECT_NUMBERS == set()

    @pytest.mark.unit
    def test_clears_identity_toolkit_artifacts(self, no_op_probes):
        gas._IDENTITY_TOOLKIT_ARTIFACTS.append({
            "probe": "signUp (stale)",
            "local_id": "should-not-persist",
            "id_token_prefix": "stale...",
            "reason": "from previous key in discovery loop",
        })
        assert len(gas._IDENTITY_TOOLKIT_ARTIFACTS) == 1
        gas.scan_gapis(SENTINEL_KEY, quiet=True, skip_jsapi=True)
        assert gas._IDENTITY_TOOLKIT_ARTIFACTS == []


# CONFIRMED vs POTENTIAL split in _build_json_output

def _mk_result(name, vulnerable, tier=None, error_class=None):
    return {
        "name": name,
        "category": "high",
        "abuse_class": "Recon",
        "url": "https://example.googleapis.com/v1/x?key=" + SENTINEL_KEY,
        "impact": "synthetic",
        "vulnerable": vulnerable,
        "tier": tier,
        "manual_note": None,
        "referer_blocked": False,
        "error_class": error_class,
        "services_seen": set(),
        "reason": "",
        "gemini_disabled": False,
        "status_code": 200 if vulnerable else 403,
        "snippet": None,
    }


class TestBuildJsonOutputSplits:
    @pytest.mark.unit
    def test_splits_confirmed_and_potential_buckets(self):
        results = [
            _mk_result("CONF Probe A", True, tier="CONFIRMED"),
            _mk_result("CONF Probe B", True, tier="CONFIRMED"),
            _mk_result("POT Probe X", True, tier="POTENTIAL"),
            _mk_result("Failed Probe", False, error_class="KEY_INVALID"),
        ]
        out = gas._build_json_output(results, tested_count=4, options={})
        assert out["confirmed_count"] == 2
        assert out["potential_count"] == 1
        assert {v["api"] for v in out["confirmed"]} == {"CONF Probe A", "CONF Probe B"}
        assert {v["api"] for v in out["potential"]} == {"POT Probe X"}
        # Old keys must not leak through (clean break, no shims)
        assert "vulnerable" not in out
        assert "vulnerable_count" not in out

    @pytest.mark.unit
    def test_tier_defaults_to_confirmed_when_missing(self):
        """Defensive: a result that somehow lacks `tier` is treated as
        CONFIRMED (matches the headline-default behavior)."""
        results = [_mk_result("Untiered", True, tier=None)]
        out = gas._build_json_output(results, tested_count=1, options={})
        assert out["confirmed_count"] == 1
        assert out["potential_count"] == 0
        assert out["confirmed"][0]["tier"] == "CONFIRMED"

    @pytest.mark.unit
    def test_empty_results_zero_counts(self):
        out = gas._build_json_output([], tested_count=0, options={})
        assert out["confirmed_count"] == 0
        assert out["potential_count"] == 0
        assert out["confirmed"] == []
        assert out["potential"] == []


# scan_gapis return value is CONFIRMED-only

class TestScanGapisReturnsConfirmedOnly:
    @pytest.fixture
    def one_synthetic_probe(self, monkeypatch):
        """Wire a single synthetic probe whose execute() returns a POTENTIAL
        finding (key acceptance). scan_gapis must drop it from the return
        value but keep it in the SUMMARY/JSON paths."""

        probe = ("Identity Toolkit signUp anon (account creation + auto-cleanup)",
                 "high", "POST",
                 "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={key}",
                 '{"returnSecureToken":true}',
                 lambda r: (True, None),  # always-true check
                 "Synthetic POTENTIAL probe")
        monkeypatch.setattr(gas, "ALL_PROBES", [probe])
        monkeypatch.setattr(gas, "FIREBASE_CHAIN_PROBES", [])
        monkeypatch.setattr(gas, "PHASE_0_PROBE_NAMES", ())

        # Mock the HTTP call so no network traffic.
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = '{"kind":"identitytoolkit#X"}'
        mock_response.json.return_value = {"kind": "identitytoolkit#X"}
        mock_response.request.url = probe[3].replace("{key}", SENTINEL_KEY)
        mock_response.content = mock_response.text.encode()
        mock_response.headers = {"Content-Type": "application/json"}

        import requests
        monkeypatch.setattr(requests, "post", lambda *a, **kw: mock_response)
        monkeypatch.setattr(requests, "get",  lambda *a, **kw: mock_response)
        yield probe

    @pytest.mark.unit
    def test_potential_excluded_from_return(self, one_synthetic_probe):
        ret = gas.scan_gapis(SENTINEL_KEY, quiet=True, skip_jsapi=True)
        # The probe name is in POTENTIAL_PROBES — so even though it returned
        # vulnerable=True, scan_gapis must NOT return it.
        assert ret == []

    @pytest.mark.unit
    def test_confirmed_included_in_return(self, monkeypatch):
        # Now use a probe NOT in POTENTIAL_PROBES — it should appear in the return.
        probe = ("Cloud Storage Buckets", "high", "GET",
                 "https://storage.googleapis.com/storage/v1/b?project={project}&key={key}",
                 None, lambda r: (True, None),
                 "Synthetic CONFIRMED probe")
        monkeypatch.setattr(gas, "ALL_PROBES", [probe])
        monkeypatch.setattr(gas, "FIREBASE_CHAIN_PROBES", [])
        monkeypatch.setattr(gas, "PHASE_0_PROBE_NAMES", ())

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = '{"items":[{"name":"b"}]}'
        mock_response.json.return_value = {"items": [{"name": "b"}]}
        mock_response.request.url = probe[3].replace("{key}", SENTINEL_KEY)
        mock_response.content = mock_response.text.encode()
        mock_response.headers = {"Content-Type": "application/json"}

        import requests
        monkeypatch.setattr(requests, "get",  lambda *a, **kw: mock_response)
        monkeypatch.setattr(requests, "post", lambda *a, **kw: mock_response)

        ret = gas.scan_gapis(SENTINEL_KEY, quiet=True, skip_jsapi=True)
        assert ret == ["Cloud Storage Buckets"]


# Symbol sanity (regression guards for accidental reintroduction)

class TestSymbolSanity:
    @pytest.mark.unit
    def test_vuln_count_replaced_by_confirmed_potential_counters(self):
        src = gas._engine_source_text()
        assert "vuln_count" not in src
        assert "total_vuln " not in src and "total_vuln," not in src \
            and "total_vuln)" not in src and "total_vuln\n" not in src
        # Positive presence checks
        assert "confirmed_count = [0]" in src
        assert "potential_count = [0]" in src

    @pytest.mark.unit
    def test_iid_derived_globally_gone(self):
        src = gas._engine_source_text()
        # All references must be gone, including comments/docstrings.
        assert "_IID_DERIVED" not in src
        assert "_IID_LOCK" not in src
