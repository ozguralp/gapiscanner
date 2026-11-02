"""Regression coverage for release invariants."""
from __future__ import annotations

import io
from contextlib import redirect_stdout

import pytest

import google_api_scanner as gas


_BILLING_PROBES = (
    "Cloud Translation",
    "Cloud Vision",
    "Cloud Natural Language",
    "Cloud Text-to-Speech",
)


# Invariant 1 — billing-only probe field contract


class TestBillingProbeFieldContract:
    @pytest.mark.unit
    @pytest.mark.parametrize("name", _BILLING_PROBES)
    def test_category_is_low(self, name):
        match = [p for p in gas.ALL_PROBES if p[0] == name]
        assert match, f"{name!r} missing from ALL_PROBES"
        assert match[0][1] == "low", (
            f"{name} must stay category 'low'; got {match[0][1]!r}")

    @pytest.mark.unit
    @pytest.mark.parametrize("name", _BILLING_PROBES)
    def test_impact_fields_are_billing_tuple(self, name):
        it, conf, ds = gas._resolve_response_fields(name, "low")
        assert it == "quota_cost", f"{name}: impact_type={it!r}"
        assert conf == "confirmed_data", f"{name}: confirmation={conf!r}"
        assert ds == "billing_reachable", f"{name}: data_sensitivity={ds!r}"

    @pytest.mark.unit
    @pytest.mark.parametrize("name", _BILLING_PROBES)
    def test_severity_is_med(self, name):
        it, conf, ds = gas._resolve_response_fields(name, "low")
        assert gas._derive_severity(it, conf, ds) == "MED", (
            f"{name} must derive MED severity (billing-only)")

    @pytest.mark.unit
    @pytest.mark.parametrize("name", _BILLING_PROBES)
    def test_probe_impact_defaults_entry_present(self, name):
        entry = gas._PROBE_IMPACT_DEFAULTS.get(name)
        assert entry is not None, (
            f"{name} must have a _PROBE_IMPACT_DEFAULTS override")
        assert entry.get("impact_type") == "quota_cost"
        assert entry.get("confirmation") == "confirmed_data"
        assert entry.get("data_sensitivity") == "billing_reachable"


# Invariant 2 — default HIGH-only scan skips the billing-only probes


class TestDefaultScanSkipsBilling:
    @pytest.mark.unit
    def test_default_probe_selection_excludes_billing(self):
        """The four Cloud-AI probes are category 'low' and must NOT be
        in the default (HIGH-only) probe set."""
        high_only = {p[0] for p in gas.ALL_PROBES if p[1] == "high"}
        for name in _BILLING_PROBES:
            assert name not in high_only, (
                f"{name} leaked into the default HIGH-only probe set")

    @pytest.mark.unit
    def test_default_scan_does_not_execute_billing(self, monkeypatch):
        """End-to-end: a default scan_gapis() must never dispatch the
        billing-only probes through `_execute_probe`."""
        executed = []

        def fake_execute(probe_tuple, apikey, project_id, base_headers,
                         verbose=False):
            executed.append(probe_tuple[0])
            return _nonvuln_result(probe_tuple)

        monkeypatch.setattr(gas, "_execute_probe", fake_execute)
        monkeypatch.setattr(gas, "PHASE_0_PROBE_NAMES", ())
        monkeypatch.setattr(gas, "FIREBASE_CHAIN_PROBES", [])
        _clear_discovery_state()
        buf = io.StringIO()
        with redirect_stdout(buf):
            gas.scan_gapis("AIzaSyTEST" + "x" * 27, quiet=True,
                           skip_jsapi=True, threads=1, no_color=True)
        for name in _BILLING_PROBES:
            assert name not in executed, (
                f"default scan executed billing-only probe {name}")

    @pytest.mark.unit
    def test_include_low_does_execute_billing(self, monkeypatch):
        """Counterpart: with --include-low the billing probes DO run
        (so the skip above is a real gate, not a missing registry)."""
        executed = []

        def fake_execute(probe_tuple, apikey, project_id, base_headers,
                         verbose=False):
            executed.append(probe_tuple[0])
            return _nonvuln_result(probe_tuple)

        monkeypatch.setattr(gas, "_execute_probe", fake_execute)
        monkeypatch.setattr(gas, "PHASE_0_PROBE_NAMES", ())
        monkeypatch.setattr(gas, "FIREBASE_CHAIN_PROBES", [])
        _clear_discovery_state()
        buf = io.StringIO()
        with redirect_stdout(buf):
            gas.scan_gapis("AIzaSyTEST" + "x" * 27, include_low=True,
                           quiet=True, skip_jsapi=True, threads=1,
                           no_color=True)
        for name in _BILLING_PROBES:
            assert name in executed, (
                f"--include-low failed to execute billing probe {name}")


# Invariant 3 — --include-low does not enable Maps / jsapi_test.html


class TestIncludeLowDoesNotEnableMaps:
    @pytest.mark.unit
    def test_include_low_excludes_maps_probes(self, monkeypatch):
        executed = []

        def fake_execute(probe_tuple, apikey, project_id, base_headers,
                         verbose=False):
            executed.append((probe_tuple[0], probe_tuple[1]))
            return _nonvuln_result(probe_tuple)

        monkeypatch.setattr(gas, "_execute_probe", fake_execute)
        monkeypatch.setattr(gas, "PHASE_0_PROBE_NAMES", ())
        monkeypatch.setattr(gas, "FIREBASE_CHAIN_PROBES", [])
        _clear_discovery_state()
        buf = io.StringIO()
        with redirect_stdout(buf):
            gas.scan_gapis("AIzaSyTEST" + "x" * 27, include_low=True,
                           quiet=True, skip_jsapi=True, threads=1,
                           no_color=True)
        maps_executed = [n for (n, cat) in executed if cat == "maps"]
        assert not maps_executed, (
            f"--include-low pulled in maps probes: {maps_executed}")

    @pytest.mark.unit
    def test_include_low_does_not_create_jsapi_file(self, monkeypatch, tmp_path):
        """The jsapi_test.html artifact is created in os.getcwd(). Run a
        full --include-low scan with skip_jsapi=False from a clean temp
        cwd and assert no jsapi_test.html appears."""
        def fake_execute(probe_tuple, apikey, project_id, base_headers,
                         verbose=False):
            return _nonvuln_result(probe_tuple)

        monkeypatch.setattr(gas, "_execute_probe", fake_execute)
        monkeypatch.setattr(gas, "PHASE_0_PROBE_NAMES", ())
        monkeypatch.setattr(gas, "FIREBASE_CHAIN_PROBES", [])
        _clear_discovery_state()
        monkeypatch.chdir(tmp_path)
        buf = io.StringIO()
        with redirect_stdout(buf):
            # skip_jsapi=False — let the (gated) jsapi creation logic run.
            gas.scan_gapis("AIzaSyTEST" + "x" * 27, include_low=True,
                           quiet=True, skip_jsapi=False, threads=1,
                           no_color=True)
        assert not (tmp_path / "jsapi_test.html").exists(), (
            "--include-low must NOT create jsapi_test.html (Maps-only artifact)")

    @pytest.mark.unit
    def test_include_maps_does_create_jsapi_file(self, monkeypatch, tmp_path):
        """Counterpart: --include-maps with skip_jsapi=False DOES create
        the jsapi_test.html (proves the gate is Maps-driven, not dead)."""
        def fake_execute(probe_tuple, apikey, project_id, base_headers,
                         verbose=False):
            return _nonvuln_result(probe_tuple)

        monkeypatch.setattr(gas, "_execute_probe", fake_execute)
        monkeypatch.setattr(gas, "PHASE_0_PROBE_NAMES", ())
        monkeypatch.setattr(gas, "FIREBASE_CHAIN_PROBES", [])
        _clear_discovery_state()
        monkeypatch.chdir(tmp_path)
        buf = io.StringIO()
        with redirect_stdout(buf):
            gas.scan_gapis("AIzaSyTEST" + "x" * 27, include_maps=True,
                           quiet=True, skip_jsapi=False, threads=1,
                           no_color=True)
        assert (tmp_path / "jsapi_test.html").exists(), (
            "--include-maps with skip_jsapi=False should create jsapi_test.html")


# Invariant 4 — severity-aware default exit code


class TestExitCodeSemantics:
    @pytest.mark.unit
    def test_high_confirmed_trips_default(self):
        gas._capture_last_confirmed_severity_counts(
            {"HIGH": 1, "MED": 0, "LOW_INFO": 0})
        assert gas._classify_scan_vulnerable(["Some HIGH"], False) is True

    @pytest.mark.unit
    def test_med_only_does_not_trip_default(self):
        gas._capture_last_confirmed_severity_counts(
            {"HIGH": 0, "MED": 3, "LOW_INFO": 0})
        assert gas._classify_scan_vulnerable(["Cloud Translation"], False) is False

    @pytest.mark.unit
    def test_low_info_only_does_not_trip_default(self):
        gas._capture_last_confirmed_severity_counts(
            {"HIGH": 0, "MED": 0, "LOW_INFO": 5})
        assert gas._classify_scan_vulnerable(["Some LOW"], False) is False

    @pytest.mark.unit
    def test_legacy_flag_trips_on_any_confirmed(self):
        gas._capture_last_confirmed_severity_counts(
            {"HIGH": 0, "MED": 1, "LOW_INFO": 0})
        # Default: MED-only does not trip.
        assert gas._classify_scan_vulnerable(["Cloud Translation"], False) is False
        # --exit-on-any-confirmed: any returned CONFIRMED name trips.
        assert gas._classify_scan_vulnerable(["Cloud Translation"], True) is True

    @pytest.mark.unit
    def test_legacy_flag_empty_does_not_trip(self):
        gas._capture_last_confirmed_severity_counts(
            {"HIGH": 0, "MED": 0, "LOW_INFO": 0})
        # No findings at all → even legacy flag does not trip.
        assert gas._classify_scan_vulnerable([], True) is False


# Helpers


def _nonvuln_result(probe_tuple):
    """A minimal non-vulnerable probe result dict matching the shape
    `scan_gapis` expects from `_execute_probe`."""
    return {
        "name": probe_tuple[0],
        "category": probe_tuple[1],
        "abuse_class": None,
        "url": "https://example.googleapis.com/v1?key=AIza" + "x" * 35,
        "impact": "fake",
        "vulnerable": False,
        "manual_note": None,
        "referer_blocked": False,
        "error_class": None,
        "services_seen": set(),
        "reason": "",
        "gemini_disabled": False,
        "status_code": 200,
        "snippet": None,
        "impact_type": "info_disclosure",
        "confirmation": "key_accepted_only",
        "data_sensitivity": "none",
        "severity": "INFO",
        "check_signature": "fake_check",
    }


def _clear_discovery_state():
    """Wipe cross-scan discovery globals so a prior test's Firebase /
    project state cannot inject extra probes into this scan."""
    with gas._DERIVED_FIREBASE_LOCK:
        gas._DERIVED_FIREBASE_CONFIGS.clear()
    with gas._DERIVED_LOCK:
        gas._DERIVED_PROJECT_IDS.clear()
        gas._DERIVED_PROJECT_NUMBERS.clear()
