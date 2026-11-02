"""Regression coverage for include matrix."""
from __future__ import annotations

from collections import Counter

import pytest

import google_api_scanner as gas

SIGNUP = "Identity Toolkit signUp anon (account creation + auto-cleanup)"
CREATE_AUTH_URI = "Identity Toolkit createAuthUri (email enum)"
_DIAGNOSTIC_GONE = (
    "Secure Token refresh (diagnostic)",
    "Identity Toolkit signInWithCustomToken (diagnostic)",
    "Identity Toolkit signInWithPassword (diagnostic)",
    "Identity Toolkit signInWithIdp (diagnostic)",
    "Identity Toolkit signInWithEmailLink (diagnostic)",
    "Identity Toolkit v3 getAccountInfo (diagnostic)",
    "Identity Toolkit v3 verifyPassword (diagnostic)",
)


def _by_cat(cat):
    return {p[0] for p in gas.ALL_PROBES if p[1] == cat}


class TestCategoriesExist:
    @pytest.mark.unit
    def test_only_expected_categories(self):
        cats = set(p[1] for p in gas.ALL_PROBES)
        assert cats == {"high", "low", "maps", "destructive", "cost-amp"}, cats

    @pytest.mark.unit
    def test_no_enum_category(self):
        assert "enum" not in {p[1] for p in gas.ALL_PROBES}
        assert "enum" not in gas._OPT_IN_CATEGORIES
        assert "enum" not in gas._CATEGORY_IMPACT_DEFAULTS

    @pytest.mark.unit
    def test_no_legacy_category(self):
        assert "legacy" not in {p[1] for p in gas.ALL_PROBES}
        assert "legacy" not in gas._OPT_IN_CATEGORIES
        assert "legacy" not in gas._CATEGORY_IMPACT_DEFAULTS

    @pytest.mark.unit
    def test_exact_counts(self):
        c = Counter(p[1] for p in gas.ALL_PROBES)
        assert dict(c) == {"high": 30, "low": 29, "maps": 22,
                           "destructive": 4, "cost-amp": 5}
        assert len(gas.ALL_PROBES) == 90


class TestDefaultProfile:
    @pytest.mark.unit
    def test_default_has_no_diagnostic_noise(self):
        names = {p[0] for p in gas.ALL_PROBES if p[1] == "high"}
        for d in _DIAGNOSTIC_GONE:
            assert d not in names

    @pytest.mark.unit
    def test_default_includes_signup_anon(self):
        assert SIGNUP in _by_cat("high")

    @pytest.mark.unit
    def test_signup_anon_is_potential_cleanup_safe(self):
        # POTENTIAL on clean success (in POTENTIAL_PROBES), uses the
        # cleanup-safe check fn that always attempts accounts:delete.
        assert SIGNUP in gas.POTENTIAL_PROBES
        probe = next(p for p in gas.ALL_PROBES if p[0] == SIGNUP)
        assert probe[5] is gas._check_it_signup_anon

    @pytest.mark.unit
    def test_default_excludes_maps_low_costamp_destructive(self):
        high = _by_cat("high")
        for cat in ("maps", "low", "cost-amp", "destructive"):
            assert not (high & _by_cat(cat))


class TestLowProfile:
    @pytest.mark.unit
    def test_low_includes_cloud_ai_billing(self):
        low = _by_cat("low")
        for n in ("Cloud Translation", "Cloud Vision",
                  "Cloud Natural Language", "Cloud Text-to-Speech"):
            assert n in low

    @pytest.mark.unit
    def test_low_includes_create_auth_uri(self):
        assert CREATE_AUTH_URI in _by_cat("low")

    @pytest.mark.unit
    def test_create_auth_uri_derives_med(self):
        it, c, ds = gas._resolve_response_fields(CREATE_AUTH_URI, "low")
        assert gas._derive_severity(it, c, ds) == "MED"


class TestSeparation:
    @pytest.mark.unit
    def test_maps_separate(self):
        assert len(_by_cat("maps")) == 22

    @pytest.mark.unit
    def test_cost_amp_separate(self):
        assert len(_by_cat("cost-amp")) == 5

    @pytest.mark.unit
    def test_destructive_only_real_side_effects(self):
        # Every destructive probe must be a real write/create (POST/PUT) or
        # an operator-controlled OOB probe — never a neutered capability ping.
        for p in gas.ALL_PROBES:
            if p[1] != "destructive":
                continue
            assert p[2] in ("POST", "PUT", "DELETE"), (
                f"{p[0]}: destructive probe must be a mutating method")
        # The neutered capability probes are gone.
        names = _by_cat("destructive")
        assert "Identity Toolkit sendOobCode (capability)" not in names
        assert "Identity Toolkit sendVerificationCode (capability)" not in names


class TestNoStaleProbes:
    @pytest.mark.unit
    @pytest.mark.parametrize("name", _DIAGNOSTIC_GONE)
    def test_diagnostic_probe_absent_everywhere(self, name):
        names = {p[0] for p in gas.ALL_PROBES}
        assert name not in names
        assert name not in gas._PROBE_IMPACT_DEFAULTS
        assert name not in gas.ABUSE_CLASS_OVERRIDES
        assert name not in gas.POTENTIAL_PROBES

    @pytest.mark.unit
    @pytest.mark.parametrize("name", [
        "FCM Legacy send (Authorization header)",
        "IID info (project + app disclosure)",
        "FCM Legacy topic broadcast (mass push)",
        "IID batchAdd (topic subscription hijack)",
        "Gemini Tuned Model create (write)",
        "Identity Toolkit v3 signupNewUser (legacy)"])
    def test_legacy_probe_absent(self, name):
        assert name not in {p[0] for p in gas.ALL_PROBES}
