"""Tests for probe authentication."""
from __future__ import annotations

import re

import pytest

import google_api_scanner as gas


_REMOVED = (
    "Secret Manager", "Access Approval", "Bigtable Admin",
    "Binary Authorization", "Cloud Asset", "Cloud Error Reporting",
    "Cloud Profiler", "Cloud Shell", "Essential Contacts", "Data Labeling",
    "Firebase Hosting", "Firebase ML", "Firebase Storage", "Jobs",
    "Merchant API", "My Business Notifications", "ML Engine", "OS Login",
    "reCAPTCHA Enterprise", "Reader Revenue Subscription Linking",
    "Network Management", "Service Networking", "Security Center", "Spanner",
    "Smart Device Management", "Web Security Scanner",
    "Vertex AI Express generateContent (global)",
    "Vertex AI Express streamGenerateContent (global)",

    "Authorized Buyers Marketplace",

    "Cloud KMS",
    "Advisory Notifications",
    "Container Analysis",
)


_PARENT_REQUIRED_REMOVED = (
    "AdSense Platform", "Analytics Data", "Billing Budgets",
    "Business Profile Performance", "Chrome Management", "Chrome Policy",
    "Chrome Web Store", "CSS", "Manufacturers", "My Business Lodging",
    "My Business Q&A", "Payments Reseller Subscription",
)


def _names():
    return {p[0] for p in gas.ALL_PROBES}


def _host(url):
    m = re.match(r"https?://([a-z0-9.-]+)/", url or "")
    return m.group(1) if m else ""


class TestRemovedProbesAbsent:
    @pytest.mark.unit
    @pytest.mark.parametrize("name", _REMOVED)
    def test_removed_probe_absent_from_all_probes(self, name):
        assert name not in _names(), (
            f"{name!r} rejects API-key authentication but is "
            f"still in ALL_PROBES")

    @pytest.mark.unit
    @pytest.mark.parametrize("name", _REMOVED)
    def test_removed_probe_not_in_default_high(self, name):
        high = {p[0] for p in gas.ALL_PROBES if p[1] == "high"}
        assert name not in high

    @pytest.mark.unit
    @pytest.mark.parametrize("name", _REMOVED)
    def test_removed_probe_absent_from_dependent_tables(self, name):
        assert name not in gas._PROBE_IMPACT_DEFAULTS, (
            f"{name!r} still in _PROBE_IMPACT_DEFAULTS")
        assert name not in gas.ABUSE_CLASS_OVERRIDES, (
            f"{name!r} still in ABUSE_CLASS_OVERRIDES")
        assert name not in set(gas.PHASE_0_PROBE_NAMES)
        assert name not in gas.POTENTIAL_PROBES


class TestRegistryCounts:

    @pytest.mark.unit
    def test_total_registry_count_is_90(self):
        assert len(gas.ALL_PROBES) == 90, (
            f"total registry must be 90 with the current catalog "
            f"additions; got {len(gas.ALL_PROBES)}")

    @pytest.mark.unit
    def test_high_count_is_30(self):
        high = [p for p in gas.ALL_PROBES if p[1] == "high"]
        assert len(high) == 30, (
            f"HIGH run-group must be 30 with the current catalog "
            f"additions; got {len(high)}")

    @pytest.mark.unit
    def test_exact_per_category_counts(self):
        """Pin the full post-cleanup category distribution so a stray
        add/remove in any single run-group is caught."""
        from collections import Counter
        counts = Counter(p[1] for p in gas.ALL_PROBES)
        expected = {
            "high": 30,
            "low": 29,
            "maps": 22,
            "destructive": 4,
            "cost-amp": 5,
        }
        assert dict(counts) == expected, (
            f"category distribution drifted; got {dict(counts)}, "
            f"expected {expected}")
        assert sum(expected.values()) == 90
        # No enum / legacy categories remain.
        assert "enum" not in counts and "legacy" not in counts

    @pytest.mark.unit
    def test_api_key_unsupported_probes_removed(self):
        """The 7 live-validated API_KEY_UNSUPPORTED probes are gone."""
        names = {p[0] for p in gas.ALL_PROBES}
        for n in ("Cloud Trace", "FCM Data", "Firebase App Check",
                  "Firebase App Distribution", "IAP", "Runtime Config",
                  "Discovery Engine"):
            assert n not in names, f"{n!r} should be removed (API_KEY_UNSUPPORTED)"


class TestKeptProbesSurvive:
    @pytest.mark.unit
    def test_gemini_generativelanguage_probes_kept(self):
        gemini = [p for p in gas.ALL_PROBES
                  if "generativelanguage.googleapis.com" in _host(p[3])]
        assert len(gemini) >= 10, (
            f"Gemini generativelanguage probes must remain; found "
            f"{len(gemini)}")
        names = {p[0] for p in gemini}
        # spot-check the core API-key LLM-abuse + read probes
        for core in ("Gemini Models List", "Gemini Generate Content",
                     "Gemini Files List", "Gemini Cached Contents",
                     "Gemini Tuned Models"):
            assert core in names, f"{core!r} must remain"

    @pytest.mark.unit
    def test_cloud_storage_buckets_kept(self):
        # storage.googleapis.com bucket/object check is API-key-capable —
        # NOT the removed firebasestorage admin probe.
        assert "Cloud Storage Buckets" in _names()

    @pytest.mark.unit
    def test_firebase_storage_chain_kept(self):
        chain_names = {p[0] for p in gas.FIREBASE_CHAIN_PROBES
                       if isinstance(p, tuple)}
        # The chain Storage-list read probes must remain; only the
        # firebasestorage.googleapis.com ADMIN "Firebase Storage" probe
        # (a plain ALL_PROBES entry) was removed.
        assert any("Firebase Storage list" in n for n in chain_names), (
            f"Firebase Storage chain read probes must remain; chain has "
            f"{sorted(chain_names)}")
        # And the removed admin probe is NOT the chain probe.
        assert "Firebase Storage" not in chain_names

    @pytest.mark.unit
    def test_firestore_documents_chain_kept(self):
        chain_names = {p[0] for p in gas.FIREBASE_CHAIN_PROBES
                       if isinstance(p, tuple)}
        assert any("Firestore documents" in n for n in chain_names)


class TestUnsupportedKms:
    @pytest.mark.unit
    def test_cloud_kms_removed(self):
        assert "Cloud KMS" not in _names()


class TestParentRequiredRemoved:
    """These services have current APIs, but their list/read methods require
    non-project parents (analytics property, billing account, Chrome customer,
    business profile location/account, merchant/manufacturer account, etc.).
    A cold API-key scanner cannot discover those parents from `{project}`."""

    @pytest.mark.unit
    @pytest.mark.parametrize("name", _PARENT_REQUIRED_REMOVED)
    def test_parent_required_probe_absent(self, name):
        assert name not in _names()


class TestNoAiplatformProbeRemains:
    @pytest.mark.unit
    def test_no_vertex_aiplatform_probe_remains(self):
        """Both Vertex AI Express probes (the only aiplatform.googleapis.com
        probes) were removed — no probe should target that host now."""
        aiplatform = [p[0] for p in gas.ALL_PROBES
                      if "aiplatform.googleapis.com" in _host(p[3])]
        assert aiplatform == [], (
            f"no aiplatform.googleapis.com probe should remain; found "
            f"{aiplatform}")


class TestNoAuthorizedBuyersMarketplaceProbeRemains:
    @pytest.mark.unit
    def test_authorized_buyers_marketplace_absent(self):
        assert "Authorized Buyers Marketplace" not in _names()

    @pytest.mark.unit
    def test_no_authorizedbuyersmarketplace_high_probe(self):
        offenders = [p[0] for p in gas.ALL_PROBES
                     if p[1] == "high"
                     and "authorizedbuyersmarketplace.googleapis.com" in (p[3] or "")]
        assert offenders == [], (
            f"no HIGH probe should target authorizedbuyersmarketplace; "
            f"found {offenders}")


class TestThreeSurvivorsRemoved:
    """The 3 API_KEY_UNSUPPORTED survivors removed after the 10-key live
    validation (all returned the explicit OAuth2-required body 10/10,
    zero allowed sightings across 7 web + 3 mobile keys)."""

    @pytest.mark.unit
    @pytest.mark.parametrize("name", [
        "Cloud KMS", "Advisory Notifications", "Container Analysis"])
    def test_survivor_absent(self, name):
        assert name not in _names()

    @pytest.mark.unit
    @pytest.mark.parametrize("host", [
        "cloudkms.googleapis.com",
        "advisorynotifications.googleapis.com",
        "containeranalysis.googleapis.com"])
    def test_no_default_high_probe_on_host(self, host):
        offenders = [p[0] for p in gas.ALL_PROBES
                     if p[1] == "high" and host in (p[3] or "")]
        assert offenders == [], (
            f"no HIGH probe should target {host}; found {offenders}")

    @pytest.mark.unit
    def test_cloud_kms_impact_default_removed(self):
        """Cloud KMS was the only `static_catalog` _PROBE_IMPACT_DEFAULTS
        entry; it must be gone with the probe."""
        assert "Cloud KMS" not in gas._PROBE_IMPACT_DEFAULTS

    @pytest.mark.unit
    def test_no_static_catalog_override_remains(self):
        """Cloud KMS was the last probe pinned to static_catalog. After
        its removal, no _PROBE_IMPACT_DEFAULTS entry should carry
        data_sensitivity=static_catalog."""
        leftovers = [n for n, e in gas._PROBE_IMPACT_DEFAULTS.items()
                     if isinstance(e, dict)
                     and e.get("data_sensitivity") == "static_catalog"]
        assert leftovers == [], (
            f"no static_catalog _PROBE_IMPACT_DEFAULTS entry should remain; "
            f"found {leftovers}")
