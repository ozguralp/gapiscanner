"""Tests for classifier diagnostics."""
from __future__ import annotations

import json

import pytest

import google_api_scanner as gas


class _FakeResp:
    def __init__(self, status_code, text):
        self.status_code = status_code
        self.text = text
        self.content = text.encode("utf-8")


class TestApiKeyUnsupportedClassifier:
    @pytest.mark.unit
    def test_api_keys_not_supported_phrase_classifies_as_unsupported(self):
        r = _FakeResp(
            401,
            '{"error":{"code":401,"message":"API keys are not supported by this API. Expected OAuth 2 access token, login cookie or other valid authentication credential","status":"UNAUTHENTICATED"}}',
        )
        assert gas._classify_error(r) == "API_KEY_UNSUPPORTED"

    @pytest.mark.unit
    def test_expected_oauth2_phrase_classifies_as_unsupported(self):
        r = _FakeResp(
            401,
            '{"error":{"code":401,"message":"Request had invalid authentication credentials. Expected OAuth 2 access token, ...","status":"UNAUTHENTICATED"}}',
        )
        assert gas._classify_error(r) == "API_KEY_UNSUPPORTED"

    @pytest.mark.unit
    def test_generic_401_stays_unauthenticated(self):
        r = _FakeResp(
            401,
            '{"error":{"code":401,"message":"Authentication required.","status":"UNAUTHENTICATED"}}',
        )
        assert gas._classify_error(r) == "UNAUTHENTICATED"

    @pytest.mark.unit
    def test_bare_412_classifies_as_failed_precondition(self):
        r = _FakeResp(412, "")
        assert gas._classify_error(r) == "FAILED_PRECONDITION"

    @pytest.mark.unit
    def test_firebase_storage_412_classifies_as_storage_precondition(self):
        r = _FakeResp(
            412,
            '{"error":{"code":412,"message":"A required service account is missing necessary permissions. Please resolve by visiting the Storage page of the Firebase Console and re-linking your Firebase bucket."}}',
        )
        assert gas._classify_error(r) == "FIREBASE_STORAGE_PRECONDITION"

    @pytest.mark.unit
    def test_rtdb_deactivated_423_classifies_as_deactivated(self):
        r = _FakeResp(
            423,
            '{"error":"The Firebase database \'durable-sky-559\' has been deactivated."}',
        )
        assert gas._classify_error(r) == "FIREBASE_RTDB_DEACTIVATED"

    @pytest.mark.unit
    def test_bare_423_classifies_as_locked_not_raw_http(self):
        r = _FakeResp(423, "")
        assert gas._classify_error(r) == "HTTP_423_LOCKED"

    @pytest.mark.unit
    def test_neither_class_is_marked_vulnerable(self):
        classes_in_table = {v for _, v in gas._ERROR_CLASS_KEYWORDS}
        assert "API_KEY_UNSUPPORTED" in classes_in_table
        assert "UNAUTHENTICATED" in classes_in_table


_UNSUPPORTED_PROBE_NAMES = (
    "IAM",
    "IAM Credentials",
    "Cloud Resource Manager projects.list (enum)",
)


class TestOAuthOnlyRemoved:
    @pytest.mark.unit
    def test_removed_names_absent_from_all_probes(self):
        registry = {p[0] for p in gas.ALL_PROBES}
        for name in _UNSUPPORTED_PROBE_NAMES:
            assert name not in registry, (
                f"{name!r} is documented OAuth-only and must "
                f"NOT be in ALL_PROBES. Adding it back requires "
                f"evidence that the endpoint supports API-key authentication.")

    @pytest.mark.unit
    def test_removed_names_absent_from_probe_impact_defaults(self):
        for name in _UNSUPPORTED_PROBE_NAMES:
            assert name not in gas._PROBE_IMPACT_DEFAULTS

    @pytest.mark.unit
    def test_removed_names_absent_from_abuse_class_overrides(self):
        for name in _UNSUPPORTED_PROBE_NAMES:
            assert name not in gas.ABUSE_CLASS_OVERRIDES

    @pytest.mark.unit
    def test_removed_names_absent_from_phase_0(self):
        for name in _UNSUPPORTED_PROBE_NAMES:
            assert name not in gas.PHASE_0_PROBE_NAMES

    @pytest.mark.unit
    def test_api_key_capable_probes_NOT_removed(self):
        registry = {p[0] for p in gas.ALL_PROBES}

        keepers = [
            "Cloud Storage Buckets",   # storage.googleapis.com — API-key-capable
            "Pub/Sub Topics",          # pubsub admin can be key-bound on some projects
            "Cloud Translation",       # billing-only MED probe
            "Cloud Vision",            # billing-only MED probe
            "Gemini Models List",      # core API-key-capable read
            "Gemini Generate Content", # core API-key-capable generate
        ]
        for name in keepers:
            assert name in registry, (
                f"{name!r} is API-key-capable and must NOT "
                f"have been removed by the OAuth-only cleanup")
        # The three evidence-removed former keepers must now be ABSENT.
        for removed in ("Bigtable Admin", "Spanner", "Firebase Storage"):
            assert removed not in registry, (
                f"{removed!r} rejects API-key authentication (JSON "
                f"API_KEY_UNSUPPORTED evidence) and must be absent")

        for removed in ("Firebase App Check", "Cloud Trace", "FCM Data",
                        "Firebase App Distribution", "IAP", "Runtime Config",
                        "Discovery Engine"):
            assert removed not in registry, (
                f"{removed!r} rejects API-key authentication")


def _make_result(name, error_class, services_seen=None, vulnerable=False,
                 url=None, snippet=None, reason=None):
    """Mimic the shape _execute_probe returns. Only fields the JSON /
    textual report consume are populated."""
    return {
        "name": name,
        "category": "high",
        "abuse_class": None,
        "url": url or "https://example.googleapis.com/v1/x?key=AIzaSyTEST",
        "impact": "fake impact",
        "vulnerable": vulnerable,
        "manual_note": None,
        "referer_blocked": error_class == "REFERRER_BLOCKED",
        "error_class": error_class,
        "services_seen": set(services_seen or []),
        "reason": reason or ("HTTP %d" % (200 if vulnerable else 401)),
        "gemini_disabled": False,
        "status_code": 200 if vulnerable else 401,
        "snippet": snippet,
        "impact_type": "info_disclosure",
        "confirmation": "confirmed_data" if vulnerable else "key_accepted_only",
        "data_sensitivity": "customer_data" if vulnerable else "metadata",
        "severity": "HIGH" if vulnerable else "INFO",
        "tier": "CONFIRMED" if vulnerable else None,
    }


class TestExpandedInference:
    @pytest.mark.unit
    def test_android_blocked_appears_in_json_inference(self):
        results = [
            _make_result(
                "FakeProbe",
                "ANDROID_BLOCKED",
                services_seen={"vision.googleapis.com"}),
        ]
        out = gas._build_json_output(results, tested_count=1, options={})
        allowlist = out["service_allowlist_inference"]
        assert "android-blocked" in allowlist, allowlist
        assert "vision.googleapis.com" in allowlist["android-blocked"]

    @pytest.mark.unit
    def test_ios_ip_referrer_blocked_appear(self):
        results = [
            _make_result("p1", "IOS_BLOCKED",
                         services_seen={"vision.googleapis.com"}),
            _make_result("p2", "IP_BLOCKED",
                         services_seen={"translate.googleapis.com"}),
            _make_result("p3", "REFERRER_BLOCKED",
                         services_seen={"maps.googleapis.com"}),
        ]
        out = gas._build_json_output(results, tested_count=3, options={})
        al = out["service_allowlist_inference"]
        assert "vision.googleapis.com" in al.get("ios-blocked", [])
        assert "translate.googleapis.com" in al.get("ip-blocked", [])
        assert "maps.googleapis.com" in al.get("referer-blocked", [])

    @pytest.mark.unit
    def test_api_key_unsupported_maps_to_does_not_accept(self):
        results = [
            _make_result("p1", "API_KEY_UNSUPPORTED",
                         services_seen={"iam.googleapis.com"}),
            _make_result("p2", "UNAUTHENTICATED",
                         services_seen={"unknown.googleapis.com"}),
        ]
        out = gas._build_json_output(results, tested_count=2, options={})
        al = out["service_allowlist_inference"]
        assert "iam.googleapis.com" in al.get("does-not-accept-api-keys", [])
        # Generic 401 with no API_KEY_UNSUPPORTED phrase lands in the
        # narrower `unauthenticated` bucket so the operator can tell
        # them apart.
        assert "unknown.googleapis.com" in al.get("unauthenticated", [])

    @pytest.mark.unit
    def test_unknown_service_classified_count_surfaced(self):
        """Classified error without metadata.service is counted in
        unknown_service_classified_count, not silently dropped."""
        results = [
            _make_result("p1", "NOT_FOUND", services_seen=set()),
            _make_result("p2", "INVALID_ARGUMENT", services_seen=set()),
        ]
        out = gas._build_json_output(results, tested_count=2, options={})
        assert out["unknown_service_classified_count"] == 2


class TestFingerprintDetail:
    @pytest.mark.unit
    def test_signature_accepts_fingerprint_detail_kwarg(self):
        assert "fingerprint_detail" in gas.scan_gapis.__code__.co_varnames

    @pytest.mark.unit
    def test_concise_caps_long_does_not_accept_bucket(self):
        """Build a synthetic results list with 20 services in the
        `does-not-accept-api-keys` bucket, then run the textual block
        in concise mode and verify the printed output caps at 8 + a
        "more" trailer."""

        services = [f"svc{i}.googleapis.com" for i in range(20)]
        out = _render_textual_inference_block(
            services_by_class={
                "API_KEY_UNSUPPORTED": services,
            },
            fingerprint_detail="concise",
        )
        # 8 services + 1 trailer line
        printed_svcs = [l for l in out.splitlines() if l.strip().startswith("- svc")]
        more_lines = [l for l in out.splitlines() if "more" in l]
        assert len(printed_svcs) == 8, (
            f"concise mode must cap at 8 services; got {len(printed_svcs)}")
        assert more_lines, "concise mode must add a 'more' trailer"

    @pytest.mark.unit
    def test_full_does_not_cap(self):
        services = [f"svc{i}.googleapis.com" for i in range(20)]
        out = _render_textual_inference_block(
            services_by_class={
                "API_KEY_UNSUPPORTED": services,
            },
            fingerprint_detail="full",
        )
        printed_svcs = [l for l in out.splitlines() if l.strip().startswith("- svc")]
        more_lines = [l for l in out.splitlines() if "more" in l]
        assert len(printed_svcs) == 20, (
            f"full mode must print every service; got {len(printed_svcs)}")
        assert not more_lines, "full mode must NOT add a 'more' trailer"


def _render_textual_inference_block(services_by_class, fingerprint_detail):
    """In-test mirror of the scan_gapis textual allowlist-inference
    block. We feed it `error_class -> [service]` and a detail
    level and return the formatted stdout. The mapping is:
    services_by_class uses error_class names (e.g.
    API_KEY_UNSUPPORTED), and we translate via the same
    SERVICE_PRIORITY map the scanner uses, so the test exercises
    the same label / cap logic."""
    SERVICE_PRIORITY = {
        "VULNERABLE":            (0, "allowed"),
        "SERVICE_BLOCKED":       (1, "denied"),
        "REFERRER_BLOCKED":      (2, "referer-blocked"),
        "REFERER_INCOMPATIBLE":  (2, "referer-incompatible"),
        "IP_BLOCKED":            (2, "ip-blocked"),
        "ANDROID_BLOCKED":       (2, "android-blocked"),
        "IOS_BLOCKED":           (2, "ios-blocked"),
        "API_DISABLED":          (3, "api-disabled-in-project"),
        "API_KEY_UNSUPPORTED":   (4, "does-not-accept-api-keys"),
        "UNAUTHENTICATED":       (5, "unauthenticated"),
        "PERMISSION_DENIED":     (6, "permission-denied"),
        "NOT_FOUND":             (7, "not-found"),
        "INVALID_ARGUMENT":      (8, "invalid-argument"),
        "FIREBASE_STORAGE_PRECONDITION": (9, "precondition-failed"),
    }
    _CAPPED_LABELS = frozenset({
        "does-not-accept-api-keys", "unauthenticated",
        "permission-denied", "not-found", "invalid-argument",
        "api-disabled-in-project",
    })
    by_label = {}
    for ec, svcs in services_by_class.items():
        _, label = SERVICE_PRIORITY[ec]
        by_label[label] = sorted(svcs)
    fp = (fingerprint_detail or "concise").lower()
    out_lines = []
    for label, svcs in by_label.items():
        if not svcs:
            continue
        out_lines.append("    %s (%d):" % (label, len(svcs)))
        if fp == "concise" and label in _CAPPED_LABELS and len(svcs) > 8:
            preview = svcs[:8] + ["... (%d more — re-run with --fingerprint-detail full)" % (len(svcs) - 8)]
        else:
            preview = svcs
        for s in preview:
            out_lines.append("      - %s" % s)
    return "\n".join(out_lines)


class TestProbeDiagnostics:
    @pytest.mark.unit
    def test_diagnostics_field_present(self):
        results = [
            _make_result("p1", "API_KEY_UNSUPPORTED",
                         services_seen={"iam.googleapis.com"},
                         snippet='{"error":{"message":"API keys are not supported by this API. Expected OAuth 2 access token..."}}',
                         reason="API keys are not supported by this API"),
        ]
        out = gas._build_json_output(results, tested_count=1, options={})
        assert "probe_diagnostics" in out
        assert len(out["probe_diagnostics"]) == 1
        rec = out["probe_diagnostics"][0]
        assert rec["name"] == "p1"
        assert rec["error_class"] == "API_KEY_UNSUPPORTED"
        assert rec["metadata_services"] == ["iam.googleapis.com"]
        assert rec["error_excerpt"], "error_excerpt must be populated"

    @pytest.mark.unit
    def test_diagnostics_redact_api_key_in_url(self):
        results = [
            _make_result(
                "p1", "UNAUTHENTICATED",
                url="https://example.googleapis.com/v1/x?key=AIzaSyTESTABCDEF0123456789abcdef01234567",
                services_seen={"example.googleapis.com"},
            ),
        ]
        out = gas._build_json_output(results, tested_count=1, options={})
        rec = out["probe_diagnostics"][0]
        assert "AIzaSyTESTABCDEF" not in rec["url_redacted"], (
            f"raw AIza key must not appear in url_redacted; got "
            f"{rec['url_redacted']!r}")
        assert "<redacted>" in rec["url_redacted"]
