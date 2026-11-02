"""Regression coverage for mobile kb pass attribution."""
from __future__ import annotations

import json

import pytest

import google_api_scanner as gas

KEY_A = "AIzaSyA" + "A" * 32
KEY_B = "AIzaSyB" + "B" * 32


def _kb(output_dir):
    with open(gas._kb_path(output_dir=output_dir)) as fh:
        return json.loads(fh.read())


class TestPassRecordsSeparate:
    @pytest.mark.unit
    def test_legacy_source_labels_are_replayed_as_mobile_contexts(self):
        entry = {
            "mobile_restriction": "mobile:ios:com.current.app",
            "sources": [
                {"url": "mobile:android:com.legacy.app:" + "AA:" * 19 + "AA"},
                "mobile:ios:com.legacy.app",
                {"url": "https://example.com/app.js"},
            ],
        }
        labels = gas.mobile_restrictions_from_kb_entry(entry)
        contexts = gas.mobile_restriction_contexts(labels)
        assert {row[0] for row in contexts} == {"android", "ios"}
        assert any("com.legacy.app" in row[1] for row in contexts)
        assert any("com.current.app" in row[1] for row in contexts)

    @pytest.mark.unit
    def test_pass1_and_pass2_recorded_separately(self, tmp_path):
        """When pass-2 runs, two scan_history records exist: pass-1
        (unrestricted) and pass-2 (android/ios restriction)."""
        out = str(tmp_path / "artifacts")
        gas._kb_record_scan(KEY_A, "20260610_000000", probes_count=None,
                            vulnerable_apis=set(),
                            restriction_mode="unrestricted",
                            key_status="unrestricted-scan",
                            output_dir=out,
                            mobile_restriction="mobile:android:com.x.app:AABB")
        gas._kb_record_scan(KEY_A, "20260610_000000_p2", probes_count=None,
                            vulnerable_apis={"Firebase RTDB root"},
                            restriction_mode="android",
                            restriction_value="com.x.app:AABBCC",
                            key_status="VULNERABLE", output_dir=out,
                            mobile_restriction="mobile:android:com.x.app:AABB")
        entry = _kb(out)[KEY_A]
        hist = entry["scan_history"]
        assert len(hist) == 2
        modes = {h.get("restriction_mode") for h in hist}
        assert "unrestricted" in modes
        assert "android" in modes
        # The bypass-only finding is on the android (pass-2) record, NOT the
        # unrestricted one.
        p2 = [h for h in hist if h.get("restriction_mode") == "android"][0]
        p1 = [h for h in hist if h.get("restriction_mode") == "unrestricted"][0]
        assert "Firebase RTDB root" in (p2.get("vulnerable_apis") or [])
        assert "Firebase RTDB root" not in (p1.get("vulnerable_apis") or [])

    @pytest.mark.unit
    def test_mobile_restriction_persisted(self, tmp_path):
        out = str(tmp_path / "artifacts")
        gas._kb_record_scan(KEY_A, "t1", probes_count=None,
                            vulnerable_apis=set(),
                            restriction_mode="unrestricted", output_dir=out,
                            mobile_restriction="mobile:ios:com.victim.app")
        entry = _kb(out)[KEY_A]
        assert entry.get("mobile_restriction") == "mobile:ios:com.victim.app"

    @pytest.mark.unit
    def test_program_and_platform_recorded(self, tmp_path):
        out = str(tmp_path / "artifacts")
        gas._kb_record_scan(KEY_A, "t1", probes_count=None,
                            vulnerable_apis=set(),
                            restriction_mode="unrestricted", output_dir=out,
                            program="acme", platform="example")
        entry = _kb(out)[KEY_A]
        # program/platform are recorded somewhere in the entry/history.
        blob = json.dumps(entry)
        assert "acme" in blob

    @pytest.mark.unit
    def test_identity_toolkit_cleanup_failures_record_local_id_only(self, tmp_path):
        out = str(tmp_path / "artifacts")
        gas._kb_record_scan(
            KEY_A, "t1", probes_count=None,
            vulnerable_apis={"Identity Toolkit signUp anon"},
            restriction_mode="ios", restriction_value="com.example.app",
            output_dir=out,
            identity_toolkit_artifacts=[{
                "probe": "signUp (anon)",
                "local_id": "local123",
                "id_token_prefix": "SECRET_TOKEN_PREFIX",
                "reason": "delete returned HTTP 403",
            }],
        )
        entry = _kb(out)[KEY_A]
        failures = entry.get("identity_toolkit_cleanup_failures") or []
        assert failures[0]["local_id"] == "local123"
        assert failures[0]["restriction_mode"] == "ios"
        hist_failures = entry["scan_history"][0].get(
            "identity_toolkit_cleanup_failures") or []
        assert hist_failures[0]["reason"] == "delete returned HTTP 403"
        assert "SECRET_TOKEN_PREFIX" not in json.dumps(entry)

    @pytest.mark.unit
    def test_probe_diagnostics_and_histogram_persisted_redacted(self, tmp_path):
        out = str(tmp_path / "artifacts")
        gas._kb_record_scan(
            KEY_A, "t1", probes_count=None, vulnerable_apis=set(),
            restriction_mode="unrestricted", output_dir=out,
            error_class_histogram={"HTTP_423_LOCKED": 2},
            probe_diagnostics=[{
                "name": "Firebase RTDB root (.json)",
                "category": "high",
                "url_redacted": "https://x.firebaseio.com/.json?key=<redacted>",
                "status_code": 423,
                "error_class": "HTTP_423_LOCKED",
                "error_reason": "Locked",
                "metadata_services": [],
            }],
        )
        entry = _kb(out)[KEY_A]
        rec = entry["scan_history"][0]
        assert rec["error_class_histogram"]["HTTP_423_LOCKED"] == 2
        diag = rec["probe_diagnostics"][0]
        assert diag["name"] == "Firebase RTDB root (.json)"
        assert diag["status_code"] == 423
        assert diag["error_class"] == "HTTP_423_LOCKED"
        assert KEY_A not in json.dumps(entry)

    @pytest.mark.unit
    def test_finding_records_persist_potential_and_redact_key(self, tmp_path):
        out = str(tmp_path / "artifacts")
        raw_url = (
            "https://speech.googleapis.com/v1/operations?key=%s" % KEY_A
        )
        gas._kb_record_scan(
            KEY_A, "t1", probes_count=None, vulnerable_apis=set(),
            restriction_mode="unrestricted", output_dir=out,
            finding_records=[{
                "name": "Speech Operations",
                "severity": "MED",
                "tier": "POTENTIAL",
                "category": "high",
                "abuse_class": "BillDrain",
                "poc_url": raw_url,
                "confirmation": "key_accepted_only",
                "data_sensitivity": "none",
            }],
        )
        entry = _kb(out)[KEY_A]
        rec = entry["scan_history"][0]
        finding = rec["finding_records"][0]
        assert finding["name"] == "Speech Operations"
        assert finding["tier"] == "POTENTIAL"
        assert finding["abuse_class"] == "BillDrain"
        assert rec["finding_counts"]["potential"] == 1
        assert rec["finding_counts"]["potential_med"] == 1
        assert KEY_A not in json.dumps(entry)
        assert "<redacted>" in finding["poc_url"]


class TestCrossKeyIsolation:
    @pytest.mark.unit
    def test_key_b_does_not_inherit_key_a_pass2_findings(self, tmp_path):
        """Simulate the fixed loop's per-key accumulator init: Key A has a
        pass-2 finding; Key B runs pass-1 only. Key B's KB record must NOT
        contain Key A's pass-2 vulnerable API."""
        out = str(tmp_path / "artifacts")
        # Key A: pass-1 (clean) + pass-2 (finding)
        gas._kb_record_scan(KEY_A, "a1", probes_count=None,
                            vulnerable_apis=set(),
                            restriction_mode="unrestricted", output_dir=out)
        gas._kb_record_scan(KEY_A, "a1_p2", probes_count=None,
                            vulnerable_apis={"Firebase RTDB root"},
                            restriction_mode="android",
                            restriction_value="com.a.app:CC", output_dir=out)
        # Key B: pass-1 only (no pass-2 ran → vs_ref is a fresh empty set,
        # the loop must NOT carry over Key A's findings).
        vs_un_b = set()      # mimic the loop: vs_un initialized per key
        vs_ref_b = set()     # mimic the loop: vs_ref initialized per key
        _pass2_ran_b = False
        gas._kb_record_scan(KEY_B, "b1", probes_count=None,
                            vulnerable_apis=set(vs_un_b),
                            restriction_mode="unrestricted", output_dir=out)
        if _pass2_ran_b:
            gas._kb_record_scan(KEY_B, "b1_p2", probes_count=None,
                                vulnerable_apis=set(vs_ref_b),
                                restriction_mode="android", output_dir=out)
        kb = _kb(out)
        b_blob = json.dumps(kb[KEY_B])
        assert "Firebase RTDB root" not in b_blob, (
            "Key B inherited Key A's pass-2 finding (cross-key leak)")
        # Key B has exactly one (pass-1) record.
        assert len(kb[KEY_B]["scan_history"]) == 1


class TestSourceFreeOfStaleFallback:
    @pytest.mark.unit
    def test_no_vs_ref_local_nameerror_fallback_in_source(self):
        src = gas._engine_source_text()
        assert "_vs_ref_local" not in src, (
            "the NameError fallback around _vs_ref_local must be removed; "
            "vs_ref is now initialized per key")
