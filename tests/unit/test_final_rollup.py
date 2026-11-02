"""Regression coverage for final rollup."""
from __future__ import annotations

import pytest

import google_api_scanner as gas


# Result-dict factory (matches the shape _execute_probe produces)


def _vuln(name, severity="HIGH", tier="CONFIRMED", category="high",
          abuse_class="DataExfil", url=None, impact_type="data_read",
          confirmation="confirmed_data", data_sensitivity="customer_data"):
    return {
        "name": name,
        "severity": severity,
        "tier": tier,
        "category": category,
        "abuse_class": abuse_class,
        "url": url or ("https://%s.googleapis.com/v1/x?key=AIzaSyRAWSECRETKEY01234567890abcd"
                       % name.split()[0].lower()),
        "impact_type": impact_type,
        "confirmation": confirmation,
        "data_sensitivity": data_sensitivity,
        "vulnerable": True,
    }


def _snapshot(results, restriction_mode=None, restriction_value=None):
    """Capture + read back a structured snapshot for one scan_gapis call."""
    gas._capture_last_scan_result_snapshot(
        results, restriction_mode=restriction_mode,
        restriction_value=restriction_value)
    return gas._last_scan_result_snapshot()


# Snapshot capture / read contract


class TestSnapshotCapture:
    @pytest.mark.unit
    def test_only_vulnerable_rows_captured(self):
        rows = _snapshot([
            _vuln("Pub/Sub Topics"),
            {"name": "Some 404 probe", "vulnerable": False,
             "error_class": "NOT_FOUND", "url": "https://x?key=AIzaX",
             "severity": "INFO"},
        ])
        names = {r["name"] for r in rows}
        assert names == {"Pub/Sub Topics"}

    @pytest.mark.unit
    def test_snapshot_is_isolated_copy(self):
        _snapshot([_vuln("Pub/Sub Topics")])
        a = gas._last_scan_result_snapshot()
        a.append({"poison": True})
        b = gas._last_scan_result_snapshot()
        assert all("poison" not in r for r in b)

    @pytest.mark.unit
    def test_pass_context_recorded(self):
        rows = _snapshot([_vuln("Pub/Sub Topics")],
                         restriction_mode="referer",
                         restriction_value="https://app.example.com")
        assert rows[0]["pass_context"] == "referer"
        assert rows[0]["restriction_value"] == "https://app.example.com"

    @pytest.mark.unit
    def test_unrestricted_pass_context_default(self):
        rows = _snapshot([_vuln("Pub/Sub Topics")])
        assert rows[0]["pass_context"] == "unrestricted"
        assert rows[0]["restriction_value"] is None


# bypass_only computation


class TestBypassOnly:
    @pytest.mark.unit
    def test_pass2_only_is_bypass_yes(self):
        p1 = _snapshot([])  # nothing in unrestricted pass
        p2 = _snapshot([_vuln("Firebase RTDB")], restriction_mode="referer",
                       restriction_value="https://app.example.com")
        rows = gas._merge_rollup_rows_for_key(
            "https://app.example.com", "AIzaTEST…0000", p1, p2)
        assert len(rows) == 1
        assert rows[0]["bypass_only"] is True
        assert rows[0]["pass_context"] == "referer"

    @pytest.mark.unit
    def test_both_passes_is_bypass_no(self):
        p1 = _snapshot([_vuln("Pub/Sub Topics")])
        p2 = _snapshot([_vuln("Pub/Sub Topics")], restriction_mode="referer",
                       restriction_value="https://app.example.com")
        rows = gas._merge_rollup_rows_for_key(
            "https://app.example.com", "AIzaTEST…0000", p1, p2)
        assert len(rows) == 1
        assert rows[0]["bypass_only"] is False
        # Prefers the unrestricted pass context, with a note that the
        # restricted pass also surfaced it.
        assert rows[0]["pass_context"] == "unrestricted"
        assert "restricted pass also surfaced" in (rows[0]["note"] or "")

    @pytest.mark.unit
    def test_pass1_only_is_bypass_no(self):
        p1 = _snapshot([_vuln("Pub/Sub Topics")])
        rows = gas._merge_rollup_rows_for_key(
            "https://app.example.com", "AIzaTEST…0000", p1, [])
        assert rows[0]["bypass_only"] is False
        assert rows[0]["note"] is None


# Multiple keys / source preservation


class TestMultiKeyRollup:
    @pytest.mark.unit
    def test_only_high_key_listed_by_default(self):
        # Key A: HIGH finding. Key B: MED billing-only finding.
        rows = []
        a1 = _snapshot([_vuln("Pub/Sub Topics", severity="HIGH")])
        rows += gas._merge_rollup_rows_for_key(
            "https://a.example.com", "AIzaKEYA…aaaa", a1, [])
        b1 = _snapshot([_vuln("Cloud Translation", severity="MED",
                              category="low", abuse_class="BillDrain",
                              impact_type="quota_cost",
                              data_sensitivity="billing_reachable")])
        rows += gas._merge_rollup_rows_for_key(
            "https://b.example.com", "AIzaKEYB…bbbb", b1, [])
        out = gas._render_final_rollup(rows, rollup_all_findings=False)
        # Default rollup: only the HIGH key appears.
        assert "AIzaKEYA…aaaa" in out
        assert "Pub/Sub Topics" in out
        assert "AIzaKEYB…bbbb" not in out
        assert "Cloud Translation" not in out
        # The hidden-count line warns about the omitted MED finding.
        assert "non-reportable" in out

    @pytest.mark.unit
    def test_web_source_url_preserved(self):
        p1 = _snapshot([_vuln("Pub/Sub Topics")])
        rows = gas._merge_rollup_rows_for_key(
            "https://target.example.com/app.js", "AIzaTEST…0000", p1, [])
        out = gas._render_final_rollup(rows)
        assert "https://target.example.com/app.js" in out
        assert rows[0]["source"] == "https://target.example.com/app.js"

    @pytest.mark.unit
    def test_mobile_dir_two_archives_distinct_restrictions(self):
        """Two keys from two archives with different Android package/SHA1.
        Each key's pass-2 row must carry its OWN restriction label."""
        # Archive 1 key — android pkg com.foo.app.
        p1a = _snapshot([])
        p2a = _snapshot([_vuln("Firebase RTDB")], restriction_mode="android",
                        restriction_value="com.foo.app:AA:BB:CC")
        rows = gas._merge_rollup_rows_for_key(
            "mobile:android:com.foo.app", "AIzaKEY1…1111", p1a, p2a)
        # Archive 2 key — android pkg com.bar.app, different SHA1.
        p1b = _snapshot([])
        p2b = _snapshot([_vuln("Firebase RTDB")], restriction_mode="android",
                        restriction_value="com.bar.app:DD:EE:FF")
        rows += gas._merge_rollup_rows_for_key(
            "mobile:android:com.bar.app", "AIzaKEY2…2222", p1b, p2b)

        by_key = {r["key"]: r for r in rows}
        assert by_key["AIzaKEY1…1111"]["restriction_value"] == "com.foo.app:AA:BB:CC"
        assert by_key["AIzaKEY2…2222"]["restriction_value"] == "com.bar.app:DD:EE:FF"
        # Both are pass2-only → bypass_only=yes.
        assert all(r["bypass_only"] for r in rows)


# Section gating: MED / POTENTIAL only under --rollup-all-findings


class TestSectionGating:
    def _mixed_rows(self):
        rows = []
        for r in (
            _vuln("Pub/Sub Topics", severity="HIGH"),
            _vuln("Cloud Translation", severity="MED", category="low",
                  abuse_class="BillDrain", impact_type="quota_cost",
                  data_sensitivity="billing_reachable"),
            _vuln("Firebase Remote Config", severity="LOW",
                  data_sensitivity="metadata"),
            _vuln("sendOobCode (capability)", severity="INFO",
                  tier="POTENTIAL", confirmation="key_accepted_only",
                  data_sensitivity="none", abuse_class="BrandPhish"),
        ):
            snap = _snapshot([r])
            rows += gas._merge_rollup_rows_for_key(
                "https://x.example.com", "AIzaTEST…0000", snap, [])
        return rows

    @pytest.mark.unit
    def test_med_billing_hidden_by_default(self):
        out = gas._render_final_rollup(self._mixed_rows(),
                                       rollup_all_findings=False)
        assert "Pub/Sub Topics" in out
        assert "Cloud Translation" not in out

    @pytest.mark.unit
    def test_med_billing_appears_with_all_findings(self):
        out = gas._render_final_rollup(self._mixed_rows(),
                                       rollup_all_findings=True)
        assert "confirmed-med" in out
        assert "Cloud Translation" in out

    @pytest.mark.unit
    def test_potential_hidden_by_default(self):
        out = gas._render_final_rollup(self._mixed_rows(),
                                       rollup_all_findings=False)
        assert "sendOobCode" not in out

    @pytest.mark.unit
    def test_potential_appears_only_with_all_findings(self):
        out = gas._render_final_rollup(self._mixed_rows(),
                                       rollup_all_findings=True)
        assert "potential" in out
        assert "sendOobCode" in out

    @pytest.mark.unit
    def test_low_info_hidden_by_default_shown_with_all(self):
        rows = self._mixed_rows()
        default = gas._render_final_rollup(rows, rollup_all_findings=False)
        full = gas._render_final_rollup(rows, rollup_all_findings=True)
        assert "Firebase Remote Config" not in default
        assert "Firebase Remote Config" in full
        assert "confirmed-low-info" in full

    @pytest.mark.unit
    def test_section_classification(self):
        assert gas._rollup_section_for(
            {"tier": "CONFIRMED", "severity": "HIGH"}) == "reportable_high"
        assert gas._rollup_section_for(
            {"tier": "CONFIRMED", "severity": "CRITICAL"}) == "reportable_high"
        assert gas._rollup_section_for(
            {"tier": "CONFIRMED", "severity": "MED"}) == "confirmed_med"
        assert gas._rollup_section_for(
            {"tier": "CONFIRMED", "severity": "LOW"}) == "confirmed_low_info"
        assert gas._rollup_section_for(
            {"tier": "CONFIRMED", "severity": "INFO"}) == "confirmed_low_info"
        # A POTENTIAL HIGH still classifies as potential (tier dominates).
        assert gas._rollup_section_for(
            {"tier": "POTENTIAL", "severity": "HIGH"}) == "potential"


# Redaction — no raw secret ever appears in the rendered rollup


class TestRedaction:
    @pytest.mark.unit
    def test_raw_aiza_key_never_in_poc_url(self):
        raw = "AIzaSyRAWSECRETKEY01234567890abcd"
        snap = _snapshot([_vuln(
            "Pub/Sub Topics",
            url="https://pubsub.googleapis.com/v1/x?key=" + raw)])
        rows = gas._merge_rollup_rows_for_key(
            "https://x.example.com", gas._redact_key_display(raw), snap, [])
        out = gas._render_final_rollup(rows, rollup_all_findings=True)
        assert raw not in out
        assert "<redacted>" in out

    @pytest.mark.unit
    def test_redact_key_display_masks_secret(self):
        raw = "AIzaSyRAWSECRETKEY01234567890abcd"
        disp = gas._redact_key_display(raw)
        assert raw not in disp
        assert disp.startswith("AIzaSyRA")
        assert disp.endswith("abcd")
        assert "…" in disp

    @pytest.mark.unit
    def test_redact_key_display_short_input(self):
        assert gas._redact_key_display("short") == "<redacted>"
        assert gas._redact_key_display("") == "<redacted>"
        assert gas._redact_key_display(None) == "<redacted>"

    @pytest.mark.unit
    def test_restriction_value_redacted_when_keylike(self):
        # A restriction value that itself embeds a key= param is redacted.
        snap = _snapshot(
            [_vuln("Firebase RTDB")],
            restriction_mode="referer",
            restriction_value="https://app.example.com/?key=AIzaLEAK123456789")
        rows = gas._merge_rollup_rows_for_key(
            "https://app.example.com", "AIzaTEST…0000", [], snap)
        out = gas._render_final_rollup(rows, rollup_all_findings=True)
        assert "AIzaLEAK123456789" not in out

    @pytest.mark.unit
    def test_source_url_query_key_redacted(self):
        """A web source URL carrying ?key=AIza… must NOT leak the raw key
        via the rollup `source` field (the field is copied straight into
        the row and printed)."""
        raw = "AIzaSyRAWSECRET01234567890abcdefgh"
        snap = _snapshot([_vuln("Pub/Sub Topics")])
        rows = gas._merge_rollup_rows_for_key(
            "https://cdn.example/app.js?key=%s&x=1" % raw,
            "AIzaTEST…0000", snap, [])
        # Stored source is redacted (key= value scrubbed, rest preserved).
        assert raw not in rows[0]["source"]
        assert "key=<redacted>" in rows[0]["source"]
        assert "&x=1" in rows[0]["source"]  # surrounding context preserved
        # Rendered rollup never contains the raw key.
        out = gas._render_final_rollup(rows, rollup_all_findings=True)
        assert raw not in out
        assert "key=<redacted>" in out

    @pytest.mark.unit
    def test_source_raw_aiza_outside_query_redacted(self):
        """A raw AIza key embedded in the source label OUTSIDE any query
        string (e.g. a malformed source provenance string) is scrubbed."""
        raw = "AIzaSyRAWSECRET01234567890abcdefgh"
        snap = _snapshot([_vuln("Pub/Sub Topics")])
        rows = gas._merge_rollup_rows_for_key(
            "inline-script-blob containing %s here" % raw,
            "AIzaTEST…0000", snap, [])
        assert raw not in rows[0]["source"]
        assert "<AIza-redacted>" in rows[0]["source"]
        out = gas._render_final_rollup(rows, rollup_all_findings=True)
        assert raw not in out

    @pytest.mark.unit
    def test_source_mobile_label_preserved(self):
        """Redaction must NOT mangle a normal mobile label (no secrets in
        it — the SHA1 hex pairs are not AIza/JWT/ya29 shaped)."""
        label = ("mobile:android:com.foo.app:"
                 "AA:BB:CC:DD:EE:FF:11:22:33:44:55:66:77:88:99:00:AA:BB:CC:DD")
        snap = _snapshot([_vuln("Firebase RTDB")])
        rows = gas._merge_rollup_rows_for_key(label, "AIzaKEY…1111", snap, [])
        assert rows[0]["source"] == label

    @pytest.mark.unit
    def test_source_clean_url_preserved(self):
        """A secret-free source URL passes through unchanged."""
        url = "https://app.example.com/login"
        snap = _snapshot([_vuln("Pub/Sub Topics")])
        rows = gas._merge_rollup_rows_for_key(url, "AIzaTEST…0000", snap, [])
        assert rows[0]["source"] == url

    @pytest.mark.unit
    def test_redact_rollup_source_none_passthrough(self):
        assert gas._redact_rollup_source(None) is None
