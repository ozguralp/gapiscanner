"""Regression coverage for billing only med."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import google_api_scanner as gas  # noqa: E402


SENTINEL_KEY = "AIzaSy" + "X" * 33


_BILLING_ONLY_MED_PROBES = (
    "Cloud Translation",
    "Cloud Vision",
    "Cloud Natural Language",
    "Cloud Text-to-Speech",
    "Gemini Generate Content",
)


_BILLING_ONLY_MOVED_TO_LOW = (
    "Cloud Translation",
    "Cloud Vision",
    "Cloud Natural Language",
    "Cloud Text-to-Speech",
)


_BILLING_ONLY_STAYS_HIGH = (
    "Gemini Generate Content",
)


_GEMINI_READ_MUST_STAY_HIGH = (
    "Gemini Files List",
    "Gemini Cached Contents",
    "Gemini Tuned Models",
    "Gemini Corpora",
)


def _probe_by_name(name):
    for p in gas.ALL_PROBES:
        if p[0] == name:
            return p
    for p in getattr(gas, "FIREBASE_CHAIN_PROBES", []):
        if p[0] == name:
            return p
    raise AssertionError(f"probe not found: {name}")


class TestBillingOnlyMedFields:
    @pytest.mark.unit
    @pytest.mark.parametrize("name", _BILLING_ONLY_MED_PROBES)
    def test_probe_impact_defaults_entry_present(self, name):
        """Every billing-only MED probe MUST carry an explicit
        `_PROBE_IMPACT_DEFAULTS` entry. Without it, the category
        default for `high` would derive HIGH."""
        entry = gas._PROBE_IMPACT_DEFAULTS.get(name)
        assert entry is not None, (
            f"{name!r} is missing from _PROBE_IMPACT_DEFAULTS — "
            f"category default would derive HIGH instead of MED")
        assert entry.get("impact_type") == "quota_cost"
        assert entry.get("confirmation") == "confirmed_data"
        assert entry.get("data_sensitivity") == "billing_reachable"

    @pytest.mark.unit
    @pytest.mark.parametrize("name", _BILLING_ONLY_MED_PROBES)
    def test_resolve_response_fields_returns_billing_tuple(self, name):
        """The resolver MUST produce the billing-only tuple for these
        probes regardless of what the category default is."""
        probe = _probe_by_name(name)
        cat = probe[1]
        impact_type, confirmation, data_sensitivity = (
            gas._resolve_response_fields(name, cat))
        assert impact_type == "quota_cost"
        assert confirmation == "confirmed_data"
        assert data_sensitivity == "billing_reachable"

    @pytest.mark.unit
    @pytest.mark.parametrize("name", _BILLING_ONLY_MED_PROBES)
    def test_derive_severity_is_med(self, name):
        """`_derive_severity(quota_cost, confirmed_data,
        billing_reachable)` MUST be MED. This is the contract that
        guarantees report severity for these probes."""
        sev = gas._derive_severity(
            "quota_cost", "confirmed_data", "billing_reachable")
        assert sev == "MED", (
            f"billing-only tuple must derive MED; got {sev!r}")


# 2. Run-group is unchanged (still default-visible HIGH-group).

class TestBillingOnlyMedStaysDefaultVisible:
    @pytest.mark.unit
    @pytest.mark.parametrize("name", _BILLING_ONLY_STAYS_HIGH)
    def test_probe_category_stays_high(self, name):
        probe = _probe_by_name(name)
        cat = probe[1]
        assert cat == "high", (
            f"{name!r} must stay in `high` run-group (default-visible); "
            f"got {cat!r}")

    @pytest.mark.unit
    @pytest.mark.parametrize("name", _BILLING_ONLY_STAYS_HIGH)
    def test_default_scan_executes_gemini_vertex_billing_probes(
            self, name, monkeypatch):
        executed = []
        monkeypatch.setattr(
            gas, "_execute_probe",
            lambda probe, *a, **kw: executed.append(probe[0]) or None)
        gas.scan_gapis(SENTINEL_KEY, quiet=True, threads=1)
        assert name in executed, (
            f"{name!r} must execute under the default-visible profile; "
            f"executed (first 12): {executed[:12]}")

    @pytest.mark.unit
    @pytest.mark.parametrize("name", _BILLING_ONLY_MOVED_TO_LOW)
    def test_cloud_ai_probe_category_is_low(self, name):
        """The 4 Cloud AI billing-only probes (Translation, Vision, NL,
        Text-to-Speech) MUST be `low`. Default HIGH-only scans should not
        run them; they require an explicit `--include-low`."""
        probe = _probe_by_name(name)
        cat = probe[1]
        assert cat == "low", (
            f"{name!r} must be in `low` run-group (opt-in via --include-low); "
            f"got {cat!r}")

    @pytest.mark.unit
    @pytest.mark.parametrize("name", _BILLING_ONLY_MOVED_TO_LOW)
    def test_default_scan_skips_cloud_ai_probes(self, name, monkeypatch):
        """A default scan (no opt-in flags) MUST NOT run the 4 Cloud AI
        billing-only probes — they're now `low` and require explicit
        `--include-low`."""
        executed = []
        monkeypatch.setattr(
            gas, "_execute_probe",
            lambda probe, *a, **kw: executed.append(probe[0]) or None)
        gas.scan_gapis(SENTINEL_KEY, quiet=True, threads=1)
        assert name not in executed, (
            f"{name!r} must NOT execute under the default HIGH-only "
            f"profile; executed contained it (full list: {sorted(set(executed))})")

    @pytest.mark.unit
    @pytest.mark.parametrize("name", _BILLING_ONLY_MOVED_TO_LOW)
    def test_include_low_executes_cloud_ai_probes(self, name, monkeypatch):
        """`--include-low` MUST surface the 4 Cloud AI billing-only probes
        — the demotion changes the run-group, not the probe's existence."""
        executed = []
        monkeypatch.setattr(
            gas, "_execute_probe",
            lambda probe, *a, **kw: executed.append(probe[0]) or None)
        gas.scan_gapis(SENTINEL_KEY, quiet=True, threads=1,
                       include_low=True)
        assert name in executed, (
            f"{name!r} must execute under --include-low; executed "
            f"(first 20): {executed[:20]}")

    @pytest.mark.unit
    @pytest.mark.parametrize("name", _BILLING_ONLY_MOVED_TO_LOW)
    def test_cloud_ai_under_include_low_still_derives_med(self, name):
        probe = _probe_by_name(name)
        cat = probe[1]
        impact_type, confirmation, data_sensitivity = (
            gas._resolve_response_fields(name, cat))
        sev = gas._derive_severity(impact_type, confirmation, data_sensitivity)
        assert sev == "MED", (
            f"{name!r} (category={cat}) must still derive MED via the "
            f"billing-only severity tuple; got {sev!r}")


# 3. End-to-end: `_execute_probe` produces severity=MED with the
#    billing-only tuple on a representative successful response.

class _FakeResponse:
    def __init__(self, status_code=200, body="", url=None):
        self.status_code = status_code
        self.text = body if isinstance(body, str) else json.dumps(body)
        self.content = self.text.encode("utf-8") if self.text else b""
        self.headers = {"Content-Type": "application/json"}
        m = type("R", (), {"url": url or "https://x.googleapis.com/"})
        self.request = m()

    def json(self):
        return json.loads(self.text) if self.text else {}


class TestBillingOnlyMedEndToEnd:
    @pytest.mark.unit
    def test_cloud_translation_real_response_med(self):
        """Cloud Translation success body → vulnerable=True with the
        billing-only MED tuple. CONFIRMED tier is fine (the endpoint
        IS reachable/billable); only severity/impact_type/etc. changes."""
        probe = _probe_by_name("Cloud Translation")
        fake = _FakeResponse(
            200, '{"data":{"translations":[{"translatedText":"hola"}]}}')
        with patch.object(gas.requests, "get", return_value=fake):
            res = gas._execute_probe(probe, SENTINEL_KEY, "test-project",
                                     base_headers={})
        assert res["vulnerable"] is True
        assert res["severity"] == "MED", (
            f"Cloud Translation severity must be MED; got {res['severity']!r}")
        assert res["impact_type"] == "quota_cost"
        assert res["confirmation"] == "confirmed_data"
        assert res["data_sensitivity"] == "billing_reachable"

    @pytest.mark.unit
    def test_gemini_generate_content_real_response_med(self):
        probe = _probe_by_name("Gemini Generate Content")
        fake = _FakeResponse(
            200,
            '{"candidates":[{"content":{"parts":[{"text":"hello"}]}}]}')
        with patch.object(gas.requests, "post", return_value=fake):
            res = gas._execute_probe(probe, SENTINEL_KEY, "test-project",
                                     base_headers={})
        assert res["vulnerable"] is True
        assert res["severity"] == "MED"
        assert res["impact_type"] == "quota_cost"
        assert res["confirmation"] == "confirmed_data"
        assert res["data_sensitivity"] == "billing_reachable"

    @pytest.mark.unit
    def test_json_output_carries_billing_tuple(self):
        synthetic_result = {
            "name": "Cloud Translation",
            "category": "high",
            "abuse_class": "BillDrain",
            "url": "https://translation.googleapis.com/x?key=...",
            "impact": "Translation billing — ...",
            "vulnerable": True,
            "manual_note": None,
            "referer_blocked": False,
            "error_class": None,
            "services_seen": {"translation.googleapis.com"},
            "reason": "",
            "gemini_disabled": False,
            "status_code": 200,
            "snippet": None,
            "tier":             "CONFIRMED",
            "impact_type":      "quota_cost",
            "confirmation":     "confirmed_data",
            "data_sensitivity": "billing_reachable",
            "severity":         "MED",
        }
        out = gas._build_json_output([synthetic_result], tested_count=1,
                                      options={})
        # CONFIRMED bucket; MED severity; billing-only tuple.
        assert out["confirmed_count"] == 1
        row = out["confirmed"][0]
        assert row["severity"] == "MED"
        assert row["impact_type"] == "quota_cost"
        assert row["confirmation"] == "confirmed_data"
        assert row["data_sensitivity"] == "billing_reachable"
        assert row["tier"] == "CONFIRMED"
        # The wording on the probe itself should NOT be customer-data /
        # data-leak. The synthetic row uses "Translation billing — ...".
        assert "billing" in row["impact"].lower(), (
            f"impact text should reflect billing, not customer data; "
            f"got {row['impact']!r}")


# 4. Gemini READ endpoints stay HIGH (intentionally unchanged).

class TestGeminiReadEndpointsStayHigh:
    @pytest.mark.unit
    @pytest.mark.parametrize("name", _GEMINI_READ_MUST_STAY_HIGH)
    def test_gemini_read_has_no_billing_override(self, name):
        """Gemini read endpoints must NOT have an explicit
        `_PROBE_IMPACT_DEFAULTS` entry that pins them to billing_reachable —
        they need to keep deriving HIGH via the category default."""
        entry = gas._PROBE_IMPACT_DEFAULTS.get(name)
        if entry is not None:
            # If an entry exists, it MUST NOT be the billing-only tuple.
            assert entry.get("data_sensitivity") != "billing_reachable", (
                f"{name!r} accidentally has billing-only override — must "
                f"stay data_read/customer_data via category default")

    @pytest.mark.unit
    @pytest.mark.parametrize("name", _GEMINI_READ_MUST_STAY_HIGH)
    def test_gemini_read_derives_high(self, name):
        """The category-default resolution for these probes (high
        category) must derive HIGH severity."""
        probe = _probe_by_name(name)
        cat = probe[1]
        assert cat == "high"
        impact_type, confirmation, data_sensitivity = (
            gas._resolve_response_fields(name, cat))
        sev = gas._derive_severity(impact_type, confirmation,
                                    data_sensitivity)
        assert sev == "HIGH", (
            f"{name!r} must derive HIGH (data_read/confirmed_data/"
            f"customer_data via the high category default); got "
            f"({impact_type!r}, {confirmation!r}, {data_sensitivity!r}) "
            f"→ {sev!r}")


# 5. Resource-list / cost-amp behavior unchanged.

class TestUnchangedNeighbors:
    @pytest.mark.unit
    def test_resource_list_probe_still_high_via_check(self):
        probe = _probe_by_name("Pub/Sub Topics")
        assert probe[1] == "high"

        entry = gas._PROBE_IMPACT_DEFAULTS.get("Pub/Sub Topics")
        assert entry is None or entry.get("data_sensitivity") != "billing_reachable", (
            "Pub/Sub Topics must NOT be reclassified to billing_reachable")
        # Category default derives HIGH.
        impact_type, confirmation, data_sensitivity = (
            gas._resolve_response_fields("Pub/Sub Topics", "high"))
        sev = gas._derive_severity(impact_type, confirmation,
                                    data_sensitivity)
        assert sev == "HIGH"

    @pytest.mark.unit
    def test_cost_amp_probes_unchanged(self):
        """Cost-amp probes stay opt-in (category `cost-amp`) and the
        billing-only reclassification does not touch them."""
        cost_amp = [p for p in gas.ALL_PROBES if p[1] == "cost-amp"]
        assert cost_amp, "expected at least one cost-amp probe"
        for p in cost_amp:
            name = p[0]
            # Cost-amp category should remain on these probes (NOT
            # moved to `high`).
            assert p[1] == "cost-amp", (
                f"{name!r} accidentally moved out of cost-amp; got "
                f"category {p[1]!r}")


# 6. Impact text wording — billing-language, not customer-data-leak.

class TestBillingOnlyImpactText:
    @pytest.mark.unit
    @pytest.mark.parametrize("name", _BILLING_ONLY_MED_PROBES)
    def test_impact_text_uses_billing_language(self, name):
        """Impact text on these probes should mention billing /
        scanner-supplied / no-customer-data, NOT 'data access risk' or
        'data leak' phrasing that implies customer data egress."""
        probe = _probe_by_name(name)
        impact = probe[6].lower()
        # Must mention billing language.
        assert ("billing" in impact
                or "bill" in impact
                or "per-1k-token" in impact
                or "per-image" in impact
                or "per-character" in impact), (
            f"{name!r} impact text should reflect billing language; "
            f"got {probe[6]!r}")
        # Should NOT claim customer data access.
        for forbidden in ("data access risk",
                          "data processing risk",
                          "customer data leak",
                          "data exfil"):
            assert forbidden not in impact, (
                f"{name!r} impact text still claims {forbidden!r} — "
                f"reword to billing-language only; got {probe[6]!r}")
