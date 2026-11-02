"""Regression coverage for operator oob."""
from __future__ import annotations

import json

import pytest

import google_api_scanner as gas

SENTINEL_KEY = "AIzaSy" + "X" * 33


class _R:
    def __init__(self, status_code, text=""):
        self.status_code = status_code
        self.text = text


# Neutered probes removed

class TestNeuteredProbesRemoved:
    @pytest.mark.unit
    @pytest.mark.parametrize("name", [
        "Identity Toolkit sendOobCode (capability)",
        "Identity Toolkit sendVerificationCode (capability)"])
    def test_capability_probe_gone(self, name):
        names = {p[0] for p in gas.ALL_PROBES}
        assert name not in names
        assert name not in gas._PROBE_IMPACT_DEFAULTS
        assert name not in gas.ABUSE_CLASS_OVERRIDES
        assert name not in gas.POTENTIAL_PROBES

    @pytest.mark.unit
    def test_no_hardcoded_email_or_phone_in_source(self):
        src = gas._engine_source_text()
        # No literal email/phone constant should exist in the OOB builder
        # area; only the {} json placeholders + operator-substituted values.
        assert "OOB_REQ_TYPE_UNSPECIFIED" not in src, (
            "neutered unspecified-requestType payload must be gone")


# Builder

class TestBuildOperatorOobProbes:
    @pytest.mark.unit
    def test_no_params_no_probes(self):
        assert gas._build_operator_oob_probes() == []
        assert gas._build_operator_oob_probes(None, None) == []

    @pytest.mark.unit
    def test_email_builds_two_probes_with_exact_email(self):
        probes = gas._build_operator_oob_probes(it_test_email="op@example.com")
        assert len(probes) == 2
        kinds = {p[0] for p in probes}
        assert any("PASSWORD_RESET" in k for k in kinds)
        assert any("EMAIL_SIGNIN" in k for k in kinds)
        for p in probes:
            assert p[1] == "destructive"
            payload = json.loads(p[4])
            assert payload["email"] == "op@example.com"
        # PASSWORD_RESET payload shape
        pr = [p for p in probes if "PASSWORD_RESET" in p[0]][0]
        assert json.loads(pr[4])["requestType"] == "PASSWORD_RESET"
        es = [p for p in probes if "EMAIL_SIGNIN" in p[0]][0]
        assert json.loads(es[4])["requestType"] == "EMAIL_SIGNIN"
        assert json.loads(es[4])["continueUrl"] == "http://localhost"

    @pytest.mark.unit
    def test_phone_builds_one_sms_probe_with_exact_phone(self):
        probes = gas._build_operator_oob_probes(it_test_phone="+15551234567")
        assert len(probes) == 1
        p = probes[0]
        assert p[1] == "destructive"
        payload = json.loads(p[4])
        assert payload["phoneNumber"] == "+15551234567"

    @pytest.mark.unit
    def test_oob_severity_is_high(self):
        for nm in gas._OPERATOR_OOB_PROBE_NAMES:
            it, c, ds = gas._resolve_response_fields(nm, "destructive")
            assert gas._derive_severity(it, c, ds) == "HIGH"


# Check functions

class TestOobEmailCheck:
    @pytest.mark.unit
    def test_200_is_finding(self):
        assert gas._check_it_oob_email_delivery(_R(200, '{"email":"test@example.com"}'))[0] is True

    @pytest.mark.unit
    def test_email_not_found_is_non_finding(self):
        ok, note = gas._check_it_oob_email_delivery(
            _R(400, '{"error":{"message":"EMAIL_NOT_FOUND"}}'))
        assert ok is False
        assert note == "email_not_found_no_delivery"

    @pytest.mark.unit
    def test_other_4xx_non_finding(self):
        assert gas._check_it_oob_email_delivery(
            _R(400, '{"error":{"message":"INVALID_EMAIL"}}'))[0] is False


class TestSmsCheck:
    @pytest.mark.unit
    @pytest.mark.parametrize("body", [
        "CAPTCHA_CHECK_FAILED", "INVALID_RECAPTCHA",
        "MISSING_RECAPTCHA_TOKEN", "reCAPTCHA token required"])
    def test_recaptcha_gated_non_finding(self, body):
        ok, note = gas._check_it_sms_delivery(_R(400, body))
        assert ok is False
        assert note == "recaptcha_gated_sms_infeasible"

    @pytest.mark.unit
    def test_200_is_finding(self):
        assert gas._check_it_sms_delivery(_R(200, '{"sessionInfo":"synthetic-session"}'))[0] is True


# scan_gapis injection gating

class TestInjectionGating:
    def _run_and_collect(self, monkeypatch, **kw):
        seen = []
        monkeypatch.setattr(gas, "_execute_probe",
                            lambda p, *a, **k: seen.append(p[0]))
        gas.scan_gapis(SENTINEL_KEY, quiet=True, threads=1, **kw)
        return [s for s in seen if "sendOobCode" in s or "sendVerificationCode" in s]

    @pytest.mark.unit
    def test_no_oob_without_destructive(self, monkeypatch):
        assert self._run_and_collect(monkeypatch, it_test_email="me@x.com") == []

    @pytest.mark.unit
    def test_no_oob_destructive_without_param(self, monkeypatch):
        assert self._run_and_collect(monkeypatch, include_destructive=True) == []

    @pytest.mark.unit
    def test_oob_email_injected_with_destructive_and_email(self, monkeypatch):
        oob = self._run_and_collect(monkeypatch, include_destructive=True,
                                    it_test_email="me@x.com")
        assert any("sendOobCode" in s for s in oob)
        assert len(oob) == 2

    @pytest.mark.unit
    def test_oob_sms_injected_with_destructive_and_phone(self, monkeypatch):
        oob = self._run_and_collect(monkeypatch, include_destructive=True,
                                    it_test_phone="+15551234567")
        assert any("sendVerificationCode" in s for s in oob)

    @pytest.mark.unit
    def test_options_record_masked_operator_params_only(self, monkeypatch, tmp_path):
        """JSON options record a boolean + MASKED value,
        never the raw operator email/phone."""
        out = tmp_path / "o.json"
        monkeypatch.setattr(gas, "_execute_probe", lambda p, *a, **k: None)
        gas.scan_gapis(SENTINEL_KEY, quiet=True, threads=1,
                       include_destructive=True, it_test_email="me@x.com",
                       it_test_phone="+15551234567",
                       output_file=str(out))
        raw = out.read_text()
        data = json.loads(raw)
        opts = data["options"]
        assert opts["it_test_email_enabled"] is True
        assert opts["it_test_phone_enabled"] is True
        assert opts["it_test_email_masked"] == "m***@x.com"
        assert opts["it_test_phone_masked"] == "+*******4567"
        # The raw email/phone must NEVER appear anywhere in the artifact.
        assert "me@x.com" not in raw
        assert "+15551234567" not in raw
        # The old raw keys must be gone.
        assert "it_test_email" not in opts or opts.get("it_test_email") is None
        assert opts.get("it_test_email") != "me@x.com"


class TestPiiMasking:
    @pytest.mark.unit
    @pytest.mark.parametrize("value,expected", [
        ("alice@example.com", "a***@example.com"),
        ("+15551234567", "+*******4567"),
        ("15551234567", "*******4567"),
        ("+12", "+**"),
        (None, None),
        ("", None),
    ])
    def test_mask_operator_pii(self, value, expected):
        assert gas._mask_operator_pii(value) == expected

    @pytest.mark.unit
    def test_stdout_never_prints_raw_pii(self, monkeypatch, capsys):
        monkeypatch.setattr(gas, "_execute_probe", lambda p, *a, **k: None)
        gas.scan_gapis(SENTINEL_KEY, quiet=False, threads=1,
                       include_destructive=True, it_test_email="secret@corp.com",
                       it_test_phone="+15559998888")
        out = capsys.readouterr().out
        assert "secret@corp.com" not in out
        assert "+15559998888" not in out
        # masked forms ARE printed (operator confirmation).
        assert "s***@corp.com" in out
        assert "+*******8888" in out
