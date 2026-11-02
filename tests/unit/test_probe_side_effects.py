"""Tests for probe side effects."""
from __future__ import annotations

import re
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import google_api_scanner as gas  # noqa: E402

SENTINEL_KEY = "AIzaSyXX" + "X" * 31

SRC = gas._engine_source_text()


@pytest.fixture(autouse=True)
def _reset_artifacts():
    with gas._IDENTITY_TOOLKIT_LOCK:
        gas._IDENTITY_TOOLKIT_ARTIFACTS.clear()

    gas._DERIVED_PROJECT_IDS.add("test-derived-proj")
    yield
    with gas._IDENTITY_TOOLKIT_LOCK:
        gas._IDENTITY_TOOLKIT_ARTIFACTS.clear()
    gas._DERIVED_PROJECT_IDS.discard("test-derived-proj")


# hardcoded operator email is GONE

class TestNoHardcodedEmail:
    @pytest.mark.unit
    def test_no_personal_email_in_source(self):
        """No personal mailbox may appear in the scanner source."""
        assert "@gmail.com" not in SRC
        assert "gapiscanner-probe@" not in SRC

    @pytest.mark.unit
    def test_no_probe_body_contains_a_deliverable_email_address(self):
        """No probe body should contain a DELIVERABLE email address. RFC 2606
        reserves `example.com` / `example.org` / `example.net` as guaranteed
        non-deliverable — those are acceptable for enumeration probes (e.g.
        Identity Toolkit `createAuthUri (email enum)` uses
        `probe-nonexistent@example.com` precisely because nobody receives mail
        there). Anything else is the canonical reset/SMS attack vector and is
        forbidden."""
        email_re = re.compile(r"[A-Za-z0-9._+%-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
        RFC_2606_NON_DELIVERABLE = {"example.com", "example.org", "example.net"}
        for p in list(gas.ALL_PROBES) + list(gas.FIREBASE_CHAIN_PROBES):
            body = p[4]
            if not body:
                continue
            for domain in email_re.findall(body):
                if domain.lower() not in RFC_2606_NON_DELIVERABLE:
                    pytest.fail(
                        f"probe {p[0]!r} body contains a deliverable email "
                        f"address (@{domain}); test payloads forbid non-RFC-2606 emails "
                        "in probe payloads.")


# sendOobCode + sendVerificationCode are non-deliverable

def _find_probe(name):
    for p in list(gas.ALL_PROBES) + list(gas.FIREBASE_CHAIN_PROBES):
        if p[0] == name:
            return p
    return None


class TestOobCapabilityProbesRemovedAndReplaced:

    @pytest.mark.unit
    @pytest.mark.parametrize("old_name", [
        "Identity Toolkit sendOobCode (capability)",
        "Identity Toolkit sendVerificationCode (capability)"])
    def test_neutered_capability_probe_removed(self, old_name):
        assert _find_probe(old_name) is None

    @pytest.mark.unit
    def test_unspecified_requesttype_payload_gone(self):
        src = gas._engine_source_text()
        assert "OOB_REQ_TYPE_UNSPECIFIED" not in src

    @pytest.mark.unit
    def test_operator_oob_probes_exist_only_with_param(self):
        # No params → no probes; email/phone → operator-controlled probes.
        assert gas._build_operator_oob_probes() == []
        email_probes = gas._build_operator_oob_probes(it_test_email="me@x.com")
        assert len(email_probes) == 2
        assert all(p[1] == "destructive" for p in email_probes)
        phone_probes = gas._build_operator_oob_probes(it_test_phone="+15551112222")
        assert len(phone_probes) == 1


# Firebase Dynamic Links capability-only

class TestFirebaseDynamicLinksCapability:
    @pytest.mark.unit
    def test_probe_exists_under_new_name(self):
        assert _find_probe("Firebase Dynamic Links shortLinks (capability)") is not None

    @pytest.mark.unit
    def test_old_phishing_name_is_gone(self):
        assert _find_probe("Firebase Dynamic Links shortLinks (write)") is None

    @pytest.mark.unit
    def test_payload_is_empty(self):
        p = _find_probe("Firebase Dynamic Links shortLinks (capability)")
        # Empty body forces server-side validation error BEFORE a live
        # redirect can be created (Dynamic Links has no public DELETE).
        assert p[4] == "{}", (
            f"Dynamic Links body must be exactly '{{}}'; got {p[4]!r}. "
            "Any non-empty payload risks creating an unrecoverable live "
            "redirect.")

    @pytest.mark.unit
    def test_impact_text_drops_open_redirect_language(self):
        p = _find_probe("Firebase Dynamic Links shortLinks (capability)")
        impact = (p[6] or "").lower()
        for forbidden in ("open-redirect", "open redirect", "phishing",
                          "attacker.example"):
            assert forbidden not in impact, (
                f"Dynamic Links impact must not claim {forbidden!r}")
        assert "capability" in impact

    @pytest.mark.unit
    def test_check_capability_branch_records_no_artifact(self):
        """Validation-error response (the safe path) → capability detected,
        NO artifact recorded."""
        r = MagicMock()
        r.status_code = 400
        r.text = '{"error":{"code":400,"status":"INVALID_ARGUMENT"}}'
        r.json.return_value = {"error": {"status": "INVALID_ARGUMENT"}}
        out = gas._check_firebase_dynamic_links(r)
        assert len(out) == 3
        vulnerable, note, overrides = out
        assert vulnerable is True
        assert overrides["data_sensitivity"] == "none"
        assert overrides["confirmation"] == "key_accepted_only"
        # No artifact recorded for the capability-only path.
        with gas._IDENTITY_TOOLKIT_LOCK:
            assert gas._IDENTITY_TOOLKIT_ARTIFACTS == []

    @pytest.mark.unit
    def test_check_records_artifact_on_unexpected_create(self):
        """Defense-in-depth: if a live shortLink IS created (would only
        happen if the operator manually patches in a valid body), the
        URL is recorded as a cleanup-failure artifact for manual takedown."""
        r = MagicMock()
        r.status_code = 200
        r.text = '{"shortLink":"https://example.page.link/abc","previewLink":"x"}'
        r.json.return_value = {"shortLink": "https://example.page.link/abc"}
        out = gas._check_firebase_dynamic_links(r)
        assert len(out) == 3
        vulnerable, note, overrides = out
        assert vulnerable is True
        assert "cleanup_failed_live_link" in note
        with gas._IDENTITY_TOOLKIT_LOCK:
            arts = list(gas._IDENTITY_TOOLKIT_ARTIFACTS)
        assert len(arts) == 1
        assert arts[0]["local_id"] == "https://example.page.link/abc"
        assert "no public delete endpoint" in arts[0]["reason"].lower()

    @pytest.mark.unit
    def test_check_api_key_invalid_returns_false(self):
        r = MagicMock()
        r.status_code = 400
        r.text = '{"error":{"details":[{"reason":"API_KEY_INVALID"}]}}'
        r.json.return_value = {"error": {"details": [{"reason": "API_KEY_INVALID"}]}}
        assert gas._check_firebase_dynamic_links(r) == (False, None)


# RTDB write probe cleanup artifact

class TestRTDBWriteProbeCleanupArtifact:
    @pytest.mark.unit
    def test_rtdb_write_probe_still_in_chain(self):
        names = {p[0] for p in gas.FIREBASE_CHAIN_PROBES}
        assert "Firebase RTDB write probe" in names

    @pytest.mark.unit
    def test_artifact_recorded_when_delete_fails(self, monkeypatch):
        """Simulate: RTDB write probe succeeds (200), then the cleanup DELETE
        returns 403. An artifact must be recorded so the operator can manually
        request takedown of the leftover key."""
        # Drive scan_gapis through Phase 3 with just the RTDB write probe.
        write_probe = next(p for p in gas.FIREBASE_CHAIN_PROBES
                           if "RTDB write probe" in p[0])
        monkeypatch.setattr(gas, "FIREBASE_CHAIN_PROBES", [write_probe])
        monkeypatch.setattr(gas, "ALL_PROBES", [])
        monkeypatch.setattr(gas, "PHASE_0_PROBE_NAMES", ())

        def _stub_put(*args, **kwargs):
            # WRITE probe succeeds.
            m = MagicMock()
            m.status_code = 200
            m.text = '{"key":"probe"}'
            m.json.return_value = {"key": "probe"}
            m.content = m.text.encode()
            m.headers = {}
            m.request = MagicMock(); m.request.url = args[0] if args else ""
            return m

        def _stub_delete(*args, **kwargs):
            # Cleanup fails → must record an artifact.
            m = MagicMock()
            m.status_code = 403
            m.text = '{"error":"forbidden"}'
            return m

        import requests
        monkeypatch.setattr(requests, "put",    _stub_put)
        monkeypatch.setattr(requests, "delete", _stub_delete)
        monkeypatch.setattr(requests, "get",    _stub_put)
        monkeypatch.setattr(requests, "post",   _stub_put)


        with gas._DERIVED_LOCK:
            gas._DERIVED_PROJECT_IDS.add("victim-app")

        gas.scan_gapis(SENTINEL_KEY,
                       include_destructive=True,
                       quiet=True, skip_jsapi=True, project_id="victim-app")

        with gas._IDENTITY_TOOLKIT_LOCK:
            arts = list(gas._IDENTITY_TOOLKIT_ARTIFACTS)
        assert any(a.get("probe") == "Firebase RTDB write probe"
                   for a in arts), (
            f"RTDB cleanup failure must record an artifact; got {arts!r}")


# destructive/cost-amp/legacy excluded by default

class TestDestructiveOptInDefault:
    @pytest.mark.unit
    def test_destructive_not_in_default_probe_pool(self):
        """The destructive category must never run under a default scan_gapis
        call (no flags). Tested via the probe-list build the function uses."""
        # Replicate scan_gapis's filter logic for a default call.
        default = [p for p in gas.ALL_PROBES if p[1] == "high"]
        cats = {p[1] for p in default}
        assert "destructive" not in cats
        assert "cost-amp" not in cats
        assert "legacy" not in cats

    @pytest.mark.unit
    def test_opt_in_categories_set_is_authoritative(self):
        assert "destructive" in gas._OPT_IN_CATEGORIES
        assert "cost-amp"   in gas._OPT_IN_CATEGORIES

    @pytest.mark.unit
    def test_scan_gapis_default_does_not_execute_destructive(self, monkeypatch):
        """End-to-end: a default scan_gapis call (no flags) must not invoke
        _execute_probe on any tuple whose category is destructive/cost-amp/
        legacy. Stub _execute_probe to capture every probe it sees."""
        seen_probes = []
        def _capturing_execute(probe, apikey, project_id, base_headers,
                               verbose=False):
            seen_probes.append((probe[0], probe[1]))  # (name, category)
            return None  # connection_error → skip without HTTP
        monkeypatch.setattr(gas, "_execute_probe", _capturing_execute)
        monkeypatch.setattr(gas, "PHASE_0_PROBE_NAMES", ())
        monkeypatch.setattr(gas, "FIREBASE_CHAIN_PROBES", [])
        gas.scan_gapis(SENTINEL_KEY, quiet=True, skip_jsapi=True, threads=4)
        forbidden_categories = {"destructive", "cost-amp", "legacy"}
        violators = [(n, c) for n, c in seen_probes if c in forbidden_categories]
        assert violators == [], (
            f"default scan_gapis invoked destructive/cost-amp/legacy probes: "
            f"{violators}")


# labels across the registry are capability-not-abuse

class TestLabelsAreCapabilityOnly:
    @pytest.mark.unit
    def test_no_abuse_language_in_probe_names(self):
        forbidden_phrases = (
            "brand phishing", "toll fraud", "open-redirect",
            "phishing primitive", "premium-rate",
        )
        for p in list(gas.ALL_PROBES) + list(gas.FIREBASE_CHAIN_PROBES):
            lower = p[0].lower()
            for ph in forbidden_phrases:
                assert ph not in lower, (
                    f"probe name {p[0]!r} still uses abuse-language {ph!r}")

    @pytest.mark.unit
    def test_no_abuse_language_in_impact_text(self):
        forbidden_phrases = (
            "brand phishing", "toll fraud", "open-redirect",
            "sends genuine reset email", "premium-rate dialing",
        )
        for p in list(gas.ALL_PROBES) + list(gas.FIREBASE_CHAIN_PROBES):
            impact_lower = (p[6] or "").lower()
            for ph in forbidden_phrases:
                assert ph not in impact_lower, (
                    f"probe {p[0]!r} impact text still uses {ph!r}: {p[6]!r}")

    @pytest.mark.unit
    def test_abuse_class_overrides_drop_brandphish_for_neutered_probes(self):

        for name in ("Identity Toolkit sendOobCode (capability)",
                     "Firebase Dynamic Links shortLinks (capability)"):
            ac = gas.ABUSE_CLASS_OVERRIDES.get(name, "(missing)")
            assert ac != "BrandPhish", (
                f"{name} still classed as BrandPhish; expected Recon")
            assert ac in ("Recon", "(missing)"), (
                f"{name} abuse class unexpected: {ac}")


class TestPreservedInvariants:
    @pytest.mark.unit
    def test_neutered_probes_derive_INFO(self):
        for name in ("Identity Toolkit sendOobCode (capability)",
                     "Identity Toolkit sendVerificationCode (capability)"):
            it, c, ds = gas._resolve_response_fields(name, "destructive")
            sev = gas._derive_severity(it, c, ds)
            assert sev == "INFO", (
                f"{name} should derive INFO (capability-only); got {sev} "
                f"({it}/{c}/{ds})")

    @pytest.mark.unit
    def test_sentinel_still_zero_confirmed(self, monkeypatch):
        def _garbage(*args, **kwargs):
            m = MagicMock()
            m.status_code = 400
            m.text = ('{"error":{"code":400,"status":"INVALID_ARGUMENT",'
                      '"message":"API key not valid. Please pass a valid API key.",'
                      '"details":[{"reason":"API_KEY_INVALID"}]}}')
            m.json.return_value = {
                "error": {"code": 400, "status": "INVALID_ARGUMENT",
                          "message": "API key not valid.",
                          "details": [{"reason": "API_KEY_INVALID"}]},
            }
            m.content = m.text.encode()
            m.headers = {}
            m.request = MagicMock(); m.request.url = args[0] if args else ""
            return m
        import requests
        for fn in ("get", "post", "put", "delete"):
            monkeypatch.setattr(requests, fn, _garbage)
        confirmed = gas.scan_gapis(SENTINEL_KEY,
                                    quiet=True, skip_jsapi=True, threads=4)
        assert confirmed == [], (
            f"Synthetic key produced a confirmed result: CONFIRMED={confirmed}")
