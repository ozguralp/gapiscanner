"""Regression tests for key-acceptance and response-shape false positives.

Identity Toolkit authentication diagnostics must not be classified as
confirmed data access. This module pins the response-validation behavior
so a future regression — adding a new "key acceptance" probe, dropping
the enum opt-in flag, reverting the verifyPassword diagnostic, or
over-claiming on `/v1/operations` — is caught immediately.

All tests are pure-function / table-lookup. NO live network: every
HTTP response is fabricated via `_FakeResponse` so the harness
inputs match real-world probe outputs.
"""
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


@pytest.fixture(autouse=True)
def _allow_any_projects_for_v9_tests():

    gas._DERIVED_PROJECT_IDS.add("test-derived-proj")
    yield
    gas._DERIVED_PROJECT_IDS.discard("test-derived-proj")


# Test infrastructure

class _FakeResponse:
    """Minimal duck-typed `requests.Response` substitute for probe checks."""
    def __init__(self, status_code=200, body="", headers=None, url=None):
        self.status_code = status_code
        self.text = body if isinstance(body, str) else json.dumps(body)
        self.content = self.text.encode("utf-8") if self.text else b""
        self.headers = headers or {"Content-Type": "application/json"}
        m = type("R", (), {"url": url or "https://x.googleapis.com/"})
        self.request = m()

    def json(self):
        return json.loads(self.text) if self.text else {}


def _probe_by_name(name, optional=False):
    """Look up a probe tuple by name in both ALL_PROBES and the
    FIREBASE_CHAIN_PROBES extension (App Check / Firestore documents
    chain — built into the scan flow via _build_firebase_chain_probes,
    not appended to ALL_PROBES).

    With `optional=True` returns None when the probe is absent (used
    to assert non-existence of legacy probe names). Default behavior
    raises AssertionError on miss so callers do not silently swallow
    typos."""
    for p in gas.ALL_PROBES:
        if p[0] == name:
            return p
    for p in getattr(gas, "FIREBASE_CHAIN_PROBES", []):
        if p[0] == name:
            return p
    if optional:
        return None
    raise AssertionError(f"probe not found: {name}")


class TestCreateAuthUri:

    @pytest.mark.unit
    def test_probe_lives_in_low_run_group(self):
        probe = _probe_by_name("Identity Toolkit createAuthUri (email enum)")
        # probe tuple = (name, category, method, url, body, check, impact)
        assert probe[1] == "low", (
            f"createAuthUri must live in `low` run-group; got {probe[1]!r}")

    @pytest.mark.unit
    def test_no_enum_category_remains(self):
        assert not any(p[1] == "enum" for p in gas.ALL_PROBES)
        assert "enum" not in gas._OPT_IN_CATEGORIES

    @pytest.mark.unit
    def test_default_scan_excludes_create_auth_uri(self, monkeypatch):
        """Default scan (HIGH only, no flags) must NOT execute createAuthUri
        (it is now a `low` probe). We assert by spying on `_execute_probe`."""
        executed = []

        def _spy(probe, *a, **kw):
            executed.append(probe[0])
            return None  # connection_error short-circuit; scan still completes

        monkeypatch.setattr(gas, "_execute_probe", _spy)
        gas.scan_gapis(SENTINEL_KEY, quiet=True, threads=1)
        assert "Identity Toolkit createAuthUri (email enum)" not in executed

    @pytest.mark.unit
    def test_include_low_runs_create_auth_uri(self, monkeypatch):
        executed = []

        def _spy(probe, *a, **kw):
            executed.append(probe[0])
            return None

        monkeypatch.setattr(gas, "_execute_probe", _spy)
        gas.scan_gapis(SENTINEL_KEY, quiet=True, threads=1, include_low=True)
        assert "Identity Toolkit createAuthUri (email enum)" in executed, (
            f"--include-low must run createAuthUri; ran {executed[:8]}…")

    @pytest.mark.unit
    def test_create_auth_uri_severity_is_med(self):
        """A real createAuthUri enumeration verdict (response includes
        `registered: true`) must derive to severity MED, never HIGH."""
        probe = _probe_by_name("Identity Toolkit createAuthUri (email enum)")
        # Simulate a real enum hit.
        fake_body = '{"registered":true,"allProviders":["password"]}'
        fake_r = _FakeResponse(200, fake_body,
                               url=probe[3].replace("{key}", SENTINEL_KEY))
        with patch.object(gas.requests, "post", return_value=fake_r):
            res = gas._execute_probe(probe, SENTINEL_KEY, "test-project",
                                     base_headers={})
        assert res["vulnerable"] is True
        assert res["severity"] == "MED", (
            f"createAuthUri severity must be MED; got {res['severity']!r}")
        assert res["impact_type"] == "user_enumeration"
        assert res["confirmation"] == "confirmed_data"

    @pytest.mark.unit
    def test_create_auth_uri_never_uses_confirmed_high_wording(self, capsys, monkeypatch):
        """`_handle_result` must NOT print `API key is vulnerable … [HIGH]`
        for the createAuthUri enumeration result; it must use the
        enumeration wording. createAuthUri is now a `low` probe, so the
        scan needs `--include-low` to reach it."""
        probe = _probe_by_name("Identity Toolkit createAuthUri (email enum)")
        monkeypatch.setattr(gas, "ALL_PROBES", [probe])
        monkeypatch.setattr(gas, "FIREBASE_CHAIN_PROBES", [])
        fake_body = '{"registered":true,"allProviders":["password"]}'
        fake_r = _FakeResponse(200, fake_body,
                               url=probe[3].replace("{key}", SENTINEL_KEY))
        with patch.object(gas.requests, "post", return_value=fake_r):
            gas.scan_gapis(SENTINEL_KEY, quiet=False,
                           threads=1, include_low=True)
        out = capsys.readouterr().out
        # Must use enumeration wording, not CONFIRMED-HIGH wording.
        assert "Email enumeration possible" in out
        assert "[MED]" in out
        # Must NOT use the CONFIRMED-HIGH "API key is vulnerable" template
        # for createAuthUri specifically. (Other CONFIRMED probes still
        # use that path — we only forbid it for this enum probe.)
        for line in out.splitlines():
            if "createAuthUri" in line:
                assert "API key is" not in line, (
                    f"forbidden CONFIRMED-HIGH wording on enum probe: "
                    f"{line!r}")


class TestVerifyPasswordLegacy:

    @pytest.mark.unit
    def test_v3_verify_password_diagnostic_removed(self):
        assert _probe_by_name(
            "Identity Toolkit v3 verifyPassword (diagnostic)",
            optional=True) is None

    @pytest.mark.unit
    def test_old_legacy_enum_name_is_gone(self):
        for p in gas.ALL_PROBES:
            assert p[0] != "Identity Toolkit v3 verifyPassword (legacy enum)"
            assert p[0] != "Identity Toolkit v3 verifyPassword (diagnostic)"

    @pytest.mark.unit
    def test_v3_verify_password_not_executed_in_any_scan(self, monkeypatch):
        """Removed entirely: no scan profile (default or --include-legacy)
        executes v3 verifyPassword."""
        executed = []

        def _spy(probe, *a, **kw):
            executed.append(probe[0])
            return None

        monkeypatch.setattr(gas, "_execute_probe", _spy)
        gas.scan_gapis(SENTINEL_KEY, quiet=True, threads=1)
        assert "Identity Toolkit v3 verifyPassword (diagnostic)" not in executed


class TestKeyAcceptanceGate:
    @pytest.mark.unit
    def test_key_acceptance_check_fns_set(self):
        assert gas._check_it_key_accepted_not_invalid in gas._KEY_ACCEPTANCE_CHECK_FNS
        assert gas._check_secure_token_refresh in gas._KEY_ACCEPTANCE_CHECK_FNS

    @pytest.mark.unit
    def test_predicate_helper(self):
        assert gas._is_key_acceptance_check(
            gas._check_it_key_accepted_not_invalid) is True
        assert gas._is_key_acceptance_check(
            gas._check_secure_token_refresh) is True
        # createAuthUri is NOT key-acceptance — it's an enum check.
        assert gas._is_key_acceptance_check(
            gas._check_it_create_auth_uri_enum) is False
        # Diagnostic-only is NOT key-acceptance (it can't fire vulnerable
        # at all).
        assert gas._is_key_acceptance_check(
            gas._check_it_diagnostic_only) is False

    @pytest.mark.unit
    def test_app_check_exchange_debug_token_is_not_confirmed(self):
        probe = _probe_by_name("Firebase App Check exchangeDebugToken")
        # Simulate "key accepted, debug token invalid" (a plausible
        # accept-but-no-success response).
        body = '{"error":{"code":400,"message":"INVALID_ARGUMENT debugToken"}}'
        fake_r = _FakeResponse(400, body,
                               url=probe[3].replace("{key}", SENTINEL_KEY))
        with patch.object(gas.requests, "post", return_value=fake_r):

            res = gas._execute_probe(probe, SENTINEL_KEY, "test-derived-proj",
                                     base_headers={})
        # Check fn reports vulnerable=True (key was accepted, not invalid).
        # But the semantic gate forces confirmation=key_accepted_only.
        assert res["vulnerable"] is True
        assert res["confirmation"] == "key_accepted_only", (
            "Key-acceptance gate must force confirmation=key_accepted_only "
            "for any probe using a key-acceptance check; got "
            f"{res['confirmation']!r}")

    @pytest.mark.unit
    def test_synthetic_new_probe_with_key_acceptance_check_defaults_to_potential(self):
        """The systematic safeguard: a hypothetical NEW probe added to
        ALL_PROBES that uses `_check_it_key_accepted_not_invalid` and
        lives in `high` (CONFIRMED-by-default category) must STILL be
        forced to POTENTIAL via the semantic gate. Adding such a probe
        should not require any name-list edit."""
        synthetic_probe = (
            "Synthetic Key-Acceptance Probe (test only)", "high", "GET",
            "https://identitytoolkit.googleapis.com/v1/probe?key={key}",
            None, gas._check_it_key_accepted_not_invalid,
            "test-only key-acceptance probe",
        )
        body = '{"error":{"code":400,"message":"MISSING_TOKEN"}}'
        fake_r = _FakeResponse(400, body,
                               url=synthetic_probe[3].replace("{key}", SENTINEL_KEY))
        with patch.object(gas.requests, "get", return_value=fake_r):
            res = gas._execute_probe(synthetic_probe, SENTINEL_KEY,
                                     "test-project", base_headers={})
        assert res["vulnerable"] is True
        assert res["confirmation"] == "key_accepted_only"
        # `_handle_result` would mark this POTENTIAL via the confirmation
        # gate. Verify directly: severity stays at LOW or INFO, never HIGH.
        assert res["severity"] in ("LOW", "INFO"), (
            f"synthetic key-acceptance probe must not derive to HIGH/MED; "
            f"got {res['severity']!r}")

    @pytest.mark.unit
    def test_secure_token_refresh_removed(self):
        assert _probe_by_name(
            "Secure Token refresh (diagnostic)", optional=True) is None
        assert _probe_by_name(
            "Secure Token refresh (key acceptance)", optional=True) is None
        for tbl in (gas.POTENTIAL_PROBES, set(gas.ABUSE_CLASS_OVERRIDES),
                    set(gas._PROBE_IMPACT_DEFAULTS), set(gas.PHASE_0_PROBE_NAMES)):
            assert "Secure Token refresh (diagnostic)" not in tbl
        assert "Secure Token refresh (key acceptance)" not in gas.POTENTIAL_PROBES
        assert "Secure Token refresh (key acceptance)" not in gas.ABUSE_CLASS_OVERRIDES


class TestSpeechOperationsEmpty:
    @pytest.mark.unit
    def test_numeric_speech_operation_name_builds_v1_detail_url(self):
        url = gas._speech_operation_detail_url(
            "https://speech.googleapis.com/v1/operations?key=" + SENTINEL_KEY,
            "1234567890",
            SENTINEL_KEY,
        )
        assert url == (
            "https://speech.googleapis.com/v1/operations/1234567890?key="
            + SENTINEL_KEY
        )

    @pytest.mark.unit
    def test_speech_operations_uses_non_empty_check(self):
        probe = _probe_by_name("Speech Operations")
        assert probe[5] is gas._check_non_empty_operations_list, (
            "Speech Operations must use the non-empty list check")

    @pytest.mark.unit
    def test_empty_operations_list_not_vulnerable(self):
        body = '{"operations":[]}'
        fake_r = _FakeResponse(200, body)
        v, note = gas._check_non_empty_operations_list(fake_r)
        assert v is False, "empty operations list must NOT be vulnerable"

    @pytest.mark.unit
    def test_missing_operations_key_not_vulnerable(self):
        body = '{}'
        fake_r = _FakeResponse(200, body)
        v, note = gas._check_non_empty_operations_list(fake_r)
        assert v is False

    @pytest.mark.unit
    def test_non_empty_operations_list_is_vulnerable(self):
        body = '{"operations":[{"name":"projects/x/operations/abc","done":false}]}'
        fake_r = _FakeResponse(200, body)
        result = gas._check_non_empty_operations_list(fake_r)
        assert result[0] is True

    @pytest.mark.unit
    def test_metadata_only_operations_are_low_end_to_end(self):
        probe = _probe_by_name("Speech Operations")
        list_r = _FakeResponse(
            200,
            '{"operations":[{"name":"projects/x/operations/abc","done":false}]}',
            url=probe[3].replace("{key}", SENTINEL_KEY),
        )
        detail_r = _FakeResponse(
            200, '{"name":"projects/x/operations/abc","done":false}')
        with patch.object(
                gas.requests, "get", side_effect=[list_r, detail_r]):
            result = gas._execute_probe(
                probe, SENTINEL_KEY, "test-project", base_headers={})
        assert result["vulnerable"] is True
        assert result["severity"] == "LOW"
        assert result["impact_type"] == "info_disclosure"
        assert result["data_sensitivity"] == "metadata"
        assert result["operation_evidence"]["detail_attempted"] == 1
        assert result["operation_evidence"]["transcript_count"] == 0

    @pytest.mark.unit
    def test_detail_transcript_promotes_speech_to_high_without_raw_data(self):
        probe = _probe_by_name("Speech Operations")
        operation_name = "operations/private-operation-id"
        transcript = "victim private transcript"
        list_r = _FakeResponse(
            200,
            {"operations": [{"name": operation_name, "done": True}]},
            url=probe[3].replace("{key}", SENTINEL_KEY),
        )
        detail_r = _FakeResponse(
            200,
            {"name": operation_name, "done": True,
             "response": {"results": [{"alternatives": [
                 {"transcript": transcript}]}]}},
        )
        with patch.object(
                gas.requests, "get", side_effect=[list_r, detail_r]):
            result = gas._execute_probe(
                probe, SENTINEL_KEY, "test-project", base_headers={},
                verbose=True)
        assert result["vulnerable"] is True
        assert result["severity"] == "HIGH"
        assert result["operation_evidence"]["operation_count"] == 1
        assert result["operation_evidence"]["detail_200"] == 1
        assert result["operation_evidence"]["transcript_count"] == 1
        assert result["operation_evidence"]["detail_incomplete"] is False
        serialized = json.dumps({
            "snippet": result["snippet"],
            "operation_evidence": result["operation_evidence"],
        })
        assert operation_name not in serialized
        assert transcript not in serialized
        assert SENTINEL_KEY in result["url"]
        assert SENTINEL_KEY not in json.dumps(
            gas._build_rollup_row(result, "android", "com.example.app:AA"))

    @pytest.mark.unit
    def test_response_payload_operations_remain_high_end_to_end(self):
        probe = _probe_by_name("Speech Operations")
        fake_r = _FakeResponse(
            200,
            '{"operations":[{"name":"projects/x/operations/abc","done":true,'
            '"response":{"results":[{"alternatives":'
            '[{"transcript":"private"}]}]}}]}',
            url=probe[3].replace("{key}", SENTINEL_KEY),
        )
        with patch.object(gas.requests, "get", return_value=fake_r):
            result = gas._execute_probe(
                probe, SENTINEL_KEY, "test-project", base_headers={})
        assert result["vulnerable"] is True
        assert result["severity"] == "HIGH"
        assert result["impact_type"] == "data_read"
        assert result["data_sensitivity"] == "customer_data"

    @pytest.mark.unit
    def test_non_200_not_vulnerable(self):
        body = '{"operations":[{"name":"x"}]}'
        fake_r = _FakeResponse(403, body)
        v, note = gas._check_non_empty_operations_list(fake_r)
        assert v is False

    @pytest.mark.unit
    def test_garbage_body_not_vulnerable(self):
        fake_r = _FakeResponse(200, "<html>")
        v, note = gas._check_non_empty_operations_list(fake_r)
        assert v is False




# Cross-cutting — `--all` propagates to enum

class TestAllModeIncludesEnum:
    @pytest.mark.unit
    def test_all_mode_executes_enum_probes(self, monkeypatch):
        executed = []

        def _spy(probe, *a, **kw):
            executed.append(probe[0])
            return None

        monkeypatch.setattr(gas, "_execute_probe", _spy)
        gas.scan_gapis(SENTINEL_KEY, all_mode=True, quiet=True, threads=1)
        assert "Identity Toolkit createAuthUri (email enum)" in executed


_OPERATIONS_PROBE_NAMES = frozenset({
    "Service Usage",
    "Speech Operations",
    "Service Consumer Management",
    "Video Intelligence",
    "Gemini operations list",

    "Translation Hub Operations",
    "Service Management Operations",
})


class TestOperationsEndpointsUseNonEmptyCheck:
    """Each migrated probe must point at `_check_non_empty_operations_list`."""

    @pytest.mark.unit
    @pytest.mark.parametrize("name", sorted(_OPERATIONS_PROBE_NAMES))
    def test_probe_uses_non_empty_operations_list_check(self, name):
        probe = _probe_by_name(name)
        assert probe[5] is gas._check_non_empty_operations_list, (
            f"{name!r} must use _check_non_empty_operations_list "
            f"post-migration; got {probe[5]!r}")

    @pytest.mark.unit
    def test_no_operations_endpoint_uses_raw_200(self):
        """Registry-wide guard: any probe whose URL is `…/operations?key=…`
        MUST use the non-empty-list check, not a raw `"200"` DSL. Future
        additions that fall into this URL pattern are required to either
        join `_OPERATIONS_PROBE_NAMES` and use the structural check, or
        carry an explicit inline justification (we make no allowance for
        the latter here — the guard fails closed)."""
        offenders = []
        for probe in gas.ALL_PROBES:
            name, _cat, _method, url, _body, check, _impact = probe[:7]
            if "operations?key=" not in url:
                continue
            if check is gas._check_non_empty_operations_list:
                continue
            # A non-list operations endpoint (e.g., a single-operation
            # GET) would need a different check fn — flag for review.
            offenders.append((name, url, check))
        assert offenders == [], (
            f"`/v1/operations?key=` probes must use "
            f"`_check_non_empty_operations_list`; got offenders: "
            f"{offenders!r}")


class TestOperationsEmptyListNotVulnerable:
    """For every migrated probe, HTTP 200 + empty `operations: []` must
    NOT produce `vulnerable=True`; HTTP 200 + non-empty `operations`
    MUST still produce `vulnerable=True`."""

    @pytest.mark.unit
    @pytest.mark.parametrize("name", sorted(_OPERATIONS_PROBE_NAMES))
    def test_empty_operations_list_not_vulnerable_end_to_end(self, name):
        probe = _probe_by_name(name)
        body = '{"operations":[]}'
        fake_r = _FakeResponse(200, body,
                               url=probe[3].replace("{key}", SENTINEL_KEY))
        with patch.object(gas.requests, "get", return_value=fake_r):
            res = gas._execute_probe(probe, SENTINEL_KEY, "test-project",
                                     base_headers={})
        assert res["vulnerable"] is False, (
            f"{name!r} reported vulnerable on empty operations list — "
            f"this is the overclaim pattern the migration was supposed "
            f"to fix")

    @pytest.mark.unit
    @pytest.mark.parametrize("name", sorted(_OPERATIONS_PROBE_NAMES))
    def test_non_empty_operations_list_still_vulnerable_end_to_end(self, name):
        probe = _probe_by_name(name)
        body = ('{"operations":[{"name":"projects/x/operations/abc",'
                '"done":false}]}')
        fake_r = _FakeResponse(200, body,
                               url=probe[3].replace("{key}", SENTINEL_KEY))
        with patch.object(gas.requests, "get", return_value=fake_r):
            res = gas._execute_probe(probe, SENTINEL_KEY, "test-project",
                                     base_headers={})
        assert res["vulnerable"] is True, (
            f"{name!r} did NOT report vulnerable on a non-empty "
            f"operations list — the structural check must still surface "
            f"real findings")

    @pytest.mark.unit
    @pytest.mark.parametrize("name", sorted(_OPERATIONS_PROBE_NAMES))
    def test_empty_object_not_vulnerable_end_to_end(self, name):
        probe = _probe_by_name(name)
        body = '{}'
        fake_r = _FakeResponse(200, body,
                               url=probe[3].replace("{key}", SENTINEL_KEY))
        with patch.object(gas.requests, "get", return_value=fake_r):
            res = gas._execute_probe(probe, SENTINEL_KEY, "test-project",
                                     base_headers={})
        assert res["vulnerable"] is False, (
            f"{name!r} reported vulnerable without an operations array")


class TestNonEmptyOperationsListCheckUnit:

    @pytest.mark.unit
    def test_empty_list_false(self):
        r = _FakeResponse(200, '{"operations":[]}')
        v, _ = gas._check_non_empty_operations_list(r)
        assert v is False

    @pytest.mark.unit
    def test_empty_object_false(self):
        r = _FakeResponse(200, '{}')
        v, _ = gas._check_non_empty_operations_list(r)
        assert v is False

    @pytest.mark.unit
    def test_non_json_body_false(self):
        r = _FakeResponse(200, "<html>oops</html>")
        v, _ = gas._check_non_empty_operations_list(r)
        assert v is False

    @pytest.mark.unit
    def test_non_200_even_if_non_empty_false(self):
        r = _FakeResponse(403, '{"operations":[{"name":"x"}]}')
        v, _ = gas._check_non_empty_operations_list(r)
        assert v is False

    @pytest.mark.unit
    def test_non_empty_list_true(self):
        r = _FakeResponse(
            200, '{"operations":[{"name":"projects/x/operations/abc"}]}')
        result = gas._check_non_empty_operations_list(r)
        assert result[0] is True


_T1_LIST_PROBE_NAMES = (
    "Cloud Storage Buckets",      # /b list
    "Firebase Rules",             # rulesets list (Firebase App Check removed

    "Pub/Sub Topics",             # /topics list
    "Gemini Files List",          # /files list (generativelanguage, kept)
    "Integrations",               # /integrations list
)


class TestNonEmptyListHelperRules:
    """Pure-function coverage for the generalized `_check_non_empty_list`
    rule matrix — empty-list suppression vs single-resource fallback vs
    top-level array handling vs pagination-noise filtering."""

    @pytest.mark.unit
    def test_non_200_not_vulnerable(self):
        r = _FakeResponse(403, '{"buckets":[{"name":"x"}]}')
        v, _ = gas._check_non_empty_list(r)
        assert v is False

    @pytest.mark.unit
    def test_api_key_invalid_not_vulnerable(self):
        body = ('{"error":{"code":400,"message":"API key not valid. '
                'Please pass a valid API key.","status":"INVALID_ARGUMENT"}}')
        r = _FakeResponse(200, body)
        v, _ = gas._check_non_empty_list(r)
        assert v is False

    @pytest.mark.unit
    def test_non_json_body_not_vulnerable(self):
        r = _FakeResponse(200, "<html>oops</html>")
        v, _ = gas._check_non_empty_list(r)
        assert v is False

    @pytest.mark.unit
    def test_top_level_empty_array_not_vulnerable(self):
        r = _FakeResponse(200, '[]')
        v, _ = gas._check_non_empty_list(r)
        assert v is False

    @pytest.mark.unit
    def test_top_level_non_empty_array_vulnerable(self):
        r = _FakeResponse(200, '[{"name":"x"}]')
        v, _ = gas._check_non_empty_list(r)
        assert v is True

    @pytest.mark.unit
    @pytest.mark.parametrize("body", [
        # Each entry mimics a different list endpoint's empty response.
        '{"buckets":[]}',
        '{"sites":[]}',
        '{"models":[]}',
        '{"apps":[]}',
        '{"serviceAccounts":[]}',
        '{"topics":[]}',
        '{"items":[]}',
        '{"assets":[]}',
        '{"instances":[]}',
        # With pagination noise present.
        '{"buckets":[],"nextPageToken":""}',
        '{"buckets":[],"nextPageToken":null,"etag":"x"}',
        # Multiple empty arrays.
        '{"items":[],"unreachable":[]}',
    ])
    def test_empty_list_object_not_vulnerable(self, body):
        r = _FakeResponse(200, body)
        v, _ = gas._check_non_empty_list(r)
        assert v is False, f"body {body!r} must be classified empty"

    @pytest.mark.unit
    @pytest.mark.parametrize("body", [
        '{"buckets":[{"name":"projects/x/buckets/foo"}]}',
        '{"sites":[{"name":"sites/foo"}]}',
        '{"models":[{"name":"projects/x/models/foo"}]}',
        '{"apps":[{"appId":"1:1234:web:abcd"}]}',
        '{"serviceAccounts":[{"email":"x@example.iam.gserviceaccount.com"}]}',
        '{"topics":[{"name":"projects/x/topics/foo"}]}',
        '{"assets":[{"name":"//compute.../instance/foo"}]}',
        '{"instances":[{"name":"projects/x/instances/foo"}]}',
        # Mixed: one empty + one non-empty.
        '{"items":[],"buckets":[{"name":"projects/x/buckets/foo"}]}',
        # Non-empty + pagination noise.
        '{"buckets":[{"name":"x"}],"nextPageToken":"abc"}',
    ])
    def test_non_empty_list_object_vulnerable(self, body):
        r = _FakeResponse(200, body)
        v, _ = gas._check_non_empty_list(r)
        assert v is True, f"body {body!r} must be classified vulnerable"

    @pytest.mark.unit
    @pytest.mark.parametrize("body", [
        # Single-resource representations — NO arrays at all.
        '{"name":"projects/x/policy","admissionWhitelistPatterns":"any"}',
        '{"loginProfile":"x","ownerKey":"a"}',
        '{"name":"projects/x/instances/foo","state":"READY"}',
        # Missing collection fields do not establish a list/data exposure.
        '{}',
    ])
    def test_list_helper_rejects_missing_collection(self, body):
        r = _FakeResponse(200, body)
        v, _ = gas._check_non_empty_list(r)
        assert v is False, f"body {body!r} does not contain a collection"

    @pytest.mark.unit
    def test_operations_metadata_only_returns_low_semantic_override(self):
        r = _FakeResponse(200, '{"operations":[{"name":"x"}]}')
        vulnerable, note, overrides = gas._check_non_empty_operations_list(r)
        assert vulnerable is True
        assert "detail" in note
        assert overrides["impact_type"] == "info_disclosure"
        assert overrides["data_sensitivity"] == "metadata"

    @pytest.mark.unit
    def test_operations_response_payload_keeps_customer_data_defaults(self):
        r = _FakeResponse(
            200,
            '{"operations":[{"name":"x","done":true,'
            '"response":{"results":[{"alternatives":'
            '[{"transcript":"private"}]}]}}]}',
        )
        assert gas._check_non_empty_operations_list(r) == (True, None)


class TestT1ProbeMigration:
    """Every HIGH probe that was previously on raw `"200"` and lives on
    a collection-list endpoint must now route through
    `_check_non_empty_list`. The migration script's blocklist
    (`Binary Authorization` policy + `OS Login` loginProfile) must
    STILL stay on `"200"` so single-resource semantics are preserved."""

    @pytest.mark.unit
    @pytest.mark.parametrize("probe_name", _T1_LIST_PROBE_NAMES)
    def test_representative_list_probe_uses_generalized_helper(
            self, probe_name):
        probe = _probe_by_name(probe_name)
        assert probe[5] is gas._check_non_empty_list, (
            f"{probe_name!r} should use _check_non_empty_list (T1); "
            f"got {probe[5]!r}")

    @pytest.mark.unit
    def test_single_resource_raw_200_probes_all_removed(self):
        names = {p[0] for p in gas.ALL_PROBES}
        assert "Binary Authorization" not in names
        assert "OS Login" not in names
        raw_200_high_get = [
            p[0] for p in gas.ALL_PROBES
            if p[1] == "high" and p[2] == "GET" and p[5] == "200"]
        assert raw_200_high_get == [], (
            f"no HIGH GET probe should use raw '200' after the removal; "
            f"found {raw_200_high_get!r}")

    @pytest.mark.unit
    def test_no_high_collection_probe_still_uses_bare_200(self):
        """Registry-wide guard: every HIGH probe whose URL clearly
        targets a collection-list endpoint MUST use
        `_check_non_empty_list`. The two single-resource exceptions
        (`/policy` and `/loginProfile`) are explicit allowlist."""
        SINGLE_RESOURCE_ALLOWLIST = {
            "Binary Authorization": "/policy",
            "OS Login":             "/loginProfile",
        }
        offenders = []
        for p in gas.ALL_PROBES:
            name, cat, method, url, _body, check, _impact = p[:7]
            if cat != "high" or method != "GET":
                continue
            if check != "200":
                continue
            if name in SINGLE_RESOURCE_ALLOWLIST:
                expected_path = SINGLE_RESOURCE_ALLOWLIST[name]
                assert expected_path in url, (
                    f"{name!r} kept raw '200' but URL no longer carries "
                    f"the expected single-resource path {expected_path!r}; "
                    f"got {url!r}")
                continue
            # Any other bare-"200" HIGH GET is an offender.
            offenders.append((name, url))
        assert offenders == [], (
            f"these HIGH probes still use raw `'200'` — T1 migration "
            f"missed them: {offenders!r}")

    @pytest.mark.unit
    def test_real_list_probe_empty_response_not_vulnerable_end_to_end(self):
        probe = _probe_by_name("Pub/Sub Topics")
        fake = _FakeResponse(200, '{"topics":[]}')
        with patch.object(gas.requests, "get", return_value=fake):
            res = gas._execute_probe(probe, SENTINEL_KEY, "test-project",
                                     base_headers={})
        assert res["vulnerable"] is False

    @pytest.mark.unit
    def test_real_list_probe_non_empty_response_vulnerable_end_to_end(self):
        probe = _probe_by_name("Pub/Sub Topics")
        fake = _FakeResponse(
            200, '{"topics":[{"name":"projects/x/topics/foo"}]}')
        with patch.object(gas.requests, "get", return_value=fake):
            res = gas._execute_probe(probe, SENTINEL_KEY, "test-project",
                                     base_headers={})
        assert res["vulnerable"] is True

    @pytest.mark.unit
    def test_binary_authorization_single_resource_probe_removed(self):
        names = {p[0] for p in gas.ALL_PROBES}
        assert "Binary Authorization" not in names
