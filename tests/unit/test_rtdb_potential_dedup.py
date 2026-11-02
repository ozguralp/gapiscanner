"""Regression coverage for rtdb potential dedup."""
from __future__ import annotations

import io
import json
import re
import sys
from contextlib import redirect_stdout
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import google_api_scanner as gas  # noqa: E402

# `_handle_result` uses ANSI colour codes in its printed output. Strip them
# before asserting on substrings so tests don't have to embed escape sequences.
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


SENTINEL_KEY = "AIza" + "X" * 35


class FakeResponse:
    """Minimal response fixture for RTDB checks."""

    def __init__(self, status_code, text):
        self.status_code = status_code
        self.text = text
        self.content = text.encode("utf-8") if text else b""
        self.headers = {"Content-Type": "application/json"}
        m = type("R", (), {"url": "https://x.firebaseio.com/.json"})
        self.request = m()

    def json(self):
        return json.loads(self.text) if self.text else {}


def _run_get_probe(monkeypatch, probe, response):
    def fake_get(*a, **kw):
        return response

    monkeypatch.setattr(gas.requests, "get", fake_get)
    return gas._execute_probe(probe, SENTINEL_KEY, "test-project-123",
                              {}, verbose=False)


# 1. `_check_firebase_rtdb_root` — non-empty body returns POTENTIAL override

class TestCheckFirebaseRtdbRoot:
    @pytest.mark.unit
    def test_non_empty_returns_potential_open_rtdb_override(self):
        """The check function MUST return the POTENTIAL override tuple
        when the response is a non-empty 200 — `confirmation` becomes
        `key_accepted_only` (POTENTIAL), `impact_type` becomes
        `info_disclosure`, `data_sensitivity` becomes `metadata`."""
        r = FakeResponse(200, '{"users":{"alice":{"score":100}}}')
        vulnerable, note, overrides = gas._check_firebase_rtdb_root(r)
        assert vulnerable is True
        assert note == "potential_open_rtdb"
        assert overrides["confirmation"] == "key_accepted_only"
        assert overrides["impact_type"] == "info_disclosure"
        assert overrides["data_sensitivity"] == "metadata"
        assert "potential" in overrides["impact"].lower() or \
               "manual review" in overrides["impact"].lower()

    @pytest.mark.unit
    def test_empty_body_unchanged_open_empty(self):
        """Empty `{}` body MUST still return the legacy `open_empty`
        override so the existing INFO/none classification is preserved."""
        r = FakeResponse(200, "{}")
        vulnerable, note, overrides = gas._check_firebase_rtdb_root(r)
        assert vulnerable is True
        assert note == "open_empty"
        assert overrides["data_sensitivity"] == "none"

    @pytest.mark.unit
    def test_null_body_unchanged_open_empty(self):
        """`null` body MUST still return the legacy `open_empty` override."""
        r = FakeResponse(200, "null")
        vulnerable, note, overrides = gas._check_firebase_rtdb_root(r)
        assert vulnerable is True
        assert note == "open_empty"
        assert overrides["data_sensitivity"] == "none"

    @pytest.mark.unit
    def test_permission_denied_not_vulnerable(self):
        """A 401 'Permission denied' MUST remain not-vulnerable (rules
        enforced)."""
        r = FakeResponse(401, '{"error":"Permission denied"}')
        result = gas._check_firebase_rtdb_root(r)
        assert result[0] is False

    @pytest.mark.unit
    def test_non_200_not_vulnerable(self):
        """Any non-200 status MUST remain not-vulnerable."""
        r = FakeResponse(403, "")
        result = gas._check_firebase_rtdb_root(r)
        assert result[0] is False


# 2. End-to-end — `_execute_probe` returns the right tier + severity

class TestNonEmptyRtdbEndToEnd:
    @pytest.mark.unit
    def test_non_empty_rtdb_is_potential_info_not_confirmed_high(
            self, monkeypatch):
        probe = (
            "Firebase RTDB root (.json)", "high", "GET",
            "https://{project}.firebaseio.com/.json?auth={key}",
            None, gas._check_firebase_rtdb_root,
            "Realtime Database root read",
        )
        result = _run_get_probe(
            monkeypatch, probe,
            FakeResponse(200, '{"users":{"alice":{"score":100}}}'))
        assert result["vulnerable"] is True
        assert result["confirmation"] == "key_accepted_only"
        assert result["impact_type"] == "info_disclosure"
        assert result["data_sensitivity"] == "metadata"
        assert result["severity"] != "HIGH", (
            "non-empty RTDB must not derive HIGH; got %r" % result["severity"])
        assert result["severity"] == "INFO", (
            "info_disclosure + key_accepted_only + metadata derives INFO; "
            "got %r" % result["severity"])


# 3. `_canonical_rtdb_database_url` — URL canonicalisation

class TestCanonicalRtdbUrl:
    @pytest.mark.unit
    @pytest.mark.parametrize("url,canonical", [
        # Legacy <pid>.firebaseio.com
        ("https://victim.firebaseio.com/.json",
         "https://victim.firebaseio.com"),
        ("https://victim.firebaseio.com/.json?shallow=true",
         "https://victim.firebaseio.com"),
        # Post-2020 <pid>-default-rtdb.firebaseio.com
        ("https://victim-default-rtdb.firebaseio.com/.json",
         "https://victim-default-rtdb.firebaseio.com"),
        ("https://victim-default-rtdb.firebaseio.com/.json?shallow=true",
         "https://victim-default-rtdb.firebaseio.com"),
        # Regional .firebasedatabase.app — root only (the chain table only
        # ships root variants for non-US regions, but canonicalisation must
        # work for shallow too so an extracted DATABASE_URL with shallow can
        # collapse with its root sibling).
        ("https://victim-default-rtdb.europe-west1.firebasedatabase.app/.json",
         "https://victim-default-rtdb.europe-west1.firebasedatabase.app"),
        ("https://victim-default-rtdb.europe-west1.firebasedatabase.app/.json?shallow=true",
         "https://victim-default-rtdb.europe-west1.firebasedatabase.app"),
        # Other query params (e.g. ?auth=...) MUST also be stripped — the
        # canonical key is the database identity, not the request shape.
        ("https://victim.firebaseio.com/.json?auth=AIzaXXX",
         "https://victim.firebaseio.com"),
    ])
    def test_canonicalisation(self, url, canonical):
        assert gas._canonical_rtdb_database_url(url) == canonical

    @pytest.mark.unit
    def test_missing_url_returns_none(self):
        assert gas._canonical_rtdb_database_url(None) is None
        assert gas._canonical_rtdb_database_url("") is None


# 4. `_dedup_rtdb_findings` — drops duplicates, prefers shallow

def _make_rtdb_result(name, url, vulnerable=True):
    return {
        "name": name,
        "url": url,
        "vulnerable": vulnerable,
        "category": "high",
        "tier": "POTENTIAL",
        "severity": "INFO",
        "impact_type": "info_disclosure",
        "confirmation": "key_accepted_only",
        "data_sensitivity": "metadata",
    }


class TestDedupRtdbFindings:
    @pytest.mark.unit
    def test_root_and_shallow_collapse_to_one(self):
        """Same canonical DB, both root + shallow non-empty → keep shallow,
        drop root."""
        results = [
            _make_rtdb_result(
                "Firebase RTDB root (.json) [project=victim]",
                "https://victim.firebaseio.com/.json"),
            _make_rtdb_result(
                "Firebase RTDB shallow keys [project=victim]",
                "https://victim.firebaseio.com/.json?shallow=true"),
        ]
        dropped = gas._dedup_rtdb_findings(results)
        assert dropped == 1
        assert len(results) == 1
        kept = results[0]
        assert "shallow" in kept["name"].lower(), (
            "dedup MUST prefer the shallow variant; kept root instead: "
            "%r" % kept["name"])

    @pytest.mark.unit
    def test_only_root_present_keeps_root(self):
        results = [
            _make_rtdb_result(
                "Firebase RTDB root (.json) [project=victim]",
                "https://victim.firebaseio.com/.json"),
        ]
        dropped = gas._dedup_rtdb_findings(results)
        assert dropped == 0
        assert len(results) == 1

    @pytest.mark.unit
    def test_only_shallow_present_keeps_shallow(self):
        results = [
            _make_rtdb_result(
                "Firebase RTDB shallow keys [project=victim]",
                "https://victim.firebaseio.com/.json?shallow=true"),
        ]
        dropped = gas._dedup_rtdb_findings(results)
        assert dropped == 0
        assert len(results) == 1

    @pytest.mark.unit
    def test_legacy_and_default_rtdb_are_separate_databases(self):
        """`<pid>.firebaseio.com` and `<pid>-default-rtdb.firebaseio.com`
        are DIFFERENT databases — they MUST NOT dedup together even though
        both belong to the same project ID."""
        results = [
            _make_rtdb_result(
                "Firebase RTDB shallow keys [project=victim]",
                "https://victim.firebaseio.com/.json?shallow=true"),
            _make_rtdb_result(
                "Firebase RTDB shallow keys (regional default) [project=victim]",
                "https://victim-default-rtdb.firebaseio.com/.json?shallow=true"),
        ]
        dropped = gas._dedup_rtdb_findings(results)
        assert dropped == 0
        assert len(results) == 2

    @pytest.mark.unit
    def test_extracted_database_url_root_and_shallow_collapse(self):
        """Extracted-DATABASE_URL root + shallow against the same database
        canonical URL MUST collapse."""
        results = [
            _make_rtdb_result(
                "Firebase RTDB root (extracted DATABASE_URL) [project=victim]",
                "https://victim-default-rtdb.firebaseio.com/.json"),
            _make_rtdb_result(
                "Firebase RTDB shallow keys (extracted DATABASE_URL) [project=victim]",
                "https://victim-default-rtdb.firebaseio.com/.json?shallow=true"),
        ]
        dropped = gas._dedup_rtdb_findings(results)
        assert dropped == 1
        assert len(results) == 1
        assert "shallow" in results[0]["name"].lower()

    @pytest.mark.unit
    def test_regional_root_and_shallow_collapse(self):
        """`.europe-west1.firebasedatabase.app` root + shallow MUST
        collapse to one finding when both are present (e.g. via extracted
        DATABASE_URL variants)."""
        base = "https://victim-default-rtdb.europe-west1.firebasedatabase.app"
        results = [
            _make_rtdb_result(
                "Firebase RTDB root (europe-west1) [project=victim]",
                base + "/.json"),
            _make_rtdb_result(
                "Firebase RTDB shallow keys (europe-west1)",
                base + "/.json?shallow=true"),
        ]
        dropped = gas._dedup_rtdb_findings(results)
        assert dropped == 1
        assert len(results) == 1
        assert "shallow" in results[0]["name"].lower()

    @pytest.mark.unit
    def test_non_rtdb_results_untouched(self):
        """Non-RTDB results MUST NEVER be deduped — only the RTDB read
        probes target the same database via two URL variants."""
        results = [
            {
                "name": "Cloud Vision",
                "url": "https://vision.googleapis.com/v1/images:annotate?key=…",
                "vulnerable": True,
                "category": "low",
            },
            {
                "name": "Gemini Generate Content",
                "url": "https://generativelanguage.googleapis.com/v1beta/models/gemini:generateContent?key=…",
                "vulnerable": True,
                "category": "high",
            },
        ]
        dropped = gas._dedup_rtdb_findings(results)
        assert dropped == 0
        assert len(results) == 2

    @pytest.mark.unit
    def test_empty_open_rtdb_does_not_collapse_against_non_empty(self):
        """`Firebase RTDB open but empty` is a SEPARATE finding name — the
        dedup filter targets RTDB read variants, and the empty-open finding
        keeps its own row. The two are valid distinct signals."""
        results = [
            {
                "name": "Firebase RTDB open but empty [project=victim]",
                "url": "https://victim.firebaseio.com/.json",
                "vulnerable": True,
                "category": "low",
            },
            _make_rtdb_result(
                "Firebase RTDB shallow keys [project=victim]",
                "https://victim.firebaseio.com/.json?shallow=true"),
        ]
        dropped = gas._dedup_rtdb_findings(results)
        # `Firebase RTDB open but empty` does NOT match the RTDB-read
        # markers, so the shallow finding stays alone in its bucket and
        # nothing collapses.
        assert dropped == 0
        assert len(results) == 2

    @pytest.mark.unit
    def test_vulnerable_false_results_ignored(self):
        """Non-vulnerable RTDB probe rows (e.g. 401 Permission denied) MUST
        NOT participate in dedup — they're not findings to begin with."""
        results = [
            _make_rtdb_result(
                "Firebase RTDB root (.json) [project=victim]",
                "https://victim.firebaseio.com/.json",
                vulnerable=False),
            _make_rtdb_result(
                "Firebase RTDB shallow keys [project=victim]",
                "https://victim.firebaseio.com/.json?shallow=true"),
        ]
        dropped = gas._dedup_rtdb_findings(results)
        assert dropped == 0
        assert len(results) == 2


# 5. Immediate stdout regression — POTENTIAL print branch never says [HIGH]

class TestPotentialPrintBranchRegression:

    @pytest.mark.unit
    def test_non_empty_rtdb_log_line_is_severity_first_not_high(
            self, monkeypatch):
        """Drive a scan where every probe returns either no-op or a single
        non-empty RTDB POTENTIAL finding; the immediate inline log line MUST
        be severity-first (`[INFO/POTENTIAL/HIGH]`) and MUST NOT contain a
        bare `[HIGH]` tag."""

        rtdb_result = {
            "name": "Firebase RTDB shallow keys [project=victim]",
            "category": "high",
            "abuse_class": "Recon",
            "url": "https://victim.firebaseio.com/.json?shallow=true",
            "impact": ("Potential open RTDB — readable without auth. "
                       "Top-level keys / shallow content returned; manual "
                       "review needed to confirm whether any sensitive "
                       "customer data is exposed."),
            "vulnerable": True,
            "manual_note": "potential_open_rtdb",
            "referer_blocked": False,
            "error_class": None,
            "services_seen": set(),
            "reason": "",
            "gemini_disabled": False,
            "status_code": 200,
            "snippet": None,
            "impact_type":      "info_disclosure",
            "confirmation":     "key_accepted_only",
            "data_sensitivity": "metadata",
            "severity":         "INFO",
        }

        emitted = [False]

        def _fake_execute_probe(*a, **kw):
            # Emit the RTDB POTENTIAL once (Phase 0 / Phase 2 / Phase 3 all
            # route through `_execute_probe`); subsequent calls return None
            # so the scan terminates quickly without doing any other work.
            if not emitted[0]:
                emitted[0] = True
                return dict(rtdb_result)
            return None

        monkeypatch.setattr(gas, "_execute_probe", _fake_execute_probe)

        buf = io.StringIO()
        with redirect_stdout(buf):
            gas.scan_gapis(SENTINEL_KEY,
                           quiet=False, threads=1)
        out = _ANSI.sub("", buf.getvalue())

        # The POTENTIAL line MUST appear — proves the result was handled.
        assert "POTENTIAL VULNERABLE" in out, (
            "expected the POTENTIAL VULNERABLE print line; not found in "
            "scan output (first 400 chars): %r" % out[:400])

        # The bracketed tag MUST be severity-first (`[INFO/POTENTIAL/HIGH]`)
        # and MUST NOT be a bare run-group tag (`[HIGH]`) that misleads the
        # operator into thinking this is a confirmed HIGH finding.
        assert "[INFO/POTENTIAL/HIGH]" in out, (
            "POTENTIAL line MUST print severity-first [SEV/POTENTIAL/CAT]; "
            "instead got (POTENTIAL section of stdout): %r"
            % out[out.find("POTENTIAL VULNERABLE"):
                  out.find("POTENTIAL VULNERABLE") + 400])

        # Regression: the legacy single-tag form is forbidden because it
        # cannot distinguish `category=high` from `severity=HIGH`.
        legacy_tag_idx = out.find("POTENTIAL VULNERABLE")
        legacy_tag_line = out[legacy_tag_idx: legacy_tag_idx + 400]
        assert " [HIGH]" not in legacy_tag_line, (
            "POTENTIAL line MUST NOT print bare `[HIGH]` — that's the "
            "regression this test pins. Saw: %r" % legacy_tag_line)

    @pytest.mark.unit
    def test_confirmed_branch_unchanged_severity_first(self, monkeypatch):
        confirmed_result = {
            "name": "Cloud Storage Buckets",
            "category": "high",
            "abuse_class": "DataExfil",
            "url": "https://storage.googleapis.com/storage/v1/b?project=x&key=…",
            "impact": "Data leak — list storage buckets",
            "vulnerable": True,
            "manual_note": None,
            "referer_blocked": False,
            "error_class": None,
            "services_seen": set(),
            "reason": "",
            "gemini_disabled": False,
            "status_code": 200,
            "snippet": None,
            "impact_type":      "data_read",
            "confirmation":     "confirmed_data",
            "data_sensitivity": "customer_data",
            "severity":         "HIGH",
        }

        emitted = [False]

        def _fake_execute_probe(*a, **kw):
            if not emitted[0]:
                emitted[0] = True
                return dict(confirmed_result)
            return None

        monkeypatch.setattr(gas, "_execute_probe", _fake_execute_probe)
        buf = io.StringIO()
        with redirect_stdout(buf):
            gas.scan_gapis(SENTINEL_KEY,
                           quiet=False, threads=1)
        out = _ANSI.sub("", buf.getvalue())
        assert "API key is vulnerable for Cloud Storage Buckets!" in out
        assert "[HIGH/CONFIRMED/HIGH]" in out, (
            "CONFIRMED branch must still print severity-first; got "
            "stdout (head): %r" % out[:600])
