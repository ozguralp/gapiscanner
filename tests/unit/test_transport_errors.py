"""Transport-error reporting + --insecure kill switch + exit-code-3 semantics.

These tests are pure-function / pure-mock (no live HTTP). They verify:

  1. `_request_kwargs_for_url` honors the destination + `_INSECURE_TLS` switch.
  2. `_execute_probe` distinguishes SSL / Timeout / Connection / generic
     `RequestException`, prints a visible message, and bumps the right
     counter (so the SUMMARY block and CLI exit code can tell transport
     incomplete from clean).
  3. `_reset_transport_errors` / `_capture_last_transport_errors` /
     `_last_transport_error_*` snapshot pair behave correctly under
     repeated scans (no stale-count bleed).
  4. CLI exit semantics: 1 = vulnerable, 3 = transport incomplete +
     no findings, 0 = clean + no findings. Discovery loops aggregate.
"""
from __future__ import annotations

import io
import sys
import tempfile
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import pytest
import requests

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import google_api_scanner as gas  # noqa: E402


# Test fixtures — reset module-level state before/after each test so one
# test never leaks counter state into the next.

@pytest.fixture(autouse=True)
def _reset_transport_state():
    gas._reset_transport_errors()
    # Wipe the captured "last" snapshot too — otherwise the previous test's
    # final scan state leaks into this test's CLI exit assertions.
    with gas._TRANSPORT_ERROR_LOCK:
        for k in list(gas._LAST_TRANSPORT_ERROR_COUNTS):
            gas._LAST_TRANSPORT_ERROR_COUNTS[k] = 0
    prior_insecure = gas._INSECURE_TLS
    yield
    gas._INSECURE_TLS = prior_insecure
    gas._reset_transport_errors()
    with gas._TRANSPORT_ERROR_LOCK:
        for k in list(gas._LAST_TRANSPORT_ERROR_COUNTS):
            gas._LAST_TRANSPORT_ERROR_COUNTS[k] = 0


# 1. `_request_kwargs_for_url` — destination + `_INSECURE_TLS` matrix

class TestRequestKwargs:
    @pytest.mark.unit
    def test_googleapis_verifies_by_default(self):
        kw = gas._request_kwargs_for_url(
            "https://identitytoolkit.googleapis.com/v1/accounts:signUp")
        assert kw["verify"] is True

    @pytest.mark.unit
    def test_unrelated_host_verifies_by_default(self):
        kw = gas._request_kwargs_for_url("https://example.com/api")
        assert kw["verify"] is True

    @pytest.mark.unit
    def test_target_crawl_unrelated_host_skips_verify(self):
        kw = gas._request_kwargs_for_url("https://example.com/api",
                                         target_crawl=True)
        assert kw["verify"] is False

    @pytest.mark.unit
    def test_insecure_overrides_googleapis(self):
        gas._INSECURE_TLS = True
        try:
            kw = gas._request_kwargs_for_url(
                "https://identitytoolkit.googleapis.com/v1/accounts:signUp")
            assert kw["verify"] is False
        finally:
            gas._INSECURE_TLS = False

    @pytest.mark.unit
    def test_insecure_overrides_unrelated_host(self):
        gas._INSECURE_TLS = True
        try:
            kw = gas._request_kwargs_for_url("https://example.com/api")
            assert kw["verify"] is False
        finally:
            gas._INSECURE_TLS = False


# 2. `_execute_probe` exception handling — visible + counter-tracked

_PROBE = (
    "Test Probe",
    "high",
    "GET",
    "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={key}",
    None,
    "200",
    "test impact",
)


def _run_probe_with_exception(exc):
    """Invoke `_execute_probe` with the GET call raising `exc`. Captures
    stdout so callers can assert on the printed message. Returns the
    captured stdout text (the function itself returns None for any
    transport error)."""
    buf = io.StringIO()
    with redirect_stdout(buf), patch.object(gas.requests, "get",
                                            side_effect=exc):
        result = gas._execute_probe(_PROBE, "AIza" + "x" * 35,
                                    project_id=None,
                                    base_headers={},
                                    verbose=False)
    return result, buf.getvalue()


class TestExecuteProbeTransportErrors:
    @pytest.mark.unit
    def test_ssl_error_records_ssl_and_prints_insecure_hint(self):
        result, out = _run_probe_with_exception(
            requests.exceptions.SSLError("certificate verify failed"))
        assert result is None
        snap = gas._transport_error_snapshot()
        assert snap["ssl"] == 1
        assert snap["connection"] == 0
        assert snap["timeout"] == 0
        assert snap["other"] == 0
        assert "TLS error" in out
        assert "--insecure" in out

    @pytest.mark.unit
    def test_timeout_records_timeout(self):
        result, out = _run_probe_with_exception(
            requests.exceptions.Timeout("read timed out"))
        assert result is None
        snap = gas._transport_error_snapshot()
        assert snap["timeout"] == 1
        assert snap["ssl"] == 0
        assert "Timeout" in out

    @pytest.mark.unit
    def test_connection_error_records_connection(self):
        result, out = _run_probe_with_exception(
            requests.exceptions.ConnectionError("connection refused"))
        assert result is None
        snap = gas._transport_error_snapshot()
        assert snap["connection"] == 1
        assert snap["ssl"] == 0
        assert "Connection error" in out

    @pytest.mark.unit
    def test_generic_request_exception_records_other(self):
        # Use a `RequestException` subclass that is NOT SSL/Timeout/Connection.
        # `ChunkedEncodingError` inherits from `RequestException` directly.
        result, out = _run_probe_with_exception(
            requests.exceptions.ChunkedEncodingError("broken stream"))
        assert result is None
        snap = gas._transport_error_snapshot()
        assert snap["other"] == 1
        assert snap["ssl"] == 0
        assert "Request failed" in out


# 3. Counter hygiene — reset / capture / last-snapshot pair

class TestCounterHygiene:
    @pytest.mark.unit
    def test_reset_clears_all_kinds(self):
        gas._record_transport_error("ssl")
        gas._record_transport_error("connection")
        gas._record_transport_error("timeout")
        gas._record_transport_error("other")
        assert gas._transport_error_total() == 4
        gas._reset_transport_errors()
        assert gas._transport_error_total() == 0
        snap = gas._transport_error_snapshot()
        assert snap == {"ssl": 0, "connection": 0, "timeout": 0, "other": 0}

    @pytest.mark.unit
    def test_capture_freezes_snapshot(self):
        gas._record_transport_error("ssl")
        gas._record_transport_error("ssl")
        gas._record_transport_error("timeout")
        gas._capture_last_transport_errors()
        # Bumping after capture must NOT affect the snapshot.
        gas._record_transport_error("ssl")
        gas._record_transport_error("ssl")
        last = gas._last_transport_error_snapshot()
        assert last["ssl"] == 2
        assert last["timeout"] == 1
        assert gas._last_transport_error_total() == 3

    @pytest.mark.unit
    def test_reset_does_not_clear_last_snapshot(self):
        """`_reset_transport_errors` only touches the LIVE counter — the
        last-snapshot must survive so the CLI can still inspect it after
        the next scan resets the live state."""
        gas._record_transport_error("ssl")
        gas._capture_last_transport_errors()
        gas._reset_transport_errors()
        last = gas._last_transport_error_snapshot()
        assert last["ssl"] == 1


# 4. scan_gapis hygiene — entry-reset + exit-capture, no cross-scan bleed

class TestScanGapisHygiene:
    """Validates the reset + capture pair by short-circuiting `_execute_probe`
    so we don't need live network or the full probe pipeline."""

    @pytest.mark.unit
    def test_entry_reset_clears_stale_counts(self):
        """If a prior scan left ssl=5 on the live counter, the next scan
        must start at 0 — otherwise the per-scan SUMMARY block lies."""
        gas._record_transport_error("ssl")
        gas._record_transport_error("ssl")
        gas._record_transport_error("ssl")
        # Stub the probe loop entirely so no network happens.
        with patch.object(gas, "_execute_probe", return_value=None):
            with redirect_stdout(io.StringIO()):
                gas.scan_gapis(
                    "AIza" + "x" * 35,
                    include_maps=False, include_low=False,
                    include_destructive=False, include_cost_amp=False,

                    skip_jsapi=True, proxy=None, referer=None,
                    quiet=True, threads=1,
                )
        # scan_gapis() resets the live counter at entry. After return the
        # captured snapshot reflects the CURRENT scan, not the prior ssl=3.
        assert gas._last_transport_error_total() == 0

    @pytest.mark.unit
    def test_all_ssl_scan_captures_last_snapshot_and_marks_not_clean(self):
        """A scan whose every probe raises SSLError must (a) capture the
        last-snapshot with ssl > 0 and (b) the SUMMARY must say "NOT clean"
        instead of the green "No vulnerable APIs found" line."""
        def _raise_ssl(*a, **kw):
            gas._record_transport_error("ssl")
            return None

        buf = io.StringIO()
        with patch.object(gas, "_execute_probe", side_effect=_raise_ssl):
            with redirect_stdout(buf):
                gas.scan_gapis(
                    "AIza" + "x" * 35,
                    include_maps=False, include_low=False,
                    include_destructive=False, include_cost_amp=False,

                    skip_jsapi=True, proxy=None, referer=None,
                    quiet=True, threads=1,
                )
        out = buf.getvalue()
        last = gas._last_transport_error_snapshot()
        assert last["ssl"] > 0
        assert "NOT clean" in out

    @pytest.mark.unit
    def test_clean_scan_after_transport_failures_does_not_inherit(self):
        """A second scan whose probes succeed (or no-op) must end with a
        zero last-snapshot — the prior scan's transport errors cannot leak
        across the entry-reset boundary."""
        # First scan: every probe records SSL.
        def _raise_ssl(*a, **kw):
            gas._record_transport_error("ssl")
            return None

        with patch.object(gas, "_execute_probe", side_effect=_raise_ssl):
            with redirect_stdout(io.StringIO()):
                gas.scan_gapis(
                    "AIza" + "x" * 35,
                    include_maps=False, include_low=False,
                    include_destructive=False, include_cost_amp=False,

                    skip_jsapi=True, proxy=None, referer=None,
                    quiet=True, threads=1,
                )
        assert gas._last_transport_error_total() > 0

        # Second scan: probe loop returns None without recording. The
        # entry-reset must wipe the live counter; the exit-capture must
        # overwrite the last-snapshot.
        with patch.object(gas, "_execute_probe", return_value=None):
            with redirect_stdout(io.StringIO()):
                gas.scan_gapis(
                    "AIza" + "x" * 35,
                    include_maps=False, include_low=False,
                    include_destructive=False, include_cost_amp=False,

                    skip_jsapi=True, proxy=None, referer=None,
                    quiet=True, threads=1,
                )
        assert gas._last_transport_error_total() == 0


# 5. CLI exit semantics — direct --api-key path

def _run_main_with_argv(argv, vuln_return, transport_total,
                        confirmed_high_count=None):
    if confirmed_high_count is None:
        confirmed_high_count = len(vuln_return or [])

    def _fake_scan(*a, **kw):
        # Mimic what real scan_gapis would do: reset live counter at
        # entry, then capture a fake transport total at exit so the CLI
        # sees the value we want.
        gas._reset_transport_errors()
        for _ in range(transport_total):
            gas._record_transport_error("ssl")
        gas._capture_last_transport_errors()

        gas._capture_last_confirmed_severity_counts({
            "HIGH": confirmed_high_count,
            "MED":  max(0, len(vuln_return or []) - confirmed_high_count),
            "LOW_INFO": 0,
        })
        return vuln_return

    with tempfile.TemporaryDirectory(prefix="gapiscanner_cli_exit_") as tmpdir:
        safe_argv = list(argv)
        if hasattr(gas, "_kb_path") and "--output-dir" not in safe_argv:
            safe_argv.extend(["--output-dir", tmpdir])
        with patch.object(sys, "argv", ["google_api_scanner.py"] + safe_argv), \
             patch.object(gas, "scan_gapis", side_effect=_fake_scan), \
             redirect_stdout(io.StringIO()):
            with pytest.raises(SystemExit) as exc_info:
                gas.main()
    code = exc_info.value.code
    return code if code is not None else 0


class TestCLIExitSemantics:
    @pytest.fixture(autouse=True)
    def _reset_severity_snapshot(self):
        gas._capture_last_confirmed_severity_counts(
            {"HIGH": 0, "MED": 0, "LOW_INFO": 0})
        yield
        gas._capture_last_confirmed_severity_counts(
            {"HIGH": 0, "MED": 0, "LOW_INFO": 0})

    @pytest.mark.unit
    def test_clean_scan_exits_zero(self):
        code = _run_main_with_argv(
            ["--api-key", "AIza" + "x" * 35],
            vuln_return=[], transport_total=0)
        assert code == 0

    @pytest.mark.unit
    def test_vulnerable_scan_exits_one(self):
        code = _run_main_with_argv(
            ["--api-key", "AIza" + "x" * 35],
            vuln_return=["Some Vulnerable API"], transport_total=0)
        assert code == 1

    @pytest.mark.unit
    def test_transport_incomplete_no_findings_exits_three(self):
        code = _run_main_with_argv(
            ["--api-key", "AIza" + "x" * 35],
            vuln_return=[], transport_total=5)
        assert code == 3

    @pytest.mark.unit
    def test_vulnerable_with_transport_errors_still_exits_one(self):
        """Confirmed findings dominate transport noise — operator must see
        the CRITICAL signal even if some probes failed in transport."""
        code = _run_main_with_argv(
            ["--api-key", "AIza" + "x" * 35],
            vuln_return=["Some Vulnerable API"], transport_total=5)
        assert code == 1

    @pytest.mark.unit
    def test_insecure_flag_flips_global(self):
        """`--insecure` on the CLI must set `_INSECURE_TLS=True` for the
        duration of the scan so `_request_kwargs_for_url` honors it."""
        observed = {"insecure": None}

        def _capture_insecure(*a, **kw):
            observed["insecure"] = gas._INSECURE_TLS
            gas._reset_transport_errors()
            gas._capture_last_transport_errors()
            return []

        with patch.object(sys, "argv",
                          ["google_api_scanner.py", "--insecure",
                           "--api-key", "AIza" + "x" * 35]), \
             patch.object(gas, "scan_gapis", side_effect=_capture_insecure), \
             redirect_stdout(io.StringIO()):
            with pytest.raises(SystemExit):
                gas.main()
        assert observed["insecure"] is True
