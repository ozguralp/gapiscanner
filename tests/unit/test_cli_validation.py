"""Offline regressions for public installation, CLI and discovery failures."""
import json
import sys
from types import SimpleNamespace

import pytest

import google_api_scanner as gas
from gapiscanner_core import build_url_fetch_plan

KEY = "AIza" + "x" * 35
PUBLIC = pytest.mark.skipif(getattr(gas, "_OVERLAY_FILENAME", None) is not None,
                            reason="private frontend owns CLI and state placement")


@pytest.fixture(autouse=True)
def isolated_offline_run(monkeypatch):
    import socket
    monkeypatch.setattr(socket.socket, "connect", lambda *a, **k: pytest.fail("network forbidden"))
    monkeypatch.setattr(gas, "_which", lambda cmd: None)
    monkeypatch.setattr(gas, "_crawl_with_playwright", lambda *a: set())
    gas._begin_discovery_session()
    yield
    gas._begin_discovery_session()


@PUBLIC
@pytest.mark.parametrize("args", [
    ["--typo"], ["--threads", "no"], ["--threads", "0"],
    ["--threads", "-2"], ["--api-key", "--output", "file.json"],
    ["--url", "file:///tmp/page"], ["--url", "https://example.com:bad"],
    ["--mobile", "/nonexistent/missing.apk"],
    ["--mobile-dir", "/nonexistent/missing-bundles"],
    ["--resume"], ["--restriction-mode", "android"],
    ["--api-key", KEY, "--url", "https://example.com"],
])
def test_cli_rejects_bad_input_before_scanning(monkeypatch, args):
    monkeypatch.setattr(gas, "scan_gapis", lambda *a, **k: pytest.fail("input validation must precede scanning"))
    monkeypatch.setattr(sys, "argv", ["gapiscanner", *args])
    with pytest.raises(SystemExit) as exc:
        gas.main()
    assert exc.value.code == 2


@PUBLIC
def test_public_kb_uses_user_state_not_install_location(monkeypatch, tmp_path):
    monkeypatch.setenv("GAPISCANNER_DATA_DIR", str(tmp_path / "state"))
    monkeypatch.setattr(gas, "_FRONTEND_ROOT", "/read-only/site-packages")
    assert gas._kb_path() == str(tmp_path / "state" / "_global" / "key_kb.json")


@pytest.mark.parametrize("exc_type", [
    gas.requests.exceptions.ConnectionError, gas.requests.exceptions.Timeout,
    gas.requests.exceptions.SSLError, gas.requests.exceptions.RequestException,
])
@pytest.mark.parametrize("prefix_length", [0, 150])
def test_transport_messages_redact_before_truncating(monkeypatch, capsys, exc_type, prefix_length):
    def fail(*args, **kwargs):
        raise exc_type("x" * prefix_length + " https://example.com/?key=" + KEY)
    monkeypatch.setattr(gas.requests, "get", fail)
    gas._execute_probe(("test", "high", "GET", "https://example.com/?key={key}",
                        None, "200", "test"), KEY, None, {})
    out = capsys.readouterr().out
    assert KEY not in out
    assert KEY[:10] not in out


def test_resume_replays_keys_without_explicit_cache_directory(monkeypatch, tmp_path):
    state = str(tmp_path / "queue.json")
    urls = {"https://example.com/app.js"}
    monkeypatch.setattr(gas.requests, "get", lambda *a, **k: SimpleNamespace(
        text=KEY, status_code=200, headers={}))
    first, _ = gas._fetch_and_extract_keys(urls, queue_state_path=state)
    def no_fetch(*a, **k):
        pytest.fail("a completed cached response should be replayed")
    monkeypatch.setattr(gas.requests, "get", no_fetch)
    resumed, _ = gas._fetch_and_extract_keys(urls, queue_state_path=state, resume=True)
    assert first == resumed == {KEY}


def test_resume_refetches_when_body_missing(monkeypatch, tmp_path):
    cache = tmp_path / "cache"
    state = str(tmp_path / "queue.json")
    urls = {"https://example.com/app.js"}
    calls = []
    def fetch(url, **kwargs):
        calls.append(url)
        return SimpleNamespace(text=KEY, status_code=200, headers={})
    monkeypatch.setattr(gas.requests, "get", fetch)
    gas._fetch_and_extract_keys(urls, cache_dir=str(cache), queue_state_path=state)
    for body in (cache / "bodies").glob("*.bin"):
        body.unlink()
    keys, _ = gas._fetch_and_extract_keys(urls, cache_dir=str(cache),
                                          queue_state_path=state, resume=True)
    assert keys == {KEY}
    assert len(calls) == 2


def test_malformed_and_ipv6_crawl_urls():
    plan = build_url_fetch_plan([
        "https://example.com:bad/a.js", "https://example.com:99999/b.js",
        "http://[::1]:8080/app.js", "https://example.com/valid.js"])
    assert set(plan.selected) == {"http://[::1]:8080/app.js",
                                  "https://example.com/valid.js"}


def test_output_failure_is_not_silently_successful(tmp_path):
    with pytest.raises(OSError):
        gas._save_output(str(tmp_path), {"result": "test"})


@PUBLIC
def test_invalid_archive_is_incomplete_and_still_writes_json(monkeypatch, tmp_path):
    archive = tmp_path / "broken.apk"
    archive.write_bytes(b"not an archive")
    output = tmp_path / "results.json"
    monkeypatch.setattr(sys, "argv", ["gapiscanner", "--mobile", str(archive),
                                      "--output", str(output)])
    with pytest.raises(SystemExit) as exc:
        gas.main()
    assert exc.value.code == 3
    data = json.loads(output.read_text())
    assert data["discovery_incomplete"] is True
    assert data["in_scope_key_count"] == 0


@PUBLIC
def test_failed_fetch_is_not_clean_no_key_result(monkeypatch, tmp_path):
    def fail(*a, **k):
        raise gas.requests.exceptions.Timeout("offline fixture")
    monkeypatch.setattr(gas.requests, "get", fail)
    monkeypatch.setattr(gas, "_which", lambda cmd: None)
    monkeypatch.setattr(gas, "_crawl_with_playwright", lambda *a: set())
    output = tmp_path / "results.json"
    monkeypatch.setattr(sys, "argv", ["gapiscanner", "--url", "https://example.com",
                                      "--output", str(output)])
    with pytest.raises(SystemExit) as exc:
        gas.main()
    assert exc.value.code == 3
    assert json.loads(output.read_text())["discovery_incomplete"] is True


def test_referer_origin_has_no_path():
    headers = gas._build_restriction_headers("referer", "https://example.com/page?q=x")
    assert headers["Referer"] == "https://example.com/page?q=x"
    assert headers["Origin"] == "https://example.com"


@pytest.mark.parametrize("check", ["ne:error", "ne:error_message", "not_auth"])
@pytest.mark.parametrize("status,body", [(500, "gateway failure"), (404, "{}"),
                                         (200, "<html>sign in</html>")])
def test_http_failures_and_html_are_not_api_success(check, status, body):
    response = gas.requests.Response()
    response.status_code = status
    response._content = body.encode()
    assert gas._parse_check(check)(response)[0] is False


@pytest.mark.parametrize("body", [{}, {"nextPageToken": "abc"}, {"error": {"message": "denied"}}])
def test_missing_list_is_not_customer_data(body):
    response = SimpleNamespace(status_code=200, text=json.dumps(body))
    assert gas._check_non_empty_list(response)[0] is False


def test_json_findings_scrub_urls_and_notes():
    row = dict(name="test", category="high", url="https://example.com?key=" + KEY,
               impact="test", vulnerable=True, tier="CONFIRMED", services_seen=set(),
               manual_note=KEY)
    assert KEY not in json.dumps(gas._build_json_output([row], 1, {}))


def test_archive_decompression_limit_is_incomplete(monkeypatch, tmp_path):
    import zipfile
    path = tmp_path / "big.apk"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("large.txt", b"x" * 64)
    monkeypatch.setattr(gas, "_MOBILE_MEMBER_MAX_BYTES", 16)
    keys, _ = gas.discover_keys_from_mobile(str(path), quiet=True)
    assert not keys
    assert gas._discovery_issue_snapshot()["archive_size_limits"] >= 1


def test_proxy_does_not_leak_to_next_scan():
    gas._configure_proxy("http://localhost:8080")
    gas._configure_proxy(None)
    assert "proxies" not in gas._REQUEST_KWARGS


def test_android_v1_certificate_uses_der_api(monkeypatch, tmp_path):
    import hashlib
    apk = SimpleNamespace(get_package=lambda: "com.example.app",
                          get_signature_name=lambda: "META-INF/TEST.RSA",
                          get_certificate_der=lambda name: b"synthetic DER")
    monkeypatch.setitem(sys.modules, "androguard.core.apk", SimpleNamespace(APK=lambda path: apk))
    package, cert = gas._extract_android_package_and_sha1(str(tmp_path / "v1.apk"))
    assert package == "com.example.app"
    assert cert.replace(":", "") == hashlib.sha1(b"synthetic DER").hexdigest().upper()


@PUBLIC
def test_json_stdout_is_parseable_for_empty_discovery(monkeypatch, tmp_path, capsys):
    import zipfile
    path = tmp_path / "empty.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("text.txt", "no keys")
    monkeypatch.setattr(sys, "argv", ["gapiscanner", "--mobile", str(path), "--json"])
    with pytest.raises(SystemExit) as exc:
        gas.main()
    out = capsys.readouterr()
    assert exc.value.code == 0
    assert json.loads(out.out)["in_scope_key_count"] == 0
    assert "No AIza keys" in out.err


@pytest.mark.parametrize("url", [
    "https://attacker.example", "http://app.firebaseio.com",
    "https://app.firebaseio.com.attacker.example",
    "https://app.firebaseio.com@attacker.example",
    "https://app.firebaseio.com/?redirect=https://attacker.example",
    "https://app.firebaseio.com:444", "https://app.firebaseio.com/data",
])
def test_untrusted_database_url_never_receives_id_token(monkeypatch, url):
    def unexpected(*args, **kwargs):
        pytest.fail("must reject the destination before sending credentials")
    monkeypatch.setattr(gas.requests, "get", unexpected)
    assert gas._authenticated_rtdb_read(url, "secret-id-token") is None


def test_api_credentials_do_not_follow_redirects():
    assert gas._request_kwargs_for_url("https://app.firebaseio.com")["allow_redirects"] is False


def test_long_error_excerpt_keeps_diagnostics():
    assert gas._safe_error_excerpt("x" * 100, 8) == "xxxxxxxx ..."
