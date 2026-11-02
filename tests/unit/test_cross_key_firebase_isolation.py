"""Regression coverage for cross key firebase isolation."""
from __future__ import annotations

import sys
import json
import zipfile
import contextlib
import io
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import google_api_scanner as gas  # noqa: E402

KEY_A = "AIzaSy" + "A" * 33
KEY_B = "AIzaSy" + "B" * 33
KEY_NO_CFG = "AIzaSy" + "C" * 33


def test_select_prefers_exact_api_key_match():
    cfgs = [
        {"project_id": "proj-A", "api_key": KEY_A},
        {"project_id": "proj-B", "api_key": KEY_B},
    ]
    sel = gas._select_configs_for_key(KEY_A, cfgs)
    assert [c["project_id"] for c in sel] == ["proj-A"]


def test_select_falls_back_to_all_when_no_api_key():
    # Tier 3 — no config is keyed at all (legacy extractors): cannot
    # disambiguate, fall back to all archive-local configs.
    cfgs = [{"project_id": "proj-A"}, {"project_id": "proj-B"}]
    sel = gas._select_configs_for_key(KEY_A, cfgs)
    assert sorted(c["project_id"] for c in sel) == ["proj-A", "proj-B"]


def test_select_unmatched_key_with_all_keyed_configs_returns_nothing():
    # Tier 2 (the reported over-binding) — an unrelated key (e.g. pulled from
    # dex) against an archive whose configs are ALL keyed to OTHER keys must NOT
    # bind to any of them.
    cfgs = [
        {"project_id": "proj-A", "api_key": KEY_A},
        {"project_id": "proj-B", "api_key": KEY_B},
    ]
    sel = gas._select_configs_for_key(KEY_NO_CFG, cfgs)
    assert sel == []


def test_select_unmatched_key_binds_only_unkeyed_configs():
    # Tier 2b — when some configs are keyed (owned by other keys) and some are
    # unkeyed (no proven owner), an unmatched key binds ONLY the unkeyed ones.
    cfgs = [
        {"project_id": "proj-A", "api_key": KEY_A},
        {"project_id": "proj-unowned"},
    ]
    sel = gas._select_configs_for_key(KEY_NO_CFG, cfgs)
    assert [c["project_id"] for c in sel] == ["proj-unowned"]


def test_select_empty_archive_returns_empty():
    assert gas._select_configs_for_key(KEY_A, []) == []


def test_select_returns_copies_not_caller_objects():
    cfgs = [{"project_id": "proj-A", "api_key": KEY_A}]
    sel = gas._select_configs_for_key(KEY_A, cfgs)
    assert sel[0] is not cfgs[0]


def test_google_services_json_preserves_per_client_api_key():
    gs = {
        "project_info": {"project_id": "proj-X"},
        "client": [
            {"client_info": {"mobilesdk_app_id": "1:1:android:a"},
             "api_key": [{"current_key": KEY_A}]},
        ],
    }
    cfgs = gas._extract_firebase_configs_from_google_services_json(
        json.dumps(gs).encode())
    assert len(cfgs) == 1
    assert cfgs[0].get("api_key") == KEY_A


def test_strings_xml_preserves_google_api_key():
    xml = ('<resources>'
           '<string name="project_id">proj-X</string>'
           '<string name="google_api_key">%s</string>'
           '</resources>' % KEY_A)
    cfgs = gas._extract_firebase_configs_from_strings_xml(xml.encode())
    assert len(cfgs) == 1
    assert cfgs[0].get("api_key") == KEY_A


def test_plist_preserves_api_key():
    import plistlib
    info = {"PROJECT_ID": "proj-X", "API_KEY": KEY_A}
    cfgs = gas._extract_firebase_configs_from_plist(plistlib.dumps(info))
    assert len(cfgs) == 1
    assert cfgs[0].get("api_key") == KEY_A


def test_js_config_promotes_api_key():
    body = 'const firebaseConfig = {apiKey: "%s", projectId: "proj-X"};' % KEY_A
    cfgs = gas._extract_firebase_configs_from_js(body)
    assert len(cfgs) == 1
    assert cfgs[0].get("api_key") == KEY_A


def _make_apk_no_config(path, key):
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("classes.dex", ("x " + key + " x").encode())


def _make_apk_with_config(path, key, project_id):
    gs = {
        "project_info": {"project_id": project_id},
        "client": [
            {"client_info": {"mobilesdk_app_id": "1:1:android:a"},
             "api_key": [{"current_key": key}]},
        ],
    }
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("google-services.json", json.dumps(gs))
        z.writestr("classes.dex", ("x " + key + " x").encode())


def test_p1a_config_less_mobile_key_not_bound_to_other_archive(tmp_path):
    """A key from an archive WITHOUT a Firebase config must not inherit a
    different archive's project."""
    a_nocfg = tmp_path / "noCfg.apk"
    b_cfg = tmp_path / "withCfg.apk"
    _make_apk_no_config(str(a_nocfg), KEY_NO_CFG)
    _make_apk_with_config(str(b_cfg), KEY_B, "project-beta")

    gas._begin_discovery_session()
    keys, _sources, key_configs = gas._run_mobile_batch(
        [str(a_nocfg), str(b_cfg)], quiet=True)

    assert KEY_NO_CFG in keys and KEY_B in keys
    # config-less key: either absent from the map or bound to nothing —
    # never bound to project-beta.
    assert key_configs.get(KEY_NO_CFG, []) == []
    assert [c["project_id"] for c in key_configs.get(KEY_B, [])] == ["project-beta"]


def test_p1b_multi_config_archive_binds_each_key_to_its_project(tmp_path):
    """One archive, two Firebase projects (each with its own api_key) — each key
    must bind ONLY to its matching project."""
    multi = tmp_path / "multi.apk"
    gs_a = {"project_info": {"project_id": "proj-A"},
            "client": [{"client_info": {"mobilesdk_app_id": "1:1:android:a"},
                        "api_key": [{"current_key": KEY_A}]}]}
    gs_b = {"project_info": {"project_id": "proj-B"},
            "client": [{"client_info": {"mobilesdk_app_id": "1:2:android:b"},
                        "api_key": [{"current_key": KEY_B}]}]}
    with zipfile.ZipFile(str(multi), "w") as z:
        z.writestr("flavorA/google-services.json", json.dumps(gs_a))
        z.writestr("flavorB/google-services.json", json.dumps(gs_b))
        z.writestr("classes.dex", ("x " + KEY_A + " y " + KEY_B + " z").encode())

    gas._begin_discovery_session()
    keys, _sources, key_configs = gas._run_mobile_batch([str(multi)], quiet=True)

    assert KEY_A in keys and KEY_B in keys
    assert sorted(c["project_id"] for c in key_configs.get(KEY_A, [])) == ["proj-A"]
    assert sorted(c["project_id"] for c in key_configs.get(KEY_B, [])) == ["proj-B"]


def test_p1b_unrelated_dex_key_not_bound_to_keyed_configs(tmp_path):
    """Multi-config archive where every config is keyed to a specific key, plus
    an UNRELATED key embedded only in dex. The dex key matches no config's
    api_key, so it must bind to NOTHING (not to proj-A/proj-B)."""
    multi = tmp_path / "multi_with_dex_key.apk"
    gs_a = {"project_info": {"project_id": "proj-A"},
            "client": [{"client_info": {"mobilesdk_app_id": "1:1:android:a"},
                        "api_key": [{"current_key": KEY_A}]}]}
    gs_b = {"project_info": {"project_id": "proj-B"},
            "client": [{"client_info": {"mobilesdk_app_id": "1:2:android:b"},
                        "api_key": [{"current_key": KEY_B}]}]}
    with zipfile.ZipFile(str(multi), "w") as z:
        z.writestr("flavorA/google-services.json", json.dumps(gs_a))
        z.writestr("flavorB/google-services.json", json.dumps(gs_b))
        # KEY_NO_CFG appears only in dex, matching no config's api_key.
        z.writestr("classes.dex",
                   ("x " + KEY_A + " " + KEY_B + " " + KEY_NO_CFG + " z").encode())

    gas._begin_discovery_session()
    keys, _sources, key_configs = gas._run_mobile_batch([str(multi)], quiet=True)

    assert KEY_NO_CFG in keys
    # The unrelated dex key must NOT inherit either keyed project.
    assert key_configs.get(KEY_NO_CFG, []) == []
    # The keyed keys still bind only to their own project.
    assert sorted(c["project_id"] for c in key_configs.get(KEY_A, [])) == ["proj-A"]
    assert sorted(c["project_id"] for c in key_configs.get(KEY_B, [])) == ["proj-B"]


def test_empty_list_does_not_touch_global_store(monkeypatch):
    """key_firebase_configs=[] must chain ONLY the key's own derivations, never
    the process-global store."""
    gas._begin_discovery_session()
    gas._record_firebase_config({"project_id": "global-leak",
                                 "sources": ["other.apk"]})
    seen = []

    def _spy(probe, apikey, project_id, base_headers, verbose):
        if project_id and not str(project_id).isdigit():
            seen.append(project_id)
        return None

    monkeypatch.setattr(gas, "_execute_probe", _spy)
    with contextlib.redirect_stdout(io.StringIO()):
        with contextlib.suppress(SystemExit, Exception):
            gas.scan_gapis(KEY_A, key_firebase_configs=[], quiet=True, threads=2)
    assert "global-leak" not in seen


def test_auth_read_empty_list_does_not_touch_global_store(monkeypatch):
    """Auth-read runs during Phase 2 before Phase 3 builds its scoped config
    snapshot. It must still honor key_firebase_configs=[] and avoid the
    process-global Firebase config store."""
    gas._begin_discovery_session()
    gas._record_firebase_config({"project_id": "global-leak",
                                 "database_url": "https://global-leak.firebaseio.com",
                                 "storage_bucket": "global-leak.appspot.com",
                                 "sources": ["other.ipa"]})
    gas._set_auth_read_enabled(True)
    gas._set_auth_read_scope_ok(True)
    seen_projects = []
    seen_dbs = []
    seen_buckets = []

    monkeypatch.setattr(gas, "_authenticated_firestore_read",
                        lambda pid, *a, **k: seen_projects.append(pid))
    monkeypatch.setattr(gas, "_authenticated_rtdb_read",
                        lambda db, *a, **k: seen_dbs.append(db))
    monkeypatch.setattr(gas, "_authenticated_storage_list",
                        lambda bucket, *a, **k: seen_buckets.append(bucket))

    gas._set_auth_read_firebase_configs([])
    gas._run_authenticated_read_chain(KEY_A, "tok", "lid")
    gas._set_auth_read_firebase_configs(None)
    gas._set_auth_read_enabled(False)

    assert "global-leak" not in seen_projects
    assert "https://global-leak.firebaseio.com" not in seen_dbs
    assert "global-leak.appspot.com" not in seen_buckets


def test_auth_read_uses_only_key_scoped_configs(monkeypatch):
    gas._begin_discovery_session()
    gas._record_firebase_config({"project_id": "global-leak",
                                 "database_url": "https://global-leak.firebaseio.com",
                                 "storage_bucket": "global-leak.appspot.com",
                                 "sources": ["other.ipa"]})
    gas._set_auth_read_enabled(True)
    gas._set_auth_read_scope_ok(True)
    seen_projects = []
    seen_dbs = []
    seen_buckets = []

    monkeypatch.setattr(gas, "_authenticated_firestore_read",
                        lambda pid, *a, **k: seen_projects.append(pid))
    monkeypatch.setattr(gas, "_authenticated_rtdb_read",
                        lambda db, *a, **k: seen_dbs.append(db))
    monkeypatch.setattr(gas, "_authenticated_storage_list",
                        lambda bucket, *a, **k: seen_buckets.append(bucket))

    scoped = [{
        "project_id": "this-key",
        "database_url": "https://this-key.firebaseio.com",
        "storage_bucket": "this-key.appspot.com",
    }]
    gas._set_auth_read_firebase_configs(scoped)
    gas._run_authenticated_read_chain(KEY_A, "tok", "lid")
    gas._set_auth_read_firebase_configs(None)
    gas._set_auth_read_enabled(False)

    assert "this-key" in seen_projects
    assert "global-leak" not in seen_projects
    assert "https://this-key.firebaseio.com" in seen_dbs
    assert "https://global-leak.firebaseio.com" not in seen_dbs
    assert "this-key.appspot.com" in seen_buckets
    assert "global-leak.appspot.com" not in seen_buckets


def test_scan_gapis_scopes_auth_read_configs_during_signup(monkeypatch):
    """scan_gapis must install key_firebase_configs before Phase 2. The
    signUp check runs in Phase 2, so this is the regression that leaked prior
    mobile archive projects into auth-read."""
    gas._begin_discovery_session()
    gas._record_firebase_config({"project_id": "global-leak",
                                 "database_url": "https://global-leak.firebaseio.com",
                                 "storage_bucket": "global-leak.appspot.com",
                                 "sources": ["other.ipa"]})
    gas._set_auth_read_enabled(True)
    gas._set_auth_read_scope_ok(True)
    seen_projects = []
    seen_dbs = []
    seen_buckets = []

    monkeypatch.setattr(gas, "_authenticated_firestore_read",
                        lambda pid, *a, **k: seen_projects.append(pid))
    monkeypatch.setattr(gas, "_authenticated_rtdb_read",
                        lambda db, *a, **k: seen_dbs.append(db))
    monkeypatch.setattr(gas, "_authenticated_storage_list",
                        lambda bucket, *a, **k: seen_buckets.append(bucket))

    def _fake_execute(probe, apikey, project_id, base_headers, verbose):
        if probe[0] == "Identity Toolkit signUp anon (account creation + auto-cleanup)":
            gas._run_authenticated_read_chain(apikey, "tok", "lid")
        return None

    scoped = [{
        "project_id": "this-key",
        "database_url": "https://this-key.firebaseio.com",
        "storage_bucket": "this-key.appspot.com",
    }]
    monkeypatch.setattr(gas, "_execute_probe", _fake_execute)
    with contextlib.redirect_stdout(io.StringIO()):
        with contextlib.suppress(SystemExit, Exception):
            gas.scan_gapis(KEY_A, key_firebase_configs=scoped,
                           quiet=True, threads=1)
    gas._set_auth_read_enabled(False)
    gas._set_auth_read_firebase_configs(None)

    assert "this-key" in seen_projects
    assert "global-leak" not in seen_projects
    assert "https://this-key.firebaseio.com" in seen_dbs
    assert "https://global-leak.firebaseio.com" not in seen_dbs
    assert "this-key.appspot.com" in seen_buckets
    assert "global-leak.appspot.com" not in seen_buckets


def test_none_uses_global_store(monkeypatch):
    """key_firebase_configs=None keeps the legacy web/url/scope behavior: the
    global store IS consulted (multi-source web fan-out for one project)."""
    gas._begin_discovery_session()
    gas._record_firebase_config({"project_id": "webproj",
                                 "sources": ["https://x"]})
    seen = []

    def _spy(probe, apikey, project_id, base_headers, verbose):
        if project_id and not str(project_id).isdigit():
            seen.append(project_id)
        return None

    monkeypatch.setattr(gas, "_execute_probe", _spy)
    with contextlib.redirect_stdout(io.StringIO()):
        with contextlib.suppress(SystemExit, Exception):
            gas.scan_gapis(KEY_A, key_firebase_configs=None, quiet=True, threads=2)
    assert "webproj" in seen
