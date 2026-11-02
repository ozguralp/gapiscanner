from __future__ import annotations

import json

import pytest

import google_api_scanner as gas  # noqa: E402 - resolves installed/sibling core

from gapiscanner_core import (
    AUTHORIZATION_IAM_LOCATIONS,
    AUTHORIZATION_PROBE_NAME,
    build_authorization_probes,
    build_url_fetch_plan,
    check_vertex_authorization_count_tokens,
    known_project_from_history,
    merge_mobile_restrictions,
    mobile_restriction_contexts,
)


class _Response:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload
        self.text = json.dumps(payload)

    def json(self):
        return self._payload


@pytest.mark.unit
def test_url_plan_is_deterministic_and_unlimited_by_default():
    urls = {
        "https://example.com/z/page",
        "https://cdn.example.net/bundle.js",
        "https://example.com/app.js",
        "https://example.com/data.json",
        "https://example.com/image.png",
    }
    first = build_url_fetch_plan(urls, seed_url="https://example.com/")
    second = build_url_fetch_plan(reversed(sorted(urls)), seed_url="https://example.com/")

    assert first == second
    assert first.pending == ()
    assert first.selected == (
        "https://example.com/app.js",
        "https://cdn.example.net/bundle.js",
        "https://example.com/data.json",
        "https://example.com/z/page",
    )
    assert first.skipped_binary == ("https://example.com/image.png",)


@pytest.mark.unit
def test_explicit_url_budget_keeps_auditable_pending_queue():
    plan = build_url_fetch_plan(
        {
            "https://example.com/c.js",
            "https://example.com/a.js",
            "https://example.com/b.js",
        },
        seed_url="https://example.com/",
        budget=2,
    )

    assert plan.selected == (
        "https://example.com/a.js",
        "https://example.com/b.js",
    )
    assert plan.pending == ("https://example.com/c.js",)


@pytest.mark.unit
def test_scanner_fetches_more_than_legacy_200_cap(monkeypatch):
    called = set()

    class _FetchResponse:
        text = ""
        status_code = 200
        headers = {"Content-Type": "application/javascript"}

    def fake_get(url, **kwargs):
        called.add(url)
        return _FetchResponse()

    monkeypatch.setattr(gas.requests, "get", fake_get)
    urls = {"https://example.com/%03d.js" % index for index in range(205)}
    gas._fetch_and_extract_keys(urls, threads=4)

    assert called == urls


@pytest.mark.unit
def test_mobile_kb_retains_every_platform_context_and_known_project():
    ios = "mobile:ios:com.example.ios"
    android = "mobile:android:com.example.android:" + "AA:" * 19 + "AA"
    merged = merge_mobile_restrictions([ios], android)

    assert merged == sorted([android, ios])
    assert {(mode, value) for mode, value, _ in mobile_restriction_contexts(merged)} == {
        ("ios", "com.example.ios"),
        ("android", android.split("mobile:android:", 1)[1]),
    }
    assert known_project_from_history({
        "scan_history": [
            {"project_id": "old-project"},
            {"project_id": "new-project"},
        ]
    }) == "new-project"


@pytest.mark.unit
def test_authorization_probe_requires_real_vertex_operation_shape():
    vulnerable, note, overrides = check_vertex_authorization_count_tokens(
        _Response(200, {"totalTokens": 1})
    )
    assert vulnerable is True
    assert note == "authorization_key_confirmed"
    assert overrides["severity"] == "HIGH"

    assert check_vertex_authorization_count_tokens(
        _Response(200, {})
    ) == (False, None)
    assert check_vertex_authorization_count_tokens(
        _Response(403, {"error": {"status": "PERMISSION_DENIED"}})
    ) == (False, None)

    probes = build_authorization_probes()
    assert len(probes) == 4
    probe = probes[0]
    assert probe[0] == AUTHORIZATION_PROBE_NAME
    assert probe[1] == "authorization"
    assert probe[7]["requires_derived_project"] is True

    datasets_probe = next(p for p in probes if "datasets list" in p[0])
    vulnerable, note, overrides = datasets_probe[5](
        _Response(200, {"datasets": []})
    )
    assert vulnerable is True
    assert note == "authorization_iam_confirmed:datasets:count=0"
    assert overrides["severity"] == "HIGH"
    assert datasets_probe[5](_Response(200, {})) == (False, None)


@pytest.mark.unit
def test_authorization_region_expansion_is_evidence_gated():
    """No blind regional fan-out after a clean authorization replay."""
    assert AUTHORIZATION_IAM_LOCATIONS == ("us-central1",)
    probes = build_authorization_probes()
    regional = [probe for probe in probes if "authorization_region" in probe[7]]
    assert len(regional) == 3
    assert {probe[7]["authorization_region"] for probe in regional} == {
        "us-central1",
    }
    assert {probe[3].split("/locations/", 1)[1].split("/", 1)[0]
            for probe in regional} == {"us-central1"}
    assert not any("/locations?" in probe[3] for probe in probes)


@pytest.mark.unit
def test_authorization_probe_is_opt_in_project_gated_and_confirmed(monkeypatch):
    probe = build_authorization_probes()[0]
    called = []

    class _VertexResponse(_Response):
        headers = {"Content-Type": "application/json"}
        content = b'{"totalTokens":1}'

    def fake_post(url, **kwargs):
        called.append(url)
        return _VertexResponse(200, {"totalTokens": 1})

    def fake_get(url, **kwargs):
        called.append(url)
        return _VertexResponse(200, {"datasets": []})

    monkeypatch.setattr(gas.requests, "post", fake_post)
    monkeypatch.setattr(gas.requests, "get", fake_get)
    assert gas._execute_probe(
        probe, "AIza" + "A" * 35, None, {}, verbose=False,
    ) is None
    assert called == []

    result = gas._execute_probe(
        probe, "AIza" + "A" * 35, "owned-project", {}, verbose=False,
    )
    assert result["vulnerable"] is True
    assert result["severity"] == "HIGH"
    assert result["confirmation"] == "confirmed_data"
    assert result["manual_note"] == "authorization_key_confirmed"
    assert called and "/projects/owned-project/" in called[0]

    datasets_probe = next(
        p for p in build_authorization_probes() if "datasets list" in p[0]
    )
    iam_result = gas._execute_probe(
        datasets_probe, "AIza" + "A" * 35, "owned-project", {}, verbose=False,
    )
    assert iam_result["vulnerable"] is True
    assert iam_result["severity"] == "HIGH"
    assert iam_result["manual_note"] == (
        "authorization_iam_confirmed:datasets:count=0"
    )
    assert all("aiplatform.googleapis.com" not in row[3]
               for row in gas.ALL_PROBES)


@pytest.mark.unit
def test_authorization_only_executes_only_authorization_probes(monkeypatch):
    seen = []

    def capture(probe, apikey, project_id, base_headers, verbose=False):
        seen.append((probe[0], probe[1], project_id))
        return None

    monkeypatch.setattr(gas, "_execute_probe", capture)
    monkeypatch.setattr(gas, "FIREBASE_CHAIN_PROBES", [
        ("must-not-run", "high", "GET", "https://example.invalid", None,
         lambda response: (False, None), "test")
    ])

    gas.scan_gapis(
        "AIza" + "A" * 35,
        authorization_only=True,
        project_id="owned-project",
        quiet=True,
        skip_jsapi=True,
        threads=1,
    )

    assert len(seen) == 4
    assert {category for _, category, _ in seen} == {"authorization"}
    assert {project for _, _, project in seen} == {"owned-project"}
    assert all(name != "must-not-run" for name, _, _ in seen)


@pytest.mark.unit
def test_empty_rescan_kb_indexes_is_usage_error(monkeypatch, capsys):
    monkeypatch.setattr(
        gas.sys, "argv",
        ["google_api_scanner.py", "--rescan-kb", "--rescan-kb-indexes", ""],
    )
    with pytest.raises(SystemExit) as exc:
        gas.main()
    assert exc.value.code == 2
    assert "requires at least one integer" in capsys.readouterr().out


@pytest.mark.unit
def test_authorization_only_replays_only_matching_restriction_modes():
    assert gas._authorization_only_replay_modes({}) is None
    assert gas._authorization_only_replay_modes({
        "error_class_histogram": {"API_KEY_UNSUPPORTED": 4},
    }) == set()
    assert gas._authorization_only_replay_modes({
        "error_class_histogram": {
            "REFERRER_BLOCKED": 3,
            "ANDROID_BLOCKED": 1,
            "PERMISSION_DENIED": 2,
        },
    }) == {"referer", "android"}
