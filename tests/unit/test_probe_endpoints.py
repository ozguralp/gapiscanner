"""Tests for probe endpoints."""
from __future__ import annotations

import json

import pytest

import google_api_scanner as gas


def _probe(name: str):
    for probe in gas.ALL_PROBES:
        if probe[0] == name:
            return probe
    raise AssertionError(f"probe not found: {name}")


@pytest.mark.unit
@pytest.mark.parametrize("name,method,url_fragment", [
    ("Abusive Experience Report", "GET", "/v1/violatingSites?"),
    ("Ad Experience Report", "GET", "/v1/violatingSites?"),
    ("Civic Info", "GET", "/civicinfo/v2/elections?"),
    ("Web Risk", "GET", "/v1/uris:search?uri=https%3A%2F%2Fwww.google.com%2F"),
])
def test_low_utility_probes_use_live_validated_routes(name, method, url_fragment):
    probe = _probe(name)
    assert probe[2] == method
    assert url_fragment in probe[3]


@pytest.mark.unit
def test_amp_batch_get_uses_post_with_valid_json_body():
    probe = _probe("Accelerated Mobile Page URL")
    assert probe[2] == "POST"
    assert probe[3] == (
        "https://acceleratedmobilepageurl.googleapis.com/v1/"
        "ampUrls:batchGet?key={key}"
    )
    body = json.loads(probe[4])
    assert body["urls"] == ["https://www.google.com/"]
    assert body["lookupStrategy"] == "IN_INDEX_DOC"


@pytest.mark.unit
def test_area_insights_uses_compute_insights_post_body():
    probe = _probe("Area Insights")
    assert probe[2] == "POST"
    assert probe[3] == "https://areainsights.googleapis.com/v1:computeInsights?key={key}"
    body = json.loads(probe[4])
    assert body["insights"] == ["INSIGHT_COUNT"]
    assert body["filter"]["locationFilter"]["circle"]["radius"] == 100
    assert body["filter"]["typeFilter"]["includedTypes"] == ["restaurant"]


@pytest.mark.unit
@pytest.mark.parametrize("name,url_fragment,check_fn", [
    ("Video Intelligence", "/v1/projects/{project}/locations/global/operations?", gas._check_non_empty_operations_list),
])
def test_high_project_probes_use_current_resource_paths(name, url_fragment, check_fn):
    probe = _probe(name)
    assert probe[2] == "GET"
    assert url_fragment in probe[3]
    assert probe[5] is check_fn


@pytest.mark.unit
@pytest.mark.parametrize("name", [
    "Cloud Trace", "FCM Data", "Firebase App Check", "Firebase App Distribution",
    "IAP", "Runtime Config", "Discovery Engine",
])
def test_api_key_unsupported_probes_removed(name):
    """Keep endpoints that reject API-key authentication out of the registry."""
    assert name not in {p[0] for p in gas.ALL_PROBES}


@pytest.mark.unit
def test_gemini_replaces_dead_corpora_documents_wildcard():
    names = {p[0] for p in gas.ALL_PROBES}
    assert "Gemini Corpora documents (list across all)" not in names
    file_search = _probe("Gemini File Search Stores")
    generated = _probe("Gemini Generated Files")
    assert "/v1beta/fileSearchStores?" in file_search[3]
    assert "/v1beta/generatedFiles?" in generated[3]
    assert file_search[5] is gas._check_non_empty_list
    assert generated[5] is gas._check_non_empty_list


@pytest.mark.unit
def test_gemini_operations_uses_model_operations_parent():
    probe = _probe("Gemini operations list")
    assert "/v1beta/models/-/operations?" in probe[3]
    assert probe[5] is gas._check_non_empty_operations_list
