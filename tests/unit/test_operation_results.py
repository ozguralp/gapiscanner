"""Tests for operation results."""
from __future__ import annotations

import pytest

import google_api_scanner as gas

TRANS_HUB = "Translation Hub Operations"
SVC_MGMT = "Service Management Operations"


def _probe(name):
    matches = [p for p in gas.ALL_PROBES if p[0] == name]
    assert len(matches) == 1, f"expected exactly one {name!r}; got {len(matches)}"
    return matches[0]


class TestOperationsProbesExist:
    @pytest.mark.unit
    @pytest.mark.parametrize("name", [TRANS_HUB, SVC_MGMT])
    def test_probe_present(self, name):
        assert name in {p[0] for p in gas.ALL_PROBES}

    @pytest.mark.unit
    @pytest.mark.parametrize("name", [TRANS_HUB, SVC_MGMT])
    def test_probe_is_high_get_readonly(self, name):
        p = _probe(name)
        assert p[1] == "high"
        assert p[2] == "GET"
        assert p[4] is None  # body — read-only, no payload

    @pytest.mark.unit
    @pytest.mark.parametrize("name", [TRANS_HUB, SVC_MGMT])
    def test_probe_uses_non_empty_operations_check(self, name):
        p = _probe(name)
        assert p[5] is gas._check_non_empty_operations_list


class TestUrls:
    @pytest.mark.unit
    def test_translation_hub_url(self):
        url = _probe(TRANS_HUB)[3]
        assert url == (
            "https://translationhub.googleapis.com/v1main/projects/{project}"
            "/locations/global/operations?pageSize=1000&key={key}")

    @pytest.mark.unit
    def test_service_management_url_is_filtered(self):
        url = _probe(SVC_MGMT)[3]
        # MUST carry the service-name filter...
        assert "filter=serviceName%3Dservicemanagement.googleapis.com" in url
        # ...and MUST NOT be the bare unfiltered operations endpoint.
        assert url != (
            "https://servicemanagement.googleapis.com/v1/operations?key={key}")
        assert url == (
            "https://servicemanagement.googleapis.com/v1/operations"
            "?filter=serviceName%3Dservicemanagement.googleapis.com"
            "&pageSize=100&key={key}")


class TestReadOnlyContract:
    @pytest.mark.unit
    @pytest.mark.parametrize("name", [TRANS_HUB, SVC_MGMT])
    def test_no_write_or_destructive_classification(self, name):
        # Neither probe is destructive / cost-amp; not in any opt-in
        # dangerous set; impact text is a read-only data-leak claim.
        p = _probe(name)
        assert p[1] not in ("destructive", "cost-amp")
        assert name not in getattr(gas, "POTENTIAL_PROBES", set())
        assert "operations" in (p[6] or "").lower()


class TestRegistryWideGuardStillHolds:
    @pytest.mark.unit
    def test_no_operations_endpoint_uses_raw_200(self):
        """Registry-wide: any probe whose URL contains `operations?` must
        use `_check_non_empty_operations_list`, never a raw `"200"` DSL.
        Covers the two new probes too."""
        offenders = []
        for p in gas.ALL_PROBES:
            url = p[3]
            if "/operations?" not in url and not url.endswith("/operations"):
                continue
            if p[5] is gas._check_non_empty_operations_list:
                continue
            offenders.append((p[0], url, p[5]))
        assert offenders == [], (
            f"operations-list probes must use the non-empty check; "
            f"offenders: {offenders!r}")
