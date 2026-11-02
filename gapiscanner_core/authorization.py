"""Opt-in Google authorization-key capability probe definitions."""

from __future__ import annotations

import json
from typing import Callable, List, Tuple


AUTHORIZATION_PROBE_NAME = "Authorization key confirmed (Vertex AI countTokens)"


AUTHORIZATION_IAM_LOCATIONS = ("us-central1",)


def check_vertex_authorization_count_tokens(response):
    """Confirm an actual Vertex operation, not generic AIza acceptance.

    A standard API key that reaches only the API-key gate is not enough.  The
    verdict becomes true solely for a well-formed countTokens response.
    """
    if response.status_code != 200:
        return False, None
    try:
        payload = response.json()
    except Exception:
        try:
            payload = json.loads(response.text or "")
        except (TypeError, ValueError):
            return False, None
    total_tokens = payload.get("totalTokens") if isinstance(payload, dict) else None
    if isinstance(total_tokens, bool) or not isinstance(total_tokens, int):
        return False, None
    if total_tokens < 0 or payload.get("error"):
        return False, None
    return True, "authorization_key_confirmed", {
        "impact_type": "account",
        "confirmation": "confirmed_data",
        "data_sensitivity": "metadata",
        "severity": "HIGH",
    }


def _check_vertex_iam_list(field: str) -> Callable:
    """Require a well-formed response from an IAM-protected list method.

    Vertex list methods require an aiplatform.*.list IAM permission.  A 200
    containing the documented collection field therefore proves more than
    generic API-key acceptance, even when the collection is currently empty.
    """
    def check(response):
        if response.status_code != 200:
            return False, None
        try:
            payload = response.json()
        except Exception:
            try:
                payload = json.loads(response.text or "")
            except (TypeError, ValueError):
                return False, None
        rows = payload.get(field) if isinstance(payload, dict) else None
        if (not isinstance(rows, list) or payload.get("error")
                or any(not isinstance(row, dict)
                       or not isinstance(row.get("name"), str) or not row["name"]
                       for row in rows)):
            return False, None
        return True, "authorization_iam_confirmed:%s:count=%d" % (
            field, len(rows)), {
                "impact_type": "account",
                "confirmation": "confirmed_data",
                "data_sensitivity": "customer_data" if rows else "metadata",
                "severity": "HIGH",
            }

    check.__name__ = "check_vertex_authorization_%s" % field
    return check


_check_vertex_authorization_models = _check_vertex_iam_list("models")
_check_vertex_authorization_datasets = _check_vertex_iam_list("datasets")
_check_vertex_authorization_endpoints = _check_vertex_iam_list("endpoints")


def build_authorization_probes() -> List[Tuple[object, ...]]:
    """Return safe, read-only probes that require a real/derived project."""
    common_extra = {
        "requires_derived_project": True,
        "authorization_key_probe": True,
    }
    probes = [(
        AUTHORIZATION_PROBE_NAME,
        "authorization",
        "POST",
        "https://aiplatform.googleapis.com/v1/projects/{project}/locations/"
        "global/publishers/google/models/gemini-3.8-flash:countTokens?key={key}",
        '{"contents":[{"role":"user","parts":[{"text":"test"}]}]}',
        check_vertex_authorization_count_tokens,
        "The exposed AIza key completed a Vertex AI operation as an "
        "authorization-capable credential; other IAM permissions remain untested.",
        {
            "content_type": "application/json",
            **common_extra,
        },
    )]

    iam_lists = (
        ("models", _check_vertex_authorization_models,
         "aiplatform.models.list", "model"),
        ("datasets", _check_vertex_authorization_datasets,
         "aiplatform.datasets.list", "dataset"),
        ("endpoints", _check_vertex_authorization_endpoints,
         "aiplatform.endpoints.list", "endpoint"),
    )
    for location in AUTHORIZATION_IAM_LOCATIONS:
        for resource, check, permission, metadata_name in iam_lists:
            probes.append((
                "Authorization key IAM (Vertex AI %s list, %s)" % (
                    resource, location),
                "authorization",
                "GET",
                "https://aiplatform.googleapis.com/v1/projects/{project}/locations/"
                "%s/%s?pageSize=1&readMask=name,displayName&key={key}" % (
                    location, resource),
                None,
                check,
                "The AIza key exercised %s as its bound service account; a "
                "non-empty response also exposes %s metadata." % (
                    permission, metadata_name),
                {
                    **common_extra,
                    "authorization_region": location,
                },
            ))
    return probes
