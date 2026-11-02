"""Shared, importable scanner-core primitives.

Contains reusable scanner functions for the command-line tool and Python callers.
"""

from .authorization import (
    AUTHORIZATION_IAM_LOCATIONS,
    AUTHORIZATION_PROBE_NAME,
    build_authorization_probes,
    check_vertex_authorization_count_tokens,
)
from .mobile_kb import (
    known_project_from_history,
    merge_mobile_restrictions,
    mobile_restriction_contexts,
    mobile_restrictions_from_kb_entry,
)
from .url_budget import (
    URLFetchPlan,
    build_url_fetch_plan,
    load_completed_manifest_urls,
    load_url_queue_completed_urls,
    write_url_queue_state,
)

__all__ = [
    "AUTHORIZATION_IAM_LOCATIONS",
    "AUTHORIZATION_PROBE_NAME",
    "URLFetchPlan",
    "build_authorization_probes",
    "build_url_fetch_plan",
    "check_vertex_authorization_count_tokens",
    "known_project_from_history",
    "load_completed_manifest_urls",
    "load_url_queue_completed_urls",
    "merge_mobile_restrictions",
    "mobile_restriction_contexts",
    "mobile_restrictions_from_kb_entry",
    "write_url_queue_state",
]
