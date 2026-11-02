"""
Importable gapiscanner scanner engine.

Tests a Google API key for unauthorized access across Gemini, Cloud AI,
GCP Infrastructure, Google Maps Platform, and utility APIs.

All endpoints are hardcoded — no dynamic discovery.
"""
import requests
import warnings
import json
import math
import sys
import os
import re
import csv
import hashlib
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from threading import Lock
from urllib.parse import urlparse

# Filesystem behavior is rooted at the active frontend, not this package.
# Embedding applications can set this before installing their operation layer.
_FRONTEND_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

from gapiscanner_core import (
    URLFetchPlan,
    build_authorization_probes,
    build_url_fetch_plan,
    known_project_from_history,
    load_completed_manifest_urls,
    load_url_queue_completed_urls,
    merge_mobile_restrictions,
    mobile_restriction_contexts,
    mobile_restrictions_from_kb_entry,
    write_url_queue_state,
)


# Engine layout: semantic source sections execute in this module's namespace.
# This preserves the historical frontend monkeypatch and isolated mutable-state
# contract while keeping each responsibility in a reviewable file.
_ENGINE_SOURCE_PATH = os.path.abspath(str(globals().get("_ENGINE_PATH", __file__)))
_ENGINE_SECTION_ROOT = os.path.join(
    os.path.dirname(_ENGINE_SOURCE_PATH), "_engine_sections"
)
_ENGINE_SECTION_NAMES = (
    'runtime.py',
    'firebase_identity.py',
    'probe_catalog.py',
    'classification.py',
    'execution.py',
    'persistence.py',
    'mobile.py',
    'discovery.py',
    'scan.py',
    'cli.py',
)
_ENGINE_SECTION_PATHS = tuple(
    os.path.join(_ENGINE_SECTION_ROOT, name) for name in _ENGINE_SECTION_NAMES
)


def _engine_source_text():
    """Return the complete scanner implementation source for invariants/tests."""
    chunks = []
    for path in _ENGINE_SECTION_PATHS:
        with open(path, "r", encoding="utf-8") as handle:
            chunks.append(handle.read())
    return "".join(chunks)


for _engine_section_path in _ENGINE_SECTION_PATHS:
    with open(_engine_section_path, "rb") as _engine_section_handle:
        _engine_section_source = _engine_section_handle.read()
    exec(
        compile(_engine_section_source, _engine_section_path, "exec"),
        globals(),
    )

del _engine_section_handle
del _engine_section_path
del _engine_section_source
