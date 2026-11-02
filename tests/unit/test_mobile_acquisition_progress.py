"""Mobile acquisition progress regression tests."""
from __future__ import annotations

import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import google_api_scanner as gas  # noqa: E402


@dataclass
class _MobileApp:
    platform: str
    identifier: str
    local_path: str | None = None
    bounty_eligible: bool = True


@dataclass
class _Bundle:
    program: str
    platform: str
    web_assets: list = field(default_factory=list)
    api_assets: list = field(default_factory=list)
    executable_assets: list = field(default_factory=list)
    mobile_apps: list = field(default_factory=list)
    oos: list = field(default_factory=list)
    raw_source: dict = field(default_factory=dict)


@pytest.mark.unit
def test_failed_android_acquisition_not_marked_complete(monkeypatch):
    """Resume must retry apps whose APK/IPA archive was never acquired."""
    bundle = _Bundle(
        program="mobile-acquisition-test",
        platform="example",
        mobile_apps=[
            _MobileApp(platform="android", identifier="com.missing.app"),
        ],
    )
    saved_mobile_sets = []

    monkeypatch.setattr(gas, "_download_android_apk", lambda *a, **k: None)
    monkeypatch.setattr(gas, "_progress_load", lambda *a, **k: {})

    def _fake_progress_save(scope_dir, completed_seeds, scanned_keys,
                            mobile_completed, **kwargs):
        saved_mobile_sets.append(set(mobile_completed))

    monkeypatch.setattr(gas, "_progress_save", _fake_progress_save)

    with tempfile.TemporaryDirectory() as td:
        keys = gas._run_bundle(
            bundle, dry_run=False, verbose=False, quiet=True,
            output_dir=td, scan_callback=lambda *_: None,
            cache_dir=None, exclude_third_party=False, resume=False,
            ts="20260601_000000", platform="example",
            mobile_only=True,
        )

    assert keys == set()
    assert all("mobile:android:com.missing.app" not in completed
               for completed in saved_mobile_sets)
