from __future__ import annotations

import sys
from pathlib import Path

from dataclasses import dataclass
from types import SimpleNamespace

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import google_api_scanner as gas


@dataclass
class WebAsset:
    value: str
    asset_type: str
    bounty_eligible: bool = True


def test_wildcard_omits_dns_service_labels_from_web_seeds(tmp_path, monkeypatch):
    bundle = SimpleNamespace(
        program="wildcard-web-seed-filter",
        platform="test",
        web_assets=[WebAsset(value="*.example.com", asset_type="wildcard")],
        mobile_apps=[], raw_source={}, api_assets=[], executable_assets=[],
        oos=[],
    )
    monkeypatch.setattr(
        gas,
        "dns_enum",
        lambda *args, **kwargs: ["_dmarc.example.com", "api.example.com", "foo._tcp.example.com"],
    )

    gas._run_bundle(bundle, dry_run=True, quiet=True, output_dir=str(tmp_path))

    target_files = list(tmp_path.rglob(gas._BUNDLE_ARTIFACT_PREFIX + "_targets.txt"))
    assert len(target_files) == 1
    targets = target_files[0].read_text().splitlines()
    assert targets == ["https://api.example.com/"]
