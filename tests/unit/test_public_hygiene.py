"""Regression coverage for standalone discovery and neutral output naming."""
import sys
from types import SimpleNamespace

import google_api_scanner as scanner


def test_dns_enumeration_uses_bundled_clients_without_changing_import_path(monkeypatch):
    original_path = list(sys.path)

    sources = ("subfinder", "crtsh", "hackertarget", "rapiddns", "wayback", "otx")
    for source in sources:
        monkeypatch.setattr(scanner, "_dns_enum_" + source,
                            lambda *args, **kwargs: {"api.example.com"})
    monkeypatch.setattr(scanner, "_dns_enum_certspotter",
                        lambda *args, **kwargs: {"fallback.example.com"})
    assert scanner.dns_enum("example.com", quiet=True) == ["api.example.com"]
    assert sys.path == original_path


def test_bundle_output_respects_frontend_filename_prefix(tmp_path, monkeypatch):
    monkeypatch.setattr(scanner, "_BUNDLE_ARTIFACT_PREFIX", "custom")
    bundle = SimpleNamespace(program="sample", platform="test", web_assets=[],
                             mobile_apps=[], api_assets=[], executable_assets=[],
                             raw_source="synthetic", oos=[], extra={}, warnings=[])
    scanner._run_bundle(bundle, dry_run=True, quiet=True, output_dir=str(tmp_path))
    paths = list(tmp_path.rglob("custom_targets.txt"))
    assert len(paths) == 1
    assert paths[0].read_text() == ""
