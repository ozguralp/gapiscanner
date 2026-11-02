"""Architecture contract for the single public, sectioned scanner engine."""

import ast
import inspect
from pathlib import Path

import google_api_scanner as scanner


ROOT = Path(__file__).resolve().parents[2]
WRAPPER = ROOT / "google_api_scanner.py"
FORBIDDEN_SHARED_FUNCTIONS = {
    "scan_gapis",
    "_execute_probe",
    "_classify_error",
    "_run_bundle",
    "_which",
    "_crawl_with_python",
    "discover_keys_from_scope",
    "dns_enum",
}
FORBIDDEN_SHARED_ASSIGNMENTS = {
    "ALL_PROBES",
    "ABUSE_CLASS_OVERRIDES",
    "_PROBE_IMPACT_DEFAULTS",
}


def _top_level_assignment_names(tree):
    names = set()
    for node in tree.body:
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        else:
            continue
        names.update(target.id for target in targets if isinstance(target, ast.Name))
    return names


def test_frontend_wrapper_is_thin_and_contains_no_scanner_engine():
    source = WRAPPER.read_text(encoding="utf-8")
    tree = ast.parse(source)
    assert len(source.splitlines()) < 100
    assert not (FORBIDDEN_SHARED_FUNCTIONS & {
        node.name for node in tree.body if isinstance(node, ast.FunctionDef)
    })
    assert not (FORBIDDEN_SHARED_ASSIGNMENTS & _top_level_assignment_names(tree))


def test_scan_engine_code_comes_from_the_public_core():
    code_path = Path(scanner.scan_gapis.__code__.co_filename).resolve()
    engine_path = Path(scanner._ENGINE_PATH).resolve()
    section_paths = {
        Path(path).resolve() for path in scanner._ENGINE_SECTION_PATHS
    }
    assert code_path in section_paths
    assert code_path.name == "scan.py"
    assert code_path.parent.name == "_engine_sections"
    assert code_path.parent.parent == engine_path.parent
    assert engine_path.name == "engine.py"
    assert engine_path.parent.name == "gapiscanner_core"


def test_public_engine_bootstrap_and_sections_stay_reviewable():
    engine_path = Path(scanner._ENGINE_PATH).resolve()
    section_paths = [
        Path(path).resolve() for path in scanner._ENGINE_SECTION_PATHS
    ]
    assert len(engine_path.read_text(encoding="utf-8").splitlines()) < 120
    assert tuple(path.name for path in section_paths) == (
        "runtime.py",
        "firebase_identity.py",
        "probe_catalog.py",
        "classification.py",
        "execution.py",
        "persistence.py",
        "mobile.py",
        "discovery.py",
        "scan.py",
        "cli.py",
    )
    section_sources = [path.read_text(encoding="utf-8") for path in section_paths]
    assert max(len(source.splitlines()) for source in section_sources) < 2_000
    assert scanner._engine_source_text() == "".join(section_sources)


def test_engine_executes_in_frontend_namespace_for_monkeypatch_compatibility(monkeypatch):
    assert scanner.scan_gapis.__globals__ is scanner.__dict__
    monkeypatch.setattr(scanner, "_INSECURE_TLS", True)
    assert scanner.scan_gapis.__globals__["_INSECURE_TLS"] is True


def test_frontend_filesystem_root_is_not_the_public_package_root():
    assert Path(scanner._FRONTEND_ROOT).resolve() == ROOT


def test_private_frontend_does_not_vendor_shared_core():
    if getattr(scanner, "_OVERLAY_FILENAME", None) is not None:
        assert not (ROOT / "gapiscanner_core").exists()


def test_platform_overlay_contains_only_local_operations():
    overlay_name = getattr(scanner, "_OVERLAY_FILENAME", None)
    if overlay_name is None:
        return
    overlay = ROOT / overlay_name
    tree = ast.parse(overlay.read_text(encoding="utf-8"))
    functions = {
        node.name for node in tree.body if isinstance(node, ast.FunctionDef)
    }
    assert not (FORBIDDEN_SHARED_FUNCTIONS & functions)
    assert not (FORBIDDEN_SHARED_ASSIGNMENTS & _top_level_assignment_names(tree))


def test_frontend_functions_come_from_its_declared_source_files():
    allowed_paths = {Path(path).resolve() for path in scanner._ENGINE_SECTION_PATHS}
    allowed_paths.update({Path(scanner._ENGINE_PATH).resolve(), WRAPPER.resolve()})
    overlay_name = getattr(scanner, "_OVERLAY_FILENAME", None)
    if overlay_name:
        allowed_paths.add((ROOT / overlay_name).resolve())
    for function in vars(scanner).values():
        if inspect.isfunction(function) and function.__globals__ is scanner.__dict__:
            assert Path(function.__code__.co_filename).resolve() in allowed_paths
