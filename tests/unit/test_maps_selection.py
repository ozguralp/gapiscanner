"""Maps are an optional addition to the Google API scan."""
import sys

import pytest

import google_api_scanner as scanner


@pytest.mark.parametrize('include_maps', [False, True])
def test_maps_option_adds_to_default_checks(monkeypatch, include_maps):
    executed = []
    monkeypatch.setattr(scanner, '_execute_probe', lambda probe, *a, **kw: executed.append(probe))
    monkeypatch.setattr(scanner, 'FIREBASE_CHAIN_PROBES', [])
    scanner.scan_gapis('AIza' + 'x' * 35, include_maps=include_maps,
                      include_authorization=False, authorization_only=False,
                      skip_jsapi=True, quiet=True, threads=1, no_color=True)
    expected = {'high', 'maps'} if include_maps else {'high'}
    assert {probe[1] for probe in executed} == expected
    assert any(probe[0] == 'Gemini Models List' for probe in executed)


@pytest.mark.skipif(getattr(scanner, '_OVERLAY_FILENAME', None) is not None, reason='Public CLI contract')
def test_cli_forwards_maps_option(monkeypatch):
    calls = []

    def scan(*args, **kwargs):
        calls.append(kwargs)
        scanner._reset_transport_errors()
        scanner._capture_last_transport_errors()
        scanner._capture_last_confirmed_severity_counts({})
        return []

    monkeypatch.setattr(scanner, 'scan_gapis', scan)
    monkeypatch.setattr(sys, 'argv', ['gapiscanner', '--api-key', 'synthetic', '--include-maps'])
    with pytest.raises(SystemExit) as result:
        scanner.main()
    assert result.value.code == 0
    assert calls[0]['include_maps'] is True


@pytest.mark.skipif(getattr(scanner, '_OVERLAY_FILENAME', None) is not None, reason='Public CLI contract')
def test_removed_selection_flag_is_rejected_before_scanning(monkeypatch):
    monkeypatch.setattr(scanner, 'scan_gapis', lambda *a, **kw: pytest.fail('Invalid option must not scan'))
    monkeypatch.setattr(sys, 'argv', ['gapiscanner', '--api-key', 'synthetic', '--maps-only'])
    with pytest.raises(SystemExit) as result:
        scanner.main()
    assert result.value.code == 2
