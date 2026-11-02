"""Response contracts, URL restriction replay and diagnostic redaction."""
import json
import sys
from types import SimpleNamespace

import pytest
import requests
import google_api_scanner as scanner


KEY = 'AIza' + 'R' * 35


def response(body, status=200):
    result = requests.Response()
    result.status_code = status
    result._content = body.encode()
    result.request = requests.Request('GET', 'https://example.googleapis.com/v1/test?key=synthetic').prepare()
    return result


@pytest.mark.parametrize('payload', [None, False, 7, 'registered', {'registered': None}, {'allProviders': False}])
def test_enum_requires_documented_field_types(payload):
    assert scanner._check_it_create_auth_uri_enum(response(json.dumps(payload)))[0] is False


@pytest.mark.parametrize('check', ['_check_imagen_reachable', '_check_it_key_accepted_not_invalid'])
@pytest.mark.parametrize('body', ['<html>maintenance</html>', 'null', '[]', '{"error":{"message":"denied"}}'])
def test_reachability_rejects_invalid_success_body(check, body):
    assert getattr(scanner, check)(response(body))[0] is False


@pytest.mark.parametrize('body', ['[null]', '{"files":[null]}', '{"files":[{}]}'])
def test_collection_requires_a_meaningful_record(body):
    assert scanner._check_non_empty_list(response(body))[0] is False


def test_operation_type_marker_alone_does_not_prove_customer_data():
    result = scanner._check_non_empty_operations_list(response('{"operations":[{"name":"operations/1","response":{"@type":"type.googleapis.com/google.protobuf.Empty"}}]}'))
    assert result[0] is True
    assert result[2]['data_sensitivity'] == 'metadata'


@pytest.mark.parametrize('body', ['NaN', 'Infinity', '-Infinity'])
def test_rtdb_rejects_non_json_numbers(monkeypatch, body):
    monkeypatch.setattr(scanner.requests, 'get', lambda *a, **k: response(body))
    assert scanner._authenticated_rtdb_read('https://example-project.firebaseio.com', 'token') is None


def test_discovery_console_redacts_source_query_keys(monkeypatch, capsys):
    source = 'https://example.com/script.js?key=' + KEY
    monkeypatch.setattr(scanner.requests, 'get', lambda *a, **k: SimpleNamespace(status_code=200, text=KEY, headers={}, url=source))
    keys, sources = scanner._fetch_and_extract_keys({source}, verbose=True, resume=False)
    assert keys == {KEY}
    assert sources[KEY] == {source}
    assert KEY not in capsys.readouterr().out








@pytest.mark.skipif(getattr(scanner, '_OVERLAY_FILENAME', None) is not None, reason='Public CLI contract')
@pytest.mark.parametrize('extra,expected_modes', [([], [None, 'referer']), (['--no-auto-referer'], [None])])
def test_url_discovery_replays_source_referer(monkeypatch, tmp_path, extra, expected_modes):
    url = 'https://example.com/app.js'
    calls = []
    monkeypatch.setenv('GAPISCANNER_DATA_DIR', str(tmp_path))
    monkeypatch.setattr(scanner, 'discover_keys_from_url', lambda *a, **k: ({KEY}, {KEY: {url}}))
    monkeypatch.setattr(scanner, '_kb_path', lambda output_dir=None: str(tmp_path / 'key_kb.json'))
    def scan(*args, **kw):
        calls.append(kw)
        scanner._reset_transport_errors()
        scanner._capture_last_transport_errors()
        scanner._capture_last_confirmed_severity_counts({})
        scanner._capture_last_scan_result_snapshot([])
        scanner._capture_last_scan_diagnostic_snapshot([])
        return []
    monkeypatch.setattr(scanner, 'scan_gapis', scan)
    monkeypatch.setattr(sys, 'argv', ['gapiscanner', '--url', url, *extra])
    with pytest.raises(SystemExit) as result:
        scanner.main()
    assert result.value.code == 0
    assert [call['restriction_mode'] for call in calls] == expected_modes
    if len(calls) > 1:
        assert calls[1]['restriction_value'] == url


@pytest.mark.parametrize('payload', [
    {'allProviders': []}, {'signinMethods': []}, {'allProviders': [None]},
    {'registered': True, 'error': {'message': 'denied'}},
])
def test_enum_protection_and_errors_do_not_confirm_enumeration(payload):
    assert scanner._check_it_create_auth_uri_enum(response(json.dumps(payload)))[0] is False


@pytest.mark.parametrize('payload', [
    {'registered': True}, {'registered': False},
    {'allProviders': ['password']}, {'signinMethods': ['google.com']},
])
def test_enum_retains_documented_disclosures(payload):
    assert scanner._check_it_create_auth_uri_enum(response(json.dumps(payload)))[0] is True


@pytest.mark.parametrize('check,marker', [
    ('_check_imagen_reachable', 'INVALID_ARGUMENT'),
    ('_check_it_key_accepted_not_invalid', 'INVALID_CUSTOM_TOKEN'),
])
@pytest.mark.parametrize('template', ['<html>{}</html>', '{{"message":"{}"}}'])
def test_reachability_requires_structured_api_error(check, marker, template):
    assert getattr(scanner, check)(response(template.format(marker), 400))[0] is False


@pytest.mark.parametrize('check,marker', [
    ('_check_imagen_reachable', 'INVALID_ARGUMENT'),
    ('_check_it_key_accepted_not_invalid', 'INVALID_CUSTOM_TOKEN'),
])
def test_reachability_retains_api_argument_diagnostic(check, marker):
    body = json.dumps({'error': {'code': 400, 'message': marker}})
    assert getattr(scanner, check)(response(body, 400))[0] is True


@pytest.mark.parametrize('payload', [None, [], False, 7, {'error': {'message': 'denied'}}])
def test_iid_invalid_response_is_not_a_disclosure(payload):
    assert scanner._check_iid_info(response(json.dumps(payload)))[0] is False


@pytest.mark.parametrize('body', ['NaN', 'Infinity', '-Infinity'])
def test_unauthenticated_rtdb_rejects_non_json_numbers(body):
    assert scanner._check_firebase_rtdb_root(response(body))[0] is False
