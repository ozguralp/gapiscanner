"""Reject malformed success fields and distinguish empty input from findings."""
import json
import sys

import pytest
import requests

import google_api_scanner as scanner
from gapiscanner_core.authorization import _check_vertex_authorization_models


def response(payload):
    result = requests.Response()
    result.status_code = 200
    result._content = json.dumps(payload).encode()
    return result


@pytest.mark.parametrize('error', [True, False, 0, 7, [], ['denied']])
def test_json_error_field_never_confirms_success(error):
    assert scanner._parse_check('200+ne:error')(response({'error': error}))[0] is False


@pytest.mark.parametrize('field,value', [
    ('models', False), ('models', 'unavailable'), ('candidates', None),
    ('candidates', [None]), ('responses', 5), ('translations', False),
    ('entities', 'unavailable'), ('routes', {}), ('items', [False]),
    ('totalItems', True), ('totalTokens', -1), ('totalTokens', False),
    ('audioContent', {}), ('fid', 7),
])
def test_known_success_fields_require_their_json_types(field, value):
    check = scanner._parse_check('200+kw:' + field)
    assert check(response({field: value}))[0] is False


@pytest.mark.parametrize('field,value', [
    ('models', [{'name': 'models/example'}]), ('candidates', [{'content': {}}]),
    ('responses', [{}]), ('translations', [{'translatedText': 'hola'}]),
    ('entities', []), ('routes', []), ('items', []), ('totalItems', 0),
    ('totalTokens', 0), ('audioContent', 'YQ=='), ('fid', 'example-installation'),
])
def test_known_success_fields_retain_valid_values(field, value):
    check = scanner._parse_check('200+kw:' + field)
    assert check(response({field: value}))[0] is True


@pytest.mark.parametrize('name', [True, 12, [], {'value': 'name'}])
def test_authorization_inventory_requires_resource_name_strings(name):
    assert _check_vertex_authorization_models(response({'models': [{'name': name}]}))[0] is False


@pytest.mark.skipif(getattr(scanner, '_OVERLAY_FILENAME', None) is not None, reason='Public CLI contract')
@pytest.mark.parametrize('with_other_program', [False, True])
def test_empty_kb_selection_is_input_error_not_finding(monkeypatch, with_other_program):
    kb = {'synthetic-key': {'first_program': 'other', 'sources': [], 'scan_history': []}} if with_other_program else {}
    monkeypatch.setattr(scanner, '_kb_load', lambda **kw: kb)
    monkeypatch.setattr(scanner, 'scan_gapis', lambda *a, **kw: pytest.fail('No selected keys'))
    monkeypatch.setattr(sys, 'argv', ['gapiscanner', '--rescan-kb', '--program', 'selected'])
    with pytest.raises(SystemExit) as result:
        scanner.main()
    assert result.value.code == 2


@pytest.mark.parametrize('body', [b'<html>maintenance</html>', b'', b'{"items":'])
def test_invalid_json_success_marks_probe_incomplete(monkeypatch, body):
    scanner._reset_transport_errors()
    result = response({})
    result._content = body
    monkeypatch.setattr(scanner.requests, 'get', lambda *a, **kw: result)
    probe = ('Synthetic JSON probe', 'high', 'GET',
             'https://example.googleapis.com/v1/items?key={key}', None, '200+kw:items', 'test')
    checked = scanner._execute_probe(probe, 'synthetic', None, {})
    assert checked['vulnerable'] is False
    assert scanner._transport_error_total() == 1


@pytest.mark.parametrize('payload', [{}, {'corpora': []}, {'tunedModels': []}, {'error': None}])
def test_empty_gemini_reachability_contract_is_preserved(payload):
    assert scanner._parse_check('200+ne:error')(response(payload))[0] is True


@pytest.mark.parametrize("reason,expected", [
    ("API_KEY_INVALID", "KEY_INVALID"),
    ("API_KEY_SERVICE_BLOCKED", "SERVICE_BLOCKED"),
])
@pytest.mark.parametrize("with_service", [False, True])
def test_error_reason_is_not_changed_by_service_metadata(reason, expected, with_service):
    metadata = {"service": "generativelanguage.googleapis.com"} if with_service else {}
    result = response({"error": {
        "code": 400, "status": "INVALID_ARGUMENT",
        "details": [{"@type": "type.googleapis.com/google.rpc.ErrorInfo",
                     "reason": reason, "domain": "googleapis.com", "metadata": metadata}],
    }})
    result.status_code = 400
    assert scanner._classify_error(result) == expected
