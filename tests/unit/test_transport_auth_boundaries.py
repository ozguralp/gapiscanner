"""Exercise the real HTTP request preparation without opening a socket."""
import json

import pytest
import requests

import google_api_scanner as scanner


@pytest.fixture
def netrc_file(tmp_path, monkeypatch):
    path = tmp_path / 'netrc'
    path.write_text('default login synthetic-user password synthetic-password\n')
    monkeypatch.setenv('NETRC', str(path))


def reply(request, status=403, payload=None, location=None):
    response = requests.Response()
    response.status_code = status
    response._content = json.dumps(payload or {'error': {'message': 'denied'}}).encode()
    response.request = request
    response.url = request.url
    if location:
        response.headers['Location'] = location
    return response


@pytest.mark.parametrize('authorization', [None, 'Bearer temporary-identity', 'key=synthetic-api-key'])
def test_probe_ignores_netrc_and_preserves_explicit_auth(monkeypatch, netrc_file, authorization):
    sent = []
    def send(self, request, **kwargs):
        sent.append(request)
        return reply(request)
    monkeypatch.setattr(requests.adapters.HTTPAdapter, 'send', send)
    headers = {'Authorization': authorization} if authorization else {}
    probe = ('Synthetic probe', 'high', 'GET',
             'https://example.googleapis.com/v1/items?key={key}', None, '200', 'test')
    scanner._execute_probe(probe, 'synthetic-key', None, headers)
    assert len(sent) == 1
    assert sent[0].headers.get('Authorization') == authorization


def test_discovery_ignores_netrc_on_initial_and_redirect_requests(monkeypatch, netrc_file):
    sent = []
    def send(self, request, **kwargs):
        sent.append(request)
        if len(sent) == 1:
            return reply(request, 302, location='https://cdn.example.com/app.js')
        return reply(request, 200, {'text': 'public script'})
    monkeypatch.setattr(requests.adapters.HTTPAdapter, 'send', send)
    scanner._fetch_and_extract_keys({'https://example.com'}, resume=False)
    assert [r.url for r in sent] == ['https://example.com/', 'https://cdn.example.com/app.js']
    assert all('Authorization' not in r.headers for r in sent)


def test_crawl_redirects_preserve_cookie_scope_and_environment_proxy(monkeypatch, netrc_file):
    sent = []
    proxy = 'http://proxy.example:8080'
    monkeypatch.setenv('HTTPS_PROXY', proxy)
    monkeypatch.setenv('NO_PROXY', '')
    monkeypatch.setenv('no_proxy', '')
    monkeypatch.setattr(scanner, '_REQUEST_KWARGS', {'timeout': 15})
    def send(self, request, **kwargs):
        sent.append((request, kwargs))
        if len(sent) == 1:
            result = reply(request, 302, location='/next')
            result.cookies.set('session', 'synthetic-cookie', domain='example.com', path='/')
            return result
        if len(sent) == 2:
            return reply(request, 307, location='https://other.example/final')
        return reply(request, 200)
    monkeypatch.setattr(requests.adapters.HTTPAdapter, 'send', send)
    response = scanner._get_crawl_response('https://example.com/start')
    assert response.url == 'https://other.example/final'
    assert len(response.history) == 2
    assert sent[1][0].headers['Cookie'] == 'session=synthetic-cookie'
    assert 'Cookie' not in sent[2][0].headers
    assert all('Authorization' not in request.headers for request, _ in sent)
    assert all(options['proxies'].get('https') == proxy for _, options in sent)


@pytest.mark.parametrize('location', ['file:///etc/passwd', 'javascript:alert(1)', 'https://[invalid'])
def test_crawl_rejects_invalid_redirects(monkeypatch, location):
    def send(self, request, **kwargs):
        return reply(request, 302, location=location)
    monkeypatch.setattr(requests.adapters.HTTPAdapter, 'send', send)
    with pytest.raises(requests.exceptions.InvalidURL):
        scanner._get_crawl_response('https://example.com')


def test_crawl_bounds_redirect_loops(monkeypatch):
    sent = []
    def send(self, request, **kwargs):
        sent.append(request)
        return reply(request, 302, location='/loop')
    monkeypatch.setattr(requests.adapters.HTTPAdapter, 'send', send)
    with pytest.raises(requests.TooManyRedirects):
        scanner._get_crawl_response('https://example.com/loop')
    assert len(sent) == 31
