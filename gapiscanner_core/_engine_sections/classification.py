def _configure_proxy(proxy_url):
    if proxy_url:
        _REQUEST_KWARGS["proxies"] = {"http": proxy_url, "https": proxy_url}
    else:
        _REQUEST_KWARGS.pop("proxies", None)

# API KEY VALIDATION

def _validate_api_key(apikey):
    if not apikey or not apikey.startswith("AIza") or not (35 <= len(apikey) <= 100):
        print("[!] Warning: API key format looks unusual (expected AIza... prefix, 35-100 chars). Continuing anyway.")

# RESPONSE HELPERS

def _is_auth_error(response):
    if response.status_code in (401, 403):
        return True
    try:
        text = response.text.lower()
        for kw in ("api_key_invalid", "api key not valid", "unauthorized",
                    "permission denied", "request_denied"):
            if kw in text:
                return True
    except Exception:
        pass
    return False

_ERROR_CLASS_KEYWORDS = (
    ("reported as leaked",             "KEY_LEAKED"),
    ("API key expired",                "KEY_EXPIRED"),
    ("API key is expired",             "KEY_EXPIRED"),
    # Match REFERER_INCOMPATIBLE BEFORE the generic REFERRER_BLOCKED so that
    # "API keys with referer restrictions cannot be used" is correctly classified
    # (the API rejects ANY referer header, not just the wrong one).
    ("API keys with referer restrictions cannot be used", "REFERER_INCOMPATIBLE"),
    ("API_KEY_HTTP_REFERRER_BLOCKED", "REFERRER_BLOCKED"),
    ("REQUEST_DENIED_REFERRER",       "REFERRER_BLOCKED"),
    ("API_KEY_IP_ADDRESS_BLOCKED",    "IP_BLOCKED"),
    ("API_KEY_ANDROID_APP_BLOCKED",   "ANDROID_BLOCKED"),
    ("API_KEY_IOS_APP_BLOCKED",       "IOS_BLOCKED"),
    ("API_KEY_SERVICE_BLOCKED",       "SERVICE_BLOCKED"),
    # Maps Platform service-restriction: "The provided API key is invalid." in a
    # 200/403 REQUEST_DENIED body means the key works elsewhere but is not on
    # the Maps allowlist. Must match BEFORE generic API_KEY_INVALID.
    ("The provided API key is invalid", "SERVICE_BLOCKED"),
    ("not authorized to use this API", "SERVICE_BLOCKED"),
    # Service metadata identifies the API, not whether the key is valid.
    ("API_KEY_INVALID",               "KEY_INVALID"),
    ("API key not valid",             "KEY_INVALID"),
    ("has not been used",             "API_DISABLED"),
    ("is disabled",                   "API_DISABLED"),
    ("SERVICE_DISABLED",              "API_DISABLED"),
    ("required service account is missing necessary permissions",
     "FIREBASE_STORAGE_PRECONDITION"),
    # RTDB default database endpoint returns HTTP 423 when the database exists
    # but has been deactivated. This is a terminal Firebase project state, not
    # a missing request parameter and not an access-control finding.
    ("has been deactivated",           "FIREBASE_RTDB_DEACTIVATED"),
    # Maps Platform variants for "API not enabled in project" — these arrive as
    # HTTP 200 with `"status":"REQUEST_DENIED"` plus one of these messages, so
    # without these keywords they would land in the `REQUEST_DENIED` bucket.
    ("is not enabled for your project",   "API_DISABLED"),  # Maps legacy API
    ("is not activated on your API project", "API_DISABLED"),  # Maps SKU not enabled
    ("LegacyApiNotActivatedMapError", "API_DISABLED"),  # Maps legacy reason
    ("PERMISSION_DENIED",             "PERMISSION_DENIED"),
    ("Permission denied",             "PERMISSION_DENIED"),
    ("INVALID_ARGUMENT",              "INVALID_ARGUMENT"),
    ("FAILED_PRECONDITION",           "FAILED_PRECONDITION"),
    ("NOT_FOUND",                     "NOT_FOUND"),

    ("API keys are not supported by this API", "API_KEY_UNSUPPORTED"),
    ("Expected OAuth 2 access token",          "API_KEY_UNSUPPORTED"),
    ("Expected OAuth2 access token",           "API_KEY_UNSUPPORTED"),
    ("login cookie or other valid authentication credential", "API_KEY_UNSUPPORTED"),
    ("UNAUTHENTICATED",               "UNAUTHENTICATED"),
    ("RESOURCE_EXHAUSTED",            "QUOTA_EXCEEDED"),
    ("RATE_LIMIT_EXCEEDED",           "QUOTA_EXCEEDED"),
)

# Service identifiers used in diagnostic summaries.
_SERVICE_METADATA_RE = re.compile(r'"service"\s*:\s*"([a-z0-9.-]+\.googleapis\.com)"')

def _classify_error(response):
    """Return a short error-class label or None on inscrutable bodies.

    INVALID_ARGUMENT means the key was ACCEPTED — only the body was wrong.
    PERMISSION_DENIED with no other context = generic IAM denial.
    KEY_INVALID / REFERRER_BLOCKED / ANDROID_BLOCKED etc. are restriction hints.

    Maps Platform APIs frequently return HTTP 200 with a JSON body that contains
    `"status": "REQUEST_DENIED"` plus an `error_message`. We still classify those
    by scanning the body — for non-vulnerable Maps responses the keyword table
    above includes "API keys with referer restrictions cannot be used".

    API_KEY_INVALID remains an invalid-key diagnostic even when Google includes
    metadata.service. API_KEY_SERVICE_BLOCKED identifies an API restriction.
    """
    text = (response.text or "")[:2000]
    if 200 <= response.status_code < 300:
        # Maps-style 200+REQUEST_DENIED — only classify if the body announces denial.
        if "REQUEST_DENIED" not in text and "PERMISSION_DENIED" not in text:
            return None
    klass = None
    for needle, k in _ERROR_CLASS_KEYWORDS:
        if needle in text:
            klass = k
            break
    if klass:
        return klass
    if response.status_code == 401:
        return "UNAUTHENTICATED"
    if response.status_code == 403:
        return "PERMISSION_DENIED"
    if response.status_code == 404:
        return "NOT_FOUND"
    if response.status_code == 412:
        # Fallback for non-Storage bare 412 responses without Google's
        # standard `FAILED_PRECONDITION` marker.
        return "FAILED_PRECONDITION"
    if response.status_code == 423:
        # HTTP 423 is an explicit Locked state. Firebase RTDB deactivation has
        # a more precise body match above; unknown/bare 423s stay separate from
        # generic HTTP_NNN so KB rescans can audit them probe-by-probe.
        return "HTTP_423_LOCKED"
    if response.status_code == 400:
        return "INVALID_ARGUMENT"
    if 200 <= response.status_code < 300:
        # Body said REQUEST_DENIED but no specific class matched — keep coarse signal.
        return "REQUEST_DENIED"
    return "HTTP_%d" % response.status_code


def _extract_service_metadata(text):
    """Return the set of Google service hostnames advertised in the response
    body's `details[].metadata.service` fields. Each value tells us exactly
    which Google API surface Google believes we just contacted — invaluable
    for allowlist inference on service-restricted keys."""
    if not text:
        return set()
    return set(_SERVICE_METADATA_RE.findall(text[:5000]))

def _extract_error_reason(response):
    """Extract a human-readable error reason from response."""
    try:
        data = response.json()
        if isinstance(data, list) and data and isinstance(data[0], dict):
            data = data[0]
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, str) and item:
                    return item
                if isinstance(item, dict):
                    msg = item.get("message") or item.get("error_message")
                    if msg:
                        return str(msg)
            raise TypeError("JSON list has no message field")
        if not isinstance(data, dict):
            raise TypeError("JSON response has no error-message object")
        for key in ("error_message", "errorMessage", "message"):
            val = data.get(key)
            if isinstance(val, str) and val:
                return val
            if isinstance(val, dict) and "message" in val:
                return str(val["message"])
        if "error" in data and isinstance(data["error"], dict):
            msg = data["error"].get("message") or str(data["error"])
            if msg:
                return str(msg)
    except (ValueError, TypeError):
        pass
    if response.content:
        ct = (response.headers.get("Content-Type") or "").lower()
        raw = response.content[:300].decode("utf-8", errors="replace").strip()
        if "text/html" in ct or raw.lower().lstrip().startswith(("<!doctype", "<html")):
            return "HTTP %d" % response.status_code
        if len(raw) < 280 and "\n" not in raw:
            return raw
    return "HTTP %d" % response.status_code

# CHECK PARSER

_JSON_STRUCTURAL_TOKENS = frozenset({
    "error", "error_message", "errorMessage", "items", "kind", "responses", "routes",
})
_JSON_SUCCESS_STATUSES = frozenset({"OK", "ZERO_RESULTS"})
_JSON_ERROR_STATUS_MARKERS = (
    "DENIED", "ERROR", "INVALID", "UNAUTH", "EXHAUSTED", "DISABLED",
    "NOT_FOUND", "FAILED_PRECONDITION", "RESOURCE_EXHAUSTED", "OVER_QUERY_LIMIT",
)


def _json_payload(response):
    """Best-effort JSON loader for response-eval helpers."""
    try:
        return response.json()
    except Exception:
        text = (response.text or "").strip()
        if not text:
            return None
        try:
            return json.loads(text)
        except Exception:
            return None


_JSON_LIST_FIELDS = frozenset({
    "models", "candidates", "responses", "translations", "entities", "routes", "items",
})
_JSON_COUNT_FIELDS = frozenset({"totalItems", "totalTokens"})
_JSON_STRING_FIELDS = frozenset({"audioContent", "fid"})


def _json_has_key(data, key):
    """Find a response field and validate known probe fields against their JSON types."""
    if isinstance(data, dict):
        if key in data:
            value = data[key]
            if key in _JSON_LIST_FIELDS:
                return isinstance(value, list) and all(isinstance(row, dict) for row in value)
            if key in _JSON_COUNT_FIELDS:
                return isinstance(value, int) and not isinstance(value, bool) and value >= 0
            if key in _JSON_STRING_FIELDS:
                return isinstance(value, str) and bool(value)
            return True
        return any(_json_has_key(value, key) for value in data.values())
    if isinstance(data, list):
        return any(_json_has_key(value, key) for value in data)
    return False


def _json_status_is_error(status):
    if not isinstance(status, str):
        return False
    normalized = status.strip().upper()
    if not normalized or normalized in _JSON_SUCCESS_STATUSES:
        return False
    return any(marker in normalized for marker in _JSON_ERROR_STATUS_MARKERS)


def _json_has_structural_error(data):
    if isinstance(data, dict):
        if "error" in data and data["error"] is not None:
            return True
        if data.get("error_message") or data.get("errorMessage"):
            return True
        if _json_status_is_error(data.get("status")):
            return True
        return any(_json_has_structural_error(v) for v in data.values())
    if isinstance(data, list):
        return any(_json_has_structural_error(v) for v in data)
    return False


def _json_token_present(data, token):
    if data is None:
        return None
    if token in ("error", "error_message", "errorMessage"):
        return _json_has_structural_error(data)
    return _json_has_key(data, token)


def _dsl_token_present(response, token, text=None, payload=None):
    """Match response fields without mistaking message text for a field."""
    if payload is None:
        payload = _json_payload(response)
    return bool(_json_token_present(payload, token))

def _parse_check(check_type):
    """Return a function(response) -> (vulnerable: bool, maybe_manual: str|None).

    Accepts either a string DSL or a Python callable. Callables are returned as-is
    so probes can implement arbitrary JSON-parsing / multi-step logic.
    """
    if callable(check_type):
        return check_type

    if check_type == "image":
        def _check_image(r):
            content = r.content or b""
            is_image = (
                content.startswith(b"\x89PNG\r\n\x1a\n")
                or content.startswith(b"\xff\xd8\xff")
                or content.startswith((b"GIF87a", b"GIF89a"))
                or (content.startswith(b"RIFF") and content[8:12] == b"WEBP")
            )
            if r.status_code == 200:
                return is_image, None
            if b"PNG" in r.content:
                return False, "manually_check"
            return False, None
        return _check_image

    if check_type == "302":
        def _check_302(r):
            return r.status_code == 302, None
        return _check_302

    if check_type == "not_auth":
        def _check_not_auth(r):
            # A missing auth error on a 404/500/HTML gateway page proves
            # nothing. Only a successful structured response is affirmative.
            payload = _json_payload(r)
            return (200 <= r.status_code < 300
                    and isinstance(payload, dict)
                    and bool(payload)
                    and not _json_has_structural_error(payload)), None
        return _check_not_auth

    # Parse compound checks: "200", "200+kw:X", "200+ne:X",
    # "200+kw:X+ne:Y", "ne:error_message", etc. Generic JSON tokens are
    # evaluated structurally instead of by raw substring.
    parts = check_type.split("+")
    need_200 = False
    kw_checks = []
    ne_checks = []

    for part in parts:
        if part == "200":
            need_200 = True
        elif part.startswith("kw:"):
            kw_checks.append(part[3:])
            need_200 = True  # kw implies 200
        elif part.startswith("ne:"):
            ne_checks.append(part[3:])

    if not need_200 and not kw_checks and ne_checks:
        # Negative-field checks still require a successful JSON response.
        def _check_ne_only(r):
            if r.status_code != 200:
                return False, None
            text = r.text or ""
            payload = _json_payload(r)
            if not isinstance(payload, (dict, list)):
                return False, None
            for ne in ne_checks:
                if _dsl_token_present(r, ne, text=text, payload=payload):
                    return False, None
            return True, None
        return _check_ne_only

    def _check_compound(r):
        if need_200 and r.status_code != 200:
            return False, None
        text = r.text or ""
        payload = _json_payload(r)
        if not isinstance(payload, (dict, list)) or _json_has_structural_error(payload):
            return False, None
        for kw in kw_checks:
            if not _dsl_token_present(r, kw, text=text, payload=payload):
                return False, None
        for ne in ne_checks:
            if _dsl_token_present(r, ne, text=text, payload=payload):
                return False, None
        return True, None
    return _check_compound

# PROBE RUNNER
