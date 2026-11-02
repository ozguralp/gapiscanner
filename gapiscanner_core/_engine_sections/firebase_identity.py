_MAPS_EXTRAS_INFERRED_NOTE = "inferred_not_independently_confirmed"
_MAPS_EXTRAS_INFERRED_IMPACT_SUFFIX = (
    " (inferred, not independently confirmed)"
)


def _firebase_config(project_id=None, project_number=None, database_url=None,
                     storage_bucket=None, google_app_id=None, source=None,
                     api_key=None):
    """Build a Firebase config with source and optional exact API-key binding.

    Empty fields are omitted. Exact bindings keep configs from different
    projects separate when an archive contains more than one key."""
    cfg = {}
    if project_id:     cfg["project_id"] = project_id
    if project_number: cfg["project_number"] = project_number
    if database_url:   cfg["database_url"] = database_url
    if storage_bucket: cfg["storage_bucket"] = storage_bucket
    if google_app_id:  cfg["google_app_id"] = google_app_id
    if api_key:        cfg["api_key"] = api_key
    cfg["sources"] = [source] if source else []
    return cfg


def _begin_discovery_session():
    """Clear discovery issues and extracted configs before a new input session."""
    with _DISCOVERY_ISSUES_LOCK:
        _DISCOVERY_ISSUES.clear()
    with _DERIVED_FIREBASE_LOCK:
        _DERIVED_FIREBASE_CONFIGS.clear()


_PROJECT_ID_LABEL_RE = re.compile(r"^[a-z][a-z0-9-]{3,28}[a-z0-9]$")
_PROJECT_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:.-]{2,127}$")


def _is_valid_googleapis_project_ref(project_id):
    """Return True when `project_id` is safe to place in Google API paths.

    Domain-scoped legacy project refs may contain dots/colon and are valid in
    `/v1/projects/{project}` paths, but template leftovers such as
    `$(GOOGLE_PROJECT_ID)` must never be treated as a real target.
    """
    pid = str(project_id or "").strip()
    if not pid or pid == _PLACEHOLDER_PROJECT_ID or pid.isdigit():
        return False
    return bool(_PROJECT_REF_RE.match(pid))


def _is_valid_firebase_hostname_project_id(project_id):
    """Return True when `project_id` can safely be embedded in Firebase hostnames."""
    pid = str(project_id or "").strip().lower()
    return bool(_PROJECT_ID_LABEL_RE.match(pid))


def _derive_project_id_from_config(cfg):
    """Return a best-effort project_id derived from `cfg`'s DATABASE_URL or
    STORAGE_BUCKET. Returns None if neither field allows a confident parse.
    Lowercased to match Firebase's case-insensitive project naming."""
    if not cfg:
        return None
    db = (cfg.get("database_url") or "").strip().lower()
    if db.startswith(("http://", "https://")):
        from urllib.parse import urlparse
        try:
            host = urlparse(db).netloc.split(":", 1)[0]
        except Exception:
            host = ""
        if host.endswith(".firebaseio.com"):
            label = host[: -len(".firebaseio.com")]
            if label.endswith("-default-rtdb"):
                label = label[: -len("-default-rtdb")]
            if label and _PROJECT_ID_LABEL_RE.match(label):
                return label
        elif host.endswith(".firebasedatabase.app"):
            inner = host[: -len(".firebasedatabase.app")]
            # `<pid>-default-rtdb.<region>` → split off the region label.
            if "." in inner:
                inner = inner.split(".", 1)[0]
            if inner.endswith("-default-rtdb"):
                inner = inner[: -len("-default-rtdb")]
            if inner and _PROJECT_ID_LABEL_RE.match(inner):
                return inner
    sb = (cfg.get("storage_bucket") or "").strip().lower()
    if sb:
        for suffix in (".appspot.com", ".firebasestorage.app"):
            if sb.endswith(suffix):
                label = sb[: -len(suffix)]
                if label and _PROJECT_ID_LABEL_RE.match(label):
                    return label
                break
    return None


def _validated_rtdb_url(value):
    """Extracted configs are untrusted: only Google RTDB HTTPS origins qualify."""
    if not isinstance(value, str):
        return None
    try:
        parsed = urlparse(value)
        host = (parsed.hostname or "").lower()
        if (parsed.scheme != "https" or parsed.username or parsed.password
                or parsed.port not in (None, 443) or parsed.query or parsed.fragment
                or parsed.path not in ("", "/")):
            return None
        if not (host.endswith(".firebaseio.com") or host.endswith(".firebasedatabase.app")):
            return None
        if not re.fullmatch(r"[a-z0-9.-]+", host):
            return None
        return "https://" + host
    except ValueError:
        return None


def _record_firebase_config(cfg):
    """Merge an extracted config into the project store under its lock."""
    if not cfg:
        return
    pid = cfg.get("project_id")
    if not pid:
        derived = _derive_project_id_from_config(cfg)
        if derived:
            cfg["project_id"] = derived
            pid = derived
    if not pid:
        # Still no project_id (rare — e.g. a JS config with only `apiKey`).
        # Accept once but never dedupe — Phase 3 has a projectless branch
        # that runs extras for these configs.
        with _DERIVED_FIREBASE_LOCK:
            _DERIVED_FIREBASE_CONFIGS.append(cfg)
        return
    with _DERIVED_FIREBASE_LOCK:
        for existing in _DERIVED_FIREBASE_CONFIGS:
            if existing.get("project_id") == pid:
                for k, v in cfg.items():
                    if k == "sources":
                        for s in (v or []):
                            if s and s not in existing.get("sources", []):
                                existing.setdefault("sources", []).append(s)
                    elif v and not existing.get(k):
                        existing[k] = v
                return
        _DERIVED_FIREBASE_CONFIGS.append(dict(cfg))


def _it_record_artifact(probe_name, local_id, id_token, reason):
    with _IDENTITY_TOOLKIT_LOCK:
        _IDENTITY_TOOLKIT_ARTIFACTS.append({
            "probe": probe_name,
            "local_id": local_id,
            "id_token_prefix": (id_token or "")[:20] + "...",
            "reason": _redact_diagnostic_secret_text(reason),
        })

def _identity_toolkit_artifact_snapshot():
    """Return cleanup-failure metadata safe for KB persistence.

    The raw idToken never leaves process memory; KB stores only the localId and
    failure reason needed for final cleanup/reporting.
    """
    with _IDENTITY_TOOLKIT_LOCK:
        return [{
            "probe": art.get("probe"),
            "local_id": art.get("local_id"),
            "reason": art.get("reason"),
        } for art in _IDENTITY_TOOLKIT_ARTIFACTS]

def _client_restriction_headers(headers):
    """Copy only client restriction headers; never forward ambient credentials."""
    allowed = {"referer", "origin", "x-ios-bundle-identifier", "x-android-package", "x-android-cert"}
    return {name: value for name, value in (headers or {}).items() if name.lower() in allowed}


def _check_it_signup_anon(r):
    """Check anonymous account creation and attempt account deletion.

    Authenticated reads run before deletion only when explicitly enabled and
    the source passes its scope check. Cleanup failures are retained as artifacts."""
    if r.status_code != 200:
        return False, None
    try:
        data = r.json()
    except Exception:
        return False, None
    if not isinstance(data, dict):
        return False, None
    id_token = data.get("idToken")
    local_id = data.get("localId")
    if not id_token or not local_id:
        return False, None


    try:
        _run_authenticated_read_chain(
            apikey=(r.request.url.split("key=", 1)[1] if "key=" in r.request.url else ""),
            id_token=id_token,
            local_id=local_id,
            restriction_headers=_client_restriction_headers(
                getattr(getattr(r, "request", None), "headers", {})),
        )
    except Exception:
        _record_transport_error("other")

    # Mandatory cleanup. Always fires, even if auth-read raised.
    delete_url = "https://identitytoolkit.googleapis.com/v1/accounts:delete?" \
                 + r.request.url.split("?", 1)[1]
    try:
        delete_headers = {"Content-Type": "application/json"}
        request_headers = getattr(getattr(r, "request", None), "headers", {}) or {}
        for h in ("X-Ios-Bundle-Identifier", "X-Android-Package",
                  "X-Android-Cert", "Referer", "Origin"):
            if request_headers.get(h):
                delete_headers[h] = request_headers[h]
        dr = requests.post(delete_url,
                           headers=delete_headers,
                           data=json.dumps({"idToken": id_token}),
                           **_request_kwargs_for_url(delete_url))
        if dr.status_code != 200:
            _it_record_artifact("signUp (anon)", local_id, id_token,
                                "delete returned HTTP %d" % dr.status_code)
            return True, "cleanup_failed_localId=%s" % local_id
    except requests.RequestException as e:
        _it_record_artifact("signUp (anon)", local_id, id_token,
                            "delete request failed: %s" % e)
        return True, "cleanup_failed_localId=%s" % local_id
    return True, None

def _check_it_oob_email_delivery(r):
    """Check the response to an explicitly requested test email.

    EMAIL_NOT_FOUND does not establish delivery."""
    body = (r.text or "")
    if r.status_code == 200:
        try:
            data = json.loads(body)
        except (TypeError, ValueError):
            return False, None
        if (isinstance(data, dict) and not data.get("error")
                and isinstance(data.get("email"), str) and "@" in data["email"]):
            return True, "oob_email_delivered"
        return False, None
    if "EMAIL_NOT_FOUND" in body:
        # PASSWORD_RESET needs an existing account; non-finding by design.
        return False, "email_not_found_no_delivery"
    return False, None


def _check_it_sms_delivery(r):
    """Check the response to an explicitly requested test SMS.

    CAPTCHA or app-attestation rejection does not establish delivery."""
    body = (r.text or "")
    low = body.upper()
    if any(t in low for t in ("INVALID_RECAPTCHA", "CAPTCHA_CHECK_FAILED",
                              "MISSING_RECAPTCHA_TOKEN", "RECAPTCHA")):
        return False, "recaptcha_gated_sms_infeasible"
    if r.status_code == 200:
        try:
            data = json.loads(body)
        except (TypeError, ValueError):
            return False, None
        if (isinstance(data, dict) and not data.get("error")
                and isinstance(data.get("sessionInfo"), str) and data["sessionInfo"]):
            return True, "sms_initiated"
        return False, None
    return False, None


def _check_it_create_auth_uri_enum(r):
    """Require a registration flag or disclosed sign-in providers.

    Empty provider lists alone are compatible with email enumeration protection.
    """
    if r.status_code != 200:
        return False, None
    try:
        data = r.json()
    except Exception:
        return False, None
    if not isinstance(data, dict) or data.get("error"):
        return False, None
    if isinstance(data.get("registered"), bool):
        return True, None
    for field in ("allProviders", "signinMethods"):
        providers = data.get(field)
        if (isinstance(providers, list) and providers
                and all(isinstance(value, str) and value for value in providers)):
            return True, None
    return False, None

def _check_it_key_accepted_not_invalid(r):
    """Generic probe: key was accepted (NOT API_KEY_INVALID).
    Used for signIn / mfa endpoints where we send intentionally bad payload —
    if Google returns an Identity Toolkit-specific error (INVALID_CUSTOM_TOKEN,
    INVALID_ID_TOKEN, MISSING_*) the key works on that endpoint."""
    text = (r.text or "")
    if "API key not valid" in text or "API_KEY_INVALID" in text:
        return False, None
    if r.status_code in (401, 403):
        return False, None
    if r.status_code == 200:
        try:
            data = r.json()
        except (ValueError, TypeError):
            return False, None
        return isinstance(data, dict) and not data.get("error"), None
    if r.status_code == 400:
        try:
            data = r.json()
        except (ValueError, TypeError):
            return False, None
        error = data.get("error") if isinstance(data, dict) else None
        if not isinstance(error, dict):
            return False, None
        text = " ".join(value for value in (error.get("status"), error.get("message"))
                        if isinstance(value, str))
    if r.status_code == 400 and ("INVALID_" in text or "MISSING_" in text
                                  or "EMAIL_NOT_FOUND" in text
                                  or "INVALID_PASSWORD" in text
                                  or "INVALID_LOGIN_CREDENTIALS" in text
                                  or "CAPTCHA_CHECK_FAILED" in text):
        return True, None
    return False, None

def _check_secure_token_refresh(r):

    """securetoken.googleapis.com — same "not API_KEY_INVALID" pattern."""
    return _check_it_key_accepted_not_invalid(r)


def _check_it_diagnostic_only(r):
    """Retain the legacy diagnostic result without treating key acceptance as exposure."""
    vulnerable, note = _check_it_key_accepted_not_invalid(r)
    if vulnerable:
        return False, "diagnostic_key_accepted"
    return False, note


_LIST_PAGINATION_NOISE_KEYS = frozenset({
    "nextPageToken", "pageToken", "etag", "kind", "selfLink",
    "totalSize", "unreachable",
})


def _check_non_empty_list(r):
    """Require a non-empty collection in a successful JSON response.

    Empty collections, pagination fields and single-resource objects do not
    establish data exposure for a list endpoint."""
    if r.status_code != 200:
        return False, None
    text = r.text or ""
    if "API_KEY_INVALID" in text or "API key not valid" in text:
        return False, None
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return False, None
    def has_records(rows):
        return any(isinstance(row, (dict, str)) and bool(row) for row in rows)

    if isinstance(data, list):
        return has_records(data), None
    if not isinstance(data, dict) or data.get("error"):
        return False, None
    # Filter pagination/metadata noise so a body like
    # `{"buckets": [], "nextPageToken": ""}` is still classified as
    # empty even though nextPageToken is present.
    significant_arrays = [
        v for k, v in data.items()
        if isinstance(v, list) and k not in _LIST_PAGINATION_NOISE_KEYS
    ]
    if not significant_arrays:
        return False, None
    if any(has_records(arr) for arr in significant_arrays):
        return True, None
    return False, None


def _check_non_empty_operations_list(r):
    """Classify operation-list responses by the data they expose.

    Empty/malformed responses are not findings. A non-empty operation list
    containing a response payload keeps the probe's normal customer-data
    semantics. Name/metadata-only rows remain visible, but are downgraded to
    LOW metadata so operation identifiers alone cannot become CONFIRMED HIGH.
    """
    if r.status_code != 200:
        return False, None
    text = r.text or ""
    if "API_KEY_INVALID" in text or "API key not valid" in text:
        return False, None
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return False, None
    if isinstance(data, dict):
        if data.get("error"):
            return False, None
        operations = data.get("operations")
    elif isinstance(data, list):
        operations = data
    else:
        operations = None
    if (not isinstance(operations, list) or not operations
            or any(not isinstance(row, dict) or not row for row in operations)):
        return False, None
    if any(
        isinstance(operation.get("response"), dict)
        and any(field != "@type" for field in operation["response"])
        for operation in operations
    ):
        return True, None
    return True, (
        "Operation identifiers/metadata only; manually read a documented "
        "operation detail before treating this as customer-data exposure."
    ), {
        "impact": "Operation metadata exposed; no response payload returned",
        "impact_type": "info_disclosure",
        "confirmation": "confirmed_data",
        "data_sensitivity": "metadata",
    }


_KEY_ACCEPTANCE_CHECK_FNS = frozenset({
    _check_it_key_accepted_not_invalid,
    _check_secure_token_refresh,
})


def _is_key_acceptance_check(check_fn):
    """Return True iff `check_fn` is one of the semantic
    key-acceptance/reachability checks listed in
    `_KEY_ACCEPTANCE_CHECK_FNS`."""
    return check_fn in _KEY_ACCEPTANCE_CHECK_FNS


# FCM / IID CALLABLE CHECKS
# FCM legacy `/fcm/send` uses `Authorization: key=AIza...` header, not a
# query param. Handled via the auth_header_template hook on probe tuples
# (a 9th optional field).

def _check_fcm_send(r):
    """FCM legacy /fcm/send:
    200 with multicast_id / message_id / "failure" / "success" field = key accepted
    (we send registration_ids=['INVALID_TOKEN'] so we get failure=1, NotRegistered —
     but the response confirms the key has FCM send authority)."""
    if r.status_code == 200:
        text = r.text or ""
        if "multicast_id" in text or "message_id" in text or '"failure"' in text or '"success"' in text:
            return True, None
    return False, None

def _check_iid_info(r):
    """iid.googleapis.com/iid/info/<token> — leaks application info incl. project.
    200 with 'application'/'appSigner'/etc. = vulnerable. Project numbers parsed
    from the response body are harvested via the standard `_extract_project_ids`
    pathway in `_execute_probe`; we no longer maintain a separate IID shared
    store."""
    if r.status_code != 200:
        return False, None
    try:
        data = r.json()
    except Exception:
        return False, None
    if not isinstance(data, dict) or data.get("error"):
        return False, None
    leaked = {}
    for k in ("application", "applicationVersion", "appSigner", "platform",
              "connectionType", "scope", "authorizedEntity"):
        v = data.get(k)
        if isinstance(v, str) and v:
            leaked[k] = v
    if leaked:
        return True, "iid_leaked=" + ",".join(sorted(leaked.keys()))
    return False, None

def _check_iid_batch(r):
    """iid/v1:batchAdd / batchRemove — vulnerable if 200 with results."""
    if r.status_code == 200 and ("results" in (r.text or "")):
        return True, None
    return False, None


_DERIVED_PROJECT_IDS     = set()   # alphanumeric IDs, usable everywhere incl. Firebase
_DERIVED_PROJECT_NUMBERS = set()   # numeric project numbers, usable for {project} fallback
_DERIVED_LOCK = Lock()

# Common error-message patterns that leak a project ID (alphanumeric).
_PROJECT_ID_PATTERNS = [
    re.compile(r"projects?/([a-z][a-z0-9-]{4,28}[a-z0-9])(?:/|[\s\"'])"),
    re.compile(r"project ['\"]?([a-z][a-z0-9-]{4,28}[a-z0-9])['\"]?"),
    re.compile(r"project_id['\"]?\s*[:=]\s*['\"]([a-z][a-z0-9-]{4,28}[a-z0-9])['\"]"),
    re.compile(r"\"project\":\s*\"([a-z][a-z0-9-]{4,28}[a-z0-9])\""),
]

# Patterns for purely numeric project NUMBERS (e.g. 789432212921).
# Numbers work for many GCP APIs but NOT Firebase RTDB/Storage (which want IDs).
_PROJECT_NUMBER_PATTERNS = [
    re.compile(r"in project (\d{6,15})\b"),
    re.compile(r"[?&]project=(\d{6,15})\b"),
    re.compile(r"projects?/(\d{6,15})(?:/|[\s\"'])"),
]

# Tokens that look like project IDs but are placeholders / Google's own —
# never feed these back into chain probes.
_PROJECT_DENYLIST = frozenset({
    "test-project-123", "my-project", "your-project", "your-project-id",
    "google-services", "googleapis", "firebase-public", "firebase",
})

def _extract_project_ids(text):
    """Return (ids: set, numbers: set) of project identifiers found in text."""
    ids, numbers = set(), set()
    if not text:
        return ids, numbers
    snippet = text[:5000]
    for pat in _PROJECT_ID_PATTERNS:
        for m in pat.findall(snippet):
            if m in _PROJECT_DENYLIST:
                continue
            if m.startswith("test-project-"):
                continue
            ids.add(m)
    for pat in _PROJECT_NUMBER_PATTERNS:
        for m in pat.findall(snippet):
            numbers.add(m)
    return ids, numbers

def _check_firebase_rtdb_root(r):
    """Classify readable RTDB data as a signal requiring manual sensitivity review."""
    if r.status_code != 200:
        return False, None
    text = (r.text or "").strip()
    if "Permission denied" in text:
        return False, None
    if text == "null":
        return True, "open_empty", {
            "name": "Firebase RTDB open but empty",
            "category": "low",
            "impact": "Info - RTDB rules allow read, but the response was empty (no customer data returned)",

            "impact_type": "info_disclosure",
            "confirmation": "key_accepted_only",
            "data_sensitivity": "none",
        }
    try:
        data = r.json()
    except (ValueError, TypeError):
        return False, None
    if isinstance(data, float) and not math.isfinite(data):
        return False, None
    if isinstance(data, dict) and isinstance(data.get("error"), (dict, str)):
        return False, None
    if data == {}:
        return True, "open_empty", {
            "name": "Firebase RTDB open but empty",
            "category": "low",
            "impact": "Info - RTDB rules allow read, but the response was empty (no customer data returned)",

            "impact_type": "info_disclosure",
            "confirmation": "key_accepted_only",
            "data_sensitivity": "none",
        }
    # Non-empty 200 → POTENTIAL open-RTDB / readable signal. Top-level keys
    # are a schema fingerprint; whether anything in there is sensitive needs
    # operator review. Severity must NOT be HIGH; tier MUST be POTENTIAL.
    return True, "potential_open_rtdb", {
        "impact": ("Potential open RTDB — readable without auth. Top-level "
                   "keys / shallow content returned; manual review needed to "
                   "confirm whether any sensitive customer data is exposed."),
        "impact_type": "info_disclosure",
        "confirmation": "key_accepted_only",
        "data_sensitivity": "metadata",
    }

_RTDB_READ_PROBE_NAME_MARKERS = (
    "Firebase RTDB root",
    "Firebase RTDB shallow keys",
)


def _canonical_rtdb_database_url(url):
    """Return the canonical database URL for an RTDB read probe URL by
    stripping `/.json`, the `?shallow=true` query, and any trailing slash.
    Returns `None` if `url` is missing or doesn't look like an RTDB read.

    Examples (each pair canonicalises to the same string):
      https://x.firebaseio.com/.json
      https://x.firebaseio.com/.json?shallow=true
        → https://x.firebaseio.com

      https://x-default-rtdb.europe-west1.firebasedatabase.app/.json
      https://x-default-rtdb.europe-west1.firebasedatabase.app/.json?shallow=true
        → https://x-default-rtdb.europe-west1.firebasedatabase.app

    A URL that doesn't end in `.json` (or `.json?…`) is returned as-is so
    callers can group unknown variants under their own bucket.
    """
    if not url or not isinstance(url, str):
        return None
    base = url.split("?", 1)[0]
    # Strip the `/.json` read-suffix specific to RTDB REST.
    if base.endswith("/.json"):
        base = base[: -len("/.json")]
    elif base.endswith(".json"):
        base = base[: -len(".json")]
    return base.rstrip("/")


def _is_rtdb_read_result(result):
    """True iff `result["name"]` looks like an RTDB root/shallow read probe.
    Matches the base names and derived-project variants
    (`… [project=foo]`, `… (extracted DATABASE_URL)` etc.)."""
    name = result.get("name") or ""
    return any(marker in name for marker in _RTDB_READ_PROBE_NAME_MARKERS)


def _dedup_rtdb_findings(results):
    """Collapse RTDB root + shallow findings that target the same canonical
    database URL into one finding. Mutates `results` in place and returns
    the count of dropped duplicates (0 if nothing to dedup).

    Preference rule when both variants are present for the same canonical
    URL: KEEP the shallow signal (minimal data returned, safer fingerprint),
    DROP the root variant. If only root or only shallow is present, the
    single result is kept untouched. Non-RTDB results are never touched.

    Empty-body opens (`Firebase RTDB open but empty`) are NOT collapsed
    against non-empty reads — the names differ and the open-empty finding
    is a separate, valid signal."""
    if not results:
        return 0
    # Walk results once, indexing RTDB-read findings by canonical URL.
    by_canon = {}
    for idx, r in enumerate(results):
        if not r.get("vulnerable"):
            continue
        if not _is_rtdb_read_result(r):
            continue
        canon = _canonical_rtdb_database_url(r.get("url"))
        if canon is None:
            continue
        by_canon.setdefault(canon, []).append(idx)
    drop_indices = set()
    for canon, group in by_canon.items():
        if len(group) < 2:
            continue
        # Prefer shallow — minimal data; falls back to first listed if no
        # shallow variant is in the group.
        shallow_idx = None
        for i in group:
            if "shallow" in (results[i].get("name") or "").lower():
                shallow_idx = i
                break
        keep_idx = shallow_idx if shallow_idx is not None else group[0]
        for i in group:
            if i != keep_idx:
                drop_indices.add(i)
    if not drop_indices:
        return 0
    # Build the deduped list, preserving original order for non-dropped rows.
    deduped = [r for i, r in enumerate(results) if i not in drop_indices]
    results[:] = deduped
    return len(drop_indices)


def _check_firebase_remote_config(r):
    """firebaseremoteconfig fetch — vulnerable if 200 with entries / state."""
    if r.status_code != 200:
        return False, None
    text = r.text or ""
    if "entries" in text or '"state"' in text or '"appName"' in text:
        return True, None
    return False, None


_STORAGE_OBJECT_READ_CAP_BYTES = 10240  # 10 KB max


def _try_firebase_storage_object_read(list_response, items):
    """Attempt one bounded read-only GET on the smallest listed object as a
    read confirmation. Returns True if a non-empty body came back.

    Strict ROE: read-only. Never writes, deletes, mutates, or uploads.
    Defense in depth on the byte cap:
      * HTTP `Range: bytes=0-(N-1)` header asks the server to return ≤ N bytes.
      * `stream=True` + `iter_content` reads at most N bytes regardless of
        whether the server respected the Range header (some Firebase Storage
        objects served via the CDN ignore Range and stream the full body).
      * Final slice `[:N]` is a third guardrail.
    The item-iteration cap (top-50 listed objects) bounds CPU on giant lists."""
    eligible = []
    for it in items[:50]:  # bound iteration
        if not isinstance(it, dict):
            continue
        try:
            sz = int(it.get("size", 0))
        except (TypeError, ValueError):
            continue
        name = it.get("name")
        bucket = it.get("bucket")
        if (isinstance(name, str) and name and isinstance(bucket, str)
                and re.fullmatch(r"[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]", bucket)
                and 0 < sz <= _STORAGE_OBJECT_READ_CAP_BYTES):
            eligible.append((sz, name, bucket))
    if not eligible:
        return False
    eligible.sort()
    _sz, obj_name, bucket = eligible[0]
    list_url = (getattr(list_response, "request", None)
                and getattr(list_response.request, "url", None)) or ""
    key_match = re.search(r"[?&]key=([^&]+)", list_url)
    if not key_match:
        return False
    apikey = key_match.group(1)
    from urllib.parse import quote
    download_url = (
        "https://firebasestorage.googleapis.com/v0/b/%s/o/%s?alt=media&key=%s"
        % (bucket, quote(obj_name, safe=""), apikey)
    )
    cap = _STORAGE_OBJECT_READ_CAP_BYTES
    headers = {"Range": "bytes=0-%d" % (cap - 1)}
    for name, value in (getattr(getattr(list_response, "request", None), "headers", {}) or {}).items():
        if name.lower() in {"referer", "origin", "x-ios-bundle-identifier", "x-android-package", "x-android-cert"}:
            headers[name] = value
    kwargs = _request_kwargs_for_url(download_url)
    kwargs["stream"] = True
    try:
        dr = requests.get(download_url, headers=headers, **kwargs)
    except requests.RequestException:
        return False
    try:
        # Client-side cap: stop reading once we've collected `cap` bytes,
        # regardless of what the server sends. Defends against a server that
        # ignores Range and streams the full file.
        chunks = []
        total = 0
        try:
            for chunk in dr.iter_content(chunk_size=4096, decode_unicode=False):
                if not chunk:
                    continue
                chunks.append(chunk)
                total += len(chunk)
                if total >= cap:
                    break
        except (requests.RequestException, AttributeError):
            return False
        body = b"".join(chunks)[:cap]
    finally:
        try:
            dr.close()
        except Exception:
            pass
    # 200 = full body (server ignored Range); 206 = partial content (Range honored).
    return dr.status_code in (200, 206) and len(body) > 0


def _check_firebase_storage_list(r):
    """Distinguish empty buckets from listed objects and try one bounded object read."""
    text = r.text or ""
    if "API_KEY_INVALID" in text or "API key not valid" in text:
        return False, None
    if r.status_code != 200:
        return False, None
    try:
        data = r.json()
    except Exception:
        return False, None
    if not isinstance(data, dict) or data.get("error"):
        return False, None
    if any(not isinstance(data.get(field, []), list) for field in ("items", "prefixes")):
        return False, None
    items    = data.get("items") if isinstance(data.get("items"), list) else []
    prefixes = data.get("prefixes") if isinstance(data.get("prefixes"), list) else []
    if not items and not prefixes:
        return True, "open_empty", {
            "name": "Firebase Storage bucket open but empty",
            "category": "low",
            "impact": "Info - Storage rules allow list, but bucket contains no objects",
            "impact_type": "info_disclosure",
            "confirmation": "key_accepted_only",
            "data_sensitivity": "none",
        }
    note = "items=%d prefixes=%d" % (len(items), len(prefixes))
    if items:
        try:
            if _try_firebase_storage_object_read(r, items):
                note += "; object_read_confirmed"
        except Exception:
            # Read-confirmation is best-effort; never let it mask the finding.
            pass
    return True, note, {
        "impact_type": "data_read",
        "confirmation": "confirmed_data",
        "data_sensitivity": "customer_data",
    }


def _check_firestore_documents(r):
    """Distinguish an empty document list from returned Firestore documents."""
    text = r.text or ""
    if "API_KEY_INVALID" in text or "API key not valid" in text:
        return False, None
    if r.status_code != 200:
        return False, None
    try:
        data = r.json()
    except Exception:
        return False, None
    if (not isinstance(data, dict) or data.get("error")
            or not isinstance(data.get("documents", []), list)
            or any(not isinstance(row, dict) for row in data.get("documents", []))):
        return False, None
    docs = data.get("documents")
    if not isinstance(docs, list) or not docs:
        return True, "documents_empty", {
            "name": "Firestore documents (open but empty)",
            "category": "low",
            "impact": ("Info - Firestore default DB reachable via API key but "
                       "returned no documents (empty DB or rules filter all docs)"),
            "impact_type": "info_disclosure",
            "confirmation": "key_accepted_only",
            "data_sensitivity": "none",
        }
    return True, "documents=%d" % len(docs), {
        "impact_type": "data_read",
        "confirmation": "confirmed_data",
        "data_sensitivity": "customer_data",
    }


def _authenticated_firestore_read(project_id, apikey, id_token, restriction_headers=None):
    """List collection identifiers using a scoped identity token; do not read documents."""
    if not _is_valid_googleapis_project_ref(project_id) or not id_token:
        return None
    base = "https://firestore.googleapis.com/v1/projects/%s/databases/(default)/documents" % project_id
    list_url = base + ":listCollectionIds?key=" + apikey
    headers = {**_client_restriction_headers(restriction_headers),
               "Authorization": "Bearer " + id_token,
               "Content-Type":  "application/json"}
    try:
        r = requests.post(list_url, headers=headers, data="{}",
                          **_request_kwargs_for_url(list_url))
    except requests.RequestException:
        _record_transport_error("other")
        return None
    text = r.text or ""
    if "API_KEY_INVALID" in text or "API key not valid" in text:
        return None
    if r.status_code in (401, 403):
        # Rules enforced — not a finding, but informative as a no-result.
        return {
            "name":   "signUp + authenticated Firestore read [project=%s]" % project_id,
            "category": "destructive",
            "url":    list_url,
            "impact": "Firestore listCollectionIds rejected for authenticated token",
            "vulnerable": False,
            "manual_note": "auth_read_denied_http_%d" % r.status_code,
            "referer_blocked": False,
            "error_class": "PERMISSION_DENIED",
            "services_seen": {"firestore.googleapis.com"},
            "reason": (text[:200] or ""),
            "gemini_disabled": False,
            "status_code": r.status_code,
            "snippet": None,
            "tier":             "CONFIRMED",
            "impact_type":      "info_disclosure",
            "confirmation":     "key_accepted_only",
            "data_sensitivity": "none",
            "severity":         "INFO",
        }
    if r.status_code == 429 or r.status_code >= 500:
        _record_transport_error("other")
    if r.status_code != 200:
        return None
    try:
        data = r.json()
    except (ValueError, TypeError):
        _record_transport_error("other")
        return None
    if (not isinstance(data, dict) or data.get("error")
            or not isinstance(data.get("collectionIds", []), list)
            or any(not isinstance(row, str) for row in data.get("collectionIds", []))):
        _record_transport_error("other")
        return None
    collection_ids = data.get("collectionIds") if isinstance(data, dict) else None
    if not isinstance(collection_ids, list) or not collection_ids:
        # Reachable but no collections (or DB empty) — INFO.
        return {
            "name":   "signUp + authenticated Firestore read [project=%s]" % project_id,
            "category": "destructive",
            "url":    list_url,
            "impact": ("Firestore authenticated read reachable — no collections "
                       "returned (empty DB or rules filter listCollectionIds)"),
            "vulnerable": True,
            "manual_note": "auth_read_collections_empty",
            "referer_blocked": False,
            "error_class": None,
            "services_seen": {"firestore.googleapis.com"},
            "reason": "",
            "gemini_disabled": False,
            "status_code": r.status_code,
            "snippet": None,
            "tier":             "CONFIRMED",
            "impact_type":      "info_disclosure",
            "confirmation":     "key_accepted_only",
            "data_sensitivity": "none",
            "severity":         "INFO",
        }
    # Confirmed customer data — collections enumerated. The verdict is
    # AUTHORIZATION GRANTED, NOT the contents — count only.
    n_collections = len(collection_ids)
    return {
        "name":   "signUp + authenticated Firestore read [project=%s]" % project_id,
        "category": "destructive",
        "url":    list_url,
        "impact": ("Firestore authenticated read confirmed — %d collection(s) "
                   "enumerated via signUp-minted idToken (document values "
                   "NOT read by the scanner)" % n_collections),
        "vulnerable": True,
        "manual_note": "auth_read_collections=%d" % n_collections,
        "referer_blocked": False,
        "error_class": None,
        "services_seen": {"firestore.googleapis.com"},
        "reason": "",
        "gemini_disabled": False,
        "status_code": r.status_code,
        "snippet": None,
        "tier":             "CONFIRMED",
        "impact_type":      "data_read",
        "confirmation":     "confirmed_data",
        "data_sensitivity": "customer_data",
        "severity":         "HIGH",
    }


_RTDB_AUTH_REDACTED = "<redacted>"


def _scrub_token_from_finding(finding, token):
    """Remove a known authentication token from string fields in a finding."""
    if not finding or not token:
        return finding
    for k, v in list(finding.items()):
        if isinstance(v, str) and token in v:
            finding[k] = v.replace(token, _RTDB_AUTH_REDACTED)
    return finding


def _authenticated_rtdb_read(database_url, id_token):
    """Read top-level RTDB keys using an identity token and redact the request URL."""
    database_url = _validated_rtdb_url(database_url)
    if not database_url or not id_token:
        return None
    real_url = database_url.rstrip("/") + "/.json?shallow=true&auth=" + id_token
    safe_url = database_url.rstrip("/") + "/.json?shallow=true&auth=" + _RTDB_AUTH_REDACTED
    try:
        r = requests.get(real_url, **_request_kwargs_for_url(real_url))
    except requests.RequestException:
        _record_transport_error("other")
        return None
    text = (r.text or "").strip()
    if r.status_code in (401, 403) or "Permission denied" in text:
        return _scrub_token_from_finding({
            "name":   "signUp + authenticated RTDB shallow read",
            "category": "destructive",
            "url":    safe_url,
            "impact": "RTDB rules deny the authenticated token",
            "vulnerable": False,
            "manual_note": "auth_read_denied",
            "referer_blocked": False,
            "error_class": "PERMISSION_DENIED",
            "services_seen": set(),
            "reason": text[:200],
            "gemini_disabled": False,
            "status_code": r.status_code,
            "snippet": None,
            "tier":             "CONFIRMED",
            "impact_type":      "info_disclosure",
            "confirmation":     "key_accepted_only",
            "data_sensitivity": "none",
            "severity":         "INFO",
        }, id_token)
    if r.status_code == 429 or r.status_code >= 500:
        _record_transport_error("other")
    if r.status_code != 200:
        return None
    try:
        keys_map = r.json()
    except (ValueError, TypeError):
        _record_transport_error("other")
        return None
    if isinstance(keys_map, float) and not math.isfinite(keys_map):
        _record_transport_error("other")
        return None
    if isinstance(keys_map, list) or (isinstance(keys_map, dict)
            and any(value is not True for value in keys_map.values())):
        _record_transport_error("other")
        return None
    if keys_map is None or keys_map == {}:
        # Reachable but empty.
        return _scrub_token_from_finding({
            "name":   "signUp + authenticated RTDB shallow read",
            "category": "destructive",
            "url":    safe_url,
            "impact": "RTDB authenticated read reachable — DB empty (no top-level keys)",
            "vulnerable": True,
            "manual_note": "auth_read_rtdb_empty",
            "referer_blocked": False,
            "error_class": None,
            "services_seen": set(),
            "reason": "",
            "gemini_disabled": False,
            "status_code": r.status_code,
            "snippet": None,
            "tier":             "CONFIRMED",
            "impact_type":      "info_disclosure",
            "confirmation":     "key_accepted_only",
            "data_sensitivity": "none",
            "severity":         "INFO",
        }, id_token)
    # Non-empty shallow body — top-level keys enumerated. Discard values.
    n_keys = len(keys_map) if isinstance(keys_map, dict) else None
    impact = ("RTDB authenticated read confirmed — %d top-level key(s) enumerated; values not retrieved" % n_keys
              if n_keys is not None else "RTDB authenticated read returned a primitive root value; value discarded")
    return _scrub_token_from_finding({
        "name":   "signUp + authenticated RTDB shallow read",
        "category": "destructive",
        "url":    safe_url,
        "impact": impact,
        "vulnerable": True,
        "manual_note": ("auth_read_rtdb_keys=%d" % n_keys if n_keys is not None else "auth_read_rtdb_primitive"),
        "referer_blocked": False,
        "error_class": None,
        "services_seen": set(),
        "reason": "",
        "gemini_disabled": False,
        "status_code": r.status_code,
        "snippet": None,
        "tier":             "CONFIRMED",
        "impact_type":      "data_read",
        "confirmation":     "confirmed_data",
        "data_sensitivity": "customer_data",
        "severity":         "HIGH",
    }, id_token)


def _authenticated_storage_list(storage_bucket, apikey, id_token, restriction_headers=None):
    """List storage metadata using the supplied identity token; do not download objects."""
    if (not isinstance(storage_bucket, str)
            or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]", storage_bucket)
            or not id_token):
        return None
    url = ("https://firebasestorage.googleapis.com/v0/b/%s/o?key=%s"
           % (storage_bucket, apikey))
    headers = {**_client_restriction_headers(restriction_headers),
               "Authorization": "Bearer " + id_token}
    try:
        r = requests.get(url, headers=headers, **_request_kwargs_for_url(url))
    except requests.RequestException:
        _record_transport_error("other")
        return None
    text = r.text or ""
    if r.status_code in (401, 403) or "API_KEY_INVALID" in text:
        return {
            "name":   "signUp + authenticated Storage list",
            "category": "destructive",
            "url":    url,
            "impact": "Storage rules deny the authenticated token",
            "vulnerable": False,
            "manual_note": "auth_read_denied",
            "referer_blocked": False,
            "error_class": "PERMISSION_DENIED",
            "services_seen": {"firebasestorage.googleapis.com"},
            "reason": text[:200],
            "gemini_disabled": False,
            "status_code": r.status_code,
            "snippet": None,
            "tier":             "CONFIRMED",
            "impact_type":      "info_disclosure",
            "confirmation":     "key_accepted_only",
            "data_sensitivity": "none",
            "severity":         "INFO",
        }
    if r.status_code == 429 or r.status_code >= 500:
        _record_transport_error("other")
    if r.status_code != 200:
        return None
    try:
        data = r.json()
    except (ValueError, TypeError):
        _record_transport_error("other")
        return None
    if (not isinstance(data, dict) or data.get("error")
            or not isinstance(data.get("items", []), list)
            or any(not isinstance(row, dict) for row in data.get("items", []))):
        _record_transport_error("other")
        return None
    items = data.get("items") if isinstance(data, dict) else None
    n_items = len(items) if isinstance(items, list) else 0
    if n_items == 0:
        return {
            "name":   "signUp + authenticated Storage list",
            "category": "destructive",
            "url":    url,
            "impact": "Storage authenticated list reachable — bucket empty",
            "vulnerable": True,
            "manual_note": "auth_read_storage_empty",
            "referer_blocked": False,
            "error_class": None,
            "services_seen": {"firebasestorage.googleapis.com"},
            "reason": "",
            "gemini_disabled": False,
            "status_code": r.status_code,
            "snippet": None,
            "tier":             "CONFIRMED",
            "impact_type":      "info_disclosure",
            "confirmation":     "key_accepted_only",
            "data_sensitivity": "none",
            "severity":         "INFO",
        }
    return {
        "name":   "signUp + authenticated Storage list",
        "category": "destructive",
        "url":    url,
        "impact": ("Storage authenticated list confirmed — %d object(s) "
                   "enumerated via signUp-minted idToken (object bytes "
                   "NOT downloaded)" % n_items),
        "vulnerable": True,
        "manual_note": "auth_read_storage_items=%d" % n_items,
        "referer_blocked": False,
        "error_class": None,
        "services_seen": {"firebasestorage.googleapis.com"},
        "reason": "",
        "gemini_disabled": False,
        "status_code": r.status_code,
        "snippet": None,
        "tier":             "CONFIRMED",
        "impact_type":      "data_read",
        "confirmation":     "confirmed_data",
        "data_sensitivity": "customer_data",
        "severity":         "HIGH",
    }


def _run_authenticated_read_chain(apikey, id_token, local_id=None, restriction_headers=None):
    """Run all three auth-read probes and append findings to
    `_AUTH_READ_FINDINGS`. Gated by `_AUTH_READ_ENABLED` AND
    `_AUTH_READ_SCOPE_OK`. Safe to call unconditionally — the gating
    short-circuits when either is False.

    Resolves the target Firebase resources from this scan's Phase 0 project
    IDs and Firebase configs. Mobile callers pass key-scoped configs through
    `_AUTH_READ_FIREBASE_CONFIGS`; `None` preserves legacy web/single-key
    behavior and uses the process-global config store.

    The idToken is the operator's responsibility to delete via the caller's
    cleanup path. This function does NOT delete the token (that stays with
    `_check_it_signup_anon`)."""
    if not _AUTH_READ_ENABLED:
        return []
    if not _AUTH_READ_SCOPE_OK:
        return []
    findings = []

    with _DERIVED_LOCK:
        derived_pids = sorted(_DERIVED_PROJECT_IDS)
    if _AUTH_READ_FIREBASE_CONFIGS is not None:
        configs = [dict(c) for c in _AUTH_READ_FIREBASE_CONFIGS if c]
    else:
        with _DERIVED_FIREBASE_LOCK:
            configs = list(_DERIVED_FIREBASE_CONFIGS)
    candidate_projects = set(derived_pids)
    for c in configs:
        cid = c.get("project_id")
        if cid:
            candidate_projects.add(cid)
    # Never read against the placeholder project (defensive — derivation
    # should never surface it, but a stray entry must not leak in).
    candidate_projects.discard(_PLACEHOLDER_PROJECT_ID)
    candidate_db_urls   = {c.get("database_url")   for c in configs if c.get("database_url")}
    candidate_buckets   = {c.get("storage_bucket") for c in configs if c.get("storage_bucket")}
    # Add the default-bucket guess for each derived project (Firebase default).
    for pid in candidate_projects:
        if _is_valid_firebase_hostname_project_id(pid):
            candidate_buckets.add("%s.appspot.com" % pid)
    request_options = {"restriction_headers": restriction_headers} if restriction_headers else {}
    # Firestore — one read per project_id.
    for pid in candidate_projects:
        f = _authenticated_firestore_read(pid, apikey, id_token, **request_options)
        if f is not None:
            findings.append(f)
    # RTDB — one read per extracted DATABASE_URL.
    for db in candidate_db_urls:
        f = _authenticated_rtdb_read(db, id_token)
        if f is not None:
            findings.append(f)
    # Storage — one list per bucket.
    for sb in candidate_buckets:
        f = _authenticated_storage_list(sb, apikey, id_token, **request_options)
        if f is not None:
            findings.append(f)

    findings = [_scrub_token_from_finding(f, id_token) for f in findings]
    if findings:
        with _AUTH_READ_LOCK:
            _AUTH_READ_FINDINGS.extend(findings)
    return findings


def _check_firebase_dynamic_links(r):
    """Classify link creation separately from request-validation evidence."""
    text = (r.text or "")
    if "API_KEY_INVALID" in text or "API key not valid" in text:
        return False, None
    if r.status_code in (401, 403):
        return False, None
    # Defense-in-depth: a successful create leaks a live redirect. Record
    # the URL so the operator can request takedown manually.
    if r.status_code == 200 and "shortLink" in text:
        try:
            data = r.json()
            short_link = data.get("shortLink") or "(unknown)"
        except Exception:
            short_link = "(unknown)"
        _it_record_artifact(
            "Firebase Dynamic Links shortLinks create",
            local_id=short_link, id_token=None,
            reason=("Firebase Dynamic Links API has no public delete endpoint; "
                    "operator must request manual takedown via Firebase console"))
        return True, "cleanup_failed_live_link=%s" % short_link, {
            "impact_type": "data_write",
            "confirmation": "confirmed_data",
            "data_sensitivity": "customer_data",
        }
    # Capability-only path: empty/invalid body forces 400 validation error
    # without creating a link.
    if r.status_code == 400 and ("INVALID_" in text or "MISSING_" in text
                                  or "INVALID_ARGUMENT" in text):
        return True, "capability_only_no_link_created", {
            "impact_type": "info_disclosure",
            "confirmation": "key_accepted_only",
            "data_sensitivity": "none",
        }
    return False, None


# Project-scoped chain probes — executed in phase 2, once per derived project.
# Same tuple shape as ALL_PROBES (the {project} token in URLs is substituted
# per-derived-project at execution time).
FIREBASE_CHAIN_PROBES = [
    ("Firebase RTDB root (.json)", "high", "GET",
        "https://{project}.firebaseio.com/.json",
        None, _check_firebase_rtdb_root,
        "Realtime Database root read — full DB dump if no rules"),
    ("Firebase RTDB shallow keys", "high", "GET",
        "https://{project}.firebaseio.com/.json?shallow=true",
        None, _check_firebase_rtdb_root,
        "Realtime Database top-level key list"),

    ("Firebase RTDB root (regional default)", "high", "GET",
        "https://{project}-default-rtdb.firebaseio.com/.json",
        None, _check_firebase_rtdb_root,
        "Realtime Database root read — regional default URL pattern"),
    ("Firebase RTDB shallow keys (regional default)", "high", "GET",
        "https://{project}-default-rtdb.firebaseio.com/.json?shallow=true",
        None, _check_firebase_rtdb_root,
        "Realtime Database top-level key list — regional default URL pattern"),

    ("Firebase RTDB root (europe-west1)", "high", "GET",
        "https://{project}-default-rtdb.europe-west1.firebasedatabase.app/.json",
        None, _check_firebase_rtdb_root,
        "RTDB root read — europe-west1 regional fallback (.firebasedatabase.app)"),
    ("Firebase RTDB root (asia-southeast1)", "high", "GET",
        "https://{project}-default-rtdb.asia-southeast1.firebasedatabase.app/.json",
        None, _check_firebase_rtdb_root,
        "RTDB root read — asia-southeast1 regional fallback (.firebasedatabase.app)"),

    ("Firestore documents (default DB)", "high", "GET",
        "https://firestore.googleapis.com/v1/projects/{project}/databases/(default)/documents?key={key}",
        None, _check_firestore_documents,
        "Firestore default-DB documents list — HIGH if customer data returned, INFO if empty"),
    ("Firebase Remote Config fetch", "high", "POST",
        "https://firebaseremoteconfig.googleapis.com/v1/projects/{project}/namespaces/firebase:fetch?key={key}",
        '{"appInstanceId":"PROBE","appId":"PROBE","appBuild":"1"}',
        _check_firebase_remote_config,
        "Remote Config entries — feature flags, A/B config, may contain secrets"),
    ("Firebase Storage list (default bucket)", "high", "GET",
        "https://firebasestorage.googleapis.com/v0/b/{project}.appspot.com/o?key={key}",
        None, _check_firebase_storage_list,
        "Storage bucket file listing — frequently exposes private uploads"),
    ("Firebase Storage list (.firebasestorage.app)", "high", "GET",
        "https://firebasestorage.googleapis.com/v0/b/{project}.firebasestorage.app/o?key={key}",
        None, _check_firebase_storage_list,
        "Storage bucket file listing (new default bucket naming)"),

    ("Firebase Dynamic Links shortLinks (capability)", "destructive", "POST",
        "https://firebasedynamiclinks.googleapis.com/v1/shortLinks?key={key}",
        '{}',
        _check_firebase_dynamic_links,
        "Firebase Dynamic Links endpoint accepts key — capability only (empty payload; no live link created)"),
    ("Firebase RTDB write probe", "destructive", "PUT",
        "https://{project}.firebaseio.com/{probe_path}.json",
        '"probe"', _check_firebase_rtdb_root,
        "RTDB write capability — attempts to write a probe key then delete it"),
    ("Firebase App Check exchangeDebugToken", "destructive", "POST",
        "https://firebaseappcheck.googleapis.com/v1/projects/{project}/apps/INVALID_APP_ID:exchangeDebugToken?key={key}",
        '{"debugToken":"00000000-0000-0000-0000-000000000000"}',
        _check_it_key_accepted_not_invalid,
        "App Check bypass — if key accepts the call, debug-token exchange may be open"),
]

# (Abuse class overrides for new probes are recorded post-ALL_PROBES below.)
