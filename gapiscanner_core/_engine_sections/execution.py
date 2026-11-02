_SPEECH_OPERATION_PROBE_NAMES = frozenset({"Speech Operations"})


def _count_speech_transcripts(value):
    """Count non-empty transcript fields without retaining their contents."""
    if isinstance(value, dict):
        count = 0
        for key, child in value.items():
            if key == "transcript" and isinstance(child, str) and child.strip():
                count += 1
            else:
                count += _count_speech_transcripts(child)
        return count
    if isinstance(value, list):
        return sum(_count_speech_transcripts(child) for child in value)
    return 0


def _speech_operation_detail_url(list_url, operation_name, apikey):
    """Build a same-host Speech operation-detail URL from a list row."""
    if not isinstance(operation_name, str):
        return None
    operation_name = operation_name.strip().lstrip("/")
    # Speech v1 currently returns bare numeric operation IDs from the list
    # endpoint, even though the detail resource lives at
    # ``/v1/operations/<id>``. Normalize that documented live shape before
    # applying the same-host/path validation below.
    if re.fullmatch(r"[0-9]+", operation_name):
        operation_name = "operations/" + operation_name
    if not operation_name.startswith(("operations/", "projects/")):
        return None
    if (".." in operation_name or "://" in operation_name
            or not re.fullmatch(r"[A-Za-z0-9._~/-]+", operation_name)):
        return None
    parsed = urlparse(list_url)
    if parsed.scheme != "https" or parsed.netloc != "speech.googleapis.com":
        return None
    marker = "/operations"
    marker_at = parsed.path.rfind(marker)
    if marker_at < 0:
        return None
    api_root = parsed.path[:marker_at].rstrip("/")
    return "%s://%s%s/%s?key=%s" % (
        parsed.scheme, parsed.netloc, api_root, operation_name, apikey)


def _inspect_speech_operations(response, list_url, apikey, headers, kwargs,
                               max_details=50):
    """Inspect operation details and return only redacted aggregate evidence.

    Speech list responses often contain names/metadata but omit completed
    recognition results. Follow the documented read-only operation-detail
    resource until a transcript is found or the current page is exhausted.
    Raw operation names and transcript text never leave this helper.
    """
    evidence = {
        "operation_count": 0,
        "response_count": 0,
        "transcript_count": 0,
        "detail_attempted": 0,
        "detail_200": 0,
        "detail_status_histogram": {},
        "detail_transport_errors": 0,
        "detail_incomplete": False,
        "operation_name_hashes": [],
    }
    if response.status_code != 200:
        return evidence
    try:
        payload = json.loads(response.text or "")
    except (json.JSONDecodeError, ValueError):
        return evidence
    operations = payload.get("operations") if isinstance(payload, dict) else None
    if not isinstance(operations, list):
        return evidence

    operations = [row for row in operations if isinstance(row, dict)]
    evidence["operation_count"] = len(operations)
    pending = []
    for operation in operations:
        response_payload = operation.get("response")
        if response_payload:
            evidence["response_count"] += 1
            evidence["transcript_count"] += _count_speech_transcripts(
                response_payload)
        else:
            pending.append(operation)
    if evidence["transcript_count"]:
        return evidence

    # Completed rows are the most likely to have a response available.
    pending.sort(key=lambda row: bool(row.get("done")), reverse=True)
    for operation in pending[:max_details]:
        operation_name = operation.get("name")
        detail_url = _speech_operation_detail_url(
            list_url, operation_name, apikey)
        if not detail_url:
            continue
        evidence["operation_name_hashes"].append(
            hashlib.sha256(operation_name.encode("utf-8")).hexdigest()[:12])
        evidence["detail_attempted"] += 1
        try:
            detail_response = requests.get(detail_url, headers=headers, **kwargs)
        except requests.exceptions.Timeout:
            _record_transport_error("timeout")
            evidence["detail_transport_errors"] += 1
            evidence["detail_incomplete"] = True
            continue
        except requests.exceptions.SSLError:
            _record_transport_error("ssl")
            evidence["detail_transport_errors"] += 1
            evidence["detail_incomplete"] = True
            continue
        except requests.exceptions.ConnectionError:
            _record_transport_error("connection")
            evidence["detail_transport_errors"] += 1
            evidence["detail_incomplete"] = True
            continue
        except requests.RequestException:
            _record_transport_error("other")
            evidence["detail_transport_errors"] += 1
            evidence["detail_incomplete"] = True
            continue

        status_key = str(detail_response.status_code)
        histogram = evidence["detail_status_histogram"]
        histogram[status_key] = histogram.get(status_key, 0) + 1
        if detail_response.status_code == 429:
            _record_transport_error("other")
            evidence["detail_incomplete"] = True
            break
        if detail_response.status_code != 200:
            if detail_response.status_code >= 500:
                _record_transport_error("other")
                evidence["detail_incomplete"] = True
            continue
        evidence["detail_200"] += 1
        try:
            detail_payload = json.loads(detail_response.text or "")
        except (json.JSONDecodeError, ValueError):
            _record_transport_error("other")
            evidence["detail_incomplete"] = True
            continue
        if not isinstance(detail_payload, dict):
            _record_transport_error("other")
            evidence["detail_incomplete"] = True
            continue
        response_payload = (
            detail_payload.get("response")
            if isinstance(detail_payload, dict) else None
        )
        if response_payload:
            evidence["response_count"] += 1
            evidence["transcript_count"] += _count_speech_transcripts(
                response_payload)
        if evidence["transcript_count"]:
            break
    if len(pending) > max_details and not evidence["transcript_count"]:
        _record_transport_error("other")
        evidence["detail_incomplete"] = True
    return evidence


def _classify_speech_operations(response, evidence):
    """Classify Speech operations using transcript-aware detail evidence."""
    base = _check_non_empty_operations_list(response)
    if not base[0]:
        return base
    if evidence.get("transcript_count", 0) > 0:
        return True, None, {
            "impact": "Speech operation transcript data exposed",
            "impact_type": "data_read",
            "confirmation": "confirmed_data",
            "data_sensitivity": "customer_data",
            "severity": "HIGH",
        }
    note = "Operation metadata exposed; no transcript returned by detail reads."
    if evidence.get("detail_incomplete"):
        note = "Operation metadata exposed; transcript detail follow-up incomplete."
    return True, note, {
        "impact": "Operation metadata exposed; no transcript data confirmed",
        "impact_type": "info_disclosure",
        "confirmation": "confirmed_data",
        "data_sensitivity": "metadata",
        "severity": "LOW",
    }


def _execute_probe(probe_tuple, apikey, project_id, base_headers, verbose=False):
    """Execute a single probe. Returns result dict or None on connection error.

    Probe tuple is 7 fields by default, with an optional 8th element:
        (name, cat, method, url_template, body, check_type, impact, [extras])
    where extras is a dict allowing per-probe overrides:
        - 'auth_header': header template string (e.g. 'key={key}') merged into
          the Authorization header.
        - 'content_type': override default application/json body content type.
    """
    extras = probe_tuple[7] if len(probe_tuple) >= 8 else {}
    name, cat, method, url_template, body, check_type, impact = probe_tuple[:7]
    pid = project_id or "test-project-123"
    url = url_template.replace("{key}", apikey).replace("{project}", pid)

    if "{probe_path}" in url:
        import uuid
        url = url.replace("{probe_path}", "__gapiscanner_probe__" + uuid.uuid4().hex)

    custom_executor = extras.get("custom_executor")
    if callable(custom_executor):
        return custom_executor(
            name, method, url, body, extras, apikey, base_headers
        )

    if extras.get("requires_derived_project") and (
            not project_id or project_id == _PLACEHOLDER_PROJECT_ID):
        if verbose:
            print("SKIP %s — no real project ID/number was supplied or derived"
                  % name)
        return None


    if cat in _DANGEROUS_CATEGORIES:
        _derived_pids_snapshot = set()
        with _DERIVED_LOCK:
            _derived_pids_snapshot.update(_DERIVED_PROJECT_IDS)
        with _DERIVED_FIREBASE_LOCK:
            for _cfg in _DERIVED_FIREBASE_CONFIGS:
                if not isinstance(_cfg, dict):
                    continue
                _cfg_pid = _cfg.get("project_id")
                if _cfg_pid:
                    _derived_pids_snapshot.add(_cfg_pid)
        _skip_reason = _dangerous_probe_skip_reason(
            probe_tuple, url, sorted(_derived_pids_snapshot))
        if _skip_reason is not None:
            print("SKIP %s — %s" % (name, _skip_reason))
            return None

    headers = {**base_headers}
    if body:
        headers["Content-Type"] = extras.get("content_type", "application/json")

    auth_tmpl = extras.get("auth_header")
    if auth_tmpl:
        headers["Authorization"] = auth_tmpl.replace("{key}", apikey)

    # Routes API needs X-Goog-FieldMask
    if name in _ROUTES_FIELD_MASKS:
        headers["X-Goog-FieldMask"] = _ROUTES_FIELD_MASKS[name]


    kwargs = _request_kwargs_for_url(url)
    if check_type == "302":
        kwargs["allow_redirects"] = False

    try:
        if method == "GET":
            r = requests.get(url, headers=headers, **kwargs)
        elif method == "POST":
            r = requests.post(url, headers=headers, data=body, **kwargs)
        elif method == "PUT":
            r = requests.put(url, headers=headers, data=body, **kwargs)
        elif method == "DELETE":
            r = requests.delete(url, headers=headers, **kwargs)
        else:
            return None
    except requests.exceptions.SSLError as e:
        # MUST surface — silently swallowing meant "no vulnerable APIs found"
        # got printed even when every probe failed at the TLS handshake
        # (TLS interception gateway with a CA not in certifi).
        _record_transport_error("ssl")
        msg = _safe_error_excerpt(str(e)) if str(e) else "SSLError"
        print("[!] TLS error on '%s': %s" % (name, msg))
        print("    Hint: rerun with --insecure to skip TLS verification "
              "(corp/MITM proxy).")
        return None
    except requests.exceptions.Timeout as e:
        _record_transport_error("timeout")
        print("[!] Timeout on '%s' (%s)" % (name, _safe_error_excerpt(str(e), 120)))
        return None
    except requests.exceptions.ConnectionError as e:
        _record_transport_error("connection")
        msg = _safe_error_excerpt(str(e)) if str(e) else "ConnectionError"
        print("[!] Connection error on '%s': %s" % (name, msg))
        return None
    except requests.RequestException as e:
        _record_transport_error("other")
        msg = _safe_error_excerpt(str(e)) if str(e) else type(e).__name__
        print("[!] Request failed on '%s': %s" % (name, msg))
        return None

    if r.status_code == 429 or r.status_code >= 500:
        _record_transport_error("other")

    check_fn = _parse_check(check_type)

    if callable(check_type):
        _check_signature = getattr(check_type, "__name__", "callable")
    else:
        _check_signature = str(check_type) if check_type is not None else ""
    _check_signature = _redact_diagnostic_secret_text(_check_signature)
    operation_evidence = None
    if name in _SPEECH_OPERATION_PROBE_NAMES:
        operation_evidence = _inspect_speech_operations(
            r, url, apikey, headers, kwargs)
        check_result = _classify_speech_operations(r, operation_evidence)
    else:
        try:
            check_result = check_fn(r)
        except (ValueError, TypeError, AttributeError) as exc:
            _record_transport_error("other")
            print("[!] Invalid response shape for '%s' (%s); scan incomplete."
                  % (name, type(exc).__name__))
            return None

    overrides = None
    if len(check_result) >= 3:
        vulnerable, manual_note, overrides = check_result[0], check_result[1], check_result[2]
    else:
        vulnerable, manual_note = check_result

    if (not vulnerable and r.status_code == 200
            and check_type not in ("image", "302")
            and _json_payload(r) is None
            and (r.text or "").lstrip("\ufeff").strip() != "null"):
        _record_transport_error("other")
        manual_note = manual_note or "invalid_json_response"

    # Harvest project IDs / numbers leaked in the response (error messages, body)
    ids_leaked, nums_leaked = _extract_project_ids(r.text or "")
    if ids_leaked or nums_leaked:
        with _DERIVED_LOCK:
            _DERIVED_PROJECT_IDS.update(ids_leaked)
            _DERIVED_PROJECT_NUMBERS.update(nums_leaked)

    # Harvest metadata.service values for allowlist inference. Successful 200
    # responses don't carry `details[].metadata.service` (Google only emits it
    # in error envelopes), so fall back to the request URL's host — that way
    # a vulnerable probe lands in the `allowed` bucket of the allowlist report.
    services_seen = _extract_service_metadata(r.text or "")
    if not services_seen:
        m = re.match(r"https?://([a-z0-9.-]+\.googleapis\.com)/", url)
        if m:
            services_seen = {m.group(1)}

    reason = _redact_diagnostic_secret_text(_extract_error_reason(r))
    error_class = _classify_error(r) if not vulnerable else None

    # Backwards-compat: referer_blocked surfaced separately for existing reporting
    referer_blocked = (error_class == "REFERRER_BLOCKED")

    gemini_disabled = (
        name == "Gemini Models List"
        and not vulnerable
        and error_class in ("API_DISABLED", "KEY_EXPIRED", "KEY_INVALID", "SERVICE_BLOCKED")
    )

    # Apply per-result overrides from check_fn (e.g., 403 name-disclosure
    # downgrade for Service Management, empty RTDB demotion). Only applied
    # when the probe is actually vulnerable — non-vulns keep default
    # metadata for reporting.
    final_name = name
    final_cat = cat
    final_impact = impact
    if vulnerable and overrides:
        final_name = overrides.get("name", final_name)
        final_cat = overrides.get("category", final_cat)
        final_impact = overrides.get("impact", final_impact)


    impact_type, confirmation, data_sensitivity = _resolve_response_fields(
        final_name, final_cat,
        overrides if (vulnerable and overrides) else None,
    )

    if _is_key_acceptance_check(check_fn):
        confirmation = "key_accepted_only"
    severity = _derive_severity(impact_type, confirmation, data_sensitivity)
    if vulnerable and overrides and "severity" in overrides:
        severity = overrides["severity"]

    followup_required = None
    if (vulnerable
            and final_name == (
                "Identity Toolkit signUp anon "
                "(account creation + auto-cleanup)")
            and not str(manual_note or "").startswith("cleanup_failed")):
        followup_required = "identity_toolkit_app_backend_chain"

    return {
        "name": final_name,
        "category": final_cat,
        "abuse_class": _get_abuse_class(final_name, final_cat),
        "url": url,
        "impact": final_impact,
        "vulnerable": vulnerable,
        "manual_note": manual_note,
        "referer_blocked": referer_blocked,
        "error_class": error_class,
        "services_seen": services_seen,
        "reason": reason,
        "gemini_disabled": gemini_disabled,
        "status_code": r.status_code,
        # Speech bodies can contain victim transcript text. Verbose output
        # receives only aggregate evidence for that probe.
        "snippet": (
            json.dumps({"operation_evidence": operation_evidence}, sort_keys=True)
            if verbose and operation_evidence is not None
            else (_safe_error_excerpt(r.text, 800) if verbose else None)
        ),
        "operation_evidence": operation_evidence,

        "impact_type": impact_type,
        "confirmation": confirmation,
        "data_sensitivity": data_sensitivity,
        "severity": severity,
        "followup_required": followup_required,

        "check_signature": _check_signature,
    }


_KEY_QUERY_REDACT_RE = re.compile(r"([?&]key=)[^&#]*", re.IGNORECASE)


def _redact_key_from_url(url):
    if not url or not isinstance(url, str):
        return url
    return _KEY_QUERY_REDACT_RE.sub(r"\1<redacted>", url)


_DIAG_AIZA_RE     = re.compile(r"AIza[0-9A-Za-z_-]{30,40}")

_DIAG_QUERY_KEY_RE = re.compile(r"([?&]key=)[^&#\s\"']+", re.IGNORECASE)
_YA29_TOKEN_RE    = re.compile(r"\bya29\.[A-Za-z0-9_-]+\b")
_BEARER_HEADER_RE = re.compile(
    r"(authorization\s*:\s*Bearer\s+)[A-Za-z0-9._-]+",
    re.IGNORECASE,
)
_JWT_LIKE_RE = re.compile(
    r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}(?:\.[A-Za-z0-9_-]{5,})?"
)


def _redact_diagnostic_secret_text(text):
    """Return a copy of `text` with API keys, OAuth bearer tokens, and
    idToken-shaped JWTs replaced by inert placeholders. Diagnostic-
    only — used by `_safe_error_excerpt` and downstream audit tooling
    so reason / excerpt / method fields are safe by construction.

    The function is intentionally idempotent: re-running it on an
    already-redacted string is a no-op."""
    if not text or not isinstance(text, str):
        return text
    redacted = _DIAG_AIZA_RE.sub("<AIza-redacted>", text)

    redacted = _DIAG_QUERY_KEY_RE.sub(r"\1<redacted>", redacted)
    redacted = _YA29_TOKEN_RE.sub("<ya29-redacted>", redacted)
    redacted = _BEARER_HEADER_RE.sub(r"\1<redacted>", redacted)
    redacted = _JWT_LIKE_RE.sub("<jwt-redacted>", redacted)
    return redacted


def _safe_error_excerpt(text, limit=240):
    """Return a redacted, single-line excerpt capped at the requested length."""
    if not text:
        return ""
    cleaned = re.sub(r"\s+", " ", str(text)).strip()
    cleaned = _redact_diagnostic_secret_text(cleaned)
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[:limit] + " ..."


def _redact_public_payload(value):
    """Scrub nested report data without modifying the internal scan results."""
    if isinstance(value, dict):
        return {key: _redact_public_payload(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact_public_payload(item) for item in value]
    return _redact_diagnostic_secret_text(value)


def _extract_error_method(text):
    """Extract and redact an RPC method name from response metadata."""
    if not text:
        return ""
    m = re.search(r'"method"\s*:\s*"([^"]+)"', text[:5000])
    if not m:
        return ""
    return _redact_diagnostic_secret_text(m.group(1))


def _diag_check_signature(result):
    """Return the reported checker name or a semantic fallback for diagnostics."""
    explicit = result.get("check_signature")
    if isinstance(explicit, str) and explicit:
        return _redact_diagnostic_secret_text(explicit)
    parts = []
    if result.get("confirmation"):
        parts.append("confirmation=%s" % result["confirmation"])
    if result.get("impact_type"):
        parts.append("impact_type=%s" % result["impact_type"])
    return ", ".join(parts) if parts else "n/a"


def _build_probe_diagnostic_record(result):
    """Build redacted diagnostics for a probe that did not confirm exposure."""
    raw_text = ""
    snippet = result.get("snippet")
    if isinstance(snippet, str):
        raw_text = snippet
    reason = result.get("reason") or ""
    return {
        "name":             result.get("name"),
        "category":         result.get("category"),
        "url_redacted":     _redact_key_from_url(result.get("url") or ""),
        "status_code":      result.get("status_code"),
        "error_class":      result.get("error_class"),
        "error_reason":     _safe_error_excerpt(reason),
        "error_excerpt":    _safe_error_excerpt(raw_text or reason),
        "metadata_services": sorted(result.get("services_seen") or []),
        "metadata_method":  _extract_error_method(raw_text or reason),
        "check_fn_repr":    _diag_check_signature(result),
    }


def _is_malformed_body_accepted(result):
    """True iff this result is a non-vulnerable INVALID_ARGUMENT response
    — i.e. the key was accepted by the endpoint but the body was
    malformed. Vulnerable results are excluded (they are real findings,
    not recon)."""
    if result.get("vulnerable"):
        return False
    return result.get("error_class") == "INVALID_ARGUMENT"


def _build_recon_record(result):
    """Build one `recon.malformed_body_accepted` record. The URL has its
    api-key query param redacted. `service` / `method` come from the
    Google response envelope (`details[].metadata.service` / `.method`)
    when present."""
    raw_text = ""
    snippet = result.get("snippet")
    if isinstance(snippet, str):
        raw_text = snippet
    reason = result.get("reason") or ""
    services = sorted(result.get("services_seen") or [])
    return {
        "name":            result.get("name"),
        "url":             _redact_key_from_url(result.get("url") or ""),
        "status_code":     result.get("status_code"),
        "error_class":     result.get("error_class"),
        "service":         services[0] if services else None,
        "method":          _extract_error_method(raw_text or reason),
        "check_signature": _diag_check_signature(result),
    }


def _collect_malformed_body_accepted(results):
    """Return the list of recon records for all non-vulnerable
    INVALID_ARGUMENT results. Pure — never mutates `results`."""
    return [_build_recon_record(r) for r in (results or [])
            if _is_malformed_body_accepted(r)]


def _build_json_output(results, tested_count, options):
    vuln_list = []
    err_counts = {}

    SERVICE_PRIORITY = {
        "VULNERABLE":            (0, "allowed"),
        "SERVICE_BLOCKED":       (1, "denied"),
        "REFERRER_BLOCKED":      (2, "referer-blocked"),
        "REFERER_INCOMPATIBLE":  (2, "referer-incompatible"),
        "IP_BLOCKED":            (2, "ip-blocked"),
        "ANDROID_BLOCKED":       (2, "android-blocked"),
        "IOS_BLOCKED":           (2, "ios-blocked"),
        "API_DISABLED":          (3, "api-disabled-in-project"),
        "API_KEY_UNSUPPORTED":   (4, "does-not-accept-api-keys"),
        "UNAUTHENTICATED":       (5, "unauthenticated"),
        "PERMISSION_DENIED":     (6, "permission-denied"),
        "NOT_FOUND":             (7, "not-found"),
        "INVALID_ARGUMENT":      (8, "invalid-argument"),
        "FIREBASE_STORAGE_PRECONDITION": (9, "precondition-failed"),
        "FIREBASE_RTDB_DEACTIVATED": (10, "rtdb-deactivated"),
        "HTTP_423_LOCKED":       (11, "http-423-locked"),
    }
    KNOWN_ALLOWLIST_LABELS = {v[1] for v in SERVICE_PRIORITY.values()}
    service_verdict = {}

    unknown_service_classified_count = 0

    probe_diagnostics = []
    for r in results:
        if r["vulnerable"]:
            vuln_list.append({
                "api": r["name"],
                "category": r["category"],
                "abuse_class": r.get("abuse_class"),
                "url": r["url"],
                "impact": r["impact"],

                "tier": r.get("tier") or "CONFIRMED",

                "severity":         r.get("severity") or "INFO",
                "impact_type":      r.get("impact_type") or "info_disclosure",
                "confirmation":     r.get("confirmation") or "key_accepted_only",
                "data_sensitivity": r.get("data_sensitivity") or "metadata",

                "manual_note":      r.get("manual_note"),
            })
        ec = r.get("error_class")
        if ec:
            err_counts[ec] = err_counts.get(ec, 0) + 1
        svcs = r.get("services_seen") or set()
        if svcs:
            verdict = SERVICE_PRIORITY["VULNERABLE"] if r["vulnerable"] else SERVICE_PRIORITY.get(ec, (99, ec or "unknown"))
            for svc in svcs:
                cur = service_verdict.get(svc)
                if cur is None or verdict[0] < cur[0]:
                    service_verdict[svc] = verdict
        elif ec and not r["vulnerable"]:

            unknown_service_classified_count += 1

        if not r["vulnerable"]:
            probe_diagnostics.append(
                _build_probe_diagnostic_record(r))
    allowlist = {}
    for svc, (_, label) in service_verdict.items():
        if label not in KNOWN_ALLOWLIST_LABELS:
            continue
        allowlist.setdefault(label, []).append(svc)
    for label in allowlist:
        allowlist[label].sort()
    with _DERIVED_LOCK:
        derived_ids = sorted(_DERIVED_PROJECT_IDS)
        derived_numbers = sorted(_DERIVED_PROJECT_NUMBERS)

    confirmed_list = [v for v in vuln_list if v.get("tier") == "CONFIRMED"]
    potential_list = [v for v in vuln_list if v.get("tier") == "POTENTIAL"]

    _HIGH = frozenset({"HIGH", "CRITICAL"})
    _MED = frozenset({"MED"})
    confirmed_high_list = [v for v in confirmed_list
                           if (v.get("severity") or "INFO") in _HIGH]
    confirmed_non_high_list = [v for v in confirmed_list
                               if (v.get("severity") or "INFO") not in _HIGH]
    confirmed_med_count = sum(
        1 for v in confirmed_list
        if (v.get("severity") or "INFO") in _MED)
    confirmed_low_info_count = (len(confirmed_list)
                                - len(confirmed_high_list)
                                - confirmed_med_count)
    return _redact_public_payload({
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "transport_incomplete": bool(_transport_error_total()),
        "transport_errors": _transport_error_snapshot(),
        "tested_count": tested_count,
        "confirmed_count": len(confirmed_list),

        "confirmed_high_count":     len(confirmed_high_list),
        "confirmed_med_count":      confirmed_med_count,
        "confirmed_low_info_count": confirmed_low_info_count,
        "potential_count": len(potential_list),
        "options": options,
        "derived_project_ids": derived_ids,
        "derived_project_numbers": derived_numbers,
        "error_class_histogram": err_counts,
        "service_allowlist_inference": allowlist,

        "unknown_service_classified_count": unknown_service_classified_count,
        "confirmed": confirmed_list,

        "confirmed_high":     confirmed_high_list,
        "confirmed_non_high": confirmed_non_high_list,
        "potential": potential_list,

        "probe_diagnostics": probe_diagnostics,

        "recon": {
            "malformed_body_accepted":
                _collect_malformed_body_accepted(results),
        },
    })

def _save_output(path, data):
    """Write atomically; callers must surface an output failure as an error."""
    import tempfile
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8",
                dir=os.path.dirname(os.path.abspath(path)), delete=False) as f:
            tmp = f.name
            json.dump(data, f, indent=2)
            f.write("\n")
        os.replace(tmp, path)
        print("[*] Results saved to %s" % path)
    finally:
        if tmp and os.path.exists(tmp):
            os.unlink(tmp)


def _build_discovery_json_output(mode, key_rows, rollup_rows,
                                 in_scope_key_count,
                                 out_of_scope_key_count,
                                 transport_incomplete,
                                 reportable_exit_condition):
    """Build the aggregate JSON artifact for URL/mobile discovery scans.

    Per-key ``scan_gapis`` calls intentionally disable their own output file
    because one discovery run can scan several keys and restriction contexts.
    This aggregate preserves those redacted snapshots without ever persisting
    the raw discovered keys.
    """
    return {
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "mode": mode,
        "in_scope_key_count": int(in_scope_key_count),
        "out_of_scope_key_count": int(out_of_scope_key_count),
        "transport_incomplete": bool(transport_incomplete),
        "discovery_incomplete": bool(_discovery_issue_snapshot()),
        "discovery_issues": _discovery_issue_snapshot(),
        "reportable_exit_condition": bool(reportable_exit_condition),
        "keys": list(key_rows or []),
        "rollup": list(rollup_rows or []),
    }

# MAIN SCAN FUNCTION

def _build_restriction_headers(mode, value, referer=None):
    """Translate a key-restriction profile into the request headers Google expects.

    mode = 'none' | 'referer' | 'ip' | 'android' | 'ios'
    For mode='android' value must be 'package_name:SHA1_HEX' (uppercase, colon-separated).
    For mode='ios' value is the bundle identifier.
    For mode='referer' value is the URL/host the key is allowed for.
    For mode='ip' there are no request headers; warn the user that IP restrictions
    can only be satisfied by sourcing the request from the allowed IP (use --proxy).
    """
    headers = {}
    # Legacy --referer support: if mode=='none' but referer given, treat as referer mode
    if mode in (None, "none") and referer:
        mode, value = "referer", referer
    if not mode or mode == "none":
        return headers
    if mode == "referer":
        if value and not value.startswith(("http://", "https://")):
            value = "https://" + value
        if value:
            headers["Referer"] = value
            parsed = urlparse(value)
            headers["Origin"] = "%s://%s" % (parsed.scheme, parsed.netloc)
        return headers
    if mode == "ip":
        # No HTTP-level header; the server enforces this on the source IP.
        # Caller must route the request through an allowlisted IP (e.g. --proxy).
        return headers
    if mode == "android":
        if value and ":" in value:
            pkg, cert = value.split(":", 1)
            headers["X-Android-Package"] = pkg
            headers["X-Android-Cert"] = cert.replace(":", "").upper()
        elif value:
            headers["X-Android-Package"] = value
        return headers
    if mode == "ios":
        if value:
            headers["X-Ios-Bundle-Identifier"] = value
        return headers
    return headers


_AIZA_KEY_RE = re.compile(r'AIza[0-9A-Za-z\-_]{35}')
