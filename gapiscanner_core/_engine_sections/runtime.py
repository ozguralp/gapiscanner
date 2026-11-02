# CONSTANTS

REQUEST_TIMEOUT = 15
_REQUEST_KWARGS = {"verify": False, "timeout": REQUEST_TIMEOUT}
_BUNDLE_ARTIFACT_PREFIX = "gapiscanner"
_IPATOOL_KEYCHAIN_DEFAULT = "gapiscanner-keychain"

# Discovery has its own lifetime: each key scan resets transport counters.
_DISCOVERY_ISSUES = {}
_DISCOVERY_ISSUES_LOCK = Lock()
_JSON_OUTPUT_STREAM = None


def _emit_json(data):
    print(json.dumps(data, indent=2), file=_JSON_OUTPUT_STREAM or sys.stdout)


def _record_discovery_issue(kind, count=1):
    with _DISCOVERY_ISSUES_LOCK:
        _DISCOVERY_ISSUES[kind] = _DISCOVERY_ISSUES.get(kind, 0) + count


def _discovery_issue_snapshot():
    with _DISCOVERY_ISSUES_LOCK:
        return dict(_DISCOVERY_ISSUES)

HARDCODED_ENDPOINTS_VERSION = "2026-10-31"


def _ansi_colors_enabled(no_color_request=False):
    """Return True iff ANSI color escapes should be emitted to
    stdout right now. Returns False on `--no-color`, on a set
    `NO_COLOR` env var (per https://no-color.org), and when
    stdout is not a TTY."""
    if no_color_request:
        return False
    if os.environ.get("NO_COLOR"):
        return False
    try:
        return bool(sys.stdout.isatty())
    except (AttributeError, ValueError):
        # stdout was replaced with an object that does not implement
        # isatty (some CI shims). Stay safe — no color.
        return False


def _color_palette(no_color_request=False):
    """Return `(RED, GREEN, YELLOW, RESET)`. Populated with ANSI
    escape codes when `_ansi_colors_enabled` says yes, four empty
    strings otherwise. The four-tuple shape mirrors the existing
    `scan_gapis` locals so callers can drop in a single assignment."""
    if _ansi_colors_enabled(no_color_request):
        return ("\033[1;31;40m", "\033[1;32;40m",
                "\033[1;33;40m", "\033[0m")
    return ("", "", "", "")


_KEY_STATUS_VERDICT_THRESHOLD = 5


def _pick_key_status_verdict(err_counts, total_confirmed):
    """Choose a status label and explanation from the observed error counts."""
    if not isinstance(err_counts, dict):
        return None
    th = _KEY_STATUS_VERDICT_THRESHOLD
    expired_n         = err_counts.get("KEY_EXPIRED", 0)
    leaked_n          = err_counts.get("KEY_LEAKED", 0)
    service_blocked_n = err_counts.get("SERVICE_BLOCKED", 0)
    key_invalid_n     = err_counts.get("KEY_INVALID", 0)
    ref_blocked_n     = err_counts.get("REFERRER_BLOCKED", 0)
    ip_blocked_n      = err_counts.get("IP_BLOCKED", 0)
    android_blocked_n = err_counts.get("ANDROID_BLOCKED", 0)
    ios_blocked_n     = err_counts.get("IOS_BLOCKED", 0)
    if leaked_n >= th:
        return ("LEAKED",
                "Google has blocklisted this key as publicly known — every Google API (read + destructive write) will reject it. No further testing useful.")
    if expired_n >= th:
        return ("EXPIRED",
                "key has been renewed/rotated by the owner — most probes will fail until a new key is obtained")
    if key_invalid_n >= th and (total_confirmed or 0) == 0 and service_blocked_n == 0:
        return ("INVALID/REVOKED",
                "key string is malformed or has been deleted — no Google API will accept it")
    if service_blocked_n >= th:
        return ("SERVICE-RESTRICTED",
                "key works but is locked to a small allowlist of APIs — see allowlist inference block")
    if ref_blocked_n >= th:
        return ("REFERER-RESTRICTED",
                "key is gated to specific HTTP origins — re-run with --restriction-mode referer")
    if ip_blocked_n >= th:
        return ("IP-RESTRICTED",
                "key is gated to specific source IPs — re-run via --proxy from an allowlisted IP")
    if android_blocked_n >= th:
        return ("ANDROID-RESTRICTED",
                "key is gated to a specific Android app — re-run with --restriction-mode android")
    if ios_blocked_n >= th:
        return ("IOS-RESTRICTED",
                "key is gated to a specific iOS bundle — re-run with --restriction-mode ios")
    if (total_confirmed or 0) > 0:
        return ("PARTIALLY-USABLE",
                "key works for at least one API — see RESULTS above")
    return None


ABUSE_CLASS_OVERRIDES = {
    # Gemini specifics
    "Gemini Models List": "Recon",
    "Gemini Generate Content": "BillDrain",
    "Gemini Files List": "DataExfil",
    "Gemini Cached Contents": "DataExfil",
    "Gemini Tuned Models": "DataExfil",
    "Gemini Corpora": "DataExfil",
    "Gemini File Upload (write)": "DataExfil",
    "Gemini Cached Content Create (write)": "Persistence",
    # Cloud AI
    "Cloud Vision": "BillDrain",
    "Cloud Translation": "BillDrain",
    "Cloud Natural Language": "BillDrain",
    "Cloud Text-to-Speech": "BillDrain",
    # GCP infra defaults to Recon (list endpoints leak metadata)
}


# Module-level list collecting any account artifacts that auto-cleanup failed
# to delete. Drained at end-of-scan by the reporter.
_IDENTITY_TOOLKIT_ARTIFACTS = []
_IDENTITY_TOOLKIT_LOCK = Lock()


_DERIVED_FIREBASE_CONFIGS = []
_DERIVED_FIREBASE_LOCK = Lock()


_AUTH_READ_ENABLED  = False
_AUTH_READ_SCOPE_OK = True   # default True for direct --api-key flows
_AUTH_READ_FINDINGS = []
_AUTH_READ_LOCK     = Lock()
_AUTH_READ_FIREBASE_CONFIGS = None


_DANGEROUS_CATEGORIES = frozenset({"destructive", "cost-amp"})


_PLACEHOLDER_PROJECT_ID = "test-project-123"


def _resolve_target_project_from_url(url):
    """Best-effort: extract the `<pid>` substring from a substituted
    googleapis.com URL. Handles `/projects/<pid>/...`,
    `/projects/<pid>:method?...`. Returns None when no match."""
    if not isinstance(url, str):
        return None
    m = re.search(r"/projects/([^/?#:]+)", url)
    return m.group(1) if m else None


def _resolve_target_project_from_db_url(database_url):
    """Extract a project ID from a recognized legacy or regional Firebase database URL."""
    if not database_url or not isinstance(database_url, str):
        return None
    from urllib.parse import urlparse
    try:
        host = (urlparse(database_url).netloc or database_url).lower()
    except Exception:
        return None
    if not host:
        return None
    # Strip any port suffix (operator-supplied corp proxy port etc).
    host = host.split(":", 1)[0]
    # <pid>-default-rtdb.* (both firebaseio.com and regional). Match
    # this BEFORE the bare-firebaseio.com branch so a hostname like
    # `my-proj-default-rtdb.firebaseio.com` returns the project ID
    # `my-proj` (not `my-proj-default-rtdb`).
    m = re.match(r"^([a-z0-9][a-z0-9-]*?)-default-rtdb\.", host)
    if m:
        return m.group(1)
    # Legacy: <pid>.firebaseio.com (no -default-rtdb suffix).
    m = re.match(r"^([a-z0-9][a-z0-9-]*)\.firebaseio\.com$", host)
    if m:
        return m.group(1)
    # <pid>.<region>.firebasedatabase.app (no -default-rtdb suffix)
    m = re.match(r"^([a-z0-9][a-z0-9-]*?)\.[a-z0-9-]+\.firebasedatabase\.app",
                 host)
    if m:
        return m.group(1)
    return None


def _resolve_target_project_from_bucket(bucket):
    """Parse a Firebase Storage bucket name into its project ID.
    Handles `<pid>.appspot.com`, `<pid>.firebasestorage.app`. Returns
    None on parse failure."""
    if not bucket or not isinstance(bucket, str):
        return None
    b = bucket.strip().lower()
    for suffix in (".appspot.com", ".firebasestorage.app"):
        if b.endswith(suffix):
            pid = b[:-len(suffix)]
            return pid or None
    return None


def _dangerous_probe_skip_reason(probe_tuple, substituted_url, derived_pids):
    """Reject a project-targeted write or cost probe unless this scan derived its project.

    Key-scoped probes without a project placeholder use their separate opt-in gates."""
    cat = probe_tuple[1] if len(probe_tuple) > 1 else None
    if cat not in _DANGEROUS_CATEGORIES:
        return None
    url_template = probe_tuple[3] if len(probe_tuple) > 3 else ""
    if not (isinstance(url_template, str) and "{project}" in url_template):
        # Key-own-project dangerous probe — no project ID required.
        return None
    # Resolve the substituted target project. The `{project}` placeholder
    # can land in a `/projects/<pid>/` path OR in a Firebase host
    # (`<pid>.firebaseio.com`, `<pid>-default-rtdb.*`, regional RTDB), so
    # try both resolvers.
    sub = substituted_url or ""
    pid = (_resolve_target_project_from_url(sub)
           or _resolve_target_project_from_db_url(sub))
    derived = {str(p).strip().lower() for p in (derived_pids or []) if p}
    if not pid or pid == _PLACEHOLDER_PROJECT_ID:
        return ("no project derived — refusing to run a project-targeted "
                "dangerous probe against the %s placeholder"
                % _PLACEHOLDER_PROJECT_ID)
    if str(pid).strip().lower() in derived:
        return None
    return ("target project %s was not derived by this scan — refusing "
            "dangerous project-targeted call" % pid)


def _set_auth_read_enabled(enabled):
    """Operator-explicit gate (CLI: --include-auth-read). Set once at the
    start of main()."""
    global _AUTH_READ_ENABLED
    _AUTH_READ_ENABLED = bool(enabled)


def _set_auth_read_scope_ok(allowed):
    """Set whether the current key has an eligible source for authenticated reads."""
    global _AUTH_READ_SCOPE_OK
    _AUTH_READ_SCOPE_OK = bool(allowed)


def _set_auth_read_firebase_configs(configs):
    """Per-scan Firebase config scope for the authenticated-read chain.

    `None` preserves legacy web/single-key behavior and lets auth-read consult
    the process-global config store. A list, including an empty list, means the
    caller has already selected the configs that belong to the current key, so
    auth-read must not fall back to configs from other mobile archives.
    """
    global _AUTH_READ_FIREBASE_CONFIGS
    if configs is None:
        _AUTH_READ_FIREBASE_CONFIGS = None
    else:
        _AUTH_READ_FIREBASE_CONFIGS = [dict(c) for c in configs if c]


def _is_source_in_scope_for_auth_read(source_label, bundle=None):
    """Check a source URL or mobile label against the caller-supplied exclusions.

    Unknown sources fail this check. Positive asset membership is checked
    separately by callers that supply a scope bundle."""
    if not source_label:
        return False
    if source_label.startswith("mobile:"):
        return True
    if not source_label.startswith(("http://", "https://")):
        return False
    if bundle is not None:
        from urllib.parse import urlparse
        try:
            bare = urlparse(source_label).netloc or source_label
        except Exception:
            bare = source_label
        for oos in (getattr(bundle, "oos", None) or []):
            try:
                pat = re.compile(oos, re.IGNORECASE)
                if pat.search(bare) or pat.search(source_label):
                    return False
            except re.error:
                if oos in bare or oos in source_label:
                    return False
    return True


def _wildcard_asset_apex_and_regex(value):
    """Parse a literal or regex wildcard into an apex and optional host pattern.

    Return (None, None) when a pattern cannot be parsed safely."""
    if not isinstance(value, str):
        return None, None
    v = value.strip()
    if not v:
        return None, None
    # Literal wildcard.
    if v.startswith("*."):
        apex = v[2:].lower()
        return (apex or None), None
    # Regex wildcard. Compile first so we can reject genuinely
    # malformed values rather than silently lstrip them.
    try:
        regex = re.compile(v, re.IGNORECASE)
    except re.error:
        return None, None
    # Derive apex by stripping anchors + escape sequences and walking
    # back from the tail to find the longest pure-hostname suffix.
    simplified = (v.lstrip("^").rstrip("$")
                  .replace("\\\\.", ".")
                  .replace("\\.", "."))
    HOST_SEG_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$", re.I)
    parts = simplified.split(".")
    apex_parts = []
    for p in reversed(parts):
        if HOST_SEG_RE.match(p):
            apex_parts.insert(0, p)
        else:
            break
    apex = ".".join(apex_parts).lower() if len(apex_parts) >= 2 else None
    return apex, regex


def _is_source_in_platform_scope(source_url, bundle):
    """Require positive asset membership and no matching exclusion in the scope bundle."""
    if not source_url:
        return False
    if isinstance(source_url, str) and source_url.startswith("mobile:"):
        return True
    if (not isinstance(source_url, str)
            or not source_url.startswith(("http://", "https://"))):
        return False
    # (1) — bundle.oos must not match.
    if not _is_source_in_scope_for_auth_read(source_url, bundle):
        return False
    # (2) — at least one bounty-eligible web asset must cover the source.
    from urllib.parse import urlparse
    try:
        src_p = urlparse(source_url)
        src_host = src_p.netloc.lower().split(":", 1)[0]
        src_path = src_p.path or "/"
    except Exception:
        return False
    if not src_host:
        return False
    for asset in (getattr(bundle, "web_assets", None) or []):
        if not getattr(asset, "bounty_eligible", True):
            continue
        v = (getattr(asset, "value", None) or "").strip()
        if not v:
            continue
        atype = (getattr(asset, "asset_type", None) or "").lower()
        if atype == "domain":
            ah = v.lower()
            if src_host == ah or src_host.endswith("." + ah):
                return True
        elif atype == "wildcard":

            apex, wildcard_regex = _wildcard_asset_apex_and_regex(v)
            if wildcard_regex is not None:
                if wildcard_regex.search(src_host):
                    return True
                continue
            if apex and (src_host == apex
                         or src_host.endswith("." + apex)):
                return True
        elif atype == "url":
            asset_url = v if v.startswith(("http://", "https://")) else "https://" + v
            try:
                a_p = urlparse(asset_url)
                a_host = a_p.netloc.lower().split(":", 1)[0]
                a_path = a_p.path or "/"
            except Exception:
                continue
            if not a_host:
                continue
            host_match = (src_host == a_host or src_host.endswith("." + a_host))
            if not host_match:
                continue
            if a_path in ("", "/"):
                return True
            ap = a_path.rstrip("/")
            if src_path == ap or src_path.startswith(ap + "/"):
                return True
        elif atype == "ip":
            if src_host == v.lower():
                return True
        # asset_type in ("ip-range", anything else) → conservative skip.
    return False


def _build_direct_discovery_in_scope_check(entrypoint, context):
    """Return a `check(source) -> bool` callable for the given direct-
    discovery entrypoint:

      entrypoint="url"        context = operator-supplied target URL string
      entrypoint="scope"      context = (include_matchers, exclude_matchers)
                                        from `_compile_scope`
      entrypoint="host_list"  context = set of host strings (IP or domain)
                                        from the operator's host-list file
      entrypoint="mobile"     context = None — all sources from a
                                        mobile bundle are operator-supplied
      anything else           always-False check (defensive)
    """
    if entrypoint == "mobile":
        # All sources from a mobile bundle are archive-internal paths
        # belonging to the operator-supplied APK/IPA. In-scope by construction.
        def _check(_src):
            return True
        return _check
    if entrypoint == "url":
        from urllib.parse import urlparse
        target_url = context or ""
        try:
            target_host = urlparse(target_url).netloc.lower()
        except Exception:
            target_host = ""
        def _check(src):
            if not isinstance(src, str) or not src.startswith(("http://", "https://")):
                return False
            if not target_host:
                return False
            return _same_site(src, target_host)
        return _check
    if entrypoint == "scope":
        include, exclude = context or (None, None)
        if include is None:
            return lambda _src: False
        # Resolve the scope matcher lazily and fail closed if unavailable.
        scope_check_fn = globals().get("_is_in_scope")
        if scope_check_fn is None:
            return lambda _src: False
        def _check(src):
            if not isinstance(src, str) or not src.startswith(("http://", "https://")):
                return False
            return scope_check_fn(src, include, exclude or [])
        return _check
    if entrypoint == "host_list":
        from urllib.parse import urlparse
        host_set = set((context or set()))
        # Lower-case for case-insensitive netloc match.
        host_set_lower = {h.lower() for h in host_set if isinstance(h, str)}
        def _check(src):
            if not isinstance(src, str) or not src.startswith(("http://", "https://")):
                return False
            try:
                netloc = urlparse(src).netloc.lower().split(":", 1)[0]
            except Exception:
                return False
            return netloc in host_set_lower
        return _check
    # Unknown entrypoint — defensive default.
    return lambda _src: False


def _are_key_sources_in_scope(key_sources, check_fn):
    """Return True iff at least one of `key_sources` passes `check_fn`.
    Empty/None source sets return False (defensive: unknown == OOS)."""
    if not key_sources:
        return False
    return any(check_fn(s) for s in key_sources)


def _partition_keys_by_origin_scope(keys, sources, check_fn):
    """Partition keys by whether at least one recorded source passes check_fn.

    Return the eligible keys, excluded keys and excluded source labels."""
    in_scope_keys = set()
    oos_keys = set()
    oos_reasons = {}
    src_map = sources if isinstance(sources, dict) else {}
    for k in (keys or set()):
        srcs = src_map.get(k, set()) or set()
        if _are_key_sources_in_scope(srcs, check_fn):
            in_scope_keys.add(k)
        else:
            oos_keys.add(k)
            oos_reasons[k] = sorted(srcs)
    return in_scope_keys, oos_keys, oos_reasons


_VERIFY_TLS_NETLOC_SUFFIXES = (
    "googleapis.com",
    "google.com",
    "firebaseio.com",
    "firebaseapp.com",
    "firebasedatabase.app",
    "firebasestorage.app",
    "appspot.com",
    "cloudfunctions.net",
)

# Operator-set kill switch for TLS verification. When True, `_request_kwargs_for_url`
# forces `verify=False` regardless of destination — required when an egress proxy
# MITMs *.googleapis.com (a trusted TLS interception gateway). Set via the
# `--insecure` CLI flag.
_INSECURE_TLS = False

# Transport-error tally (SSL / connection / timeout). Bumped from `_execute_probe`
# whenever a probe NEVER reaches the API — so the end-of-scan summary can warn
# that "no vulnerable APIs found" is NOT a clean result.
_TRANSPORT_ERROR_COUNTS = {"ssl": 0, "connection": 0, "timeout": 0, "other": 0}
_TRANSPORT_ERROR_LOCK = Lock()


def _record_transport_error(kind):
    with _TRANSPORT_ERROR_LOCK:
        _TRANSPORT_ERROR_COUNTS[kind] = _TRANSPORT_ERROR_COUNTS.get(kind, 0) + 1


# Compatibility API used by tests and discovery loops. The single-core
# boundary checker verifies this implementation exists only in this engine.
def _transport_error_total():
    with _TRANSPORT_ERROR_LOCK:
        return sum(_TRANSPORT_ERROR_COUNTS.values())


def _transport_error_snapshot():
    with _TRANSPORT_ERROR_LOCK:
        return dict(_TRANSPORT_ERROR_COUNTS)


def _reset_transport_errors():
    with _TRANSPORT_ERROR_LOCK:
        for k in list(_TRANSPORT_ERROR_COUNTS):
            _TRANSPORT_ERROR_COUNTS[k] = 0


_LAST_TRANSPORT_ERROR_COUNTS = {"ssl": 0, "connection": 0, "timeout": 0, "other": 0}


def _capture_last_transport_errors():
    global _LAST_TRANSPORT_ERROR_COUNTS
    with _TRANSPORT_ERROR_LOCK:
        _LAST_TRANSPORT_ERROR_COUNTS = dict(_TRANSPORT_ERROR_COUNTS)


# Compatibility API used by tests and discovery loops. Keep it as the
# stable read-only view of the last completed scan's transport state.
def _last_transport_error_snapshot():
    with _TRANSPORT_ERROR_LOCK:
        return dict(_LAST_TRANSPORT_ERROR_COUNTS)


def _last_transport_error_total():
    with _TRANSPORT_ERROR_LOCK:
        return sum(_LAST_TRANSPORT_ERROR_COUNTS.values())


_LAST_CONFIRMED_SEVERITY_COUNTS = {"HIGH": 0, "MED": 0, "LOW_INFO": 0}
_LAST_CONFIRMED_SEVERITY_LOCK = Lock()


def _capture_last_confirmed_severity_counts(counts):
    """Save severity counts for the completed scan under the snapshot lock."""
    global _LAST_CONFIRMED_SEVERITY_COUNTS
    with _LAST_CONFIRMED_SEVERITY_LOCK:
        _LAST_CONFIRMED_SEVERITY_COUNTS = {
            "HIGH":     int(counts.get("HIGH", 0)),
            "MED":      int(counts.get("MED", 0)),
            "LOW_INFO": int(counts.get("LOW_INFO", 0)),
        }


def _last_confirmed_severity_snapshot():
    with _LAST_CONFIRMED_SEVERITY_LOCK:
        return dict(_LAST_CONFIRMED_SEVERITY_COUNTS)


def _last_confirmed_high_total():
    """Return the count of HIGH/CRITICAL CONFIRMED findings from the
    last completed `scan_gapis()` call. This is the number the
    severity-aware exit-code path consults to decide between
    exit 1 (reportable-high) and exit 0/3."""
    with _LAST_CONFIRMED_SEVERITY_LOCK:
        return int(_LAST_CONFIRMED_SEVERITY_COUNTS.get("HIGH", 0))


def _classify_scan_vulnerable(returned_names, exit_on_any_confirmed):
    """Apply the CLI finding threshold to the completed scan.

    HIGH and CRITICAL confirmed results count by default. The explicit
    exit_on_any_confirmed option also includes lower-severity confirmed results."""
    if _last_confirmed_high_total() > 0:
        return True
    if exit_on_any_confirmed and returned_names:
        return True
    return False


_LAST_SCAN_RESULT_SNAPSHOT = []
_LAST_SCAN_RESULT_SNAPSHOT_LOCK = Lock()
_LAST_SCAN_DIAGNOSTIC_SNAPSHOT = {}
_LAST_SCAN_DIAGNOSTIC_SNAPSHOT_LOCK = Lock()


def _redact_key_display(key):
    """Return a redacted, recognizable form of an API key for the rollup
    (`AIzaSyDN…wgmw`). Never emits the full secret. Short / empty inputs
    collapse to `<redacted>`."""
    if not key or not isinstance(key, str):
        return "<redacted>"
    if len(key) <= 12:
        return "<redacted>"
    return "%s…%s" % (key[:8], key[-4:])


def _rollup_pass_context(restriction_mode):
    """Normalize a scan's restriction_mode into the rollup `pass context`
    label. Pass 1 (no restriction) → `unrestricted`; pass 2 carries the
    operator-pinned restriction kind (`referer` / `android` / `ios` /
    `ip`)."""
    if not restriction_mode:
        return "unrestricted"
    return str(restriction_mode)


def _build_rollup_row(result, pass_context, restriction_value):
    """Build ONE structured rollup row from a vulnerable probe result
    dict (as produced by `_execute_probe` / `_handle_result`). The PoC
    URL and the restriction value are redacted. Only the fields the
    final rollup needs are retained — this is deliberately a flat,
    JSON-serializable shape so tests can assert on it directly."""
    return {
        "name":             result.get("name"),
        "severity":         result.get("severity") or "INFO",
        "tier":             result.get("tier") or "CONFIRMED",
        "category":         result.get("category"),
        "abuse_class":      result.get("abuse_class") or "-",
        "poc_url":          _redact_key_from_url(result.get("url") or ""),
        "pass_context":     pass_context,
        "restriction_value": _redact_key_from_url(
            restriction_value) if restriction_value else None,
        "impact_type":      result.get("impact_type"),
        "confirmation":     result.get("confirmation"),
        "data_sensitivity": result.get("data_sensitivity"),
        "followup_required": result.get("followup_required"),
        "operation_evidence": (
            dict(result.get("operation_evidence"))
            if isinstance(result.get("operation_evidence"), dict) else None
        ),
    }


def _capture_last_scan_result_snapshot(results, restriction_mode=None,
                                       restriction_value=None):
    """Persist a structured snapshot of the just-finished scan's VULNERABLE
    findings (CONFIRMED + POTENTIAL, all severities). The discovery-loop
    rollup reads this AFTER `scan_gapis()` returns. Non-vulnerable probe
    results are excluded — they belong to the fingerprint / recon
    channels, not the findings rollup."""
    pass_context = _rollup_pass_context(restriction_mode)
    rows = [
        _build_rollup_row(r, pass_context, restriction_value)
        for r in (results or [])
        if r.get("vulnerable")
    ]
    global _LAST_SCAN_RESULT_SNAPSHOT
    with _LAST_SCAN_RESULT_SNAPSHOT_LOCK:
        _LAST_SCAN_RESULT_SNAPSHOT = rows


def _last_scan_result_snapshot():
    with _LAST_SCAN_RESULT_SNAPSHOT_LOCK:
        return [dict(r) for r in _LAST_SCAN_RESULT_SNAPSHOT]


def _capture_last_scan_diagnostic_snapshot(results):
    """Persist the just-finished scan's non-finding diagnostics for KB audit.

    The final rollup snapshot intentionally stores only vulnerable rows. KB
    rescan review also needs the negative/error rows (for example HTTP 423 by
    probe), so keep a separate redacted snapshot that callers can write into
    scan_history without re-running or scraping console logs.
    """
    err_counts = {}
    probe_diagnostics = []
    for r in results or []:
        ec = r.get("error_class")
        if ec:
            err_counts[ec] = err_counts.get(ec, 0) + 1
        if not r.get("vulnerable"):
            probe_diagnostics.append(_build_probe_diagnostic_record(r))
    snap = {
        "error_class_histogram": dict(err_counts),
        "probe_diagnostics": probe_diagnostics,
    }
    global _LAST_SCAN_DIAGNOSTIC_SNAPSHOT
    with _LAST_SCAN_DIAGNOSTIC_SNAPSHOT_LOCK:
        _LAST_SCAN_DIAGNOSTIC_SNAPSHOT = snap


def _last_scan_diagnostic_snapshot():
    with _LAST_SCAN_DIAGNOSTIC_SNAPSHOT_LOCK:
        return {
            "error_class_histogram": dict(
                _LAST_SCAN_DIAGNOSTIC_SNAPSHOT.get(
                    "error_class_histogram") or {}),
            "probe_diagnostics": [
                dict(r) for r in _LAST_SCAN_DIAGNOSTIC_SNAPSHOT.get(
                    "probe_diagnostics") or []
            ],
        }


# Rollup section classification — each vulnerable finding lands in
# exactly one section. The default rollup prints only `reportable_high`;
# `--rollup-all-findings` adds the other three.
_ROLLUP_HIGH_SEVERITIES = frozenset({"HIGH", "CRITICAL"})
_ROLLUP_MED_SEVERITIES = frozenset({"MED"})


def _rollup_section_for(row):
    """Return the rollup section name for a snapshot/accumulator row:
    `reportable_high`, `confirmed_med`, `confirmed_low_info`, or
    `potential`."""
    tier = (row.get("tier") or "CONFIRMED").upper()
    if tier == "POTENTIAL":
        return "potential"
    sev = (row.get("severity") or "INFO").upper()
    if sev in _ROLLUP_HIGH_SEVERITIES:
        return "reportable_high"
    if sev in _ROLLUP_MED_SEVERITIES:
        return "confirmed_med"
    return "confirmed_low_info"


def _redact_rollup_source(source):
    """Redact secrets from a rollup `source` label before it is stored
    and printed. Source labels are usually a discovery URL or a mobile
    label (`mobile:android:<pkg>:<SHA1>` / `mobile:ios:<bundle>`), but a
    web source URL can carry a `?key=AIza…` query param — so without
    this the final rollup would leak the raw key via the `source` field
    even though `poc_url` / `restriction_value` are redacted.

    Reuses `_redact_diagnostic_secret_text`, which scrubs `key=` query
    values, bare AIza keys, ya29 OAuth tokens, `Authorization: Bearer …`
    headers, and idToken-shaped JWTs while leaving normal mobile labels
    and secret-free URLs untouched. Idempotent; `None` / non-str pass
    through unchanged."""
    return _redact_diagnostic_secret_text(source)


def _merge_rollup_rows_for_key(source, redacted_key, pass1_rows, pass2_rows):
    """Combine a single key's pass-1 and pass-2 snapshots into final
    rollup rows, computing the `bypass_only` flag per finding.

    `bypass_only=yes` when a finding appears ONLY in pass 2 (restricted
    mode) and not in pass 1 (unrestricted). When a finding appears in
    BOTH passes, `bypass_only=no` and the unrestricted pass context is
    preferred with a note that the restricted pass also surfaced it.

    `pass1_rows` / `pass2_rows` are lists from `_last_scan_result_snapshot`."""
    by_name_p1 = {r["name"]: r for r in (pass1_rows or [])}
    by_name_p2 = {r["name"]: r for r in (pass2_rows or [])}
    out = []
    for name in sorted(set(by_name_p1) | set(by_name_p2)):
        in_p1 = name in by_name_p1
        in_p2 = name in by_name_p2
        if in_p1:
            base = dict(by_name_p1[name])
            bypass_only = False
            note = None
            if in_p2:
                note = "restricted pass also surfaced this finding"
        else:
            base = dict(by_name_p2[name])
            bypass_only = True
            note = None
        base["source"] = _redact_rollup_source(source)
        base["key"] = redacted_key
        base["bypass_only"] = bypass_only
        base["note"] = note
        out.append(base)
    return out


def _render_final_rollup(rows, rollup_all_findings=False):
    """Render the final multi-key/multi-source rollup as a text block
    (returned, not printed — so tests can assert on the string). `rows`
    is a flat list of merged rollup rows (see `_merge_rollup_rows_for_key`).

    Default: only the `reportable_high` section. With
    `rollup_all_findings=True`, append `confirmed_med`,
    `confirmed_low_info`, and `potential` sections. POTENTIAL findings
    appear ONLY under `--rollup-all-findings`."""
    sectioned = {
        "reportable_high":    [],
        "confirmed_med":      [],
        "confirmed_low_info": [],
        "potential":          [],
    }
    for r in rows:
        sectioned[_rollup_section_for(r)].append(r)

    lines = []
    lines.append("")
    lines.append("=" * 78)
    lines.append("  FINAL ROLLUP — findings by source / key / API")
    lines.append("=" * 78)

    def _emit_section(title, section_rows):
        lines.append("")
        lines.append("  [%s] %d finding(s)" % (title, len(section_rows)))
        if not section_rows:
            return
        for r in sorted(section_rows, key=lambda x: (
                x.get("source") or "", x.get("key") or "", x.get("name") or "")):
            bypass = "yes" if r.get("bypass_only") else "no"
            lines.append("    - source=%s key=%s" % (
                r.get("source") or "(direct)", r.get("key") or "?"))
            lines.append("      api=%s sev=%s tier=%s cat=%s abuse=%s" % (
                r.get("name"), r.get("severity"), r.get("tier"),
                r.get("category"), r.get("abuse_class")))
            restr = r.get("restriction_value")
            lines.append("      pass=%s%s bypass_only=%s" % (
                r.get("pass_context") or "unrestricted",
                (" restriction=%s" % restr) if restr else "",
                bypass))
            lines.append("      poc=%s" % (r.get("poc_url") or "-"))
            if r.get("note"):
                lines.append("      note: %s" % r["note"])

    # Default section — reportable HIGH/CRITICAL CONFIRMED only.
    _emit_section("reportable-high", sectioned["reportable_high"])
    if rollup_all_findings:
        _emit_section("confirmed-med", sectioned["confirmed_med"])
        _emit_section("confirmed-low-info", sectioned["confirmed_low_info"])
        _emit_section("potential", sectioned["potential"])
    else:
        hidden = (len(sectioned["confirmed_med"])
                  + len(sectioned["confirmed_low_info"])
                  + len(sectioned["potential"]))
        if hidden:
            lines.append("")
            lines.append("  (%d non-reportable finding(s) hidden — re-run with "
                         "--rollup-all-findings)" % hidden)
    lines.append("")
    return "\n".join(lines)


def _print_final_rollup(rows, rollup_all_findings=False, quiet=False):
    """Print the final rollup once. Suppressed entirely under --quiet.
    Always prints the header even when there are zero reportable
    findings, so the operator gets a definitive end-of-scan marker."""
    if quiet:
        return
    print(_render_final_rollup(rows, rollup_all_findings))


def _should_verify_tls(url):
    """Return True iff `url` belongs to a Google-controlled / Firebase /
    appspot endpoint where TLS verification must NOT be disabled. The
    function returns False for any other host (including operator-supplied
    crawl targets, IPs, and unknown 3rd-party CDNs)."""
    if not isinstance(url, str):
        return False
    try:
        from urllib.parse import urlparse
        netloc = urlparse(url).netloc.lower().split(":", 1)[0]
    except Exception:
        return False
    if not netloc:
        return False
    for suf in _VERIFY_TLS_NETLOC_SUFFIXES:
        if netloc == suf or netloc.endswith("." + suf):
            return True
    return False


class _ExplicitRequestAuth(requests.auth.AuthBase):
    """Keep caller-supplied headers without loading credentials from netrc."""

    def __call__(self, request):
        return request


_EXPLICIT_REQUEST_AUTH = _ExplicitRequestAuth()


def _request_kwargs_for_url(url, target_crawl=False):
    """Build request options without mutating shared transport settings.

    API requests disable redirects and verify TLS unless --insecure is set.
    Target crawling tolerates untrusted certificates. Proxy settings are preserved."""
    kwargs = dict(_REQUEST_KWARGS)
    kwargs["auth"] = _EXPLICIT_REQUEST_AUTH
    if not target_crawl:
        kwargs["allow_redirects"] = False
    if _INSECURE_TLS:
        kwargs["verify"] = False
    elif _should_verify_tls(url):
        kwargs["verify"] = True
    elif target_crawl:
        kwargs["verify"] = False
    else:
        kwargs["verify"] = True
    return kwargs


_COST_AMP_DISPLAY_CAP_USD_PER_HR = 1000.0
_COST_AMP_THEORETICAL_LABEL = (
    "theoretical max, ignores per-project quotas/rate limits"
)


def _cap_cost_amp_drain(drain_per_hr):
    """Clamp a projected USD/hr drain to `_COST_AMP_DISPLAY_CAP_USD_PER_HR`.
    Returns `(capped_value, was_capped_bool)`."""
    try:
        v = float(drain_per_hr)
    except (TypeError, ValueError):
        return 0.0, False
    if v > _COST_AMP_DISPLAY_CAP_USD_PER_HR:
        return _COST_AMP_DISPLAY_CAP_USD_PER_HR, True
    return v, False
