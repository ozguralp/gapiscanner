def _print_usage():
    print("""Usage: gapiscanner --api-key KEY [OPTIONS]
       gapiscanner --url URL [OPTIONS]
       gapiscanner --mobile FILE [--mobile FILE ...] [OPTIONS]

The gapiscanner default includes generation and anonymous account creation
with cleanup. Use authorized
keys and targets; successful API use alone may not be a vulnerability.

Probe groups:
  --include-maps          Add Google Maps Platform probes.
  --include-low           Add utility and billing-only probes.
  --include-destructive   Write/create resources; cleanup may leave artifacts.
  --include-cost-amp      Test paid operations; may incur charges and use quota.
  --all                   Enable Maps, low, destructive and cost-amp groups;
                          includes writes, paid operations and their risks.
  --include-authorization-key
                          Add Vertex countTokens and three IAM list probes.
  --authorization-only    Run only the four authorization probes.
  --include-auth-read     Use a temporary anonymous identity to read derived
                          Firebase projects. Lists metadata; a primitive RTDB
                          root value may be returned and is discarded.
  --it-test-email EMAIL   Test email dispatch to your own address; requires
                          --include-destructive.
  --it-test-phone E164    Test SMS dispatch to your own phone; requires
                          --include-destructive.

Key and transport:
  -a, --api-key KEY       Google API key to test.
  -P, --project-id ID     Project ID or number for project-scoped endpoints.
  --restriction-mode MODE
                          none, referer, ip, android or ios.
  --restriction-value V  Referer URL, package:SHA1 or iOS bundle identifier.
  -r, --referer URL       Referer header override.
  -p, --proxy URL         HTTP/HTTPS proxy; SOCKS needs PySocks installed.
  --insecure             Disable TLS verification for API requests.
  -t, --threads N         Concurrent probe workers (default: 10).
  --no-jsapi              Do not create the local Maps JavaScript HTML test.
  --exit-on-dead-key      Stop when all initial checks show an invalid key.

Discovery:
  --url URL              Crawl one site and scan discovered keys.
  --mobile FILE          Scan an APK/XAPK/IPA/AAB/ZIP archive; repeatable.
  --mobile-dir DIR       Scan supported archives in a directory.
  --program NAME         Label discovery and filter KB rescans by program.
  --output-dir DIR       Store the key KB and artifacts under DIR.
  --url-fetch-budget N   Maximum text URLs fetched; default/0 is unlimited.
  --url-fetch-state FILE Persist the URL queue and adjacent response cache.
  --resume               Replay cached bodies and resume the saved queue.
  --max-per-template N   URLs retained per page template (default: 5).
  --max-per-locale N     Locale variants retained per template (default: 1).
  --no-playwright        Disable rendered-browser discovery.
  --no-auto-referer      Disable automatic restricted-context second passes.
  --debug-mobile-extract Show mobile extraction diagnostics.

Key knowledge base:
  --show-kb              Print stored key summaries with redacted keys.
  --bootstrap-kb         Import prior local scan artifacts into the KB.
  --rescan-kb            Scan stored keys without repeating discovery.
  --rescan-kb-start-index N / --rescan-kb-end-index N
                         Restrict rescan to a sorted, 1-based index range.
  --rescan-kb-indexes CSV Restrict rescan to selected 1-based indexes.
  --export-kb-csv FILE   Export raw keys and sources; keep the CSV private.

Output:
  -v, --verbose          Include diagnostic probe output.
  -q, --quiet            Reduce non-finding output.
  --json                Write JSON to stdout; progress goes to stderr.
  -o, --output FILE      Write direct-key or discovery results to JSON.
  --fingerprint-detail concise|full
                         Select console fingerprint detail (default: concise).
  --rollup-all-findings  Include lower-severity and potential rollup rows.
  --no-color            Disable terminal colors; NO_COLOR is also supported.
  --exit-on-any-confirmed
                         Return 1 for any confirmed result, regardless of severity.
  -h, --help            Show this help.

Exit codes: 0 complete without a reportable result; 1 confirmed HIGH/CRITICAL
(or any confirmed result with --exit-on-any-confirmed); 2 input/output error;
3 incomplete discovery or requests without a reportable result; 130 interrupted.

Examples:
  gapiscanner -a KEY --include-maps --output results.json
  gapiscanner --url https://example.com --url-fetch-state queue.json
  gapiscanner --mobile app.apk --no-jsapi""")


def _validate_public_arguments(args):
    """Validate values before flag stripping or any network/filesystem work."""
    value_flags = {
        "--api-key", "-a", "--url", "--mobile", "--mobile-dir", "--program",
        "--output-dir", "--max-per-template", "--max-per-locale",
        "--url-fetch-budget", "--url-fetch-state", "--proxy", "-p",
        "--referer", "-r", "--project-id", "-P", "--threads", "-t",
        "--output", "-o", "--restriction-mode", "--restriction-value",
        "--export-kb-csv", "--rescan-kb-start-index", "--rescan-kb-end-index",
        "--rescan-kb-indexes", "--fingerprint-detail", "--it-test-email",
        "--it-test-phone",
    }
    integer_min = {"--threads": 1, "-t": 1, "--max-per-template": 1,
                   "--max-per-locale": 1, "--url-fetch-budget": 0,
                   "--rescan-kb-start-index": 1, "--rescan-kb-end-index": 1}
    index = 0
    while index < len(args):
        flag = args[index]
        if flag not in value_flags:
            index += 1
            continue
        if index + 1 >= len(args) or args[index + 1].startswith("--") or args[index + 1] in value_flags:
            raise ValueError("%s requires a value" % flag)
        value = args[index + 1]
        if flag in integer_min:
            try:
                valid = int(value) >= integer_min[flag]
            except ValueError:
                valid = False
            if not valid:
                raise ValueError("%s must be an integer >= %d" % (flag, integer_min[flag]))
        if flag == "--url":
            parsed = urlparse(value)
            if parsed.scheme not in ("http", "https") or not parsed.hostname:
                raise ValueError("--url requires an http:// or https:// URL")
            _ = parsed.port  # Validate malformed and out-of-range ports.
        if flag == "--mobile" and not os.path.isfile(value):
            raise ValueError("--mobile requires an existing file")
        if flag == "--mobile-dir" and not os.path.isdir(value):
            raise ValueError("--mobile-dir requires an existing directory")
        index += 2


def main() -> None:
    """Public CLI error boundary; the Python scan API still raises errors."""
    import contextlib
    global _JSON_OUTPUT_STREAM
    original_stream = _JSON_OUTPUT_STREAM
    try:
        if "--json" in sys.argv[1:] and not any(a in sys.argv for a in ("--help", "-h")):
            _JSON_OUTPUT_STREAM = sys.stdout
            with contextlib.redirect_stdout(sys.stderr):
                _main()
        else:
            _main()
    except (ValueError, OSError) as exc:
        print("[!] %s" % _safe_error_excerpt(str(exc)), file=sys.stderr)
        sys.exit(2)
    except KeyboardInterrupt:
        print("\n[!] Interrupted; scan incomplete.", file=sys.stderr)
        sys.exit(130)
    finally:
        _JSON_OUTPUT_STREAM = original_stream


def _main() -> None:
    warnings.filterwarnings("ignore")
    args = sys.argv[1:]
    if "--help" in args or "-h" in args:
        _print_usage()
        return
    _validate_public_arguments(args)
    # Every public invocation starts fresh, including embedding/tests.
    global _INSECURE_TLS, _MAX_PER_TEMPLATE, _MAX_PER_LOCALE
    _INSECURE_TLS = False
    _MAX_PER_TEMPLATE, _MAX_PER_LOCALE = 5, 1
    _begin_discovery_session()

    # Boolean flags
    skip_jsapi          = "--no-jsapi"            in args; args = [a for a in args if a != "--no-jsapi"]
    include_maps        = "--include-maps"        in args; args = [a for a in args if a != "--include-maps"]
    include_low         = "--include-low"         in args; args = [a for a in args if a != "--include-low"]
    include_destructive = "--include-destructive" in args; args = [a for a in args if a != "--include-destructive"]
    include_cost_amp    = "--include-cost-amp"    in args; args = [a for a in args if a != "--include-cost-amp"]

    exit_on_dead_key    = "--exit-on-dead-key"    in args; args = [a for a in args if a != "--exit-on-dead-key"]

    no_color            = "--no-color"            in args; args = [a for a in args if a != "--no-color"]

    exit_on_any_confirmed = "--exit-on-any-confirmed" in args; args = [a for a in args if a != "--exit-on-any-confirmed"]

    rollup_all_findings = "--rollup-all-findings" in args; args = [a for a in args if a != "--rollup-all-findings"]
    include_authorization = "--include-authorization-key" in args
    args = [a for a in args if a != "--include-authorization-key"]
    authorization_only = "--authorization-only" in args
    args = [a for a in args if a != "--authorization-only"]
    if authorization_only:
        include_authorization = True

    debug_mobile_extract = "--debug-mobile-extract" in args; args = [a for a in args if a != "--debug-mobile-extract"]

    fingerprint_detail = "concise"
    _fp_idx = 0
    while _fp_idx < len(args):
        if args[_fp_idx] == "--fingerprint-detail":
            if _fp_idx + 1 >= len(args):
                print("[!] --fingerprint-detail requires a value (concise|full)")
                sys.exit(2)
            _fp_val = args[_fp_idx + 1].lower()
            if _fp_val not in ("concise", "full"):
                print("[!] --fingerprint-detail must be 'concise' or 'full'; got %r" % _fp_val)
                sys.exit(2)
            fingerprint_detail = _fp_val
            del args[_fp_idx:_fp_idx + 2]
        else:
            _fp_idx += 1

    include_auth_read   = "--include-auth-read"   in args; args = [a for a in args if a != "--include-auth-read"]
    _set_auth_read_enabled(include_auth_read)


    def _take_value_flag(flag):
        val = None
        _j = 0
        while _j < len(args):
            if args[_j] == flag:
                if _j + 1 >= len(args):
                    print("[!] %s requires a value" % flag)
                    sys.exit(2)
                val = args[_j + 1]
                del args[_j:_j + 2]
            else:
                _j += 1
        return val
    it_test_email = _take_value_flag("--it-test-email")
    it_test_phone = _take_value_flag("--it-test-phone")
    # Default scope: True for direct --api-key / --rescan-kb flows
    # (operator's explicit key choice). Discovery flows below set it to
    # False when an out-of-scope key origin is detected.
    _set_auth_read_scope_ok(True)
    if "--include-risky" in args:
        print("[!] --include-risky has been renamed to --include-destructive. Aborting.")
        sys.exit(2)
    all_mode      = "--all"           in args; args = [a for a in args if a != "--all"]
    if authorization_only and any((include_maps, include_low,
                                   include_destructive, include_cost_amp,
                                   include_auth_read, all_mode)):
        print("[!] --authorization-only cannot be combined with other probe groups.")
        sys.exit(2)
    verbose       = "--verbose" in args or "-v" in args; args = [a for a in args if a not in ("--verbose", "-v")]
    quiet         = "--quiet"   in args or "-q" in args; args = [a for a in args if a not in ("--quiet",   "-q")]
    output_json   = "--json"          in args; args = [a for a in args if a != "--json"]
    no_playwright = "--no-playwright" in args; args = [a for a in args if a != "--no-playwright"]
    # `--insecure` — force verify=False for ALL requests including Google
    # endpoints. Required when an egress proxy MITMs *.googleapis.com (corp
    # network with a TLS interception proxy). Off by default.
    insecure_tls  = "--insecure"      in args; args = [a for a in args if a != "--insecure"]
    if insecure_tls:
        _INSECURE_TLS = True
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass
        print("[!] --insecure: TLS verification DISABLED for all requests.")
    show_kb       = "--show-kb"        in args; args = [a for a in args if a != "--show-kb"]
    bootstrap_kb  = "--bootstrap-kb"   in args; args = [a for a in args if a != "--bootstrap-kb"]
    rescan_kb     = "--rescan-kb"      in args; args = [a for a in args if a != "--rescan-kb"]
    # Resume URL queue state and cached completed bodies after interruption.
    resume        = "--resume"         in args; args = [a for a in args if a != "--resume"]
    # Auto-retry with the discovered source URL as Referer.
    no_auto_referer = "--no-auto-referer" in args; args = [a for a in args if a != "--no-auto-referer"]
    global _DISABLE_PLAYWRIGHT
    global _URL_FETCH_BUDGET, _URL_FETCH_QUEUE_STATE, _URL_FETCH_RESUME
    global _INCLUDE_AUTHORIZATION_KEY, _AUTHORIZATION_ONLY
    _DISABLE_PLAYWRIGHT = no_playwright
    _URL_FETCH_RESUME = resume
    _INCLUDE_AUTHORIZATION_KEY = include_authorization
    _AUTHORIZATION_ONLY = authorization_only

    # Key-value flags
    apikey = proxy = referer = project_id = output_file = url_target = None
    mobile_file = None

    mobile_files = []
    mobile_dir = None
    program_slug = None
    output_dir_override = None
    url_fetch_budget = None
    url_fetch_state = None
    export_kb_csv = None
    rescan_kb_start_index = None
    rescan_kb_end_index = None
    rescan_kb_indexes = None
    restriction_mode = restriction_value = None
    threads = 10
    i = 0
    remaining = []

    while i < len(args):
        arg = args[i]
        def _next(flag):
            nonlocal i
            if i + 1 < len(args):
                val = args[i + 1]; i += 2; return val
            print("Missing value after %s, aborting." % flag); _print_usage(); sys.exit(2)

        if   arg in ("--api-key",          "-a"): apikey            = _next(arg)
        elif arg == "--url":                      url_target        = _next(arg)
        elif arg == "--mobile":

            _mf = _next(arg)
            mobile_files.append(_mf)
            if mobile_file is None:
                mobile_file = _mf
        elif arg == "--mobile-dir":
            mobile_dir = _next(arg)
        elif arg == "--program":                  program_slug      = _next(arg)
        elif arg == "--output-dir":               output_dir_override = _next(arg)
        elif arg == "--max-per-template":         _MAX_PER_TEMPLATE   = int(_next(arg))
        elif arg == "--max-per-locale":           _MAX_PER_LOCALE     = int(_next(arg))
        elif arg == "--url-fetch-budget":         url_fetch_budget    = int(_next(arg))
        elif arg == "--url-fetch-state":          url_fetch_state     = _next(arg)
        elif arg in ("--proxy",            "-p"): proxy             = _next(arg)
        elif arg in ("--referer",          "-r"): referer           = _next(arg)
        elif arg in ("--project-id",       "-P"): project_id        = _next(arg)
        elif arg in ("--threads",          "-t"): threads           = int(_next(arg))
        elif arg in ("--output",           "-o"): output_file       = _next(arg)
        elif arg == "--restriction-mode":         restriction_mode  = _next(arg)
        elif arg == "--restriction-value":        restriction_value = _next(arg)
        elif arg == "--export-kb-csv":            export_kb_csv     = _next(arg)
        elif arg == "--rescan-kb-start-index":    rescan_kb_start_index = int(_next(arg))
        elif arg == "--rescan-kb-end-index":      rescan_kb_end_index = int(_next(arg))
        elif arg == "--rescan-kb-indexes":
            raw_indexes = _next(arg)
            try:
                rescan_kb_indexes = {
                    int(x.strip()) for x in raw_indexes.split(",") if x.strip()
                }
            except ValueError:
                print("[!] --rescan-kb-indexes expects comma-separated integers")
                sys.exit(2)
            if not rescan_kb_indexes:
                print("[!] --rescan-kb-indexes requires at least one integer")
                sys.exit(2)
        elif arg in ("--help",             "-h"): _print_usage(); return
        else: remaining.append(arg); i += 1

    if remaining:
        print("Unknown arguments: %s" % _redact_diagnostic_secret_text(" ".join(remaining)))
        _print_usage(); sys.exit(2)

    if restriction_mode and restriction_mode not in ("none", "referer", "ip", "android", "ios"):
        print("[!] --restriction-mode must be one of: none, referer, ip, android, ios")
        sys.exit(2)

    if url_fetch_budget is not None and url_fetch_budget < 0:
        print("[!] --url-fetch-budget must be >= 0 (0 means unlimited).")
        sys.exit(2)
    _URL_FETCH_BUDGET = url_fetch_budget
    _URL_FETCH_QUEUE_STATE = url_fetch_state

    if threads < 1:
        raise ValueError("--threads must be >= 1")
    if resume and not (url_target and url_fetch_state):
        raise ValueError("--resume requires --url and --url-fetch-state")
    if restriction_mode in ("referer", "android", "ios") and not restriction_value:
        raise ValueError("--restriction-mode %s requires --restriction-value" % restriction_mode)
    if apikey and (url_target or mobile_files or mobile_dir):
        raise ValueError("--api-key cannot be combined with a discovery mode")
    kb_modes = sum(bool(x) for x in (show_kb, export_kb_csv, bootstrap_kb, rescan_kb))
    if kb_modes > 1 or (kb_modes and (apikey or url_target or mobile_files or mobile_dir)):
        raise ValueError("Choose exactly one scan or knowledge-base mode")
    if kb_modes and (output_json or output_file):
        raise ValueError("--json/--output require --api-key, --url or --mobile; use --export-kb-csv for the KB")

    _configure_proxy(proxy)
    if proxy:
        print("Using configured proxy.")

    if show_kb:
        _kb_show(output_dir=output_dir_override)
        sys.exit(0)
    if export_kb_csv:
        _kb_export_csv(export_kb_csv, output_dir=output_dir_override)
        sys.exit(0)
    if bootstrap_kb:
        _kb_bootstrap(output_dir=output_dir_override, verbose=verbose)
        sys.exit(0)
    if rescan_kb:
        from datetime import datetime as _dt

        _begin_discovery_session()

        _set_auth_read_scope_ok(False)
        if include_auth_read:
            print("[!] --include-auth-read is set, but --rescan-kb cannot prove")
            print("    a live in-scope origin for persisted keys. The auth-read")
            print("    chain WILL NOT fire during rescan. Re-discover the key")
            print("    via --url or --mobile to enable.")
        kb = _kb_load(output_dir=output_dir_override)
        if not kb:
            print("[!] KB is empty. Run --bootstrap-kb first or scan a target.")
            sys.exit(2)
        # Optional program filter: --rescan-kb --program X re-scans only keys
        # first seen in program X (sources matching `program=X` still count).
        if program_slug:

            def _src_matches_prog(s, prog):
                if isinstance(s, dict):
                    return s.get("program") == prog
                if isinstance(s, str):
                    return prog in s.split(":") or s == prog
                return False
            kb = {k: e for k, e in kb.items()
                  if e.get("first_program") == program_slug
                  or any(_src_matches_prog(s, program_slug) for s in e.get("sources", []))}
            if not kb:
                print("[!] KB has no keys for program '%s'." % program_slug)
                sys.exit(2)
        ts = _dt.now().strftime("%Y%m%d_%H%M%S")
        kb_items_all = sorted(kb.items())
        total_kb_items = len(kb_items_all)
        start_idx = rescan_kb_start_index or 1
        end_idx = rescan_kb_end_index or total_kb_items
        if start_idx < 1 or end_idx < start_idx or start_idx > total_kb_items:
            print("[!] Invalid --rescan-kb index range %s-%s for %d key(s)."
                  % (start_idx, end_idx, total_kb_items))
            sys.exit(2)
        end_idx = min(end_idx, total_kb_items)
        kb_items = [
            (idx, item) for idx, item in enumerate(kb_items_all, 1)
            if start_idx <= idx <= end_idx
            and (rescan_kb_indexes is None or idx in rescan_kb_indexes)
        ]
        if rescan_kb_indexes and not kb_items:
            print("[!] --rescan-kb-indexes selected no keys in range %s-%s."
                  % (start_idx, end_idx))
            sys.exit(2)
        if rescan_kb_indexes:
            print("[*] Re-scanning %d KB key(s) — discovery skipped (explicit indexes of %d)."
                  % (len(kb_items), total_kb_items))
        elif start_idx != 1 or end_idx != total_kb_items:
            print("[*] Re-scanning %d KB key(s) — discovery skipped (index %d-%d of %d)."
                  % (len(kb_items), start_idx, end_idx, total_kb_items))
        else:
            print("[*] Re-scanning %d KB key(s) — discovery skipped." % len(kb_items))
        any_vulnerable = False
        # Track whether ANY per-key scan finished transport-incomplete (SSL /
        # connection / timeout). If no key turns up vulnerable but at least one
        # scan was transport-incomplete, the final exit code is 3, not 0.
        any_transport_incomplete = False

        _rollup_rows = []

        def _src_label(s):
            if isinstance(s, dict):
                return "%s/%s" % (s.get("platform") or "?", s.get("program") or "?")
            if isinstance(s, str):
                return s if "/" in s or ":" in s else "?/%s" % s
            return "?/?"
        for idx, (k, entry) in kb_items:
            print("\n" + "#" * 70)
            print("# KB key %d/%d: %s" % (
                idx, total_kb_items, _redact_key_display(k)))
            print("#   sources: " + (", ".join(
                _redact_diagnostic_secret_text(_src_label(s)) for s in entry.get("sources", [])[:5]) or "(none)"))
            print("#" * 70)

            kb_source_url = None
            for s in entry.get("sources", []):
                u = (s.get("url") or "") if isinstance(s, dict) else ""
                if u.startswith(("http://", "https://")):
                    kb_source_url = u
                    break
            # --- Pass 1: unrestricted (or user-pinned restriction) ---
            vs_un = set()
            vs_ref = set()
            _p1_rows = []
            _p2_rows = []
            _p1_diag = {}
            _p2_diag = {}
            _rollup_source = (kb_source_url
                              or next((_src_label(s)
                                       for s in entry.get("sources", [])), None))
            _effective_project_id = (
                project_id or known_project_from_history(entry)
            )
            try:
                vs_un = scan_gapis(
                    k,
                    include_maps=include_maps,
                    include_low=include_low,
                    include_destructive=include_destructive,
                    include_cost_amp=include_cost_amp,
                    it_test_email=it_test_email,
                    it_test_phone=it_test_phone,
                    all_mode=all_mode, skip_jsapi=True,
                    proxy=proxy, referer=referer,
                    restriction_mode=restriction_mode,
                    restriction_value=restriction_value,
                    verbose=verbose, quiet=quiet, threads=threads,
                    project_id=_effective_project_id,
                    output_file=None, output_json=False,
                    exit_on_dead_key=exit_on_dead_key,
                    fingerprint_detail=fingerprint_detail,
                    no_color=no_color,
                )
            except Exception as e:
                print("    [!] scan_gapis (pass1) raised %s: %s — continuing"
                      % (type(e).__name__, _safe_error_excerpt(str(e))))

                any_transport_incomplete = True
            else:
                if _classify_scan_vulnerable(vs_un, exit_on_any_confirmed):
                    any_vulnerable = True
                if _last_transport_error_total() > 0:
                    any_transport_incomplete = True
                _p1_rows = _last_scan_result_snapshot()
                _p1_diag = _last_scan_diagnostic_snapshot()
            pid = next(iter(sorted(_DERIVED_PROJECT_IDS)), None)
            pnum = next(iter(sorted(_DERIVED_PROJECT_NUMBERS)), None)
            _kb_record_scan(k, ts, probes_count=None,
                            vulnerable_apis=set(vs_un),
                            project_id=pid, project_number=pnum,
                            restriction_mode=restriction_mode or "unrestricted",
                            restriction_value=restriction_value,
                            key_status=(
                                "VULNERABLE" if vs_un
                                else (restriction_mode or "unrestricted") + "-scan"),
                            output_dir=output_dir_override,
                            identity_toolkit_artifacts=(
                                _identity_toolkit_artifact_snapshot()),
                            probe_diagnostics=(
                                _p1_diag.get("probe_diagnostics")),
                            error_class_histogram=(
                                _p1_diag.get("error_class_histogram")),
                            finding_records=_p1_rows)
            # --- Pass 2: replay every known restriction context. ---
            # A shared key can ship in web + iOS + Android clients. The old
            # scalar model silently tested only one; the KB now retains and
            # replays all distinct contexts.
            _p2_contexts = []
            if not no_auto_referer and not restriction_mode:
                if kb_source_url:
                    _p2_contexts.append(("referer", kb_source_url, None))
                _mobile_labels = mobile_restrictions_from_kb_entry(entry)
                _p2_contexts.extend(
                    mobile_restriction_contexts(_mobile_labels)
                )
            if authorization_only:
                _auth_replay_modes = _authorization_only_replay_modes(_p1_diag)
                if _auth_replay_modes is not None:
                    _p2_contexts = [
                        context for context in _p2_contexts
                        if context[0] in _auth_replay_modes
                    ]
            _seen_p2 = set()
            for _p2_mode, _p2_value, _p2_label in _p2_contexts:
                if (_p2_mode, _p2_value) in _seen_p2:
                    continue
                _seen_p2.add((_p2_mode, _p2_value))
                print("\n    [pass2/%s] Running restricted-mode scan with %s=%s"
                      % (_p2_mode, _p2_mode, _redact_diagnostic_secret_text(_p2_value)))
                _vs_current = set()
                _p2_diag = {}
                _p2_current_rows = []
                try:
                    _vs_current = set(scan_gapis(
                        k,
                        include_maps=include_maps,
                        include_low=include_low,
                        include_destructive=include_destructive,
                        include_cost_amp=include_cost_amp,
                        it_test_email=it_test_email,
                        it_test_phone=it_test_phone,
                        all_mode=all_mode, skip_jsapi=True,
                        proxy=proxy, referer=referer,
                        restriction_mode=_p2_mode,
                        restriction_value=_p2_value,
                        verbose=verbose, quiet=quiet, threads=threads,
                        project_id=_effective_project_id,
                        output_file=None, output_json=False,
                        exit_on_dead_key=exit_on_dead_key,
                        fingerprint_detail=fingerprint_detail,
                        no_color=no_color,
                    ) or [])
                    _pass2_success = True
                except Exception as e:
                    print("    [!] scan_gapis (pass2) raised %s: %s — skipping"
                          % (type(e).__name__, _safe_error_excerpt(str(e))))

                    any_transport_incomplete = True
                    _pass2_success = False
                vs_ref.update(_vs_current)
                vs_ref_s = set(_vs_current)
                vs_un_s  = set(vs_un)  if vs_un  else set()
                if _pass2_success:
                    if _classify_scan_vulnerable(
                            _vs_current, exit_on_any_confirmed):
                        any_vulnerable = True
                    if vs_ref_s:
                        extra = vs_ref_s - vs_un_s
                        if extra:
                            print("    [pass2/%s] FOUND %d additional vulnerable API(s)"
                                  % (_p2_mode, len(extra)))
                    if _last_transport_error_total() > 0:
                        any_transport_incomplete = True
                    _p2_current_rows = _last_scan_result_snapshot()
                    _p2_rows.extend(_p2_current_rows)
                    _p2_diag = _last_scan_diagnostic_snapshot()
                pid2 = next(iter(sorted(_DERIVED_PROJECT_IDS)), None)
                pnum2 = next(iter(sorted(_DERIVED_PROJECT_NUMBERS)), None)
                _kb_record_scan(k, ts, probes_count=None,
                                vulnerable_apis=vs_ref_s,
                                project_id=pid2, project_number=pnum2,
                                restriction_mode=_p2_mode,
                                restriction_value=_p2_value,
                                key_status=(
                                    "VULNERABLE" if vs_ref_s else _p2_mode + "-scan"),
                                output_dir=output_dir_override,
                                identity_toolkit_artifacts=(
                                    _identity_toolkit_artifact_snapshot()),
                                probe_diagnostics=(
                                    _p2_diag.get("probe_diagnostics")),
                                error_class_histogram=(
                                    _p2_diag.get("error_class_histogram")),
                                finding_records=_p2_current_rows,
                                mobile_restriction=_p2_label)

            _rollup_rows.extend(_merge_rollup_rows_for_key(
                _rollup_source, _redact_key_display(k), _p1_rows, _p2_rows))

        _print_final_rollup(_rollup_rows, rollup_all_findings, quiet)

        if any_vulnerable:
            sys.exit(1)
        if any_transport_incomplete:
            sys.exit(3)
        sys.exit(0)


    _mobile_mode_active = bool(mobile_file or mobile_files or mobile_dir)
    discovery_modes = sum(1 for x in (url_target, _mobile_mode_active) if x)
    if discovery_modes > 1:
        print("[!] --url and --mobile/--mobile-dir are mutually exclusive.")
        sys.exit(2)
    if discovery_modes:
        if apikey:
            print("[!] Discovery mode active — --api-key ignored.")

        _begin_discovery_session()

        _mobile_key_configs = {}

        _direct_in_scope_check = None  # set per entrypoint below
        if url_target:
            keys, sources = discover_keys_from_url(url_target,
                                                   verbose=verbose, quiet=quiet)
            _direct_in_scope_check = _build_direct_discovery_in_scope_check(
                "url", url_target)
        else:  # mobile_file / mobile_files / mobile_dir

            _mobile_paths = _expand_mobile_input(mobile_files, mobile_dir)
            if not _mobile_paths:
                raise ValueError("No supported mobile archives were selected")

            keys, sources, _mobile_key_configs = _run_mobile_batch(
                _mobile_paths, verbose=verbose, quiet=quiet,
                debug_mobile_extract=debug_mobile_extract)
            _direct_in_scope_check = _build_direct_discovery_in_scope_check(
                "mobile", None)

        if not keys:
            print("\n[*] No AIza keys discovered.")

        in_scope_keys, oos_keys, oos_reasons = _partition_keys_by_origin_scope(
            keys, sources, _direct_in_scope_check)
        if oos_keys:
            print("\n[*] %d key(s) skipped (out-of-scope source only):"
                  % len(oos_keys))
            for ok in sorted(oos_keys):
                srcs = oos_reasons.get(ok, [])
                preview = srcs[0] if srcs else "(no source recorded)"
                print("    - %s  source: %s" % (
                    _redact_key_display(ok), _redact_diagnostic_secret_text(preview)))
        if not in_scope_keys:
            print("\n[*] No in-scope AIza keys to scan.")
        any_vulnerable = False
        # Track whether ANY per-key scan finished transport-incomplete (SSL /
        # connection / timeout). If no key turns up vulnerable but at least one
        # scan was transport-incomplete, the final exit code is 3, not 0.
        any_transport_incomplete = False

        _direct_scope_prior = _AUTH_READ_SCOPE_OK

        _rollup_rows = []
        # Aggregate redacted per-key/pass snapshots for --output/--json.
        # Individual scan_gapis calls cannot write the shared path because a
        # discovery run may contain many keys and restriction contexts.
        _discovery_output_keys = []
        for idx, k in enumerate(sorted(in_scope_keys), 1):
            print("\n" + "#" * 70)
            print("# Key %d/%d: %s" % (
                idx, len(in_scope_keys), _redact_key_display(k)))

            _origin = (_describe_key_origin(sources.get(k))
                       if isinstance(sources, dict) else None)
            if _origin:
                print("# Source: %s" % _origin)
            print("#" * 70)
            _p1_rows = []
            _p2_rows = []
            _p1_diag = {}
            _p2_diag = {}
            _p2_kb_records = []
            _p1_pid = _p1_pnum = None
            _p1_artifacts = []
            _p1_success = False
            _rollup_source = None
            if isinstance(sources, dict):
                _src_set = sources.get(k) or set()
                _rollup_source = next(iter(sorted(_src_set)), None) if _src_set else None

            _key_sources_for_k = (sources.get(k, set())
                                  if isinstance(sources, dict) else None)
            _key_in_scope = _are_key_sources_in_scope(
                _key_sources_for_k, _direct_in_scope_check)
            _set_auth_read_scope_ok(_key_in_scope)
            if not _key_in_scope and verbose:
                print("    [*] auth-read disabled for this key — no source "
                      "URL ties to the operator-supplied scope/target")
            try:

                _source_labels = (
                    sources.get(k) if isinstance(sources, dict) else None
                )
                _pass2_contexts = mobile_restriction_contexts(_source_labels)
                for source_url in sorted(_source_labels or []):
                    if (source_url.startswith(("https://", "http://"))
                            and _direct_in_scope_check(source_url)):
                        _pass2_contexts.insert(0, ("referer", source_url, None))
                        break
                _k_configs = _mobile_key_configs.get(k)
                if _mobile_mode_active:
                    _k_configs_arg = list(_k_configs) if _k_configs else []
                else:
                    _k_configs_arg = _k_configs if _k_configs else None

                vs_un = set()
                vs_ref = set()
                _p1_rows = []
                _p2_rows = []
                _p1_diag = {}
                _p2_diag = {}
                _pass2_ran = False
                try:
                    r = scan_gapis(
                        k,
                        include_maps=include_maps,
                        include_low=include_low,
                        include_destructive=include_destructive,
                        include_cost_amp=include_cost_amp,
                        it_test_email=it_test_email,
                        it_test_phone=it_test_phone,
                        all_mode=all_mode, skip_jsapi=True,
                        proxy=proxy, referer=referer,
                        restriction_mode=restriction_mode,
                        restriction_value=restriction_value,
                        verbose=verbose, quiet=quiet, threads=threads,
                        project_id=project_id, output_file=None, output_json=False,
                        exit_on_dead_key=exit_on_dead_key,
                        fingerprint_detail=fingerprint_detail,
                        no_color=no_color,
                        key_firebase_configs=_k_configs_arg,
                    )
                    vs_un = set(r) if r else set()
                    _p1_success = True
                except Exception as e:
                    print("    [!] scan_gapis (pass1) raised %s: %s" % (type(e).__name__, _safe_error_excerpt(str(e))))

                    any_transport_incomplete = True
                else:
                    if _classify_scan_vulnerable(vs_un, exit_on_any_confirmed):
                        any_vulnerable = True
                    if _last_transport_error_total() > 0:
                        any_transport_incomplete = True
                    _p1_rows = _last_scan_result_snapshot()
                    _p1_diag = _last_scan_diagnostic_snapshot()
                _p1_pid = next(iter(sorted(_DERIVED_PROJECT_IDS)), None)
                _p1_pnum = next(iter(sorted(_DERIVED_PROJECT_NUMBERS)), None)
                _p1_artifacts = _identity_toolkit_artifact_snapshot()
                if authorization_only:
                    _auth_replay_modes = _authorization_only_replay_modes(_p1_diag)
                    if _auth_replay_modes is not None:
                        _pass2_contexts = [
                            context for context in _pass2_contexts
                            if context[0] in _auth_replay_modes
                        ]
                if not no_auto_referer and not restriction_mode:
                    for pass2_mode, pass2_value, _pass2_label in _pass2_contexts:
                        print("\n    [pass2/%s] Running restricted scan with %s=%s"
                              % (pass2_mode, pass2_mode, _redact_diagnostic_secret_text(pass2_value)))
                        _current_ref = set()
                        _current_rows = []
                        _current_diag = {}
                        try:
                            r2 = scan_gapis(
                                k,
                                include_maps=include_maps,
                                include_low=include_low,
                                include_destructive=include_destructive,
                                include_cost_amp=include_cost_amp,
                                it_test_email=it_test_email,
                                it_test_phone=it_test_phone,
                                all_mode=all_mode, skip_jsapi=True,
                                proxy=proxy, referer=referer,
                                restriction_mode=pass2_mode,
                                restriction_value=pass2_value,
                                verbose=verbose, quiet=quiet, threads=threads,
                                project_id=project_id,
                                output_file=None, output_json=False,
                                exit_on_dead_key=exit_on_dead_key,
                                fingerprint_detail=fingerprint_detail,
                                no_color=no_color,
                                key_firebase_configs=_k_configs_arg,
                            )
                            _current_ref = set(r2) if r2 else set()
                            _pass2_success = True
                        except Exception as e:
                            print("    [!] scan_gapis (pass2) raised %s: %s"
                                  % (type(e).__name__, _safe_error_excerpt(str(e))))
                            any_transport_incomplete = True
                            _pass2_success = False
                        if _pass2_success:
                            _pass2_ran = True
                            vs_ref.update(_current_ref)
                            if _classify_scan_vulnerable(
                                    _current_ref, exit_on_any_confirmed):
                                any_vulnerable = True
                            extra = _current_ref - vs_un
                            if extra:
                                print("    [pass2/%s] FOUND %d additional vulnerable API(s)"
                                      % (pass2_mode, len(extra)))
                            if _last_transport_error_total() > 0:
                                any_transport_incomplete = True
                            _current_rows = _last_scan_result_snapshot()
                            _current_diag = _last_scan_diagnostic_snapshot()
                            _p2_rows.extend(_current_rows)
                        _p2_kb_records.append({
                            "mode": pass2_mode,
                            "value": pass2_value,
                            "label": _pass2_label,
                            "vulnerable": _current_ref,
                            "rows": _current_rows,
                            "diagnostics": _current_diag,
                            "success": _pass2_success,
                            "project_id": next(iter(sorted(_DERIVED_PROJECT_IDS)), None),
                            "project_number": next(iter(sorted(_DERIVED_PROJECT_NUMBERS)), None),
                            "artifacts": _identity_toolkit_artifact_snapshot(),
                        })

                try:
                    _kb_ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                    _mob_restr = [row[2] for row in _pass2_contexts]
                    _kb_prog = program_slug
                    _kb_plat = "mobile" if _mobile_mode_active else "url"
                    # Pass-1 record (unrestricted or operator-pinned restriction).
                    for source in sorted(_source_labels or []):
                        _kb_record_discovery(
                            k, source, _kb_prog, _kb_plat, _kb_ts,
                            output_dir=output_dir_override,
                        )
                    _kb_record_scan(
                        k, _kb_ts, probes_count=None,
                        vulnerable_apis=set(vs_un),
                        project_id=_p1_pid, project_number=_p1_pnum,
                        restriction_mode=restriction_mode or "unrestricted",
                        restriction_value=restriction_value,
                        key_status=(
                            "incomplete" if not _p1_success else "VULNERABLE" if vs_un
                            else (restriction_mode or "unrestricted") + "-scan"),
                        output_dir=output_dir_override,
                        mobile_restriction=_mob_restr,
                        program=_kb_prog, platform=_kb_plat,
                        identity_toolkit_artifacts=(
                            _p1_artifacts),
                        probe_diagnostics=(
                            _p1_diag.get("probe_diagnostics")),
                        error_class_histogram=(
                            _p1_diag.get("error_class_histogram")),
                        finding_records=_p1_rows)
                    # Pass-2 record — ONLY if pass-2 actually ran, with its
                    # real android/ios restriction mode+value. This is where
                    # a bypass-only finding lands with the correct context.
                    for _p2_index, _p2_record in enumerate(
                            _p2_kb_records, 1):
                        if not _p2_record.get("success"):
                            continue
                        _p2_mode = _p2_record["mode"]
                        _p2_value = _p2_record["value"]
                        _p2_vs = set(_p2_record["vulnerable"])
                        _p2_diag_record = _p2_record["diagnostics"]
                        _kb_record_scan(
                            k, _kb_ts + "_p2_%d" % _p2_index,
                            probes_count=None,
                            vulnerable_apis=_p2_vs,
                            project_id=_p2_record["project_id"],
                            project_number=_p2_record["project_number"],
                            restriction_mode=_p2_mode,
                            restriction_value=_p2_value,
                            key_status=(
                                "VULNERABLE" if _p2_vs
                                else "%s-scan" % _p2_mode),
                            output_dir=output_dir_override,
                            mobile_restriction=_p2_record["label"],
                            program=_kb_prog, platform=_kb_plat,
                            identity_toolkit_artifacts=(
                                _p2_record["artifacts"]),
                            probe_diagnostics=(
                                _p2_diag_record.get("probe_diagnostics")),
                            error_class_histogram=(
                                _p2_diag_record.get("error_class_histogram")),
                            finding_records=_p2_record["rows"])
                except Exception as _kb_e:
                    _record_discovery_issue("kb_write_failures")
                    print("    [!] KB record failed: %s" % _safe_error_excerpt(str(_kb_e)))
            finally:

                _set_auth_read_scope_ok(_direct_scope_prior)

                _merged_rows = _merge_rollup_rows_for_key(
                    _rollup_source, _redact_key_display(k), _p1_rows, _p2_rows)
                _rollup_rows.extend(_merged_rows)
                _discovery_output_keys.append({
                    "key": _redact_key_display(k),
                    "source": _redact_diagnostic_secret_text(_rollup_source),
                    "findings": _merged_rows,
                    "pass1": {
                        "restriction_mode": restriction_mode or "unrestricted",
                        "restriction_value": _redact_diagnostic_secret_text(
                            restriction_value),
                        "findings": list(_p1_rows),
                        "diagnostics": dict(_p1_diag),
                    },
                    "pass2": [{
                        "restriction_mode": row.get("mode"),
                        "restriction_value": _redact_diagnostic_secret_text(
                            row.get("value")),
                        "source_label": _redact_diagnostic_secret_text(
                            row.get("label")),
                        "success": bool(row.get("success")),
                        "findings": list(row.get("rows") or []),
                        "diagnostics": dict(row.get("diagnostics") or {}),
                    } for row in _p2_kb_records],
                })

        _print_final_rollup(_rollup_rows, rollup_all_findings, quiet)
        discovery_incomplete = bool(_discovery_issue_snapshot())
        if discovery_incomplete:
            print("[!] Discovery incomplete: %s" % json.dumps(_discovery_issue_snapshot(), sort_keys=True))
        if output_json or output_file:
            _discovery_output = _build_discovery_json_output(
                "mobile" if _mobile_mode_active else "url",
                _discovery_output_keys,
                _rollup_rows,
                len(in_scope_keys),
                len(oos_keys),
                any_transport_incomplete,
                any_vulnerable,
            )
            if output_json:
                _emit_json(_discovery_output)
            if output_file:
                _save_output(output_file, _discovery_output)

        if any_vulnerable:
            sys.exit(1)
        if any_transport_incomplete or discovery_incomplete:
            sys.exit(3)
        sys.exit(0)

    if not apikey:
        print("[!] Error: --api-key / -a (or --url) is required.")
        _print_usage()
        sys.exit(2)

    vulnerable = scan_gapis(
        apikey,
        include_maps=include_maps,
        include_low=include_low,
        include_destructive=include_destructive,
        include_cost_amp=include_cost_amp,
        it_test_email=it_test_email,
        it_test_phone=it_test_phone,
        all_mode=all_mode,
        skip_jsapi=skip_jsapi,
        proxy=proxy,
        referer=referer,
        restriction_mode=restriction_mode,
        restriction_value=restriction_value,
        verbose=verbose,
        quiet=quiet,
        threads=threads,
        project_id=project_id,
        output_file=output_file,
        output_json=output_json,
        exit_on_dead_key=exit_on_dead_key,
        fingerprint_detail=fingerprint_detail,
        no_color=no_color,
    )

    reportable_high = _last_confirmed_high_total()
    if reportable_high > 0:
        sys.exit(1)
    if exit_on_any_confirmed and vulnerable:
        sys.exit(1)
    if _last_transport_error_total() > 0:
        sys.exit(3)
    sys.exit(0)
