def scan_gapis(apikey, include_maps=False, include_low=False,
               include_destructive=False, include_cost_amp=False,
               all_mode=False, skip_jsapi=False, proxy=None, referer=None,
               restriction_mode=None, restriction_value=None,
               verbose=False, quiet=False, threads=10, project_id=None,
               output_file=None, output_json=False,
               exit_on_dead_key=False,
               fingerprint_detail="concise",
               no_color=False,
               it_test_email=None, it_test_phone=None,
               include_risky=None,
               key_firebase_configs=None,
               extra_probes=None,
               include_authorization=None,
               authorization_only=None):
    """Scan a key with the selected Google API probes.

    Project derivation precedes the concurrent probe pool and Firebase checks.
    key_firebase_configs binds discovered configs to the current key.
    authorization_only restricts execution to the authorization probe group.
    The deprecated include_risky argument produces a migration error."""
    if include_risky is not None:
        raise TypeError(
            "include_risky is deprecated; use include_destructive instead "
            "(or --include-destructive on the CLI)."
        )

    _configure_proxy(proxy)
    _validate_api_key(apikey)

    _reset_transport_errors()


    _capture_last_confirmed_severity_counts(
        {"HIGH": 0, "MED": 0, "LOW_INFO": 0})

    _capture_last_scan_result_snapshot([])
    _capture_last_scan_diagnostic_snapshot([])


    with _DERIVED_LOCK:
        _DERIVED_PROJECT_IDS.clear()
        _DERIVED_PROJECT_NUMBERS.clear()
    with _IDENTITY_TOOLKIT_LOCK:
        _IDENTITY_TOOLKIT_ARTIFACTS.clear()

    with _AUTH_READ_LOCK:
        _AUTH_READ_FINDINGS.clear()
    _set_auth_read_firebase_configs(key_firebase_configs)


    if authorization_only is None:
        authorization_only = _AUTHORIZATION_ONLY
    if authorization_only:
        include_authorization = True
    probes = [] if authorization_only else [
        p for p in ALL_PROBES if p[1] == "high"
    ]
    if not authorization_only and (include_maps or all_mode):
        probes += [p for p in ALL_PROBES if p[1] == "maps"]
    if not authorization_only and (include_low or all_mode):
        probes += [p for p in ALL_PROBES if p[1] == "low"]
    if not authorization_only and (include_destructive or all_mode):
        probes += [p for p in ALL_PROBES if p[1] == "destructive"]

        _oob_probes = _build_operator_oob_probes(it_test_email, it_test_phone)
        probes += _oob_probes
        if not quiet:
            if include_destructive and not (it_test_email or it_test_phone):
                print("[*] --include-destructive set but no --it-test-email / "
                      "--it-test-phone — skipping operator-controlled OOB "
                      "email/SMS probes (no deliverable request issued).")
            if it_test_email:
                print("[*] OOB email probes ENABLED against operator address "
                      "%s (PASSWORD_RESET + EMAIL_SIGNIN)."
                      % _mask_operator_pii(it_test_email))
            if it_test_phone:
                print("[*] OOB SMS probe ENABLED against operator phone %s."
                      % _mask_operator_pii(it_test_phone))
    if include_authorization is None:
        include_authorization = _INCLUDE_AUTHORIZATION_KEY
    if not authorization_only and (include_cost_amp or all_mode):
        probes += [p for p in ALL_PROBES if p[1] == "cost-amp"]
    if include_authorization:
        probes += build_authorization_probes()

    if extra_probes and not authorization_only:
        probes += list(extra_probes)


    base_headers = _build_restriction_headers(restriction_mode, restriction_value, referer=referer)


    RED, GREEN, YELLOW, RESET = _color_palette(no_color)

    # Banner
    cat_counts = {}
    for p in probes:
        cat_counts[p[1]] = cat_counts.get(p[1], 0) + 1
    cat_summary = ", ".join("%s(%d)" % (k.upper(), v) for k, v in sorted(cat_counts.items()))
    print("\n[*] gapiscanner v%s — %d probes [%s]" % ("2.0.0", len(probes), cat_summary))
    if project_id:
        print("    Project ID (CLI): %s" % project_id)
    print()

    results = []
    lock = Lock()
    referer_blocked_list = []

    confirmed_count = [0]
    potential_count = [0]
    tested_count = [0]

    def _handle_result(result):
        if result is None:
            return
        with lock:
            tested_count[0] += 1
            results.append(result)
            if result["vulnerable"]:

                confirmation_is_kao = (
                    result.get("confirmation") == "key_accepted_only")
                is_potential_by_name = result["name"] in POTENTIAL_PROBES
                is_potential = confirmation_is_kao or is_potential_by_name

                if str(result.get("manual_note") or "").startswith("cleanup_failed"):
                    is_potential = False
                result["tier"] = "POTENTIAL" if is_potential else "CONFIRMED"
                if is_potential:
                    potential_count[0] += 1
                else:
                    confirmed_count[0] += 1
                if not quiet:
                    if is_potential:
                        # Severity-first tag mirrors the CONFIRMED branch so a
                        # POTENTIAL finding in a `high` run-group probe (e.g.
                        # non-empty RTDB → INFO/POTENTIAL/HIGH) can never print
                        # `[HIGH]` alone and be misread as a confirmed HIGH.
                        sev_tag = result.get("severity") or "INFO"
                        cat_tag = result["category"].upper()
                        print("%sPOTENTIAL VULNERABLE%s for %s [%s/POTENTIAL/%s] — manual verification needed"
                              % (RED, RESET, result["name"],
                                 sev_tag, cat_tag))
                    elif result.get("impact_type") == "user_enumeration":

                        sev_tag = result.get("severity") or "MED"
                        print("%sEmail enumeration possible%s — enumeration "
                              "protection appears disabled for %s [%s]"
                              % (YELLOW, RESET, result["name"], sev_tag))
                        print("  Caveat: differential not independently "
                              "confirmed (single-probe). Re-run with an "
                              "operator-supplied known-existing seed email "
                              "to confirm the differential.")
                    else:

                        sev_tag = result.get("severity") or "INFO"
                        tier_tag = result.get("tier") or "CONFIRMED"
                        cat_tag = result["category"].upper()

                        impact_type = result.get("impact_type")
                        if sev_tag in ("HIGH", "CRITICAL"):
                            print("API key is %svulnerable%s for %s! [%s/%s/%s]"
                                  % (RED, RESET, result["name"],
                                     sev_tag, tier_tag, cat_tag))
                        elif impact_type == "quota_cost":
                            print("%sBilling exposure confirmed%s for %s [%s/%s/%s]"
                                  % (YELLOW, RESET, result["name"],
                                     sev_tag, tier_tag, cat_tag))
                        else:
                            print("%sDiagnostic finding confirmed%s for %s [%s/%s/%s]"
                                  % (YELLOW, RESET, result["name"],
                                     sev_tag, tier_tag, cat_tag))
                    print("  PoC: %s" % _redact_key_from_url(result["url"]))
                    print("  Impact: %s" % result["impact"])
                    if is_potential:
                        print("  >> POTENTIAL note: %s" % POTENTIAL_NOTE_SHORT)
                        if result.get("followup_required") == (
                                "identity_toolkit_app_backend_chain"):
                            print("  >> Required follow-up: app-specific "
                                  "Firebase idToken/backend trust review")
            elif result["manual_note"] == "manually_check":
                if not quiet:
                    print("[?] %s — manually check: %s" % (result["name"], _redact_diagnostic_secret_text(result["url"])))
            elif result["referer_blocked"]:
                referer_blocked_list.append(result)
                if verbose:
                    print("  [REFERER] %s — %s" % (result["name"], result["reason"]))
            elif verbose:
                print("  [FAIL] %s — %s" % (result["name"], result["reason"]))
            if result.get("snippet") and verbose:
                print("  [verbose] %s" % _redact_diagnostic_secret_text(
                    result["snippet"]))

    probes_by_name = {p[0]: p for p in probes}
    already_run = set()
    gemini_disabled = False
    gemini_skip_reason = None  # error_class that triggered the skip (for reporting)
    phase_0_source = None


    phase_0_scheduled = tuple(name for name in PHASE_0_PROBE_NAMES
                              if name in probes_by_name)
    phase_0_completed_classes = []  # per-completed error_class, in order
    phase_0_transport_failure = False

    def _phase_0_attempt(probe):
        """Run a single Phase 0 probe with one transient retry."""
        last = None
        for attempt in range(2):
            res = _execute_probe(probe, apikey, project_id, base_headers, verbose)
            if res is None:
                continue
            sc = res.get("status_code") or 0
            if sc not in _PHASE_0_RETRY_STATUSES:
                return res
            last = res
        return last

    if not quiet:
        print("[*] Phase 0: Project enumeration...")

    for enum_name in PHASE_0_PROBE_NAMES:
        probe = probes_by_name.get(enum_name)
        if not probe:
            continue
        result = _phase_0_attempt(probe)
        if result is None:

            phase_0_transport_failure = True
            continue
        already_run.add(enum_name)
        _handle_result(result)
        phase_0_completed_classes.append(result.get("error_class"))
        if enum_name == "Gemini Models List" and result.get("gemini_disabled"):
            gemini_disabled = True
            gemini_skip_reason = result.get("error_class")
        # Did anything land in the derived sets yet?
        with _DERIVED_LOCK:
            have_id  = bool(_DERIVED_PROJECT_IDS)
            have_num = bool(_DERIVED_PROJECT_NUMBERS)
        if have_id or have_num:
            phase_0_source = enum_name
            break

    # Decide the effective {project} substitution value used by Phase 2.
    # Precedence: explicit --project-id > derived ID > derived number > placeholder.
    with _DERIVED_LOCK:

        if project_id and project_id != _PLACEHOLDER_PROJECT_ID:
            _DERIVED_PROJECT_IDS.add(project_id)
        derived_id  = next(iter(sorted(_DERIVED_PROJECT_IDS)),     None)
        derived_num = next(iter(sorted(_DERIVED_PROJECT_NUMBERS)), None)
    effective_project = project_id or derived_id or derived_num
    if not quiet:
        if phase_0_source:
            print("    Derived from '%s': id=%s number=%s" % (phase_0_source, derived_id or "-", derived_num or "-"))
        elif effective_project:
            print("    Using --project-id: %s" % effective_project)
        else:
            # Contextual hint: if every Phase 0 probe got SERVICE_BLOCKED or
            # KEY_INVALID, the key is likely service-restricted (allowlist) and
            # this is expected — not a scanner problem. Anything else suggests
            # a quota/connectivity issue worth flagging more loudly.
            phase_0_classes = {r.get("error_class") for r in results if r.get("error_class")}
            blocked_classes = {"SERVICE_BLOCKED", "KEY_INVALID", "KEY_EXPIRED", "UNAUTHENTICATED"}
            if phase_0_classes and phase_0_classes.issubset(blocked_classes):
                if "KEY_EXPIRED" in phase_0_classes:
                    print("    No project derived — Phase 0 probes returned KEY_EXPIRED.")
                    print("    The key has been rotated/expired; Phase 2 results will be similar.")
                else:
                    print("    No project derived — Phase 0 probes all blocked at the API-allowlist layer.")
                    print("    This is normal for service-restricted keys; Phase 2 will still test allowed APIs.")
            else:
                print("    No project ID/number derived — Phase 2 will use placeholder 'test-project-123'.")


    _DEAD_KEY_CLASSES = frozenset({"KEY_EXPIRED", "KEY_INVALID"})
    _phase_0_classes = set(phase_0_completed_classes)
    _dead_key_short_circuit = bool(
        exit_on_dead_key
        and not phase_0_transport_failure
        and len(phase_0_completed_classes) == len(phase_0_scheduled)
        and phase_0_completed_classes
        and _phase_0_classes.issubset(_DEAD_KEY_CLASSES)
    )
    if _dead_key_short_circuit and not quiet:
        _verdict = ("KEY_EXPIRED" if "KEY_EXPIRED" in _phase_0_classes
                    else "KEY_INVALID")
        print("[*] --exit-on-dead-key: Phase 0 classified key as %s — "
              "skipping Phase 2 / Phase 3." % _verdict)

    # Filter the remaining probe set: drop already-run + skip Gemini probes if API disabled.
    # When the dead-key short-circuit tripped, leave other_probes empty
    # so the Phase 2 executor below becomes a no-op naturally.
    other_probes = []
    if not _dead_key_short_circuit:
        for p in probes:
            if p[0] in already_run:
                continue
            if gemini_disabled and p[0] in _GEMINI_SKIP_PROBES:
                continue
            other_probes.append(p)

    if gemini_disabled and not quiet:
        skipped = sum(1 for p in probes if p[0] in _GEMINI_SKIP_PROBES and p[0] not in already_run)
        if skipped:
            reason_blurb = {
                "API_DISABLED":    "Generative Language API is disabled in the project",
                "KEY_EXPIRED":     "key is expired",
                "KEY_INVALID":     "key is invalid/revoked",
                "SERVICE_BLOCKED": "key allowlist excludes generativelanguage.googleapis.com",
            }.get(gemini_skip_reason, "Gemini Models List rejected the key")
            print("[*] %s — skipping %d Gemini endpoints." % (reason_blurb, skipped))

    # ── Phase 2: Parallel scan of remaining probes ──
    if not quiet and other_probes:
        print("[*] Phase 2: Running %d probes with %d threads (project=%s)...\n"
              % (len(other_probes), threads, effective_project or "test-project-123"))

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(_execute_probe, p, apikey, effective_project, base_headers, verbose): p
            for p in other_probes
        }
        for fut in as_completed(futures):
            result = fut.result()
            _handle_result(result)


    if _dead_key_short_circuit or authorization_only:
        chain_projects = set()
        _configs_snapshot = []
    else:
        chain_projects = set()
        if _is_valid_googleapis_project_ref(project_id):
            chain_projects.add(project_id)
        # This key's OWN Phase-0 derivations (cleared per scan at the top of
        # scan_gapis, so these never carry across keys).
        with _DERIVED_LOCK:
            chain_projects.update(_DERIVED_PROJECT_IDS)

        if key_firebase_configs is not None:
            _cfg_pool = list(key_firebase_configs)
            for _cfg in _cfg_pool:
                _cid = (_cfg or {}).get("project_id")
                if _is_valid_googleapis_project_ref(_cid):
                    chain_projects.add(_cid)
            _configs_snapshot = [dict(c) for c in _cfg_pool if c]
        else:
            with _DERIVED_FIREBASE_LOCK:
                for _cfg in _DERIVED_FIREBASE_CONFIGS:
                    _cid = _cfg.get("project_id")
                    if _is_valid_googleapis_project_ref(_cid):
                        chain_projects.add(_cid)
                # Snapshot configs for use below — avoid holding the lock across HTTP.
                _configs_snapshot = [dict(c) for c in _DERIVED_FIREBASE_CONFIGS]

    if chain_projects and not quiet:
        _scope_note = (" (this key only)" if key_firebase_configs is not None
                       else "")
        print("\n[*] Phase 3: Firebase chain — %d project ID(s) derived%s: %s"
              % (len(chain_projects), _scope_note,
                 ", ".join(sorted(chain_projects))))
        if _configs_snapshot:
            print("    %d Firebase config(s) extracted (DATABASE_URL/"
                  "STORAGE_BUCKET substitution available)" % len(_configs_snapshot))


    def _extra_chain_probes_for_config(cfg):
        out = []
        db_url = _validated_rtdb_url(cfg.get("database_url")) or ""
        if db_url and db_url.startswith(("http://", "https://")):
            try:
                _db_host = urlparse(db_url).netloc
            except Exception:
                _db_host = ""
        else:
            _db_host = ""
        if _db_host and "$" not in _db_host and "(" not in _db_host and ")" not in _db_host:
            out.append((
                "Firebase RTDB root (extracted DATABASE_URL)",
                "high", "GET",
                db_url + "/.json",
                None, _check_firebase_rtdb_root,
                "Realtime Database root read — extracted DATABASE_URL from config",
            ))
            out.append((
                "Firebase RTDB shallow keys (extracted DATABASE_URL)",
                "high", "GET",
                db_url + "/.json?shallow=true",
                None, _check_firebase_rtdb_root,
                "Realtime Database top-level key list — extracted DATABASE_URL",
            ))
        bucket = (cfg.get("storage_bucket") or "").strip()
        if any(ch in bucket for ch in ("$", "(", ")", "/", "\\")):
            bucket = ""
        if bucket:
            # storage_bucket entries from Firebase configs are like "my-app.appspot.com"
            out.append((
                "Firebase Storage list (extracted STORAGE_BUCKET)",
                "high", "GET",
                "https://firebasestorage.googleapis.com/v0/b/%s/o?key={key}" % bucket,
                None, _check_firebase_storage_list,
                "Storage bucket file listing — extracted STORAGE_BUCKET from config",
            ))
        return out

    chain_results = []
    for pid in sorted(chain_projects):
        chain_probes = list(FIREBASE_CHAIN_PROBES)
        if not _is_valid_firebase_hostname_project_id(pid):
            chain_probes = [
                p for p in chain_probes
                if not (
                    "{project}.firebaseio.com" in p[3]
                    or "{project}-default-rtdb" in p[3]
                    or "{project}.appspot.com" in p[3]
                    or "{project}.firebasestorage.app" in p[3]
                )
            ]

        seen_urls = {p[3] for p in chain_probes}
        for cfg in _configs_snapshot:
            if cfg.get("project_id") != pid:
                continue
            for ep in _extra_chain_probes_for_config(cfg):
                if ep[3] not in seen_urls:
                    chain_probes.append(ep)
                    seen_urls.add(ep[3])
        # Skip destructive chain probes unless opted-in
        if not (include_destructive or all_mode):
            chain_probes = [p for p in chain_probes if p[1] != "destructive"]
        for probe in chain_probes:
            res = _execute_probe(probe, apikey, pid, base_headers, verbose)
            if res is None:
                continue
            res["name"] = "%s [project=%s]" % (res["name"], pid)
            _handle_result(res)
            chain_results.append(res)

            if res["vulnerable"] and "RTDB write probe" in probe[0]:
                cleanup_url = res["url"]
                try:
                    dr = requests.delete(cleanup_url, headers=base_headers, **_request_kwargs_for_url(cleanup_url))
                    if dr.status_code not in (200, 204):
                        _it_record_artifact(
                            "Firebase RTDB write probe",
                            local_id=cleanup_url, id_token=None,
                            reason="DELETE returned HTTP %d" % dr.status_code)
                except requests.RequestException as e:
                    _it_record_artifact(
                        "Firebase RTDB write probe",
                        local_id=cleanup_url, id_token=None,
                        reason="DELETE request failed: %s" % e)


    projectless = [c for c in _configs_snapshot if not c.get("project_id")]
    if projectless:
        if not quiet:
            print("    %d Firebase config(s) without derivable project_id — "
                  "running extracted-URL probes directly" % len(projectless))
        seen_projectless_urls = set()
        for cfg in projectless:
            for probe in _extra_chain_probes_for_config(cfg):
                if probe[3] in seen_projectless_urls:
                    continue
                seen_projectless_urls.add(probe[3])
                # Honor the same destructive opt-in gate as the per-pid loop.
                if probe[1] == "destructive" and not (include_destructive or all_mode):
                    continue
                res = _execute_probe(probe, apikey, None, base_headers, verbose)
                if res is None:
                    continue
                res["name"] = "%s [no-project]" % res["name"]
                _handle_result(res)
                chain_results.append(res)


    with _AUTH_READ_LOCK:
        harvested_auth_read = list(_AUTH_READ_FINDINGS)
        _AUTH_READ_FINDINGS.clear()
    _set_auth_read_firebase_configs(None)
    for res in harvested_auth_read:
        # Surface abuse class through the same lookup as other probes.
        res.setdefault("abuse_class", _get_abuse_class(res["name"], res["category"]))
        _handle_result(res)
        chain_results.append(res)


    extras = []
    vuln_names = {r["name"] for r in results if r["vulnerable"]}
    for trigger_name, (extra_name, extra_impact) in _MAPS_EXTRAS.items():
        if trigger_name in vuln_names:
            inferred_impact = extra_impact + _MAPS_EXTRAS_INFERRED_IMPACT_SUFFIX
            extras.append({
                "name": extra_name, "category": "maps",
                "impact": inferred_impact,
                "vulnerable": True,
                "url": "(included with %s)" % trigger_name,
                "referer_blocked": False,
                "manual_note": _MAPS_EXTRAS_INFERRED_NOTE,
                "reason": "",
                # POTENTIAL — does not count toward CONFIRMED-only headline.
                "tier": "POTENTIAL",
                "impact_type": "quota_cost",
                # key_accepted_only — we did not independently execute it.
                "confirmation": "key_accepted_only",
                "data_sensitivity": "billing_reachable",
                "severity": _derive_severity(
                    "quota_cost", "key_accepted_only", "billing_reachable"),
            })
            potential_count[0] += 1
            if not quiet:
                print("API key is %sinferred-vulnerable%s for %s! [MAPS / POTENTIAL]"
                      % (YELLOW, RESET, extra_name))
                print("  Impact: %s" % inferred_impact)
    results.extend(extras)


    if (include_maps or all_mode) and not skip_jsapi:
        from urllib.parse import quote
        jsapi_key = quote(apikey, safe="")
        jsapi_path = os.path.join(os.getcwd(), "jsapi_test.html")
        try:
            with open(jsapi_path, "w", encoding="utf-8") as f:
                f.write('<!DOCTYPE html><html><head>'
                        '<script src="https://maps.googleapis.com/maps/api/js?key=%s&callback=initMap&libraries=&v=weekly" defer></script>'
                        '<style type="text/css">#map{height:100%%;;}html,body{height:100%%;margin:0;padding:0;}</style>'
                        '<script>let map;function initMap(){map=new google.maps.Map(document.getElementById("map"),{center:{lat:-34.397,lng:150.644},zoom:8,});}</script>'
                        '</head><body><div id="map"></div></body></html>' % jsapi_key)
            print("\n[*] JavaScript API test: created %s" % jsapi_path)
            print("    Open in browser. If the map loads, the key permits a Maps JavaScript request from this origin.")
            print("    If you see 'Sorry! Something went wrong.' — key is not allowed for JS API.")
            print("    Delete the file when done: rm %s" % jsapi_path)
        except Exception as e:
            print("[!] Could not create jsapi_test.html: %s" % e)

    _rtdb_dropped = _dedup_rtdb_findings(results)
    if _rtdb_dropped:
        if not quiet:
            print("\n[*] RTDB dedup: collapsed %d duplicate root/shallow "
                  "finding(s) (same canonical database URL)."
                  % _rtdb_dropped)
        # Recompute tier counters from the deduped vulnerable results so the
        # SUMMARY headline and exit-code logic don't reflect dropped duplicates.
        confirmed_count[0] = sum(
            1 for r in results
            if r.get("vulnerable") and (r.get("tier") or "CONFIRMED") == "CONFIRMED")
        potential_count[0] = sum(
            1 for r in results
            if r.get("vulnerable") and r.get("tier") == "POTENTIAL")


    total_confirmed = confirmed_count[0]
    total_potential = potential_count[0]
    total_tested = tested_count[0]


    _CONFIRMED_HIGH_SEVERITIES = frozenset({"HIGH", "CRITICAL"})
    _CONFIRMED_MED_SEVERITIES = frozenset({"MED"})
    confirmed_high_count = sum(
        1 for r in results
        if r.get("vulnerable")
        and (r.get("tier") or "CONFIRMED") == "CONFIRMED"
        and (r.get("severity") or "INFO") in _CONFIRMED_HIGH_SEVERITIES)
    confirmed_med_count = sum(
        1 for r in results
        if r.get("vulnerable")
        and (r.get("tier") or "CONFIRMED") == "CONFIRMED"
        and (r.get("severity") or "INFO") in _CONFIRMED_MED_SEVERITIES)
    confirmed_low_info_count = sum(
        1 for r in results
        if r.get("vulnerable")
        and (r.get("tier") or "CONFIRMED") == "CONFIRMED"
        and (r.get("severity") or "INFO") not in _CONFIRMED_HIGH_SEVERITIES
        and (r.get("severity") or "INFO") not in _CONFIRMED_MED_SEVERITIES)

    _capture_last_confirmed_severity_counts({
        "HIGH": confirmed_high_count,
        "MED":  confirmed_med_count,
        "LOW_INFO": confirmed_low_info_count,
    })

    _capture_last_scan_result_snapshot(
        results, restriction_mode=restriction_mode,
        restriction_value=restriction_value)
    _capture_last_scan_diagnostic_snapshot(results)

    print("\n" + "=" * 70)
    print("  RESULTS                                 Abuse / Impact")
    print("=" * 70)
    for r in results:
        if r["vulnerable"]:
            cat_tag = r["category"].upper()
            ab = r.get("abuse_class") or "-"
            tier_tag = "POT" if r.get("tier") == "POTENTIAL" else "CONF"
            sev_tag = (r.get("severity") or "INFO")

            print("  %s%-38s%s [%s/%s/%s/%s] %s"
                  % (RED, r["name"], RESET, sev_tag, tier_tag, cat_tag, ab, r["impact"]))
    # Transport-error guard — if the probe loop NEVER reached the API on a
    # significant share of attempts, "No vulnerable APIs found" is misleading
    # (every probe failed at the network layer, not at the auth check).
    _te_snap = _transport_error_snapshot()
    _te_total = sum(_te_snap.values())
    if total_confirmed == 0 and total_potential == 0:
        if _te_total > 0:
            print("  %sNo vulnerable APIs found — but %d probe(s) failed in transport "
                  "(SSL=%d, conn=%d, timeout=%d, other=%d). Result is NOT clean.%s"
                  % (YELLOW, _te_total,
                     _te_snap.get("ssl", 0), _te_snap.get("connection", 0),
                     _te_snap.get("timeout", 0), _te_snap.get("other", 0),
                     RESET))
            if _te_snap.get("ssl", 0):
                print("  %s    SSL failures dominate — retry with --insecure "
                      "(corp/MITM proxy).%s" % (YELLOW, RESET))
        else:
            print("  %sNo vulnerable APIs found.%s" % (GREEN, RESET))
    elif _te_total > 0:
        print("  %s[!] %d probe(s) failed in transport (SSL=%d, conn=%d, timeout=%d, "
              "other=%d) — coverage may be incomplete.%s"
              % (YELLOW, _te_total,
                 _te_snap.get("ssl", 0), _te_snap.get("connection", 0),
                 _te_snap.get("timeout", 0), _te_snap.get("other", 0),
                 RESET))
    print("=" * 70)

    err_counts = {}
    for r in results:
        ec = r.get("error_class")
        if ec:
            err_counts[ec] = err_counts.get(ec, 0) + 1


    verdict = _pick_key_status_verdict(err_counts, total_confirmed)
    if verdict:
        label, hint = verdict
        color = RED if label in ("EXPIRED", "INVALID/REVOKED", "LEAKED") else YELLOW if "RESTRICTED" in label else GREEN
        print("\n%s[*] Key status: %s%s — %s" % (color, label, RESET, hint))

    if err_counts:
        print("\n[*] Key capability fingerprint (error-class histogram):")
        for ec, n in sorted(err_counts.items(), key=lambda x: -x[1]):
            print("    %-22s %d" % (ec, n))

    restriction_hints = {
        "REFERRER_BLOCKED":     "--restriction-mode referer --restriction-value https://<allowed-host>",
        "IP_BLOCKED":           "--restriction-mode ip   (route requests via --proxy from allowed IP)",
        "ANDROID_BLOCKED":      "--restriction-mode android --restriction-value <package>:<SHA1>",
        "IOS_BLOCKED":          "--restriction-mode ios --restriction-value <bundle.id>",
        "SERVICE_BLOCKED":      "key is API-restricted (allowlist) — see the 'Key allowlist inference' block below for the denied service list",
        "REFERER_INCOMPATIBLE": "these APIs reject ANY referer header — re-run WITHOUT --restriction-mode referer",
    }
    for klass, hint in restriction_hints.items():
        n = err_counts.get(klass, 0)
        if n:
            color = YELLOW
            print("\n%s[!] %d probe(s) returned %s — likely key restriction in effect.%s" % (color, n, klass, RESET))
            print("    Re-run with: %s" % hint)


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
    service_verdict = {}  # service_host -> (priority, label)
    unknown_service_classified_count = 0
    for r in results:
        svcs = r.get("services_seen") or set()
        ec = r.get("error_class")
        if not svcs:
            if ec and not r["vulnerable"]:
                unknown_service_classified_count += 1
            continue
        if r["vulnerable"]:
            verdict = SERVICE_PRIORITY["VULNERABLE"]
        else:
            verdict = SERVICE_PRIORITY.get(ec, (99, ec or "unknown"))
        for svc in svcs:
            cur = service_verdict.get(svc)
            if cur is None or verdict[0] < cur[0]:
                service_verdict[svc] = verdict
    # Bucket services by label for the report.
    by_label = {}
    for svc, (_, label) in service_verdict.items():
        by_label.setdefault(label, set()).add(svc)
    if by_label:
        print("\n[*] Key allowlist inference (per metadata.service field):")
        # Show allowed first (most actionable), then denied (next
        # target list), then the restriction-profile hints, then the
        # diagnostic catch-alls last.
        order = ["allowed", "denied",
                 "referer-blocked", "referer-incompatible",
                 "ip-blocked", "android-blocked", "ios-blocked",
                 "api-disabled-in-project",
                 "does-not-accept-api-keys", "unauthenticated",
                 "permission-denied", "not-found", "invalid-argument",
                 "precondition-failed", "rtdb-deactivated"]

        fp_detail = (fingerprint_detail or "concise").lower()
        # In concise mode cap any non-actionable bucket that grows
        # large. `allowed` / `denied` / the restriction-profile
        # buckets are ALWAYS uncapped because they drive operator
        # next-steps.
        _CAPPED_LABELS = frozenset({
            "does-not-accept-api-keys", "unauthenticated",
            "permission-denied", "not-found", "invalid-argument",
            "api-disabled-in-project", "precondition-failed",
            "rtdb-deactivated",
        })

        _BUCKET_NOTES = {
            "api-disabled-in-project":
                "(per-project: this API is disabled on THIS project — "
                "not a key vulnerability; the key may reach it on another "
                "project)",
            "unauthenticated":
                "(generic 401 auth failure — not necessarily forbidden, "
                "and NOT the precise 'API keys unsupported' class; see "
                "does-not-accept-api-keys for that)",
            "does-not-accept-api-keys":
                "(endpoint protocol-rejects API-key auth — OAuth2 bearer "
                "required; not exploitable with an API key)",
        }
        for label in order:
            svcs = sorted(by_label.get(label, set()))
            if not svcs:
                continue
            head = "    %s (%d):" % (label, len(svcs))
            if (fp_detail == "concise"
                    and label in _CAPPED_LABELS
                    and len(svcs) > 8):
                preview = svcs[:8] + ["... (%d more — re-run with --fingerprint-detail full)" % (len(svcs) - 8)]
            else:
                preview = svcs
            print(head)
            _note = _BUCKET_NOTES.get(label)
            if _note:
                print("      %s" % _note)
            for s in preview:
                print("      - %s" % s)
        if unknown_service_classified_count:

            print("    (%d classified error(s) had no metadata.service "
                  "— see probe_diagnostics in JSON output)"
                  % unknown_service_classified_count)


    SUSTAINED_RPS = 10
    SECONDS_PER_HR = 3600
    confirmed_rows = []   # confirmation == "confirmed_data"
    reachable_rows = []   # confirmation == "key_accepted_only" / unknown
    for r in results:
        if not r["vulnerable"]:
            continue
        cost_key = COST_PROBE_MAP.get(r["name"])
        if not cost_key:
            continue
        per_call = PER_CALL_USD.get(cost_key)
        if not per_call:
            continue
        drain_per_hr_raw = per_call * SUSTAINED_RPS * SECONDS_PER_HR
        drain_per_hr, capped = _cap_cost_amp_drain(drain_per_hr_raw)
        confirmation = r.get("confirmation") or "key_accepted_only"
        row = (r["name"], cost_key, per_call, drain_per_hr, capped, confirmation)
        if confirmation == "confirmed_data":
            confirmed_rows.append(row)
        else:
            reachable_rows.append(row)
    if confirmed_rows or reachable_rows:
        print("\n[*] Cost amplification estimate (sustained %d req/sec):"
              % SUSTAINED_RPS)
        print("    (%s; capped at $%.2f/hr per row)"
              % (_COST_AMP_THEORETICAL_LABEL,
                 _COST_AMP_DISPLAY_CAP_USD_PER_HR))
        if confirmed_rows:
            confirmed_rows.sort(key=lambda x: -x[3])
            print("    [confirmed data egress]")
            for name, cost_key, per_call, drain_per_hr, capped, _conf in confirmed_rows[:10]:
                cap_tag = " (capped)" if capped else ""
                print("    %-42s  $%-8.4f/call  $%9.2f/hr%s"
                      % (name[:42], per_call, drain_per_hr, cap_tag))
            max_row = confirmed_rows[0]
            print("    %sMax theoretical confirmed-drain: $%.2f/hr via %s "
                  "(%s)%s"
                  % (RED, max_row[3], max_row[0],
                     _COST_AMP_THEORETICAL_LABEL, RESET))
        if reachable_rows:
            reachable_rows.sort(key=lambda x: -x[3])
            print("    [reachability-only — key accepted, no confirmed drain]")
            for name, cost_key, per_call, drain_per_hr, capped, _conf in reachable_rows[:10]:
                cap_tag = " (capped)" if capped else ""
                print("    %-42s  $%-8.4f/call  $%9.2f/hr%s"
                      % (name[:42], per_call, drain_per_hr, cap_tag))
            print("    (these are NOT confirmed drains — key acceptance does "
                  "not prove the endpoint will charge billable usage)")

    if _IDENTITY_TOOLKIT_ARTIFACTS:
        print("\n%s[!] WARNING: %d Identity Toolkit artifact(s) left in victim project (auto-delete failed):%s"
              % (RED, len(_IDENTITY_TOOLKIT_ARTIFACTS), RESET))
        for art in _IDENTITY_TOOLKIT_ARTIFACTS:
            print("    - %s | localId=%s | reason: %s" % (art["probe"], art["local_id"], art["reason"]))
        print("    Include these IDs in your bounty report so the program owner can remove them.")

    # Report Referer denials not already covered by the error summary.
    if referer_blocked_list and not err_counts.get("REFERRER_BLOCKED"):
        print("\n%s[!] WARNING: %d API(s) returned referer restriction errors:%s" % (YELLOW, len(referer_blocked_list), RESET))
        for r in referer_blocked_list:
            print("    - %s [%s]" % (r["name"], r["category"].upper()))
        print("    Re-run with --restriction-mode referer --restriction-value <allowed-domain>")


    print("\n[*] Scan complete: %d confirmed-high / %d confirmed-med / "
          "%d confirmed-low-info / %d potential / %d tested"
          % (confirmed_high_count, confirmed_med_count,
             confirmed_low_info_count, total_potential, total_tested))

    _recon_accepted = _collect_malformed_body_accepted(results)
    if _recon_accepted:
        print("[*] Recon: %d malformed-body accepted endpoint(s) "
              "(key reachable, not a finding)" % len(_recon_accepted))
    print("Pricing references:")
    print("  https://ai.google.dev/pricing")
    print("  https://cloud.google.com/maps-platform/pricing")
    print("  https://cloud.google.com/vision/pricing")
    print("Thanks for using Google API Scanner!")

    # JSON output
    if output_json or output_file:
        options = {

            "include_maps": include_maps or all_mode,
            "authorization_only": bool(authorization_only),
            "include_authorization_key": bool(include_authorization),
            "include_low": include_low or all_mode,
            "include_destructive": include_destructive or all_mode,
            "include_cost_amp": include_cost_amp or all_mode,

            "it_test_email_enabled": bool(it_test_email),
            "it_test_phone_enabled": bool(it_test_phone),
            "it_test_email_masked": _mask_operator_pii(it_test_email),
            "it_test_phone_masked": _mask_operator_pii(it_test_phone),
            "restriction_mode": restriction_mode or "none",
            "restriction_value": restriction_value,

            "fingerprint_detail": (fingerprint_detail or "concise").lower(),

            "exit_on_dead_key": bool(exit_on_dead_key),
        }
        out = _build_json_output(results, total_tested, options)
        if output_json:
            _emit_json(out)
        if output_file:
            _save_output(output_file, out)

    # Snapshot the per-scan transport counter so the CLI / discovery loop can
    # inspect transport state after we return without racing the NEXT scan's
    # reset_transport_errors() call.
    _capture_last_transport_errors()


    return [r["name"] for r in results
            if r["vulnerable"] and (r.get("tier") or "CONFIRMED") == "CONFIRMED"]

# CLI

def _authorization_only_replay_modes(probe_diagnostics):
    """Return restriction modes worth replaying after an auth-only pass.

    ``None`` means the first pass was not diagnostic enough (for example a
    transport failure), so callers must keep every known context. A concrete
    set means only matching application-restriction contexts can change the
    result; an empty set suppresses duplicates after definitive responses.
    """
    histogram = (probe_diagnostics or {}).get("error_class_histogram")
    if not isinstance(histogram, dict) or not histogram:
        return None
    class_to_mode = {
        "REFERRER_BLOCKED": "referer",
        "ANDROID_BLOCKED": "android",
        "IOS_BLOCKED": "ios",
        "IP_BLOCKED": "ip",
    }
    return {
        mode for error_class, mode in class_to_mode.items()
        if histogram.get(error_class, 0)
    }
