def _which(cmd):
    """Lightweight `which` — returns absolute path or None.

    Windows environments can have an incomplete PATH, so
    we also look for repo-local binaries such as `tools/katana.exe` and common
    operator install paths. `KATANA_PATH`, `SUBFINDER_PATH`, etc. override all
    search locations.
    """
    env_key = "%s_PATH" % re.sub(r"[^A-Za-z0-9]", "_", cmd).upper()
    explicit = os.environ.get(env_key)
    if explicit and os.path.isfile(explicit):
        return explicit

    names = [cmd]
    root, ext = os.path.splitext(cmd)
    if os.name == "nt" and not ext:
        names.append(cmd + ".exe")

    here = _FRONTEND_ROOT
    candidate_dirs = [
        here,
        os.path.join(here, "tools"),
        os.path.join(here, "bin"),
        os.path.join(here, "vendor"),
        os.path.join(here, "vendor", cmd),
    ]
    if os.name == "nt":
        userprofile = os.environ.get("USERPROFILE") or ""
        candidate_dirs.extend([
            os.path.join(userprofile, "go", "bin"),
            os.path.join("C:\\", "Tools"),
            os.path.join("C:\\", "Tools", cmd),
        ])
    for d in candidate_dirs:
        for name in names:
            p = os.path.join(d, name)
            if os.path.isfile(p):
                return p
    for d in os.environ.get("PATH", "").split(os.pathsep):
        for name in names:
            p = os.path.join(d, name)
            if os.path.isfile(p):
                return p
    return None


def _public_data_root():
    """Writable per-user state, independent of pip/pipx's installation path."""
    explicit = os.environ.get("GAPISCANNER_DATA_DIR")
    if explicit:
        return os.path.abspath(os.path.expanduser(explicit))
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~/AppData/Local")
    elif sys.platform == "darwin":
        base = os.path.expanduser("~/Library/Application Support")
    else:
        base = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
    return os.path.join(base, "gapiscanner")


def _artifact_dir(program, override=None, subdir="scope", platform=None):
    """Return (and create) the artifact directory for `program`.

    Precedence:
      1. `override`     — explicit --output-dir from CLI
      2. Per-user data directory: `<user-data-dir>/{program}/`
    """
    if override:
        root = os.path.join(override, program)
    else:
        root = os.path.join(_public_data_root(), program)
    out = os.path.normpath(os.path.join(root, subdir))
    os.makedirs(out, exist_ok=True)
    return out


def _scan_registry_path(override=None):
    """Path to the cross-program scan registry. One JSON file under
    `<user-data-dir>/_global/scan_registry.json` listing every completed bundle scan
    so we don't re-scan the same program back-to-back. Read-only by humans,
    write-only by _record_scan()."""
    if override:
        root = override
    else:
        root = os.path.join(_public_data_root(), "_global")
    os.makedirs(root, exist_ok=True)
    return os.path.normpath(os.path.join(root, "scan_registry.json"))


def _record_scan(platform, program, ts, seeds_count, hosts_count, mobile_count,
                 fetches_count, bodies_count, keys_found, vulnerable_keys,
                 duration_sec, scan_log_path, findings_path, output_dir=None):
    """Append an entry to the shared scan registry."""
    path = _scan_registry_path(override=output_dir)
    entries = []
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                entries = json.load(f)
                if not isinstance(entries, list):
                    entries = []
        except (json.JSONDecodeError, OSError):
            entries = []
    entries.append({
        "platform": platform,
        "program": program,
        "timestamp": ts,
        "seeds_count": seeds_count,
        "hosts_count": hosts_count,
        "mobile_apps": mobile_count,
        "http_fetches": fetches_count,
        "unique_bodies": bodies_count,
        "keys_found": keys_found,
        "vulnerable_keys": vulnerable_keys,
        "duration_sec": duration_sec,
        "scan_log": scan_log_path,
        "findings_json": findings_path,
    })
    with open(path, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2)


def _registry_lookup(platform, program, output_dir=None):
    """Return the most recent registry entry for (platform, program), or None.
    Lets main() warn the user before re-scanning a target they already hit."""
    path = _scan_registry_path(override=output_dir)
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            entries = json.load(f)
    except (json.JSONDecodeError, OSError):
        return None
    if not isinstance(entries, list):
        return None
    matches = [e for e in entries if isinstance(e, dict) and e.get("platform") == platform
               and e.get("program") == program]
    if not matches:
        return None
    return sorted(matches, key=lambda e: str(e.get("timestamp") or ""))[-1]


def _kb_path(output_dir=None):
    """Path to the cross-program key knowledge base."""
    if output_dir:
        root = output_dir
    else:
        root = os.path.join(_public_data_root(), "_global")
    os.makedirs(root, mode=0o700, exist_ok=True)
    return os.path.normpath(os.path.join(root, "key_kb.json"))


def _kb_load(output_dir=None):
    """Read compatible KB records; preserve corrupt files for manual recovery."""
    path = _kb_path(output_dir=output_dir)
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError("expected an object keyed by API key")
        for entry in data.values():
            if not isinstance(entry, dict):
                raise ValueError("invalid key record")
            entry.setdefault("first_seen_ts", None)
            for field in ("sources", "scan_history", "identity_toolkit_cleanup_failures"):
                rows = entry.get(field) or []
                if field == "sources" and isinstance(rows, (str, dict)):
                    rows = [rows]
                if not isinstance(rows, list):
                    raise ValueError("invalid %s list" % field)
                normalized = []
                for row in rows:
                    if field == "sources" and isinstance(row, str):
                        row = {"url": row}
                    if not isinstance(row, dict):
                        raise ValueError("invalid %s record" % field)
                    if field == "scan_history":
                        for name, default in (("ts", None), ("probes_count", None),
                                              ("vulnerable_count", 0), ("vulnerable_apis", [])):
                            row.setdefault(name, default)
                        if (not isinstance(row["vulnerable_count"], int)
                                or not isinstance(row["vulnerable_apis"], list)
                                or any(not isinstance(v, str) for v in row["vulnerable_apis"])):
                            raise ValueError("invalid scan history values")
                    normalized.append(row)
                entry[field] = normalized
        return data
    except (ValueError, UnicodeError) as exc:
        raise ValueError("Cannot read key KB at %s; file preserved: %s" % (path, exc)) from exc


def _kb_save(kb, output_dir=None):
    """Atomic-ish whole-file rewrite (tmp + rename) so a crash mid-write
    doesn't leave a half-written JSON that breaks the next scan."""
    path = _kb_path(output_dir=output_dir)
    import tempfile
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8",
                dir=os.path.dirname(path), delete=False) as f:
            tmp = f.name
            json.dump(kb, f, indent=2, sort_keys=True)
        os.replace(tmp, path)
    finally:
        if tmp and os.path.exists(tmp):
            os.unlink(tmp)


def _kb_record_discovery(key, source_url, program, platform, ts, output_dir=None):
    """Record that `key` was observed at `source_url` for (program, platform)
    at timestamp `ts`. Idempotent — re-recording the same (key, source) tuple
    is a no-op. Returns the updated entry."""
    kb = _kb_load(output_dir=output_dir)
    entry = kb.get(key)
    if entry is None:
        entry = {
            "first_seen_ts":   ts,
            "first_program":   program,
            "first_platform":  platform,
            "sources":         [],
            "scan_history":    [],
            "last_scan_ts":    None,
            "last_key_status": "unscanned",
        }
        kb[key] = entry
    # Dedup sources by (url, program) — the same URL crawled in two different
    # scans counts as the same source, just refresh its `ts`.
    new_source = {"url": source_url, "program": program,
                  "platform": platform, "ts": ts}
    found = False
    for s in entry["sources"]:

        if isinstance(s, dict) and s.get("url") == source_url and s.get("program") == program:
            s["ts"] = ts
            found = True
            break
    if not found:
        entry["sources"].append(new_source)
    _kb_save(kb, output_dir=output_dir)
    return entry


def _kb_record_scan(key, ts, probes_count, vulnerable_apis,
                    project_id=None, project_number=None,
                    key_status=None, restriction_mode=None,
                    restriction_value=None, output_dir=None,
                    mobile_restriction=None,
                    program=None, platform=None,
                    identity_toolkit_artifacts=None,
                    probe_diagnostics=None,
                    error_class_histogram=None,
                    finding_records=None):
    """Append a scan_history entry to the KB record for `key`. If the key
    isn't in the KB yet (e.g., --rescan-kb on a hand-added key) create a
    minimal entry. `restriction_mode` is persisted so unrestricted vs
    referer/android/ios passes are distinguishable later.

    ``mobile_restrictions`` stores every distinct iOS/Android context for a
    key shared by multiple apps. The legacy scalar ``mobile_restriction`` is
    retained as a compatibility view of the first stable entry.
    This preserves each app context when a key is shared across apps."""
    kb = _kb_load(output_dir=output_dir)
    entry = kb.get(key)
    if entry is None:
        entry = {
            "first_seen_ts":   ts,
            "first_program":   program,
            "first_platform":  platform,
            "sources":         [],
            "scan_history":    [],
            "last_scan_ts":    None,
            "last_key_status": "unscanned",
        }
        kb[key] = entry

    if program and not entry.get("first_program"):
        entry["first_program"] = program
    if platform and not entry.get("first_platform"):
        entry["first_platform"] = platform
    if program:
        _have = any(
            isinstance(s, dict) and s.get("program") == program
            and s.get("platform") == (platform or "mobile")
            for s in entry.get("sources", []))
        if not _have:
            entry.setdefault("sources", []).append({
                "platform": platform or "mobile",
                "program":  program,
                "url":      None,
                "ts":       ts,
            })
    # Preserve every restriction context instead of overwriting one platform
    # with another when the same key ships in multiple APK/IPA bundles.
    prior_restrictions = merge_mobile_restrictions(entry.get("mobile_restrictions"))
    if entry.get("mobile_restriction"):
        prior_restrictions = list(prior_restrictions) + [
            entry.get("mobile_restriction")]
    merged_restrictions = merge_mobile_restrictions(
        prior_restrictions, mobile_restriction,
    )
    if merged_restrictions:
        entry["mobile_restrictions"] = merged_restrictions
        entry["mobile_restriction"] = merged_restrictions[0]
    vuln_list = sorted(vulnerable_apis) if vulnerable_apis else []
    it_artifacts = []
    for art in identity_toolkit_artifacts or []:
        local_id = art.get("local_id") if isinstance(art, dict) else None
        if not local_id:
            continue
        it_artifacts.append({
            "probe": art.get("probe") or "Identity Toolkit",
            "local_id": local_id,
            "reason": art.get("reason") or "cleanup failed",
        })
    finding_records_clean = []
    for row in finding_records or []:
        if not isinstance(row, dict):
            continue
        finding_records_clean.append({
            "name": row.get("name"),
            "severity": row.get("severity") or "INFO",
            "tier": row.get("tier") or "CONFIRMED",
            "category": row.get("category"),
            "abuse_class": row.get("abuse_class") or "-",
            "poc_url": _redact_key_from_url(row.get("poc_url") or row.get("url") or ""),
            "pass_context": row.get("pass_context") or (restriction_mode or "unrestricted"),
            "restriction_value": _redact_key_from_url(
                row.get("restriction_value") or restriction_value or ""),
            "impact_type": row.get("impact_type"),
            "confirmation": row.get("confirmation"),
            "data_sensitivity": row.get("data_sensitivity"),
            "followup_required": row.get("followup_required"),
            "operation_evidence": (
                dict(row.get("operation_evidence"))
                if isinstance(row.get("operation_evidence"), dict) else None
            ),
        })
    finding_counts = {}
    for row in finding_records_clean:
        tier = (row.get("tier") or "CONFIRMED").lower()
        sev = (row.get("severity") or "INFO").lower()
        finding_counts[tier] = finding_counts.get(tier, 0) + 1
        finding_counts["%s_%s" % (tier, sev)] = (
            finding_counts.get("%s_%s" % (tier, sev), 0) + 1)
    scan_record = {
        "ts":                ts,
        "probes_count":      probes_count,
        "vulnerable_count":  len(vuln_list),
        "vulnerable_apis":   vuln_list,
        "project_id":        project_id,
        "project_number":    project_number,
        "restriction_mode":  restriction_mode or "unrestricted",
        "restriction_value": restriction_value,
        "key_status":        key_status or ("VULNERABLE" if vuln_list else "fully-restricted"),
    }
    if finding_records_clean:
        scan_record["finding_records"] = finding_records_clean
        scan_record["finding_counts"] = finding_counts
    if error_class_histogram:
        scan_record["error_class_histogram"] = dict(error_class_histogram)
    if probe_diagnostics:
        scan_record["probe_diagnostics"] = [dict(d) for d in probe_diagnostics]
    if it_artifacts:
        scan_record["identity_toolkit_cleanup_failures"] = it_artifacts
        entry.setdefault("identity_toolkit_cleanup_failures", [])
        seen = {x.get("local_id") for x in entry["identity_toolkit_cleanup_failures"]
                if isinstance(x, dict)}
        for art in it_artifacts:
            if art["local_id"] not in seen:
                entry["identity_toolkit_cleanup_failures"].append({
                    "ts": ts,
                    "restriction_mode": restriction_mode or "unrestricted",
                    "restriction_value": restriction_value,
                    "probe": art["probe"],
                    "local_id": art["local_id"],
                    "reason": art["reason"],
                })
                seen.add(art["local_id"])
    entry["scan_history"].append(scan_record)
    entry["last_scan_ts"]    = ts
    entry["last_key_status"] = key_status or ("VULNERABLE" if vuln_list else "fully-restricted")
    _kb_save(kb, output_dir=output_dir)
    return entry


def _kb_show(output_dir=None):
    """Print a human-readable summary of the KB."""
    kb = _kb_load(output_dir=output_dir)
    if not kb:
        print("[*] Key KB is empty: %s" % _kb_path(output_dir=output_dir))
        return
    print("[*] Key KB: %d unique key(s)" % len(kb))
    print("    Path: %s" % _kb_path(output_dir=output_dir))
    print()
    for k in sorted(kb.keys()):
        e = kb[k]
        print("  %s" % _redact_key_display(k))
        print("    first seen: %s (%s/%s)" % (e["first_seen_ts"],
                                              e.get("first_platform") or "-",
                                              e.get("first_program") or "-"))
        print("    sources:    %d" % len(e["sources"]))
        for s in e["sources"][:5]:

            if isinstance(s, dict):
                print("      - %s (%s/%s @ %s)" % (_redact_diagnostic_secret_text(s.get("url") or ""), s.get("platform"),
                                                    s.get("program"), s.get("ts")))
            else:
                print("      - (mobile source: %s)" % s)
        if len(e["sources"]) > 5:
            print("      ... (%d more)" % (len(e["sources"]) - 5))
        last = e["scan_history"][-1] if e["scan_history"] else None
        if last:
            print("    last scan:  %s — %d/%s vulnerable [%s]" % (
                last["ts"], last["vulnerable_count"],
                last["probes_count"] if last["probes_count"] is not None else "?",
                last.get("key_status", "?")))
            if last.get("project_id") or last.get("project_number"):
                print("                project_id=%s number=%s"
                      % (last.get("project_id") or "-",
                         last.get("project_number") or "-"))
            if last["vulnerable_apis"]:
                print("                vulnerable APIs: %s"
                      % ", ".join(last["vulnerable_apis"]))
        else:
            print("    last scan:  (never scanned)")
        print()


def _kb_export_csv(out_path, output_dir=None):
    """Flatten KB to a CSV: one row per (key, source). For pentest reporting."""
    import csv as _csv
    kb = _kb_load(output_dir=output_dir)
    if not kb:
        print("[*] KB is empty, nothing to export.")
        return 0
    rows = 0
    with open(out_path, "w", encoding="utf-8", newline="") as f:
        w = _csv.writer(f)
        w.writerow(["key", "first_seen_ts", "platform", "program", "source_url",
                    "last_scan_ts", "last_key_status", "vulnerable_count",
                    "vulnerable_apis", "project_id", "project_number"])
        for k in sorted(kb.keys()):
            e = kb[k]
            last = e["scan_history"][-1] if e["scan_history"] else {}
            for s in e["sources"] or [{}]:
                w.writerow([k, e["first_seen_ts"], s.get("platform"),
                            s.get("program"), s.get("url"),
                            e.get("last_scan_ts") or "",
                            e.get("last_key_status") or "",
                            last.get("vulnerable_count", ""),
                            ";".join(last.get("vulnerable_apis", [])),
                            last.get("project_id") or "",
                            last.get("project_number") or ""])
                rows += 1
    print("[*] KB exported to %s — %d row(s)" % (out_path, rows))
    return rows


def _kb_bootstrap(output_dir=None, verbose=False):
    """Walk artifacts/<program>/scan_logs/<ts>/findings.json files and
    seed the KB from past scans. Idempotent — re-running won't duplicate
    sources or scan_history entries (we dedup on (key, source.url, scan.ts))."""
    if output_dir:
        artifacts_root = output_dir
    else:
        artifacts_root = _public_data_root()
    artifacts_root = os.path.normpath(artifacts_root)
    if not os.path.isdir(artifacts_root):
        print("[!] artifacts root not found: %s" % artifacts_root)
        return 0
    seen_keys = 0
    seen_scans = 0
    kb = _kb_load(output_dir=output_dir)
    # Bundle findings.json shape: {"program", "platform", "timestamp",
    #                                "findings":[{"key","source","vulnerable_apis"}]}
    for prog in os.listdir(artifacts_root):
        if prog.startswith("_"):
            continue  # skip _global
        scan_logs_dir = os.path.join(artifacts_root, prog, "scan_logs")
        if not os.path.isdir(scan_logs_dir):
            continue
        for ts in sorted(os.listdir(scan_logs_dir)):
            findings_path = os.path.join(scan_logs_dir, ts, "findings.json")
            if not os.path.exists(findings_path):
                continue
            try:
                with open(findings_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except (json.JSONDecodeError, OSError) as e:
                if verbose:
                    print("    [skip] %s: %s" % (findings_path, e))
                continue
            if not isinstance(data, dict) or not isinstance(data.get("findings", []), list):
                continue
            program  = data.get("program") or prog
            platform = data.get("platform") or "unknown"
            scan_ts  = data.get("timestamp") or ts
            for f_entry in data.get("findings") or []:
                if not isinstance(f_entry, dict):
                    continue
                k = f_entry.get("key")
                if not k:
                    continue
                source = f_entry.get("source") or "(unknown source)"
                vs     = f_entry.get("vulnerable_apis") or []
                # discovery
                entry = kb.get(k)
                if entry is None:
                    entry = {
                        "first_seen_ts":   scan_ts,
                        "first_program":   program,
                        "first_platform":  platform,
                        "sources":         [],
                        "scan_history":    [],
                        "last_scan_ts":    None,
                        "last_key_status": "unscanned",
                    }
                    kb[k] = entry
                    seen_keys += 1
                src_dedup = False
                for s in entry["sources"]:
                    if s.get("url") == source and s.get("program") == program:
                        src_dedup = True
                        break
                if not src_dedup:
                    entry["sources"].append({"url": source, "program": program,
                                             "platform": platform, "ts": scan_ts})
                # scan history
                scan_dedup = any(h.get("ts") == scan_ts for h in entry["scan_history"])
                if not scan_dedup:
                    entry["scan_history"].append({
                        "ts":               scan_ts,
                        "probes_count":     None,   # not recorded historically
                        "vulnerable_count": len(vs),
                        "vulnerable_apis":  sorted(vs),
                        "project_id":       None,
                        "project_number":   None,
                        "key_status":       "VULNERABLE" if vs else "fully-restricted",
                    })
                    entry["last_scan_ts"]    = scan_ts
                    entry["last_key_status"] = "VULNERABLE" if vs else "fully-restricted"
                    seen_scans += 1
    _kb_save(kb, output_dir=output_dir)
    print("[*] KB bootstrap: %d new key(s), %d new scan entries from %s"
          % (seen_keys, seen_scans, artifacts_root))
    print("    KB now: %d unique key(s) at %s"
          % (len(kb), _kb_path(output_dir=output_dir)))
    return seen_keys
