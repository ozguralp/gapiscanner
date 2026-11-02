_MOBILE_MEMBER_MAX_BYTES = 512 * 1024 * 1024


def _read_mobile_member(archive, name):
    """Bound decompression before allocating an untrusted archive member."""
    if archive.getinfo(name).file_size > _MOBILE_MEMBER_MAX_BYTES:
        _record_discovery_issue("archive_size_limits")
        raise RuntimeError("Archive member exceeds the 512 MiB safety limit")
    with archive.open(name) as member:
        data = member.read(_MOBILE_MEMBER_MAX_BYTES + 1)
    if len(data) > _MOBILE_MEMBER_MAX_BYTES:
        _record_discovery_issue("archive_size_limits")
        raise RuntimeError("Archive member exceeds the 512 MiB safety limit")
    return data


def _extract_ios_bundle_id(ipa_path, quiet=True):
    """Read the main application bundle identifier from an IPA."""
    import zipfile, plistlib
    try:
        with zipfile.ZipFile(ipa_path) as zf:
            plist_names = [n for n in zf.namelist()
                           if n.startswith("Payload/") and n.endswith(".app/Info.plist")]
            if not plist_names:
                return None
            data = _read_mobile_member(zf, plist_names[0])
            try:
                info = plistlib.loads(data)
            except Exception:
                return None
            return info.get("CFBundleIdentifier") if isinstance(info, dict) else None
    except Exception as e:
        if not quiet:
            print("    [!] iOS bundle-id extraction failed: %s" % e)
        return None


def _extract_ios_key_bundle_map(ipa_path, quiet=True):
    """Map keys to their bundle identifiers using each embedded Firebase plist."""
    import zipfile, plistlib
    out = {}
    try:
        with zipfile.ZipFile(ipa_path) as zf:
            for name in zf.namelist():
                if not name.endswith(".plist"):
                    continue
                fname = name.rsplit("/", 1)[-1]
                if not fname.startswith("GoogleService-Info"):
                    continue
                try:
                    info = plistlib.loads(_read_mobile_member(zf, name))
                except Exception:
                    continue
                if not isinstance(info, dict):
                    continue
                api_key = info.get("API_KEY")
                bundle  = info.get("BUNDLE_ID")
                if api_key and bundle:
                    out[api_key] = bundle
    except Exception as e:
        if not quiet:
            print("    [!] iOS key→bundle map extraction failed: %s" % e)
    return out


def _extract_firebase_configs_from_plist(plist_bytes, source=None):
    """Parse a single GoogleService-Info.plist body. Returns a list of
    `_firebase_config(...)` dicts (typically zero or one).

    Field map (Apple plist key → FirebaseConfig field):
        PROJECT_ID      → project_id
        GCM_SENDER_ID   → project_number
        DATABASE_URL    → database_url
        STORAGE_BUCKET  → storage_bucket
        GOOGLE_APP_ID   → google_app_id
    """
    import plistlib
    try:
        info = plistlib.loads(plist_bytes)
    except Exception:
        return []
    if not isinstance(info, dict):
        return []
    cfg = _firebase_config(
        project_id=info.get("PROJECT_ID"),
        project_number=info.get("GCM_SENDER_ID"),
        database_url=info.get("DATABASE_URL"),
        storage_bucket=info.get("STORAGE_BUCKET"),
        google_app_id=info.get("GOOGLE_APP_ID"),
        source=source,
        api_key=info.get("API_KEY"),
    )
    # Drop trivially-empty entries (no usable identifying field).
    if not any(k for k in ("project_id", "project_number", "database_url",
                           "storage_bucket", "google_app_id") if cfg.get(k)):
        return []
    return [cfg]


def _extract_firebase_configs_from_google_services_json(json_bytes, source=None):
    """Parse a single google-services.json body. Returns a list of
    `_firebase_config(...)` dicts (one per `client[]` entry — multi-flavor
    Android apps ship one config but many clients).

    Field map (Google JSON path → FirebaseConfig field):
        project_info.project_id        → project_id
        project_info.project_number    → project_number
        project_info.firebase_url      → database_url
        project_info.storage_bucket    → storage_bucket
        client[i].client_info.mobilesdk_app_id → google_app_id
    """
    try:
        data = json.loads(json_bytes if isinstance(json_bytes, (bytes, str))
                          else json_bytes.decode("utf-8", errors="replace"))
    except (json.JSONDecodeError, ValueError, AttributeError):
        return []
    if not isinstance(data, dict):
        return []
    pinfo = data.get("project_info") or {}
    if not isinstance(pinfo, dict):
        return []
    base_project_id     = pinfo.get("project_id")
    base_project_number = pinfo.get("project_number")
    base_database_url   = pinfo.get("firebase_url")
    base_storage_bucket = pinfo.get("storage_bucket")
    clients = data.get("client") or []
    if not isinstance(clients, list) or not clients:
        cfg = _firebase_config(
            project_id=base_project_id,
            project_number=base_project_number,
            database_url=base_database_url,
            storage_bucket=base_storage_bucket,
            source=source,
        )
        return [cfg] if any(cfg.get(k) for k in
                            ("project_id", "project_number",
                             "database_url", "storage_bucket")) else []
    out = []
    for c in clients:
        if not isinstance(c, dict):
            continue
        ci = c.get("client_info") or {}
        if not isinstance(ci, dict):
            continue

        _client_api_key = None
        _ak_list = c.get("api_key")
        if isinstance(_ak_list, list):
            for _ak in _ak_list:
                if isinstance(_ak, dict) and _ak.get("current_key"):
                    _client_api_key = _ak.get("current_key")
                    break
        cfg = _firebase_config(
            project_id=base_project_id,
            project_number=base_project_number,
            database_url=base_database_url,
            storage_bucket=base_storage_bucket,
            google_app_id=ci.get("mobilesdk_app_id"),
            source=source,
            api_key=_client_api_key,
        )
        if any(cfg.get(k) for k in ("project_id", "project_number",
                                     "database_url", "storage_bucket",
                                     "google_app_id")):
            out.append(cfg)
    return out


_ANDROID_STRINGS_FIREBASE_KEYS = (
    ("firebase_database_url", "database_url"),
    ("google_storage_bucket", "storage_bucket"),
    ("google_app_id",         "google_app_id"),
    ("gcm_defaultSenderId",   "project_number"),
    ("project_id",            "project_id"),

    ("google_api_key",        "api_key"),
)


def _extract_firebase_configs_from_strings_xml(xml_bytes, source=None):
    """Parse an Android res/values/strings.xml body. Returns a list of zero
    or one `_firebase_config(...)` dicts. Some apps inline Firebase fields
    here as a fallback when google-services.json wasn't applied; we want
    those too.

    Uses defusedxml when available (defensive against billion-laughs), else
    falls back to ElementTree.fromstring with a size cap as a basic guard."""
    if not xml_bytes:
        return []
    if isinstance(xml_bytes, bytes) and len(xml_bytes) > 1 * 1024 * 1024:
        # 1 MB cap — strings.xml is normally a few KB.
        return []
    try:
        try:
            from defusedxml import ElementTree as DET
            root = DET.fromstring(xml_bytes)
        except ImportError:
            from xml.etree import ElementTree as ET
            root = ET.fromstring(xml_bytes)
    except Exception:
        return []
    fields = {}
    for elem in root.findall(".//string"):
        name = (elem.attrib.get("name") or "").strip()
        if not name:
            continue
        text = (elem.text or "").strip()
        if not text:
            continue
        for xml_key, cfg_field in _ANDROID_STRINGS_FIREBASE_KEYS:
            if name == xml_key:
                fields[cfg_field] = text
                break

    if not any(f for f in ("project_id", "project_number", "database_url",
                           "storage_bucket", "google_app_id") if fields.get(f)):
        return []
    cfg = _firebase_config(source=source, **fields)
    return [cfg]


def _extract_firebase_configs_from_archive(path, quiet=True):
    """Walk an APK/IPA/ZIP archive and extract every Firebase config found.
    Returns a list of `_firebase_config(...)` dicts. Caller is responsible
    for calling `_record_firebase_config(cfg)` to push them into the shared
    store (the extractor itself is side-effect-free).

    Read-only. No archive bytes are written; no remote calls."""
    import zipfile, io
    out = []
    try:
        with zipfile.ZipFile(path) as zf:
            for name in zf.namelist():
                bn = name.rsplit("/", 1)[-1]
                try:
                    if bn.startswith("GoogleService-Info") and bn.endswith(".plist"):
                        out.extend(_extract_firebase_configs_from_plist(
                            _read_mobile_member(zf, name), source="%s!%s" % (path, name)))
                    elif bn == "google-services.json":
                        out.extend(_extract_firebase_configs_from_google_services_json(
                            _read_mobile_member(zf, name), source="%s!%s" % (path, name)))
                    elif bn == "strings.xml" and "res/values" in name:
                        out.extend(_extract_firebase_configs_from_strings_xml(
                            _read_mobile_member(zf, name), source="%s!%s" % (path, name)))
                    elif name.lower().endswith((".jar", ".aab", ".apk", ".ipa", ".zip")):
                        try:
                            with zipfile.ZipFile(io.BytesIO(_read_mobile_member(zf, name))) as inner:
                                for iname in inner.namelist():
                                    ibn = iname.rsplit("/", 1)[-1]
                                    if ibn.startswith("GoogleService-Info") and ibn.endswith(".plist"):
                                        out.extend(_extract_firebase_configs_from_plist(
                                            _read_mobile_member(inner, iname),
                                            source="%s!%s!%s" % (path, name, iname)))
                                    elif ibn == "google-services.json":
                                        out.extend(_extract_firebase_configs_from_google_services_json(
                                            _read_mobile_member(inner, iname),
                                            source="%s!%s!%s" % (path, name, iname)))
                                    elif ibn == "strings.xml" and "res/values" in iname:
                                        out.extend(_extract_firebase_configs_from_strings_xml(
                                            _read_mobile_member(inner, iname),
                                            source="%s!%s!%s" % (path, name, iname)))
                        except zipfile.BadZipFile:
                            pass
                except (zipfile.BadZipFile, RuntimeError, KeyError):
                    continue
    except (zipfile.BadZipFile, FileNotFoundError, OSError) as e:
        if not quiet:
            print("    [!] Firebase config extract from %s failed: %s" % (path, e))
        return []
    if out and not quiet:
        print("    [+] Firebase configs extracted: %d" % len(out))
    return out


_FIREBASE_JS_CONFIG_RE = re.compile(
    r"""(?:firebase\.initializeApp|firebaseConfig\s*=)\s*\(?\s*(\{[^{}]*\})""",
    re.DOTALL,
)
_FIREBASE_JS_FIELDS = (
    ("apiKey",            "_api_key"),
    ("authDomain",        "_auth_domain"),
    ("projectId",         "project_id"),
    ("databaseURL",       "database_url"),
    ("storageBucket",     "storage_bucket"),
    ("messagingSenderId", "project_number"),
    ("appId",             "google_app_id"),
)


def _extract_firebase_configs_from_js(body, source=None):
    """Bounded extractor for inline Firebase JS config objects. Returns a
    list of zero or more `_firebase_config(...)` dicts.

    Anchors on `firebase.initializeApp(...)` / `firebaseConfig = {...}` and
    parses the object literal as a JS-like string. We accept either valid
    JSON (`"apiKey": "..."`) or the looser JS form (`apiKey: "..."`). We
    convert the latter to JSON before parsing.

    To avoid false extraction from unrelated JS objects, we require at least
    one of {projectId, appId, apiKey} to be present in the matched block."""
    if not body or not isinstance(body, str):
        return []
    out = []
    for m in _FIREBASE_JS_CONFIG_RE.finditer(body):
        obj_text = m.group(1)
        # Strip JS line comments, but NOT URL schemes — `(?<!:)//` skips `://`
        # so a `databaseURL: "https://…"` value survives intact.
        cleaned = re.sub(r"(?<!:)//[^\n]*", "", obj_text)
        cleaned = re.sub(r"/\*.*?\*/", "", cleaned, flags=re.DOTALL)
        # Normalize bare keys (`foo:`) to JSON-quoted keys (`"foo":`).
        cleaned = re.sub(r"([{,]\s*)([A-Za-z_$][A-Za-z0-9_$]*)\s*:",
                         r'\1"\2":', cleaned)
        # Remove trailing commas before } or ].
        cleaned = re.sub(r",\s*([}\]])", r"\1", cleaned)
        # Convert single quotes to double quotes for string values (best effort).
        cleaned = re.sub(r":\s*'([^']*)'", r': "\1"', cleaned)
        try:
            data = json.loads(cleaned)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        # Sanity guard: must look like a Firebase config (at least one of
        # projectId/appId/apiKey present).
        if not any(k in data for k in ("projectId", "appId", "apiKey")):
            continue
        cfg = {}
        for js_key, cfg_field in _FIREBASE_JS_FIELDS:
            v = data.get(js_key)
            if v and isinstance(v, str):
                cfg[cfg_field] = v

        canonical = _firebase_config(
            project_id=cfg.get("project_id"),
            project_number=cfg.get("project_number"),
            database_url=cfg.get("database_url"),
            storage_bucket=cfg.get("storage_bucket"),
            google_app_id=cfg.get("google_app_id"),
            source=source,
            api_key=cfg.get("_api_key"),
        )
        if any(canonical.get(k) for k in
               ("project_id", "project_number", "database_url",
                "storage_bucket", "google_app_id")):
            out.append(canonical)
    return out


def _extract_android_package_and_sha1(apk_path, quiet=True):
    """Return (package_name, sha1_hex) for an Android APK.
    Uses androguard if available (clean parse of binary AndroidManifest +
    signing cert); falls back to None if androguard isn't installed.
    package_name is the AndroidManifest's `package` attribute; sha1_hex is
    the SHA-1 hash of the signing certificate's DER bytes (this is the
    format Google API restriction-mode android expects: `package:SHA1`).
    """

    try:
        from loguru import logger as _loguru_logger
        _loguru_logger.disable("androguard")
        _loguru_logger.disable("apkInspector")
    except Exception:
        # loguru not installed, or loguru raised — fall through and
        # let androguard load with whatever logging config the
        # process already has.
        pass
    try:
        from androguard.core.apk import APK
    except ImportError:
        if not quiet:
            print("    [!] androguard not installed; cannot extract package + cert SHA1. "
                  "Install: pip install androguard")
        return None, None
    import hashlib, zipfile, tempfile, os as _os
    # XAPK / APKM wrapper: outer ZIP containing base.apk + config.*.apk splits +
    # manifest.json + icon. androguard can only parse a single APK, so unwrap
    # to a temp base.apk first. Try the inner naming conventions used by
    # APKPure XAPK ('base.apk' or '<package>.apk').
    inner_path = apk_path
    cleanup_path = None
    try:
        with zipfile.ZipFile(apk_path) as outer:
            inner_names = outer.namelist()
            candidate = None
            for n in inner_names:
                if n == "base.apk" or (n.endswith(".apk") and "/" not in n
                                        and "config." not in n):
                    candidate = n; break
            if candidate:
                body = _read_mobile_member(outer, candidate)
                with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as tmp:
                    cleanup_path = tmp.name
                    tmp.write(body)
                inner_path = tmp.name
                if not quiet:
                    print("    [*] XAPK detected — unwrapped inner %s for parsing" % candidate)
    except Exception:
        pass  # fall through and let APK() try the original
    try:
        apk = APK(inner_path)
        pkg = apk.get_package()
        # Modern apps are signed with APK Signature Scheme v2/v3 only and have
        # NO META-INF/*.RSA — androguard's `get_certificate(...)` (v1 path)
        # returns None. Try v3 → v2 → v1 in order. Each `_certificates_der_*`
        # call returns a list of DER bytes.
        cert_der = None
        for getter in ("get_certificates_der_v3",
                       "get_certificates_der_v2"):
            try:
                fn = getattr(apk, getter)
                ders = fn() if fn else None
                if ders:
                    cert_der = ders[0]
                    break
            except Exception:
                continue
        if cert_der is None:
            # v1 fallback (classic JAR signing) via X.509 object
            try:
                cert_der = apk.get_certificate_der(apk.get_signature_name())
            except Exception:
                pass
        if not pkg or not cert_der:
            if not quiet:
                print("    [!] APK package+SHA1: pkg=%s cert_der=%s "
                      "(maybe unsigned or signature scheme unrecognized)"
                      % (pkg, "yes" if cert_der else "no"))
            if cleanup_path:
                try: _os.unlink(cleanup_path)
                except Exception: pass
            return pkg, None
        sha1 = hashlib.sha1(cert_der).hexdigest().upper()
        sha1_fmt = ":".join(sha1[i:i+2] for i in range(0, len(sha1), 2))
        if cleanup_path:
            try: _os.unlink(cleanup_path)
            except Exception: pass
        return pkg, sha1_fmt
    except Exception as e:
        if not quiet:
            print("    [!] APK package+SHA1 extraction failed: %s: %s"
                  % (type(e).__name__, e))
        if cleanup_path:
            try: _os.unlink(cleanup_path)
            except Exception: pass
        return None, None


def _download_android_apk_from_apkmirror(package_name, output_dir, quiet=False):
    """Download an Android APK from APKMirror via Playwright.
    APKMirror serves developer-signature-verified APKs (often universal
    builds rather than Play Store split-APKs, so total SHA-256 differs but
    the inner DEX/resources/key strings are the developer's signed content).
    Best fallback when apkeep apk-pure backend returns truncated files and
    Google Play API is locked down.

    Returns the local APK path on success or None. The returned file is
    verified to be a real ZIP (BadZipFile check) — truncated downloads are
    rejected.
    """
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    except ImportError:
        if not quiet:
            print("    [!] playwright not installed; cannot use APKMirror fallback. "
                  "Run: pip install playwright && playwright install chromium")
        return None
    os.makedirs(output_dir, exist_ok=True)
    out_path = os.path.join(output_dir, package_name + ".apk")
    search_url = ("https://www.apkmirror.com/?post_type=app_release"
                  "&searchtype=apk&s=" + package_name)
    if not quiet:
        print("    [*] APKMirror search: %s" % search_url)
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            ctx = browser.new_context(
                user_agent=("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                            "AppleWebKit/537.36 (KHTML, like Gecko) "
                            "Chrome/138.0.0.0 Safari/537.36"),
                accept_downloads=True, ignore_https_errors=True)
            page = ctx.new_page()
            try:
                page.goto(search_url, wait_until="domcontentloaded", timeout=30000)
            except PWTimeout:
                pass
            pkg_parts = [p for p in package_name.lower().split(".")
                         if len(p) > 2 and p not in ("com", "org", "net", "app",
                                                     "android", "google", "mobile",
                                                     "the", "for", "www")]
            release_href = None
            all_links = page.locator("a[href*='-release/']")
            try:
                n = min(all_links.count(), 15)
            except Exception:
                n = 0
            for i in range(n):
                try:
                    href = all_links.nth(i).get_attribute("href", timeout=3000) or ""
                except (PWTimeout, Exception):
                    continue
                hl = href.lower()
                if any(p in hl for p in pkg_parts):
                    release_href = href
                    if not quiet:
                        print("    [*] match: result %d contains package fragment" % (i + 1))
                    break
            if not release_href:
                if not quiet:
                    print("    [!] APKMirror search returned no result matching "
                          "package fragments %s — skipping APKMirror"
                          % (pkg_parts or [package_name]))
                browser.close()
                return None
            release_url = ("https://www.apkmirror.com" + release_href
                           if release_href.startswith("/") else release_href)
            if not quiet:
                print("    [*] APKMirror release page: %s" % release_url)
            try:
                page.goto(release_url, wait_until="domcontentloaded", timeout=30000)
            except PWTimeout:
                pass
            # Variant page: prefer universal/nodpi, fallback to first variant.
            # Variants table: <a class="accent_color" href="...-android-apk-download/">
            variant_link = page.locator(
                "a.accent_color[href*='-android-apk-download/']"
            ).first
            try:
                variant_href = variant_link.get_attribute("href", timeout=10000)
            except (PWTimeout, Exception):
                variant_href = None
            if not variant_href:
                if not quiet:
                    print("    [!] APKMirror release page had no variant download link")
                browser.close()
                return None
            variant_url = ("https://www.apkmirror.com" + variant_href
                           if variant_href.startswith("/") else variant_href)
            if not quiet:
                print("    [*] APKMirror variant page: %s" % variant_url)
            try:
                page.goto(variant_url, wait_until="domcontentloaded", timeout=30000)
            except PWTimeout:
                pass
            # Variant page has a "Download APK Bundle" or "Download APK" button.
            # The actual download is on a final page after one more click.
            download_btn = page.locator(
                "a.downloadButton, a[href*='-download/']"
            ).first
            try:
                final_href = download_btn.get_attribute("href", timeout=10000)
            except (PWTimeout, Exception):
                final_href = None
            if final_href:
                final_url = ("https://www.apkmirror.com" + final_href
                             if final_href.startswith("/") else final_href)
                try:
                    page.goto(final_url, wait_until="domcontentloaded", timeout=30000)
                except PWTimeout:
                    pass
            # Final download page: <a rel="nofollow" href="...?key=...">click here</a>
            # Wait for download event triggered by clicking the link.
            final_link = page.locator("a[rel='nofollow'][href*='?key=']").first
            try:
                with page.expect_download(timeout=300_000) as dl_info:
                    final_link.click(timeout=10000)
                dl = dl_info.value
                dl.save_as(out_path)
                browser.close()
            except (PWTimeout, Exception) as e:
                if not quiet:
                    print("    [!] APKMirror final download failed: %s" % e)
                try: browser.close()
                except Exception: pass
                return None
    except Exception as e:
        if not quiet:
            print("    [!] APKMirror Playwright error: %s" % e)
        return None
    # Verify file is a real ZIP — APKMirror sometimes serves XAPK files even
    # when the URL says .apk. Either way, accept if it's a valid ZIP archive.
    import zipfile
    if not os.path.isfile(out_path) or os.path.getsize(out_path) < 1024:
        if not quiet:
            print("    [!] APKMirror download produced no file at %s" % out_path)
        return None
    try:
        with zipfile.ZipFile(out_path) as zf:
            n = len(zf.namelist())
    except zipfile.BadZipFile:
        if not quiet:
            print("    [!] APKMirror download is not a valid ZIP — discarding %s"
                  % out_path)
        os.remove(out_path)
        return None
    pkg, _sha1 = _extract_android_package_and_sha1(out_path, quiet=True)
    if pkg != package_name:
        if not quiet:
            print("    [!] APKMirror downloaded package mismatch: requested %s "
                  "but archive is %s — discarding %s"
                  % (package_name, pkg or "<unknown>", out_path))
        try:
            os.remove(out_path)
        except OSError:
            pass
        return None
    if not quiet:
        print("    [+] APKMirror %s → %s (%.1f MB, %d files in ZIP)"
              % (package_name, out_path,
                 os.path.getsize(out_path) / (1024 * 1024), n))
    return out_path


def _download_ios_ipa(app_id_or_bundle, output_dir, quiet=False):
    """Try to download an iOS IPA via `ipatool` (https://github.com/majd/ipatool).
    Accepts either a numeric App Store ID (e.g. 367003839) or a bundle ID
    (e.g. com.example.app). Returns the local path on success or None.

    Requires `ipatool auth login` to have been run prior with an Apple ID.
    Free apps still need `--purchase` to obtain a license; we always pass it.
    """
    if not _which("ipatool"):
        if not quiet:
            print("    [!] ipatool not installed; cannot auto-download iOS %s. "
                  "Install: brew install ipatool, OR pass --mobile FILE."
                  % app_id_or_bundle)
        return None
    os.makedirs(output_dir, exist_ok=True)
    out_path = os.path.join(output_dir, str(app_id_or_bundle) + ".ipa")
    # Reuse cached IPA if already on disk.
    if os.path.isfile(out_path) and os.path.getsize(out_path) > 1024:
        if not quiet:
            print("    [+] using cached iOS %s (%.1f MB) → %s"
                  % (app_id_or_bundle, os.path.getsize(out_path) / (1024 * 1024),
                     out_path))
        return out_path
    # Numeric → --app-id; otherwise --bundle-identifier
    if str(app_id_or_bundle).isdigit():
        id_flag = ["--app-id", str(app_id_or_bundle)]
    else:
        id_flag = ["--bundle-identifier", str(app_id_or_bundle)]
    keychain_pass = os.environ.get("GAPISCANNER_IPATOOL_KEYCHAIN_PASS",
                                   _IPATOOL_KEYCHAIN_DEFAULT)
    cmd = [_which("ipatool"), "download", *id_flag,
           "-o", out_path, "--purchase", "--non-interactive",
           "--keychain-passphrase", keychain_pass]
    proc = None
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except subprocess.TimeoutExpired:
        if not quiet:
            print("    [!] ipatool timed out after 600s — checking for partial/full download")
    except OSError as e:
        if not quiet:
            print("    [!] ipatool failed: %s" % e)
        return None
    if os.path.isfile(out_path) and os.path.getsize(out_path) > 1024:
        if not quiet:
            print("    [+] downloaded iOS %s (%.1f MB) → %s"
                  % (app_id_or_bundle, os.path.getsize(out_path) / (1024 * 1024),
                     out_path))
        return out_path
    if not quiet:
        if proc is not None:
            msg = (proc.stderr or proc.stdout or "no output").strip().splitlines()
            print("    [!] ipatool returned %d but no IPA at %s"
                  % (proc.returncode, out_path))
            for ln in msg[:3]:
                print("        %s" % ln)
        else:
            print("    [!] ipatool timed out and no IPA on disk at %s" % out_path)
    return None


def _download_android_apk(package_name, output_dir, quiet=False):
    """Try to download an Android APK by package name. Returns the local
    path on success, or None on failure.

    Backends, in order of preference:
      1. `apkeep`  (https://github.com/EFForg/apkeep) — recommended; supports
         APKPure as a no-auth source: `apkeep -a com.example -d apk-pure DST`
      2. (none for now) — Google Play requires auth, IPA download requires
         Apple Developer creds. Operator falls back to manual download +
         --mobile FILE.

    Callers that already have a local bundle can use --mobile FILE directly.
    This helper is for integrations that only supply a package ID.
    """
    os.makedirs(output_dir, exist_ok=True)
    # Reuse cached APK if already on disk + valid ZIP (cuts repeat runs to
    # seconds and rejects truncated downloads from a prior failed run).
    import zipfile as _zf
    for ext in (".apk", ".xapk"):
        cached = os.path.join(output_dir, package_name + ext)
        if os.path.isfile(cached) and os.path.getsize(cached) > 1024:
            try:
                with _zf.ZipFile(cached):
                    pass
                pkg, _sha1 = _extract_android_package_and_sha1(cached, quiet=True)
                if pkg != package_name:
                    if not quiet:
                        print("    [!] cached %s package mismatch: requested %s "
                              "but archive is %s; re-downloading"
                              % (os.path.basename(cached), package_name,
                                 pkg or "<unknown>"))
                    os.remove(cached)
                    continue
                if not quiet:
                    print("    [+] using cached %s (%.1f MB) → %s"
                          % (package_name, os.path.getsize(cached) / (1024 * 1024), cached))
                return cached
            except _zf.BadZipFile:
                if not quiet:
                    print("    [!] cached %s is truncated; re-downloading"
                          % os.path.basename(cached))
                os.remove(cached)
    apkm_path = _download_android_apk_from_apkmirror(package_name, output_dir, quiet=quiet)
    if apkm_path:
        return apkm_path
    if not _which("apkeep"):
        if not quiet:
            print("    [!] APKMirror returned nothing and apkeep not installed; "
                  "no APK available for %s" % package_name)
        return None
    if not quiet:
        print("    [*] APKMirror failed — falling back to apkeep apk-pure (may truncate)")
    cmd = [_which("apkeep"), "-a", package_name, "-d", "apk-pure", output_dir]
    proc = None
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except subprocess.TimeoutExpired:
        # Don't bail yet — the file may have downloaded fully and apkeep was
        # only mid-verification when we killed it. Fall through to file check.
        if not quiet:
            print("    [!] apkeep timed out after 600s — checking for partial/full download")
    except OSError as e:
        if not quiet:
            print("    [!] apkeep failed: %s" % e)
        return None
    # apkeep writes <package>.apk (or .xapk) into output_dir — verify it's a
    # real ZIP (apkeep's apk-pure backend sometimes returns truncated content
    # that has the PK magic bytes but no end-of-central-directory record).
    for ext in (".apk", ".xapk"):
        candidate = os.path.join(output_dir, package_name + ext)
        if os.path.isfile(candidate) and os.path.getsize(candidate) > 1024:
            try:
                with _zf.ZipFile(candidate):
                    pass
                pkg, _sha1 = _extract_android_package_and_sha1(candidate, quiet=True)
                if pkg != package_name:
                    if not quiet:
                        print("    [!] apkeep package mismatch: requested %s "
                              "but archive is %s — discarding %s"
                              % (package_name, pkg or "<unknown>", candidate))
                    os.remove(candidate)
                    continue
                if not quiet:
                    print("    [+] downloaded %s (%.1f MB) → %s"
                          % (package_name, os.path.getsize(candidate) / (1024 * 1024),
                             candidate))
                return candidate
            except _zf.BadZipFile:
                if not quiet:
                    print("    [!] apkeep download is truncated — falling back to APKMirror")
                os.remove(candidate)
                break
    if not quiet:
        if proc is not None:
            msg = (proc.stderr or proc.stdout or "no output").strip().splitlines()
            print("    [!] apkeep returned %d but no APK at %s/%s.apk — trying APKMirror"
                  % (proc.returncode, output_dir, package_name))
            for ln in msg[:3]:
                print("        %s" % ln)
        else:
            print("    [!] apkeep timed out and no APK on disk — trying APKMirror")
    return _download_android_apk_from_apkmirror(package_name, output_dir, quiet=quiet)


class _Tee:
    """tee() for Python file objects — writes go to every wrapped stream.
    Used to mirror per-key scan output to disk while keeping live stdout."""
    def __init__(self, *streams):
        self._streams = streams
    def write(self, data):
        for s in self._streams:
            try:
                s.write(data)
            except Exception:
                pass
    def flush(self):
        for s in self._streams:
            try:
                s.flush()
            except Exception:
                pass

def _progress_path(scope_dir):
    """Path to the pause/resume progress file for a scope. One file per
    (platform, program) — overwritten each seed. On Ctrl+C the file holds
    the last completed seed so --resume picks up exactly there."""
    return os.path.join(scope_dir, "progress.json")


def _progress_load(scope_dir):
    """Return saved progress dict, or empty defaults if no file."""
    path = _progress_path(scope_dir)
    if not os.path.exists(path):
        return {"completed_seeds": [], "scanned_keys": [],
                "mobile_completed": [], "ts": None,
                "platform": None, "program": None}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError("Invalid progress file")
        for field in ("completed_seeds", "scanned_keys", "mobile_completed"):
            if not isinstance(data.get(field), list):
                data[field] = []
            data[field] = [value for value in data[field] if isinstance(value, str)]
        return data
    except (ValueError, OSError):
        return {"completed_seeds": [], "scanned_keys": [],
                "mobile_completed": [], "ts": None,
                "platform": None, "program": None}


def _progress_save(scope_dir, completed_seeds, scanned_keys,
                   mobile_completed, ts=None, platform=None, program=None):
    """Atomic rewrite of progress.json. Called after every seed/mobile
    completes so a kill -9 still leaves a consistent state on disk."""
    path = _progress_path(scope_dir)
    tmp = path + ".tmp"
    data = {
        "completed_seeds":  sorted(completed_seeds),
        "scanned_keys":     sorted(scanned_keys),
        "mobile_completed": sorted(mobile_completed),
        "ts":               ts,
        "platform":         platform,
        "program":          program,
    }
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)


def _run_bundle(bundle, dry_run=False, verbose=False, quiet=False, output_dir=None,
                scan_callback=None, cache_dir=None, exclude_third_party=False,
                resume=False, ts=None, platform=None, mobile_only=False,
                web_only=False,
                debug_mobile_extract=False, prompt_wildcards=False,
                skip_wildcards=False):
    """Translate a ScopeBundle into discovered AIza keys.

    Steps:
      1. For each in-scope web asset:
         - "domain"  → seed = https://{host}/  → discover_keys_from_url
         - "url"     → seed = the URL itself   → discover_keys_from_url
         - "wildcard" → DNS enum + OOS filter → many seeds → discover_keys_from_url
      2. For each in-scope mobile app with local_path → discover_keys_from_mobile
      3. Dedupe across all sources, return sorted list.

    Out-of-scope identifiers (regex/exact) MUST be enforced.  We do this by
    compiling each OOS entry into a regex (exact match or pattern) and
    skipping any discovered host that matches.

    Streaming: if `scan_callback` is provided, it is invoked once per source
    (seed URL or mobile package) with `(source_label, new_keys_set)` as soon
    as keys are extracted from that source. Keys already seen during the
    same bundle run are filtered out before the callback fires (global
    dedup). This lets the caller scan keys as they appear, instead of
    waiting for the full discovery loop to finish.

    `cache_dir` is forwarded to `_fetch_and_extract_keys` to persist response
    bodies for later re-scan.

    Artifacts written:
      {artifact_dir}/scope/scope_bundle.json        — pickled bundle
      {artifact_dir}/scope/<prefix>_targets.txt — final URL seeds used
      {artifact_dir}/scope/<prefix>_discovered.csv — DNS enum result
    """
    import dataclasses

    if mobile_only and web_only:
        raise ValueError("--mobile-only and --web-only are mutually exclusive")

    scope_dir = _artifact_dir(
        bundle.program,
        override=output_dir,
        subdir="scope",
        platform=bundle.platform,
    )
    print("\n[*] gapiscanner platform=%s program=%s" % (bundle.platform, bundle.program))
    print("    Artifacts dir: %s" % scope_dir)


    _begin_discovery_session()


    bundle._key_firebase_configs = {}

    # 1. Persist the parsed bundle for audit / re-run
    bundle_json = json.dumps(
        {
            "program": bundle.program, "platform": bundle.platform,
            "raw_source": bundle.raw_source,
            "web_assets":   [dataclasses.asdict(a) for a in bundle.web_assets],
            "api_assets":   [dataclasses.asdict(a) for a in bundle.api_assets],
            "executable_assets": [dataclasses.asdict(a) for a in bundle.executable_assets],
            "mobile_apps":  [dataclasses.asdict(m) for m in bundle.mobile_apps],
            "oos": bundle.oos,
        },
        indent=2,
    )
    with open(os.path.join(scope_dir, "scope_bundle.json"), "w", encoding="utf-8") as f:
        f.write(bundle_json)

    # Compile OOS patterns — accept both exact strings and regex
    oos_patterns = []
    for o in bundle.oos:
        try:
            oos_patterns.append(re.compile(o, re.IGNORECASE))
        except re.error:
            oos_patterns.append(re.compile(re.escape(o), re.IGNORECASE))
    def _is_oos(host_or_url):
        # Test against both the bare hostname and the full string
        try:
            from urllib.parse import urlparse
            bare = urlparse(host_or_url).netloc or host_or_url
        except Exception:
            bare = host_or_url
        for pat in oos_patterns:
            if pat.search(bare) or pat.search(host_or_url):
                return True
        return False

    def _is_web_seed_hostname(host):
        """Exclude DNS service-record labels that cannot be HTTP hosts."""
        return bool(host) and not any(label.startswith("_") for label in host.split("."))


    seeds = set()
    discovered_hosts = []   # (host, source) for the CSV
    wildcard_decisions = {}

    def _should_expand_wildcard(pattern, apex):
        if skip_wildcards:
            if not quiet:
                print("    [*] Wildcard %s (apex=%s) skipped by default."
                      % (pattern, apex))
            return False
        if not prompt_wildcards:
            return True
        key = "%s|%s" % (pattern, apex)
        if key in wildcard_decisions:
            return wildcard_decisions[key]
        if not sys.stdin.isatty():
            if not quiet:
                print("    [!] Wildcard %s (apex=%s) requires confirmation; "
                      "non-interactive shell, skipping." % (pattern, apex))
            wildcard_decisions[key] = False
            return False
        while True:
            try:
                ans = input(
                    "    [?] Scan wildcard %s (apex=%s)? [y/N] "
                    % (pattern, apex)
                ).strip().lower()
            except (EOFError, KeyboardInterrupt):
                ans = ""
            if ans in ("y", "yes"):
                wildcard_decisions[key] = True
                return True
            if ans in ("", "n", "no"):
                wildcard_decisions[key] = False
                if not quiet:
                    print("    [*] Wildcard %s skipped by operator." % pattern)
                return False
            print("    Please answer y or n.")

    # --mobile-only skips the entire web-seed build (DNS enum, CNAME filter,
    # wildcard expansion all take real time — pointless if we're only going
    # to scan APK/IPA bundles).
    web_assets_iter = [] if mobile_only else bundle.web_assets
    for asset in web_assets_iter:
        if not asset.bounty_eligible:
            continue
        v = asset.value
        if asset.asset_type == "wildcard":

            apex, wildcard_regex = _wildcard_asset_apex_and_regex(v)
            if not apex:
                if not quiet:
                    print("    [!] Wildcard %r — could not derive apex for "
                          "DNS enum; skipping" % v)
                continue
            if not _should_expand_wildcard(v, apex):
                continue
            if not quiet:
                print("    [*] Expanding wildcard %s (apex=%s)" % (v, apex))
            hosts = dns_enum(apex, verbose=verbose, quiet=quiet)
            hosts_after_oos = []
            for h in hosts:
                if not _is_web_seed_hostname(h):
                    if verbose: print("      [non-web-dns-label] %s" % h)
                    continue
                if _is_oos(h):
                    if verbose: print("      [oos] %s" % h)
                    continue
                if wildcard_regex is not None and not wildcard_regex.search(h):
                    if verbose: print("      [wildcard-miss] %s" % h)
                    continue
                hosts_after_oos.append(h)
            if exclude_third_party:
                hosts_after_oos, dropped_3p = _exclude_third_party_owned(
                    hosts_after_oos, verbose=verbose, quiet=quiet)
                for h, target, saas in dropped_3p:
                    discovered_hosts.append((h, "3rd-party:%s" % saas))
            for h in hosts_after_oos:
                discovered_hosts.append((h, "dns_enum:%s" % apex))
                seeds.add("https://%s/" % h)
            if not quiet:
                print("    [*] Wildcard %s → %d in-scope hosts (after OOS%s filter)"
                      % (apex, len(hosts_after_oos),
                         " + 3rd-party" if exclude_third_party else ""))
        elif asset.asset_type == "url":
            if _is_oos(v):
                continue
            seeds.add(v if v.startswith(("http://", "https://")) else "https://" + v)
        elif asset.asset_type in ("domain", "ip"):
            if _is_oos(v):
                continue
            seeds.add("https://%s/" % v)

    # Persist final seed list + DNS-enum-discovered hosts
    with open(os.path.join(scope_dir, _BUNDLE_ARTIFACT_PREFIX + "_targets.txt"), "w", encoding="utf-8") as f:
        for s in sorted(seeds): f.write(s + "\n")
    if discovered_hosts:
        import csv as _csv
        with open(os.path.join(scope_dir, _BUNDLE_ARTIFACT_PREFIX + "_discovered.csv"), "w", encoding="utf-8", newline="") as f:
            w = _csv.writer(f)
            w.writerow(["hostname", "source"])
            for h, src in sorted(set(discovered_hosts)):
                w.writerow([h, src])

    if not quiet:
        print("    Seeds: %d concrete URL(s)" % len(seeds))
        print("    OOS patterns enforced: %d" % len(oos_patterns))
        mobile_to_inspect = sum(
            1 for m in bundle.mobile_apps if m.bounty_eligible and m.local_path)
        if mobile_only or mobile_to_inspect:
            print("    Mobile bundles to inspect: %d" % mobile_to_inspect)
        if web_only:
            skipped_mobile = sum(1 for m in bundle.mobile_apps if m.bounty_eligible)
            print("    Mobile apps skipped by --web-only: %d" % skipped_mobile)

    if dry_run:
        if not quiet:
            print("\n[*] --dry-run: not scanning. Targets written to:")
            print("    %s/%s_targets.txt" % (scope_dir, _BUNDLE_ARTIFACT_PREFIX))
        return set()

    # 3. Run discovery against each seed + each mobile bundle, streaming new
    #    keys to scan_callback as they appear (dedup'd globally per run).
    all_keys = set()
    scanned_keys = set()       # keys actually emitted for scan (in-scope source)
    oos_recorded_keys = set()  # keys emitted as OOS-record-only (no scan)

    def _emit(source_label, found_keys, is_oos=False):
        """Pass each newly discovered in-scope key to the scan callback."""
        nonlocal all_keys
        all_keys.update(found_keys)
        if is_oos:
            # Dedup against both buckets — if the key is already scanned
            # in-scope, no need to record yet another OOS skip; if it's
            # already been recorded OOS once, don't repeat the print.
            new_oos = found_keys - oos_recorded_keys - scanned_keys
            if not new_oos:
                return
            if not quiet and scan_callback is not None:
                print("    [*] %d OOS key(s) from %s — recording skip, "
                      "not scanning" % (len(new_oos), source_label))
            if scan_callback is not None:
                scan_callback(source_label, new_oos)
            oos_recorded_keys.update(new_oos)
            return
        new_keys = found_keys - scanned_keys
        if new_keys:
            if not quiet and scan_callback is not None:
                print("    [*] %d new key(s) from %s — scanning now"
                      % (len(new_keys), source_label))
            if scan_callback is not None:
                scan_callback(source_label, new_keys)
            scanned_keys.update(new_keys)
        elif found_keys and not quiet:
            print("    [*] All %d key(s) from %s already scanned — skipping"
                  % (len(found_keys), source_label))

    seeds_sorted = sorted(seeds)
    total_seeds = len(seeds_sorted)
    mobile_total = 0 if web_only else sum(
        1 for m in bundle.mobile_apps if m.bounty_eligible)
    overall_total = total_seeds + mobile_total

    # Pause/resume: load prior progress for this scope and skip seeds + mobile
    # entries already completed. Also seed `scanned_keys` so we don't re-scan
    # keys we already covered.
    progress = _progress_load(scope_dir)
    completed_seed_set = set(progress.get("completed_seeds", [])) if resume else set()
    completed_mobile_set = set(progress.get("mobile_completed", [])) if resume else set()
    if resume:
        scanned_keys.update(progress.get("scanned_keys", []))
        if not quiet:
            print("    [resume] Loaded progress: %d completed seed(s), "
                  "%d mobile completed, %d keys already scanned."
                  % (len(completed_seed_set),
                     len(completed_mobile_set),
                     len(scanned_keys)))

    def _save_progress():
        _progress_save(scope_dir, completed_seed_set, scanned_keys,
                       completed_mobile_set, ts=ts,
                       platform=platform, program=bundle.program)

    try:
        if mobile_only:
            if not quiet:
                print("\n[*] --mobile-only: skipping %d web seed(s); mobile-only phase."
                      % total_seeds)
        else:
            for idx, seed in enumerate(seeds_sorted, 1):
                if seed in completed_seed_set:
                    if not quiet and verbose:
                        print("    [resume] Skipping completed seed %d/%d: %s"
                              % (idx, overall_total, seed))
                    continue
                if not quiet:
                    print("\n[seed %d/%d  (%d keys so far)] %s"
                          % (idx, overall_total, len(all_keys), seed))
                _discover_kwargs = {
                    "verbose": verbose,
                    "quiet": quiet,
                    "cache_dir": cache_dir,
                }
                # Preserve the historical callback contract for callers and
                # tests that replace discover_keys_from_url with the old
                # four-argument form.  The new keyword is needed only for an
                # actual resumed run.
                if resume:
                    _discover_kwargs["resume"] = True
                keys, key_sources = discover_keys_from_url(
                    seed, **_discover_kwargs)

                src_map = key_sources if isinstance(key_sources, dict) else {}
                for k in sorted(keys):
                    srcs_for_k = sorted(src_map.get(k, set()) or set())
                    in_scope_srcs = [s for s in srcs_for_k
                                     if _is_source_in_platform_scope(
                                         s, bundle)]
                    if in_scope_srcs:
                        _emit(in_scope_srcs[0], {k}, is_oos=False)
                    elif srcs_for_k:
                        # No in-scope source — every source is OOS.
                        _emit(srcs_for_k[0], {k}, is_oos=True)
                    else:
                        if _is_source_in_platform_scope(seed, bundle):
                            _emit(seed, {k}, is_oos=False)
                        else:
                            _emit(seed, {k}, is_oos=True)
                completed_seed_set.add(seed)
                _save_progress()

        if web_only:
            if not quiet:
                print("\n[*] --web-only: skipping mobile acquisition/scan phase.")
            return all_keys

        apk_cache_dir = os.path.join(scope_dir, "..", "downloaded_apks")
        for j, m in enumerate(bundle.mobile_apps, 1):
            if not m.bounty_eligible:
                continue
            mobile_key = "mobile:%s:%s" % (m.platform or "?", m.identifier or m.local_path or "?")
            if mobile_key in completed_mobile_set:
                if not quiet and verbose:
                    print("    [resume] Skipping completed mobile %s" % mobile_key)
                continue
            if not quiet:
                print("\n[mobile %d/%d  (%d keys so far)] %s"
                      % (j, mobile_total, len(all_keys), m.identifier or m.local_path))
            path = m.local_path
            if not path:
                if m.platform == "android":
                    if not quiet:
                        print("    [*] Auto-downloading Android APK: %s" % m.identifier)
                    path = _download_android_apk(m.identifier, apk_cache_dir, quiet=quiet)
                    if path:
                        m.local_path = path
                elif m.platform == "ios":
                    if not quiet:
                        print("    [*] Auto-downloading iOS IPA: %s" % m.identifier)
                    path = _download_ios_ipa(m.identifier, apk_cache_dir, quiet=quiet)
                    if path:
                        m.local_path = path
            if not path:
                # Acquisition failed, so this app is not actually covered.
                # Do not mark it complete; a later --resume should retry it.
                if not quiet:
                    print("    [!] Mobile acquisition failed for %s — not marking complete"
                          % (m.identifier or m.local_path or mobile_key))
                continue
            ios_key_bundle_map = {}
            default_bundle = None
            android_pkg_sha1 = None
            if m.platform == "ios":
                default_bundle = _extract_ios_bundle_id(path, quiet=quiet)
                ios_key_bundle_map = _extract_ios_key_bundle_map(path, quiet=quiet)
                if not quiet:
                    if default_bundle:
                        print("    [*] iOS main bundle: %s" % default_bundle)
                    if ios_key_bundle_map:
                        print("    [*] iOS per-key bundle map: %d entry(ies)"
                              % len(ios_key_bundle_map))
                        for k, b in sorted(ios_key_bundle_map.items()):
                            print("        %s → %s" % (
                                _redact_key_display(k), b))
            elif m.platform == "android":
                pkg, sha1 = _extract_android_package_and_sha1(path, quiet=quiet)
                if pkg and sha1:
                    if not quiet:
                        print("    [*] Android package: %s  cert SHA1: %s" % (pkg, sha1))
                    android_pkg_sha1 = (pkg, sha1)
            _archive_configs = []
            keys, _src = discover_keys_from_mobile(
                path, verbose=verbose, quiet=quiet,
                debug_mobile_extract=debug_mobile_extract,
                config_sink=_archive_configs)

            for ext_key in keys:
                _sel = _select_configs_for_key(ext_key, _archive_configs)
                if _sel:
                    bundle._key_firebase_configs.setdefault(
                        ext_key, []).extend(_sel)
            # Emit each key with its OWN source label so scan_callback's pass2
            # uses the correct per-key restriction value.
            for ext_key in sorted(keys):
                if m.platform == "ios":
                    bid = ios_key_bundle_map.get(ext_key, default_bundle or m.identifier)
                    per_key_label = "mobile:ios:%s" % bid
                elif m.platform == "android" and android_pkg_sha1:
                    pkg, sha1 = android_pkg_sha1
                    per_key_label = "mobile:android:%s:%s" % (pkg, sha1)
                else:
                    per_key_label = mobile_key
                _emit(per_key_label, {ext_key})
            completed_mobile_set.add(mobile_key)
            _save_progress()
    except KeyboardInterrupt:
        # Ctrl+C during the loop: persist the last good progress and re-raise
        # so main() can print a clean "paused" summary.
        _save_progress()
        if not quiet:
            print("\n\n[PAUSED] %d/%d seed(s) completed, %d mobile completed, "
                  "%d key(s) scanned." % (len(completed_seed_set), total_seeds,
                                          len(completed_mobile_set),
                                          len(scanned_keys)))
            print("[*] Resume with: --platform %s --program %s --resume"
                  % (platform or "?", bundle.program))
        raise

    return all_keys


def _build_mobile_restriction_labels(path, keys, quiet=True):
    """Return `{key: source_label}` mapping each extracted key from
    `path` to its mobile-restriction source label, or an empty dict
    if `path` is not a recognised mobile archive / restriction
    extraction failed. iOS keys prefer the per-key bundle from
    `_extract_ios_key_bundle_map` (multi-config IPAs ship multiple
    `GoogleService-Info-*.plist` files, one per bundle) and fall
    back to the IPA's main bundle. Android keys all share the
    archive's package + cert SHA1 since `_extract_android_package_and_sha1`
    is whole-archive."""
    out = {}
    if not path or not keys:
        return out
    pl = path.lower()
    if pl.endswith(".ipa"):
        default_bundle = _extract_ios_bundle_id(path, quiet=quiet)
        bundle_map = _extract_ios_key_bundle_map(path, quiet=quiet) or {}
        for k in keys:
            bid = bundle_map.get(k) or default_bundle
            if bid:
                out[k] = "mobile:ios:%s" % bid
    elif pl.endswith((".apk", ".xapk")):
        pkg, sha1 = _extract_android_package_and_sha1(path, quiet=quiet)
        if pkg and sha1:
            label = "mobile:android:%s:%s" % (pkg, sha1)
            for k in keys:
                out[k] = label
    return out


def _select_configs_for_key(key, archive_configs):
    """Prefer exact key-to-config bindings within the supplied archive or source."""
    if not archive_configs:
        return []
    cfgs = [c for c in archive_configs if c]
    exact = [c for c in cfgs if c.get("api_key") and c.get("api_key") == key]
    if exact:
        chosen = exact
    elif any(c.get("api_key") for c in cfgs):
        # Some configs are owned by other keys — bind only the unowned ones.
        chosen = [c for c in cfgs if not c.get("api_key")]
    else:
        # No ownership info anywhere — archive-local fallback to all.
        chosen = cfgs
    return [dict(c) for c in chosen]


def _parse_mobile_restriction_label(sources_for_key):
    """Peek through a key's source-label set (the value side of the
    `sources` dict that the direct discovery loop carries) looking
    for a `mobile:android:…` or `mobile:ios:…` label produced by
    `_build_mobile_restriction_labels`. Returns
    `(pass2_mode, pass2_value)` or `(None, None)` when no mobile
    label is present.

    For deterministic behavior when a key appears in MULTIPLE
    archives (e.g. the same key embedded in both an Android and an
    iOS bundle of the same app), we sort the labels and return the
    first valid one — that way the same input always yields the
    same pass2 decision regardless of set iteration order."""
    if not sources_for_key:
        return (None, None)
    try:
        labels = sorted(s for s in sources_for_key if isinstance(s, str))
    except TypeError:
        return (None, None)
    for label in labels:
        if label.startswith("mobile:ios:"):
            bid = label.split("mobile:ios:", 1)[1]
            if "." in bid:
                return ("ios", bid)
        elif label.startswith("mobile:android:"):
            rest = label.split("mobile:android:", 1)[1]
            if ":" in rest:
                pkg_part, sha_part = rest.split(":", 1)
                if "." in pkg_part and len(sha_part) >= 40:
                    return ("android", "%s:%s" % (pkg_part, sha_part))
    return (None, None)


def _describe_key_origin(sources_for_key):
    """Format the archive and application attribution for a discovered key."""
    if not sources_for_key:
        return None
    try:
        labels = [s for s in sources_for_key if isinstance(s, str)]
    except TypeError:
        return None
    archives = sorted(s.split("archive:", 1)[1] for s in labels
                      if s.startswith("archive:"))
    pkg = None
    mode, value = _parse_mobile_restriction_label(labels)
    if mode == "android" and value:
        # value is "<pkg>:<sha1>" — show just the package.
        pkg = value.split(":", 1)[0]
    elif mode == "ios" and value:
        pkg = value
    if archives and pkg:
        return "%s → %s" % (", ".join(archives), pkg)
    if archives:
        return ", ".join(archives)
    if pkg:
        return pkg
    return None


_MOBILE_DIR_EXTS = (".apk", ".xapk", ".ipa", ".aab", ".zip")


def _expand_mobile_input(mobile_files, mobile_dir):
    """Combine `--mobile FILE [--mobile FILE...]` and `--mobile-dir DIR`
    into a single ordered, de-duplicated list of file paths.

    The walker:
      * sorts the directory listing so per-run output is stable
      * keeps only files with one of `_MOBILE_DIR_EXTS` (case-
        insensitive) so non-archive files (READMEs, .DS_Store, etc.)
        are silently ignored
      * does not recurse (operators often have a top-level `apks/`
        directory; nested dirs may contain unrelated artifacts and
        would be surprising to slurp)
      * de-duplicates while preserving first-seen order so a
        `--mobile X --mobile-dir <dir-containing-X>` invocation does
        not extract X twice.
    """
    seen = set()
    out = []
    for path in (mobile_files or []):
        if not path:
            continue
        canonical = os.path.abspath(path)
        if canonical in seen:
            continue
        seen.add(canonical)
        out.append(path)
    if mobile_dir:
        if not os.path.isdir(mobile_dir):
            print("[!] --mobile-dir %s is not a directory; skipping."
                  % mobile_dir)
        else:
            for name in sorted(os.listdir(mobile_dir)):
                if not any(name.lower().endswith(ext)
                           for ext in _MOBILE_DIR_EXTS):
                    continue
                full = os.path.join(mobile_dir, name)
                if not os.path.isfile(full):
                    continue
                canonical = os.path.abspath(full)
                if canonical in seen:
                    continue
                seen.add(canonical)
                out.append(full)
    return out


def _run_mobile_batch(paths, verbose=False, quiet=False,
                      debug_mobile_extract=False):
    """Extract keys from each archive while preserving per-archive configs and restrictions."""
    all_keys = set()
    merged_sources = {}
    key_configs = {}
    if not paths:
        return all_keys, merged_sources, key_configs
    if not quiet:
        print("[*] Mobile batch: %d archive(s) to process" % len(paths))
    for idx, path in enumerate(paths, 1):
        if not quiet:
            print("\n[*] Mobile batch %d/%d: %s" % (idx, len(paths), path))
        archive_configs = []
        try:
            keys, sources = discover_keys_from_mobile(
                path, verbose=verbose, quiet=quiet,
                debug_mobile_extract=debug_mobile_extract,
                config_sink=archive_configs)
        except Exception as exc:
            _record_discovery_issue("archive_errors")
            print("    [!] Mobile extract failed for %s: %s — skipping."
                  % (path, type(exc).__name__))
            continue

        for k in (keys or set()):
            _sel = _select_configs_for_key(k, archive_configs)
            if _sel:
                key_configs.setdefault(k, []).extend(_sel)

        per_key_labels = {}
        try:
            per_key_labels = _build_mobile_restriction_labels(
                path, keys or set(), quiet=quiet)
        except Exception as exc:
            print("    [!] Restriction extraction failed for %s: %s "
                  "— continuing without per-key restriction labels."
                  % (path, type(exc).__name__))
        if not quiet:
            print("    [*] %d key(s) extracted from %s"
                  % (len(keys or set()), os.path.basename(path)))
        all_keys |= (keys or set())
        if isinstance(sources, dict):
            for k, srcs in sources.items():
                if not isinstance(srcs, (set, list, tuple)):
                    continue
                merged_sources.setdefault(k, set()).update(srcs)
        for k in (keys or set()):
            label = per_key_labels.get(k)
            if label:
                merged_sources.setdefault(k, set()).add(label)

            merged_sources.setdefault(k, set()).add(
                "archive:%s" % os.path.basename(path))
    if not quiet:
        print("\n[*] Mobile batch complete — %d unique key(s) across %d archive(s)"
              % (len(all_keys), len(paths)))
    return all_keys, merged_sources, key_configs


def discover_keys_from_mobile(path, verbose=False, quiet=False,
                              debug_mobile_extract=False, config_sink=None):
    """Extract keys and optional Firebase configs from a local mobile archive.

    config_sink receives configs from this archive. Normal output reports
    archive progress and discovered keys; detailed extraction output is optional."""
    import tempfile, zipfile
    _debug = verbose or debug_mobile_extract
    if not quiet:
        print("\n[*] Mobile extract: %s" % path)
    if not os.path.isfile(path):
        _record_discovery_issue("archive_errors")
        if not quiet:
            print("    [!] File not found.")
        return set(), {}
    try:
        size = os.path.getsize(path)
    except OSError:
        size = -1
    if not quiet:
        print("    Size: %.2f MB" % (size / (1024 * 1024)) if size >= 0 else "    Size: unknown")
    keys = set()
    sources = {}
    pat = re.compile(rb"AIza[0-9A-Za-z\-_]{35}")
    try:
        with zipfile.ZipFile(path) as zf:
            members = zf.namelist()
            # DEBUG-ONLY — internal archive-entry count. A real APK has
            # thousands of entries; this floods the log without being
            # operator-actionable. Gate behind verbose / --debug-mobile-extract.
            if not quiet and _debug:
                print("    Archive entries: %d" % len(members))
            for name in members:
                # Skip directories
                if name.endswith("/"):
                    continue
                try:
                    data = _read_mobile_member(zf, name)
                except (zipfile.BadZipFile, RuntimeError, KeyError):
                    _record_discovery_issue("archive_errors")
                    continue
                if not data:
                    continue
                # Some APKs nest JARs (e.g. classes2.jar inside, or embedded SDKs);
                # also recurse into them.
                if name.lower().endswith((".jar", ".aab", ".apk", ".ipa", ".zip")):
                    try:
                        import io
                        with zipfile.ZipFile(io.BytesIO(data)) as inner:
                            for iname in inner.namelist():
                                if iname.endswith("/"):
                                    continue
                                try:
                                    idata = _read_mobile_member(inner, iname)
                                except (zipfile.BadZipFile, RuntimeError, KeyError):
                                    _record_discovery_issue("archive_errors")
                                    continue
                                for m in pat.findall(idata):
                                    k = m.decode("ascii")
                                    keys.add(k)
                                    sources.setdefault(k, set()).add("%s!%s" % (name, iname))
                                    if verbose:
                                        print("    [+] %s in %s!%s" % (
                                            _redact_key_display(k), name, iname))
                    except zipfile.BadZipFile:
                        pass
                for m in pat.findall(data):
                    k = m.decode("ascii")
                    keys.add(k)
                    sources.setdefault(k, set()).add(name)
                    if verbose:
                        print("    [+] %s in %s" % (
                            _redact_key_display(k), name))
    except zipfile.BadZipFile:
        _record_discovery_issue("archive_errors")
        if not quiet:
            print("    [!] Not a valid ZIP / APK / IPA file.")
        return set(), {}

    try:
        fb_cfgs = _extract_firebase_configs_from_archive(path, quiet=quiet)
        for cfg in fb_cfgs:
            _record_firebase_config(cfg)

        if config_sink is not None:
            config_sink.extend(dict(c) for c in fb_cfgs if c)
        if fb_cfgs and not quiet:
            # OPERATOR-ACTIONABLE — a Firebase config was harvested (it
            # drives real DATABASE_URL / STORAGE_BUCKET targeting). The
            # internal cross-bundle store running total is DEBUG-ONLY.
            if _debug:
                with _DERIVED_FIREBASE_LOCK:
                    tot = len(_DERIVED_FIREBASE_CONFIGS)
                print("    Firebase configs recorded: %d (store now: %d)"
                      % (len(fb_cfgs), tot))
            else:
                print("    Firebase configs recorded: %d" % len(fb_cfgs))
    except Exception as e:
        if not quiet:
            print("    [!] Firebase config extraction error: %s" % e)
    if not quiet:
        if keys:
            print("    Found %d unique AIza key(s):" % len(keys))
            for k in sorted(keys):
                src = sorted(sources.get(k, set()))
                print("      - %s  (in %d file(s); e.g. %s)" % (
                    _redact_key_display(k), len(src), src[0]))
        else:
            print("    [!] No AIza keys found in archive.")
    return keys, sources


_HOSTNAME_RE = re.compile(r"^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$")
