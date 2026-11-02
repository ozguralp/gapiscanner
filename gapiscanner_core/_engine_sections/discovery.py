def _is_valid_hostname(s):
    """Validate a string is a plausible DNS hostname (used to filter out
    subfinder/crt.sh error messages that leak into stdout)."""
    return isinstance(s, str) and len(s) <= 253 and bool(_HOSTNAME_RE.fullmatch(s))

def _dns_enum_crtsh(apex, timeout=30, retries=2):
    """Query crt.sh for certificates issued to *.apex and return hostnames.
    crt.sh is notoriously flaky — they 502 frequently. We retry a couple of
    times with backoff, but accept that this source may simply fail today."""
    if not apex or "/" in apex:
        return set()
    url = "https://crt.sh/?q=" + "%25." + apex + "&output=json"
    headers = {"User-Agent": "gapiscanner/2.0 (passive recon)"}
    text = None
    for attempt in range(retries + 1):
        try:
            r = requests.get(url, headers=headers, **dict(_request_kwargs_for_url(url), timeout=timeout))
            if r.status_code == 200 and r.text and r.text.strip().startswith(("[", "{")):
                text = r.text
                break
        except requests.RequestException:
            pass
        if attempt < retries:
            import time as _t; _t.sleep(2 + attempt * 2)
    if not text:
        return set()
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return set()
    hosts = set()
    for entry in data if isinstance(data, list) else ():
        if not isinstance(entry, dict):
            continue
        name_value = entry.get("name_value", "")
        for line in name_value.split("\n") if isinstance(name_value, str) else ():
            line = line.strip().lower()
            if not line or line.startswith("*."):
                continue
            if not _is_valid_hostname(line):
                continue
            if line.endswith("." + apex.lower()) or line == apex.lower():
                hosts.add(line)
    return hosts

def _dns_enum_certspotter(apex, timeout=30):
    """CertSpotter free CT-log API — fallback when crt.sh is down."""
    if not apex or "/" in apex:
        return set()
    url = ("https://api.certspotter.com/v1/issuances?domain=" + apex
           + "&include_subdomains=true&expand=dns_names")
    headers = {"User-Agent": "gapiscanner/2.0 (passive recon)"}
    try:
        r = requests.get(url, headers=headers, **dict(_request_kwargs_for_url(url), timeout=timeout))
    except requests.RequestException:
        return set()
    if r.status_code != 200:
        return set()
    try:
        data = r.json()
    except (json.JSONDecodeError, ValueError):
        return set()
    hosts = set()
    for entry in data if isinstance(data, list) else ():
        if not isinstance(entry, dict):
            continue
        names = entry.get("dns_names")
        for n in names if isinstance(names, list) else ():
            if not isinstance(n, str):
                continue
            n = n.strip().lower()
            if not n or n.startswith("*."):
                continue
            if not _is_valid_hostname(n):
                continue
            if n.endswith("." + apex.lower()) or n == apex.lower():
                hosts.add(n)
    return hosts

def _dns_enum_subfinder(apex, timeout=120):
    """Shell out to subfinder. Passive sources are the default in v2.6+, so
    we don't pass `-passive`; explicit `-active` is the opt-in (not used here)."""
    if not _which("subfinder"):
        return set()
    cmd = [_which("subfinder"), "-d", apex, "-silent", "-nc"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {ln.strip().lower() for ln in proc.stdout.splitlines()
                if ln.strip() and _is_valid_hostname(ln.strip().lower())}
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return set()


# Known SaaS providers — if a host's CNAME chain hits an apex here, the host
# is treated as third-party-owned and dropped from the seed list.
_KNOWN_SAAS_DOMAINS = {
    # Support / ticketing
    'zendesk.com', 'freshdesk.com', 'intercom.io', 'helpscout.net',
    'kayako.com', 'desk.com', 'gorgias.com', 'frontapp.com',
    # ATS / careers
    'lever.co', 'greenhouse.io', 'workday.com', 'workdayjobs.com',
    'smartrecruiters.com', 'icims.com', 'jobvite.com', 'taleo.net',
    'breezy.hr', 'recruitee.com', 'workable.com', 'ashbyhq.com',
    # CRM / marketing
    'hubspot.com', 'pardot.com', 'marketo.com', 'salesforce.com',
    'force.com', 'mktoapi.com', 'mktoresp.com',
    'sfmc-marketing.com', 'sfmc-content.com',  # Salesforce Marketing Cloud
    'siteforce.com',                            # Salesforce community sites
    # BPM / workflow SaaS
    'pega.net', 'pegacloud.net',                # Pega Systems
    # Survey / feedback
    'qualtrics.com', 'surveymonkey.com', 'typeform.com', 'medallia.com',
    'feedbackify.com', 'usabilla.com',
    # Trust / compliance portals
    'safebase.io',
    # Issue tracker / service desk
    'atlassian.com',                            # JIRA Service Desk, Confluence
    'shopify.com', 'webflow.com', 'wixsite.com',
    'squarespace.com', 'duda.co',
    # Status / monitoring
    'statuspage.io', 'status.io', 'instatus.com',
    'stspg-customer.com',                       # Atlassian Statuspage custom domain
    # Docs / knowledge base
    'gitbook.io', 'gitbook.com', 'readme.io', 'document360.io',
    'helpdocs.io', 'helpscoutdocs.com', 'mintlify.com',
    # Live chat
    'drift.com', 'snapengage.com', 'tawk.to', 'livechatinc.com',
    'olark.com', 'crisp.chat',
    # Mail / transactional
    'mailgun.org', 'sendgrid.net', 'mandrillapp.com', 'sparkpostmail.com',
    'postmarkapp.com', 'amazonses.com',
    # Custom domain SaaS
    'frontify.com', 'unbounce.com', 'instapage.com', 'leadpages.net',
    'mailchimp.com', 'list-manage.com', 'campaign-archive.com',
    # Forums / community
    'discourse.org', 'discourse.cloud', 'vanillaforums.com',
    # Event platforms
    'eventbrite.com', 'hopin.com', 'on24.com',
    # Identity (often hosted)
    'okta.com', 'oktapreview.com',              # Okta prod + preview tenants
    'auth0.com', 'auth0app.com', 'auth0edge.com',  # Auth0 prod + edge infra
    'onelogin.com', 'pingidentity.cloud',
    # Email security gateways
    'pphosted.com',                             # Proofpoint
    # Hosted dev / pages
    'gitlab.io', 'pages.dev', 'glitch.me', 'replit.app',
    # Hosted billing / payments
    'stripe.com', 'paddle.com', 'recurly.com', 'chargebee.com',
    # Analytics / tag managers (less common as CNAME targets but listed for completeness)
    'segment.io',
    # Hosted observability / dashboards
    'grafana.net',                              # Grafana Cloud
    # Hosted API docs
    'redocly.app', 'redocly.com',               # Redoc / Redocly hosted docs
    # Fraud detection / risk scoring SaaS (often used as 3rd-party JS include)
    'online-metrix.net',                        # ThreatMetrix (LexisNexis)
    # Digital agency / microsite hosting
    'onenorth.com',                             # One North (Chicago digital agency)
    # MDM / device management
    'jamfcloud.com',                            # Jamf Cloud
    # Privileged access management
    'beyondtrustcloud.com',                     # BeyondTrust
    # Email infra (management portal — mail data plane is sparkpostmail.com above)
    'sparkpost.com',
    # Microsoft Azure portal — CNAME-target hosts are non-actionable for us
    'azure.com',
    # Video hosting SaaS for businesses
    'vimeoshowcase.com',
    # Sales engagement SaaS
    'outreach.io',
    # Newsroom / press release SaaS
    'presspage.com',
    # Domain registrars / parking (CNAMEs ending up here usually mean the
    # subdomain isn't really used by the target)
    'parkingcrew.net', 'sedoparking.com',
}

# CDN / cloud infra — CNAME targets here are NOT third-party owners. These
# are infrastructure providers the TARGET itself uses. Listed here so the
# discovery report can correctly classify them as "kept, not 3rd-party".
_KNOWN_CDN_DOMAINS = {
    # CDNs
    'akamai.net', 'akamaiedge.net', 'akamaized.net', 'akamaitechnologies.com',
    'cloudfront.net', 'cloudfront.com',
    'fastly.net', 'fastlylb.net',
    'cloudflare.com', 'cloudflare.net', 'cdn.cloudflare.net',
    'edgekey.net', 'edgesuite.net',
    'azureedge.net', 'azurefd.net', 'tm-azurefd.net', 'trafficmanager.net',
    'cdn77.com', 'cdn77.org',
    'bunnycdn.com', 'b-cdn.net',
    'jsdelivr.net', 'unpkg.com',
    'kxcdn.com', 'maxcdn.com',
    # AWS / GCP / Azure infra
    'amazonaws.com', 'elb.amazonaws.com', 'awsglobalaccelerator.com',
    'googleusercontent.com', 'storage.googleapis.com', 'appspot.com',
    'azurewebsites.net', 'azure-api.net',
    # Other infra (NOT SaaS, just hosting/proxy layer)
    'github.io', 'githubusercontent.com',  # pages, raw — could be either, but neutral
    'herokuapp.com', 'herokudns.com',
    'netlify.app', 'netlifyglobalcdn.com',
    'vercel.app', 'now.sh', 'vercel.com', 'vercel-dns.com',
}


def _apex_of(host):
    """Crude registrable-domain extraction: last 2 labels. Good enough for
    matching against KNOWN_SAAS_DOMAINS / KNOWN_CDN_DOMAINS — both are
    apex-form sets. Fails on real .co.uk-style TLDs but those aren't in
    either set, so misclassification just means we keep the host (safer
    default than dropping it)."""
    parts = host.lower().rstrip('.').split('.')
    if len(parts) <= 2:
        return host.lower().rstrip('.')
    return '.'.join(parts[-2:])


def _resolve_cname_chain(host, max_hops=10, timeout=3.0):
    """Return the CNAME chain, using dnspython when available."""
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout
        resolver.timeout = timeout
        chain = [host.lower()]
        current = host
        for _ in range(max_hops):
            try:
                answers = resolver.resolve(current, 'CNAME', raise_on_no_answer=False)
                if not answers.rrset:
                    break
                target = str(answers[0].target).rstrip('.').lower()
                if target in chain:
                    break  # loop guard
                chain.append(target)
                current = target
            except Exception:
                break
        return chain
    except ImportError:
        pass
    try:
        import socket
        _, aliases, _ = socket.gethostbyname_ex(host)
        return [host.lower()] + [a.lower() for a in aliases]
    except Exception:
        return [host.lower()]


def _classify_third_party(host_chains, verbose=False, quiet=False):
    """Given a {host: cname_chain} dict, partition the hosts into:
      - kept_hosts   : ownership looks fine (same-domain, CDN, or unresolvable)
      - dropped_hosts: chain hits a KNOWN_SAAS apex → third-party owned
      - unknown_apex_counts: external apex domains we don't recognize at all
        (caller should review — these may be SaaS we haven't catalogued)
    """
    from collections import Counter
    kept, dropped = [], []
    cdn_apex = Counter()
    saas_apex = Counter()
    unknown_apex = Counter()
    same_apex = Counter()

    for host, chain in host_chains.items():
        if len(chain) <= 1:
            kept.append(host)
            continue
        host_apex = _apex_of(host)
        hit_saas = None
        for target in chain[1:]:
            tgt_apex = _apex_of(target)
            if tgt_apex == host_apex:
                same_apex[tgt_apex] += 1
            elif tgt_apex in _KNOWN_SAAS_DOMAINS:
                saas_apex[tgt_apex] += 1
                hit_saas = (target, tgt_apex)
                break  # one SaaS hit is enough to drop
            elif tgt_apex in _KNOWN_CDN_DOMAINS:
                cdn_apex[tgt_apex] += 1
            else:
                unknown_apex[tgt_apex] += 1
        if hit_saas:
            dropped.append((host, hit_saas[0], hit_saas[1]))
        else:
            kept.append(host)

    if not quiet:
        print("    CNAME discovery report:")
        print("      same-domain hops: %d (kept)" % sum(same_apex.values()))
        print("      CDN/infra hops:   %d (kept) — top: %s"
              % (sum(cdn_apex.values()),
                 ', '.join('%s×%d' % (k, v) for k, v in cdn_apex.most_common(5))))
        print("      Known SaaS hops:  %d (DROPPED) — top: %s"
              % (sum(saas_apex.values()),
                 ', '.join('%s×%d' % (k, v) for k, v in saas_apex.most_common(5))))
        if unknown_apex:
            print("      Unknown apex (KEPT, review!): %d hops — top: %s"
                  % (sum(unknown_apex.values()),
                     ', '.join('%s×%d' % (k, v) for k, v in unknown_apex.most_common(10))))
            print("      Review unknown destinations against the authorized scope before continuing.")
        if dropped and verbose:
            for h, target, saas in dropped[:30]:
                print("      [3rd-party] %s → %s (%s)" % (h, target, saas))
    return kept, dropped, unknown_apex


def _exclude_third_party_owned(hosts, verbose=False, quiet=False, threads=20):
    """Run CNAME-based 3rd-party filter on `hosts`. Returns (kept, dropped).
    Only the kept list should be added to the seed URL set.

    Wrapped in a graceful-skip: any error → log + return hosts unchanged
    (no filtering). This is opt-in via --exclude-3rd-party, so we'd rather
    err on the side of scanning too much than on dropping legitimate
    targets due to a DNS infrastructure failure."""
    if not hosts:
        return [], []
    if not quiet:
        print("[*] Resolving CNAMEs for 3rd-party check (%d host, %d threads)..."
              % (len(hosts), threads))
    chains = {}
    try:
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = {ex.submit(_resolve_cname_chain, h): h for h in hosts}
            for fut in as_completed(futures):
                h = futures[fut]
                try:
                    chains[h] = fut.result()
                except Exception:
                    chains[h] = [h.lower()]
    except Exception as e:
        if not quiet:
            print("    [!] CNAME resolution batch failed (%s) — keeping all hosts" % e)
        return list(hosts), []
    kept, dropped, _unknown = _classify_third_party(chains, verbose=verbose, quiet=quiet)
    if not quiet:
        print("    3rd-party filter: %d hosts → %d kept, %d dropped"
              % (len(hosts), len(kept), len(dropped)))
    return kept, dropped


def _dns_enum_hackertarget(apex, timeout=15):
    """HackerTarget hostsearch passive DNS endpoint."""
    if not apex or "/" in apex:
        return set()
    url = "https://api.hackertarget.com/hostsearch/?q=" + apex
    headers = {"User-Agent": "gapiscanner/2.0 (passive recon)"}
    try:
        r = requests.get(url, headers=headers, **dict(_request_kwargs_for_url(url), timeout=timeout))
    except requests.RequestException:
        return set()
    if r.status_code != 200 or not r.text:
        return set()
    hosts = set()
    for line in r.text.splitlines():
        host = line.split(",", 1)[0].strip().lower()
        if _is_valid_hostname(host) and (
                host == apex.lower() or host.endswith("." + apex.lower())):
            hosts.add(host)
    return hosts

def _dns_enum_rapiddns(apex, timeout=15):
    """RapidDNS HTML scrape fallback; passive and unauthenticated."""
    if not apex or "/" in apex:
        return set()
    url = "https://rapiddns.io/subdomain/%s?full=1" % apex
    headers = {"User-Agent": "gapiscanner/2.0 (passive recon)"}
    try:
        r = requests.get(url, headers=headers, **dict(_request_kwargs_for_url(url), timeout=timeout))
    except requests.RequestException:
        return set()
    if r.status_code != 200 or not r.text:
        return set()
    pattern = re.compile(r"([A-Za-z0-9_.-]+\." + re.escape(apex) + r")", re.I)
    return {
        h.strip(".").lower()
        for h in pattern.findall(r.text)
        if _is_valid_hostname(h.strip(".").lower())
    }

def _dns_enum_wayback(apex, timeout=20):
    """Wayback CDX URLs → hostnames. Passive historical crawl data."""
    if not apex or "/" in apex:
        return set()
    url = (
        "https://web.archive.org/cdx?url=*."
        + apex
        + "/*&output=json&fl=original&collapse=urlkey"
    )
    headers = {"User-Agent": "gapiscanner/2.0 (passive recon)"}
    try:
        r = requests.get(url, headers=headers, **dict(_request_kwargs_for_url(url), timeout=timeout))
    except requests.RequestException:
        return set()
    if r.status_code != 200 or not r.text:
        return set()
    try:
        data = r.json()
    except ValueError:
        return set()
    hosts = set()
    from urllib.parse import urlparse
    for row in data[1:] if isinstance(data, list) else ():
        raw = row[0] if isinstance(row, list) and row else None
        if not raw:
            continue
        try:
            host = urlparse(raw).netloc.lower().split(":", 1)[0]
        except Exception:
            continue
        if _is_valid_hostname(host) and (
                host == apex.lower() or host.endswith("." + apex.lower())):
            hosts.add(host)
    return hosts

def _dns_enum_otx(apex, timeout=15):
    """AlienVault OTX passive_dns endpoint."""
    if not apex or "/" in apex:
        return set()
    url = "https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns" % apex
    headers = {"User-Agent": "gapiscanner/2.0 (passive recon)"}
    try:
        r = requests.get(url, headers=headers, **dict(_request_kwargs_for_url(url), timeout=timeout))
    except requests.RequestException:
        return set()
    if r.status_code != 200:
        return set()
    try:
        data = r.json()
    except ValueError:
        return set()
    hosts = set()
    rows = data.get("passive_dns") if isinstance(data, dict) else None
    for entry in rows if isinstance(rows, list) else ():
        if not isinstance(entry, dict) or not isinstance(entry.get("hostname"), str):
            continue
        host = entry["hostname"].strip().lower()
        if _is_valid_hostname(host) and (
                host == apex.lower() or host.endswith("." + apex.lower())):
            hosts.add(host)
    return hosts


def dns_enum(apex, verbose=False, quiet=False):
    """Public entrypoint: passive subdomain enumeration for `apex`.

    Uses the bundled passive-source clients and optional subfinder.
    Returns a sorted list of deduplicated hostnames."""
    if not quiet:
        print("[*] DNS enum (passive) for apex: %s" % apex)

    # The same bundled clients run in source and installed environments.
    sub = _dns_enum_subfinder(apex)
    if not quiet:
        if _which("subfinder"):
            print("    subfinder: %d host(s)" % len(sub))
        else:
            print("    subfinder: not installed (skipped; install for ~40-source aggregation)")

    crt = _dns_enum_crtsh(apex)
    if not quiet:
        if crt:
            print("    crt.sh: %d host(s)" % len(crt))
        else:
            print("    crt.sh: 0 host(s) (service may be 502; trying CertSpotter fallback)")

    cs = set()
    if not crt:
        # crt.sh empty → try CertSpotter as CT-log fallback. Only when crt.sh
        # actually failed (not when it just returned a small legitimate set).
        cs = _dns_enum_certspotter(apex)
        if not quiet:
            print("    certspotter: %d host(s)" % len(cs))

    ht = _dns_enum_hackertarget(apex)
    if not quiet:
        print("    hackertarget: %d host(s)" % len(ht))

    rd = _dns_enum_rapiddns(apex)
    if not quiet:
        print("    rapiddns: %d host(s)" % len(rd))

    wb = _dns_enum_wayback(apex)
    if not quiet:
        print("    wayback: %d host(s)" % len(wb))

    otx = _dns_enum_otx(apex)
    if not quiet:
        print("    otx: %d host(s)" % len(otx))

    merged = sorted(crt | sub | cs | ht | rd | wb | otx)
    if not quiet:
        print("    merged unique: %d host(s)" % len(merged))
        if verbose:
            for h in merged[:20]:
                print("      - %s" % h)
            if len(merged) > 20:
                print("      ... (%d more)" % (len(merged) - 20))
    return merged


def _same_site(url, base_host):
    """True iff `url` is on the same registrable host as base_host (or a
    direct subdomain). Used to drop cross-origin hyperlinks like wikipedia.org,
    github.com references that crawlers happily follow but never contain the
    target's embedded keys."""
    from urllib.parse import urlparse
    try:
        h = urlparse(url).netloc.lower()
    except Exception:
        return False
    if not h:
        return False
    b = base_host.lower()
    h_bare = h[4:] if h.startswith("www.") else h
    b_bare = b[4:] if b.startswith("www.") else b
    return h_bare == b_bare or h_bare.endswith("." + b_bare)


def _kill_proc_tree(pid, include_parent=True):
    """Stop a child process tree using psutil or the platform process utility."""
    try:
        import psutil
    except ImportError:
        psutil = None
    if psutil is not None:
        try:
            parent = psutil.Process(pid)
            children = parent.children(recursive=True)
            for c in children:
                try:
                    c.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            if include_parent:
                try:
                    parent.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            psutil.wait_procs(children + ([parent] if include_parent else []), timeout=3)
            return
        except psutil.NoSuchProcess:
            return
        except Exception:
            pass  # fall through to POSIX
    if os.name == "nt" and include_parent:
        try:
            subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            pass
    if os.name == "posix":
        import signal
        try:
            os.killpg(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            pass


def _crawl_with_katana(target_url, depth=2, timeout=90, same_site_only=True, headless=True):
    """Collect URLs with Katana and stop its process tree on timeout.

    Headless mode enables JavaScript discovery. Missing executables return an
    empty set so other crawl tiers can continue."""
    from urllib.parse import urlparse
    base_host = urlparse(target_url).netloc.lower()
    cmd = [_which("katana") or "katana",
           "-u", target_url,
           "-jc",
           "-d", str(depth),
           "-silent", "-nc",
           "-timeout", "10"]
    if headless:
        cmd.append("-headless")
    # start_new_session is POSIX-only; Python silently ignores it on Windows.
    # No need to gate it — `subprocess.Popen` handles platform diffs internally.
    popen_kwargs = {"stdout": subprocess.PIPE, "stderr": subprocess.PIPE,
                    "text": True}
    if os.name == "posix":
        popen_kwargs["start_new_session"] = True
    try:
        proc = subprocess.Popen(cmd, **popen_kwargs)
    except (FileNotFoundError, OSError):
        return set()
    try:
        stdout, _ = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_proc_tree(proc.pid)
        try:
            proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        return set()
    except KeyboardInterrupt:
        _kill_proc_tree(proc.pid)
        raise
    urls = set()
    for ln in (stdout or "").splitlines():
        ln = ln.strip()
        if not ln or not ln.startswith(("http://", "https://")):
            continue
        if same_site_only and not _same_site(ln, base_host):
            continue
        urls.add(ln)
    return urls


_PLAYWRIGHT_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/126.0.0.0 Safari/537.36"
)


def _crawl_with_playwright(target_url, timeout=20, max_urls=400):
    """Render `target_url` in headless Chromium via Playwright, capture every
    HTTP request the page makes (HTML, JS, XHR, fetch, images, fonts), and
    return them as a set.

    This is the highest-coverage tier of the crawl pipeline. Katana misses
    many SPA sites due to bot-detection or fingerprint differences; the
    regex-based Python crawler misses everything loaded by JavaScript. Real
    Chromium catches what both miss — at the cost of ~10-20s per seed.

    Gracefully returns an empty set if Playwright is not installed (the tool
    must still work in environments where the heavy browser dep was skipped,
    e.g., environments with minimal optional dependencies)."""
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    except ImportError:
        return set()
    urls = set()

    def _record(req):
        u = req.url
        if u.startswith(("http://", "https://")) and len(u) < 500:
            urls.add(u)

    try:
        with sync_playwright() as p:
            try:
                browser = p.chromium.launch(headless=True)
            except Exception:
                return set()
            try:
                ctx = browser.new_context(user_agent=_PLAYWRIGHT_UA,
                                          ignore_https_errors=True)
                page = ctx.new_page()
                page.on("request", _record)
                try:
                    page.goto(target_url, wait_until="networkidle",
                              timeout=timeout * 1000)
                except PWTimeout:
                    pass  # partial results still useful
                except Exception:
                    pass
            finally:
                try:
                    browser.close()
                except Exception:
                    pass
    except Exception:
        return urls  # whatever we captured before the crash
    if len(urls) > max_urls:
        # Cap for runaway sites (analytics-heavy pages can fire 1000+ requests).
        # We still return all of them — the AIza-key extractor has its own cap.
        pass
    return urls

def _get_crawl_response(url, timeout=None):
    """Follow public GET redirects without sending local credentials.

    Each hop gets explicit authentication policy and destination-specific TLS
    settings. Cookies retain their normal domain/path restrictions.
    """
    from urllib.parse import urljoin

    cookies = requests.cookies.RequestsCookieJar()
    history = []
    for hop in range(31):
        kwargs = _request_kwargs_for_url(url, target_crawl=True)
        kwargs["allow_redirects"] = False
        if timeout is not None:
            kwargs["timeout"] = timeout
        if cookies:
            kwargs["cookies"] = cookies
        try:
            response = requests.get(url, **kwargs)
        except ValueError as exc:
            raise requests.exceptions.InvalidURL("Invalid crawl URL or redirect") from exc
        location = response.headers.get("Location")
        if (response.status_code not in (301, 302, 303, 307, 308)
                or not isinstance(location, str) or not location):
            response.history = history
            return response
        if isinstance(getattr(response, "cookies", None), requests.cookies.RequestsCookieJar):
            cookies.update(response.cookies)
        try:
            next_url = urljoin(getattr(response, "url", None) or url, location)
        except ValueError as exc:
            response.close()
            raise requests.exceptions.InvalidURL("Invalid crawl redirect destination") from exc
        history.append(response)
        response.close()
        if hop == 30:
            raise requests.TooManyRedirects("Exceeded 30 crawl redirects", response=response)
        try:
            parsed = urlparse(next_url)
            valid = parsed.scheme in ("http", "https") and bool(parsed.hostname)
            _ = parsed.port
        except ValueError:
            valid = False
        if not valid:
            raise requests.exceptions.InvalidURL("Invalid crawl redirect destination")
        url = next_url


def _crawl_with_python(target_url, max_pages=30, timeout=10):
    """Minimal BFS crawler: same-origin links + inline <script src>.
    Does NOT execute JS. Caps at `max_pages` to avoid runaway recursion."""
    from urllib.parse import urlparse, urljoin
    base = urlparse(target_url)
    base_host = base.netloc
    seen = set()
    queue = [target_url]
    found_urls = set()
    a_re = re.compile(r'<a[^>]+href=["\']([^"\']+)["\']', re.I)
    script_re = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)

    def _safe_urljoin(base_url, raw_url):
        try:
            return urljoin(base_url, raw_url)
        except ValueError:
            return None

    while queue and len(seen) < max_pages:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        found_urls.add(url)
        try:
            r = _get_crawl_response(url, timeout=timeout)
        except requests.RequestException:
            continue
        if not r.text:
            continue
        source_url = getattr(r, "url", None) or url
        found_urls.add(source_url)
        # Collect inline + external script srcs (always followed regardless of host)
        for m in script_re.findall(r.text):
            absu = _safe_urljoin(source_url, m)
            if not absu:
                continue
            found_urls.add(absu)
            if absu not in seen:
                queue.append(absu)
        # Same-origin <a href> links only (avoid crawling all of the internet)
        for m in a_re.findall(r.text):
            absu = _safe_urljoin(source_url, m)
            if not absu:
                continue
            try:
                abs_host = urlparse(absu).netloc
            except ValueError:
                continue
            if abs_host == base_host and absu not in seen:
                queue.append(absu)
    return found_urls

def _fetch_and_extract_keys(urls, verbose=False, max_urls=None, threads=10,
                            cache_dir=None, seed_url=None,
                            queue_state_path=None, resume=None):
    """Fetch crawled text URLs and extract AIza keys.

    Every candidate is fetched by default. ``max_urls`` is an explicit budget
    only; ordering and the pending remainder come from the public shared core.
    Cached bodies are replayed on resume so an interrupted seed cannot lose a
    key that was fetched before its scan callback ran.
    """
    budget = _URL_FETCH_BUDGET if max_urls is None else max_urls
    resume = _URL_FETCH_RESUME if resume is None else bool(resume)
    if queue_state_path is None:
        queue_state_path = _URL_FETCH_QUEUE_STATE
    if queue_state_path is None and cache_dir:
        queue_seed = seed_url or "\n".join(sorted(str(u) for u in urls))
        queue_name = hashlib.sha256(queue_seed.encode("utf-8")).hexdigest()[:16]
        queue_state_path = os.path.join(cache_dir, "url_queues", queue_name + ".json")

    # A queue alone cannot replay extracted keys. Public --url-fetch-state
    # therefore owns an adjacent response cache, also used by pipx installs.
    if queue_state_path and not cache_dir:
        cache_dir = os.fspath(queue_state_path) + ".cache"

    # Retain pending URLs even if the site's current crawl no longer emits
    # them. A state file belongs to one seed and must not mix target queues.
    urls = set(urls)
    if resume and queue_state_path and os.path.isfile(queue_state_path):
        with open(queue_state_path, "r", encoding="utf-8") as fh:
            saved = json.load(fh)
        if not isinstance(saved, dict) or saved.get("seed_url") != seed_url:
            raise ValueError("URL state belongs to a different seed; use a separate state file")
        for field in ("completed", "pending"):
            rows = saved.get(field) or []
            if not isinstance(rows, list) or any(not isinstance(row, str) for row in rows):
                raise ValueError("Invalid URL state %s list" % field)
            urls.update(rows)

    manifest_path = os.path.join(cache_dir, "manifest.csv") if cache_dir else None
    source_map_path = os.path.join(cache_dir, "sources.json") if cache_dir else None
    source_map = {}
    if source_map_path and os.path.isfile(source_map_path):
        try:
            with open(source_map_path, encoding="utf-8") as fh:
                source_map = json.load(fh)
            if not isinstance(source_map, dict):
                source_map = {}
        except (OSError, ValueError):
            source_map = {}
    completed_urls = set()
    replay_bodies = {}
    if resume and manifest_path:
        # A recorded success with a lost/corrupt body must be fetched again.
        try:
            with open(manifest_path, "r", encoding="utf-8", newline="") as fh:
                for row in csv.DictReader(fh):
                    url, digest = row.get("url"), row.get("sha256", "")
                    status = str(row.get("status", ""))
                    source = source_map.get(url)
                    if (not isinstance(source, dict) or source.get("sha256") != digest
                            or not isinstance(source.get("url"), str)
                            or not source["url"].startswith(("http://", "https://"))
                            or url not in urls or not status.isdigit() or int(status) >= 400
                            or not re.fullmatch(r"[a-f0-9]{64}", digest)):
                        continue
                    body_path = os.path.join(cache_dir, "bodies", digest + ".bin")
                    try:
                        with open(body_path, "rb") as body_fh:
                            cached = body_fh.read()
                    except OSError:
                        continue
                    if hashlib.sha256(cached).hexdigest() != digest:
                        continue
                    replay_bodies[url] = body_path
                    completed_urls.add(url)
        except (OSError, csv.Error):
            pass
    plan = build_url_fetch_plan(
        urls, seed_url=seed_url, budget=budget, completed_urls=completed_urls,
    )
    text_urls = list(plan.selected)
    if plan.pending:
        _record_discovery_issue("pending_urls", len(plan.pending))
    if verbose or plan.pending:
        budget_label = "all" if plan.budget is None else str(plan.budget)
        print("    [fetch-plan] candidates=%d completed=%d selected=%d pending=%d "
              "binary=%d budget=%s"
              % (plan.candidate_count, len(plan.completed), len(plan.selected),
                 len(plan.pending), len(plan.skipped_binary), budget_label))
        if plan.pending and not queue_state_path:
            print("    [!] Explicit URL budget left %d candidate(s) pending; "
                  "set --url-fetch-state FILE to persist the queue."
                  % len(plan.pending))

    keys = set()
    sources = {}
    lock = Lock()
    successful_urls = set()
    manifest_writer = None
    manifest_fh = None
    bodies_dir = None
    if cache_dir:
        os.makedirs(cache_dir, exist_ok=True)
        bodies_dir = os.path.join(cache_dir, "bodies")
        os.makedirs(bodies_dir, exist_ok=True)
        write_header = not os.path.exists(manifest_path)
        manifest_fh = open(manifest_path, "a", encoding="utf-8", newline="", buffering=1)
        manifest_writer = csv.writer(manifest_fh)
        if write_header:
            manifest_writer.writerow(["url", "sha256", "content_type",
                                     "status", "size", "timestamp"])

    def _extract_body(body, url):
        if not body:
            return
        try:
            for cfg in _extract_firebase_configs_from_js(body, source=url):
                _record_firebase_config(cfg)
                if verbose and cfg.get("project_id"):
                    print("    [fb-cfg] project=%s in %s"
                          % (cfg.get("project_id"), _redact_diagnostic_secret_text(url)))
        except Exception:
            pass
        local_keys = _AIZA_KEY_RE.findall(body)
        if not local_keys:
            return
        with lock:
            for key in local_keys:
                keys.add(key)
                sources.setdefault(key, set()).add(url)
                if verbose:
                    print("    [+] %s in %s" % (
                        _redact_key_display(key), _redact_diagnostic_secret_text(url)))

    def _replay_completed_cache():
        for url, body_path in replay_bodies.items():
            try:
                with open(body_path, "rb") as body_fh:
                    body = body_fh.read().decode("utf-8", errors="replace")
            except OSError:
                _record_discovery_issue("cache_errors")
                continue
            _extract_body(body, source_map[url]["url"])

    def _fetch_one(url):
        try:
            response = _get_crawl_response(url)
        except requests.RequestException as exn:
            _record_discovery_issue("fetch_failures")
            if cache_dir:
                ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
                with lock:
                    manifest_writer.writerow([
                        url, "", "", "ERR:%s" % type(exn).__name__, 0, ts,
                    ])
            return
        if response.status_code >= 400:
            _record_discovery_issue("http_errors")
        body = response.text or ""
        source_url = getattr(response, "url", None) or url
        with lock:
            if response.status_code < 400:
                successful_urls.add(url)
        if cache_dir:
            body_bytes = body.encode("utf-8", errors="replace") if body else b""
            digest = hashlib.sha256(body_bytes).hexdigest()
            ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
            with lock:
                if not os.path.exists(os.path.join(bodies_dir, digest + ".bin")):
                    with open(os.path.join(bodies_dir, digest + ".bin"), "wb") as body_fh:
                        body_fh.write(body_bytes)
                source_map[url] = {"url": source_url, "sha256": digest}
                manifest_writer.writerow([
                    url, digest, response.headers.get("Content-Type", ""),
                    response.status_code, len(body_bytes), ts,
                ])
        _extract_body(body, source_url)

    _replay_completed_cache()
    try:
        with ThreadPoolExecutor(max_workers=threads) as executor:
            list(executor.map(_fetch_one, text_urls))
    finally:
        if manifest_fh:
            manifest_fh.close()
            temp_sources = source_map_path + ".tmp"
            with open(temp_sources, "w", encoding="utf-8") as fh:
                json.dump(source_map, fh, sort_keys=True)
            os.replace(temp_sources, source_map_path)
        if queue_state_path:
            completed_after = completed_urls | successful_urls
            remaining = build_url_fetch_plan(
                urls, seed_url=seed_url, budget=0,
                completed_urls=completed_after,
            )
            final_plan = URLFetchPlan(
                selected=(), pending=remaining.selected,
                skipped_binary=remaining.skipped_binary,
                completed=tuple(sorted(completed_after)),
                candidate_count=remaining.candidate_count,
                budget=plan.budget,
            )
            write_url_queue_state(
                queue_state_path, final_plan, seed_url=seed_url,
            )
    return keys, sources


def _compile_scope(scope_json):
    """Parse a scope.json file. Returns (seeds, include_matchers,
    exclude_matchers). Seeds are concrete URLs to start crawling; matchers
    are callables (host, path) -> bool used by the crawler to decide
    whether a discovered URL is in/out of scope."""
    data = scope_json.get("target", {}).get("scope", {})
    inc_rules = [r for r in data.get("include", []) if r.get("enabled", True)]
    exc_rules = [r for r in data.get("exclude", []) if r.get("enabled", True)]

    def _compile(rules):
        out = []
        for r in rules:
            host_re = re.compile(r.get("host") or "")
            file_re = re.compile(r.get("file") or "^/.*$")
            proto   = (r.get("protocol") or "any").lower()
            out.append((host_re, file_re, proto))
        return out

    include = _compile(inc_rules)
    exclude = _compile(exc_rules)

    seeds = set()
    wildcard_rules = []  # list of (apex, host_re, file_re, proto)
    for host_re, file_re, proto in include:
        pat = host_re.pattern.strip("^$").replace("\\.", ".").replace("\\\\.", ".")
        is_concrete = "." in pat and not any(c in pat for c in "[](){}|+*?")
        if is_concrete:
            file_pat = file_re.pattern.strip("^$").replace("\\.", ".")
            file_path = re.sub(r"\.[\*\+]\$?$", "", file_pat) or "/"
            if not file_path.startswith("/"):
                file_path = "/" + file_path
            for scheme in (["http", "https"] if proto == "any" else [proto]):
                seeds.add("%s://%s%s" % (scheme, pat, file_path))
            continue
        # Wildcard / complex regex — try to recover the apex (last 2+ labels)
        # by stripping leading wildcard metachars.  Patterns like `.*\.foo\.bar`
        # → after our unescape pass = `.*.foo.bar` → split, drop everything
        # before the first label that has no metachar.
        labels = pat.split(".")
        clean_tail = []
        for lbl in reversed(labels):
            if not lbl or any(c in lbl for c in "[](){}|+*?\\"):
                break
            clean_tail.append(lbl)
        clean_tail.reverse()
        if len(clean_tail) >= 2:
            apex = ".".join(clean_tail)
            wildcard_rules.append((apex, host_re, file_re, proto))
    return seeds, include, exclude, wildcard_rules

def _is_in_scope(url, include, exclude):
    """Return True if `url` matches at least one include rule and no exclude."""
    from urllib.parse import urlparse
    p = urlparse(url)
    host = p.netloc
    path = p.path or "/"
    scheme = (p.scheme or "http").lower()
    def _match(rules):
        for host_re, file_re, proto in rules:
            if proto != "any" and proto != scheme:
                continue
            if host_re.search(host) and file_re.search(path):
                return True
        return False
    if _match(exclude):
        return False
    return _match(include)


def discover_keys_from_scope(scope_path, verbose=False, quiet=False,
                             scan_wildcards=False):
    """Web scope flow: read scope.json, derive seed URLs + in-scope matcher,
    crawl every seed (respecting exclude), then extract AIza keys site-wide."""
    with open(scope_path, "r", encoding="utf-8") as f:
        scope = json.load(f)
    seeds, include, exclude, wildcard_rules = _compile_scope(scope)
    if not quiet:
        print("\n[*] Web scope: %s" % scope_path)
        print("    Include rules: %d   Exclude rules: %d   Concrete seeds: %d   Wildcard rules: %d"
              % (len(include), len(exclude), len(seeds), len(wildcard_rules)))
        for s in sorted(seeds):
            print("      concrete seed: %s" % _redact_diagnostic_secret_text(s))

    # Wildcard expansion: passive DNS enum per apex, filter against the
    # original wildcard regex, add matches as seeds.
    if wildcard_rules:
        if not scan_wildcards:
            if not quiet:
                print("    [*] Wildcard rules detected: %d — skipped by default."
                      % len(wildcard_rules))
        else:
            apexes = sorted({apex for apex, _, _, _ in wildcard_rules})
            for apex in apexes:
                if not quiet:
                    print("    [*] Wildcard apex detected: %s — running passive DNS enum" % apex)
                hosts = dns_enum(apex, verbose=verbose, quiet=quiet)
                for h in hosts:
                    # Find every wildcard rule for this apex that matches the host
                    for w_apex, host_re, file_re, proto in wildcard_rules:
                        if w_apex != apex:
                            continue
                        if not host_re.search(h):
                            continue
                        file_pat = file_re.pattern.strip("^$").replace("\\.", ".")
                        file_path = re.sub(r"\.[\*\+]\$?$", "", file_pat) or "/"
                        if not file_path.startswith("/"):
                            file_path = "/" + file_path
                        for scheme in (["http", "https"] if proto == "any" else [proto]):
                            seeds.add("%s://%s%s" % (scheme, h, file_path))
                        break  # one rule match is enough per host
            if not quiet:
                print("    [*] Seeds after wildcard expansion: %d" % len(seeds))

    if not seeds:
        if not quiet:
            print("    [!] No seeds derived. Scope may use complex regex with no DNS-resolvable apex.")
        return set(), {}

    all_urls = set()
    for seed in seeds:
        if _which("katana"):
            all_urls.update(_crawl_with_katana(seed))
        else:
            all_urls.update(_crawl_with_python(seed))
    # Filter to in-scope only
    in_scope_urls = {u for u in all_urls if _is_in_scope(u, include, exclude)}
    dropped = len(all_urls) - len(in_scope_urls)
    if not quiet:
        print("    Crawled %d total URL(s); %d in-scope (dropped %d OOS)."
              % (len(all_urls), len(in_scope_urls), dropped))
    keys, sources = _fetch_and_extract_keys(in_scope_urls, verbose=verbose)
    if not quiet:
        if keys:
            print("    Found %d unique AIza key(s):" % len(keys))
            for k in sorted(keys):
                src = sorted(sources.get(k, set()))
                print("      - %s  (in %d page(s); e.g. %s)" % (
                    _redact_key_display(k), len(src), _redact_diagnostic_secret_text(src[0])))
        else:
            print("    [!] No AIza keys found in in-scope pages.")
    return keys, sources


# Host list importer
# A host scope is a flat .txt file of IP addresses, one per line.
# HTTP(S) probes on ports 80/443 work through HTTP proxies; raw TCP
# scanners are not required. Live endpoints feed into URL discovery.

def _http_probe(host, port, scheme, timeout=10):
    """Return the response object if `scheme://host:port/` answers, else None.
    TLS behavior follows the target-crawl request settings."""
    url = "%s://%s:%d/" % (scheme, host, port)
    try:
        r = requests.get(url, allow_redirects=False, **_request_kwargs_for_url(url, target_crawl=True))
        return url, r
    except requests.RequestException:
        return None

def discover_keys_from_host_list(path, verbose=False, quiet=False, threads=20):
    """Host scope flow: read flat IP list, find live HTTP(S) on 80/443,
    crawl each live endpoint, extract AIza keys. Returns (keys, sources)."""
    with open(path, "r", encoding="utf-8") as f:
        ips = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    if not quiet:
        print("\n[*] Host scope: %s" % path)
        print("    %d IP(s) loaded. Probing 80 + 443 (curl-equivalent, verify=False)..."
              % len(ips))

    # Parallel probe both ports per IP
    targets = [(ip, 80, "http") for ip in ips] + [(ip, 443, "https") for ip in ips]
    live_urls = []
    def _probe(t):
        return _http_probe(*t)
    with ThreadPoolExecutor(max_workers=threads) as ex:
        for fut in as_completed([ex.submit(_probe, t) for t in targets]):
            res = fut.result()
            if res:
                url, r = res
                live_urls.append(url)
                if verbose:
                    print("      [+] %s  HTTP %d  (server: %s)"
                          % (url, r.status_code, r.headers.get("Server", "-")))
    if not quiet:
        print("    %d live HTTP(S) endpoint(s) found." % len(live_urls))
        if not live_urls:
            print("    [!] No live web ports — check proxy + IP reachability.")
            return set(), {}

    # Now crawl each live endpoint (depth-limited) + extract keys
    all_urls = set()
    for url in live_urls:
        if _which("katana"):
            all_urls.update(_crawl_with_katana(url, depth=2))
        else:
            all_urls.update(_crawl_with_python(url, max_pages=15))
    keys, sources = _fetch_and_extract_keys(all_urls, verbose=verbose)
    if not quiet:
        if keys:
            print("    Found %d unique AIza key(s):" % len(keys))
            for k in sorted(keys):
                src = sorted(sources.get(k, set()))
                print("      - %s  (in %d page(s); e.g. %s)" % (
                    _redact_key_display(k), len(src), _redact_diagnostic_secret_text(src[0])))
        else:
            print("    [!] No AIza keys found in crawled host endpoints.")
    return keys, sources


_DISABLE_PLAYWRIGHT = False  # toggled by main() via --no-playwright
_MAX_PER_TEMPLATE = 5  # max URLs per path-template cluster (CLI: --max-per-template)
_MAX_PER_LOCALE = 1    # max URLs per locale variant (CLI: --max-per-locale)
_URL_FETCH_BUDGET = None  # None = fetch every text candidate
_URL_FETCH_QUEUE_STATE = None
_URL_FETCH_RESUME = False
_INCLUDE_AUTHORIZATION_KEY = False
_AUTHORIZATION_ONLY = False

# Curated list of common 2-letter locale codes. Used to distinguish a locale
# path segment (/en/, /fr/) from a coincidentally-2-3-letter path segment
# (/api/, /css/, /js/). Without a curated allowlist, "api" would be flagged as
# a locale and we'd erroneously collapse /api/v1/users with /api/v1/admin.
_KNOWN_LOCALES = {
    'en', 'fr', 'de', 'es', 'it', 'pt', 'ru', 'ja', 'ko', 'zh',
    'nl', 'sv', 'da', 'no', 'fi', 'pl', 'tr', 'ar', 'he', 'cs',
    'sk', 'hu', 'ro', 'bg', 'el', 'uk', 'th', 'vi', 'id', 'ms',
    'hi', 'bn', 'ur', 'fa', 'br', 'mx', 'jp', 'kr', 'cn', 'tw',
    'au', 'ca', 'gb', 'us', 'nz', 'in', 'za', 'ie', 'sg', 'hk',
}


def _dedupe_url_patterns(urls, max_per_template=None, max_per_locale=None, verbose=False):
    """Sample page URLs by normalized path, query keys and locale.

    Script and structured-data resources remain distinct. Sampling limits
    repeated page templates; it does not establish complete site coverage."""
    if max_per_template is None:
        max_per_template = _MAX_PER_TEMPLATE
    if max_per_locale is None:
        max_per_locale = _MAX_PER_LOCALE
    from collections import defaultdict
    from urllib.parse import urlparse, parse_qs

    NO_DEDUP_EXTS = ('.js', '.json', '.css', '.mjs', '.map', '.wasm')
    # Locale w/ optional region: en, fr, en-US, zh-CN, zh-cn
    locale_re = re.compile(r'^([a-zA-Z]{2,3})(-[a-zA-Z]{2})?$')
    digit_re = re.compile(r'^\d+$')
    uuid_re = re.compile(r'^[a-f0-9]{8,}$')

    def _template(url):
        p = urlparse(url)
        norm = []
        for seg in (p.path or '/').split('/'):
            if not seg:
                norm.append('')
                continue
            if digit_re.fullmatch(seg):
                norm.append('*')
            elif uuid_re.fullmatch(seg):
                norm.append('*')
            elif seg.count('-') >= 2 and len(seg) > 10:
                norm.append('*')
            elif locale_re.fullmatch(seg) and seg.split('-')[0].lower() in _KNOWN_LOCALES:
                norm.append('LOCALE')
            else:
                norm.append(seg)
        norm_path = '/'.join(norm)
        try:
            qkeys = sorted(parse_qs(p.query).keys())
        except Exception:
            qkeys = []
        q_sig = '&'.join(qkeys)
        return "%s|%s|%s" % (p.netloc.lower(), norm_path, q_sig)

    # JS / static assets always kept
    keep_all = {u for u in urls
                if any(u.lower().split('?', 1)[0].endswith(e) for e in NO_DEDUP_EXTS)}
    candidates = urls - keep_all

    clusters = defaultdict(list)
    for u in sorted(candidates):
        clusters[_template(u)].append(u)

    deduped = set(keep_all)
    skipped = 0
    for tpl, group in clusters.items():
        cap = max_per_locale if 'LOCALE' in tpl else max_per_template
        deduped.update(group[:cap])
        skipped += max(0, len(group) - cap)

    if verbose and skipped > 0:
        print("    Pattern dedup: %d URL(s) → %d cluster(s), %d JS kept → "
              "%d to fetch, %d skipped (template duplicates)"
              % (len(urls), len(clusters), len(keep_all), len(deduped), skipped))
    return deduped


def discover_keys_from_url(target_url, verbose=False, quiet=False, cache_dir=None,
                           fetch_budget=None, queue_state_path=None,
                           resume=None):
    """Discover keys using the available Katana, Python and Playwright crawlers.

    Optional cache and queue-state paths support resumable body fetching."""
    if not quiet:
        print("\n[*] URL discovery: %s" % _redact_diagnostic_secret_text(target_url))
    k_urls = set()
    if _which("katana"):
        if not quiet:
            print("    Using katana (JS-aware headless mode, depth=2)")
        k_urls = _crawl_with_katana(target_url)
    else:
        if not quiet:
            print("    [!] katana not in PATH — install for deeper coverage:")
            print("        go install github.com/projectdiscovery/katana/cmd/katana@latest")
    py_urls = _crawl_with_python(target_url)
    pw_urls = set() if _DISABLE_PLAYWRIGHT else _crawl_with_playwright(target_url)
    union = k_urls | py_urls | pw_urls
    if not quiet and (k_urls or py_urls or pw_urls):
        k_only = len(k_urls - py_urls - pw_urls)
        p_only = len(py_urls - k_urls - pw_urls)
        w_only = len(pw_urls - k_urls - py_urls)
        print("    Crawl tiers: katana=%d (only %d), python=%d (only %d), "
              "playwright=%d (only %d) → union %d"
              % (len(k_urls), k_only, len(py_urls), p_only,
                 len(pw_urls), w_only, len(union)))
    # Template dedup BEFORE fetch — drops repeating page templates (hotel
    # detail pages, locale clones, etc.) so we don't waste hours fetching
    # 10,000 variants of the same template. Configurable via
    # --max-per-template / --max-per-locale.
    urls = _dedupe_url_patterns(union, verbose=(not quiet))
    if not quiet:
        print("    Crawled %d URL(s); fetching for key extraction..." % len(urls))
    keys, sources = _fetch_and_extract_keys(
        urls,
        verbose=verbose,
        max_urls=fetch_budget,
        cache_dir=cache_dir,
        seed_url=target_url,
        queue_state_path=queue_state_path,
        resume=resume,
    )
    if not quiet:
        if keys:
            print("    Found %d unique AIza key(s):" % len(keys))
            for k in sorted(keys):
                src_list = sorted(sources.get(k, set()))
                print("      - %s  (in %d page(s); e.g. %s)" % (
                    _redact_key_display(k), len(src_list), _redact_diagnostic_secret_text(src_list[0])))
        else:
            print("    [!] No AIza keys found in crawled pages.")
    return keys, sources
