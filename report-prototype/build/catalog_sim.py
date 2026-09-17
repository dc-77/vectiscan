#!/usr/bin/env python3
"""Katalog-Simulation: Fakten aus results.json aller Orders extrahieren, einen
Regelkatalog (Entwurf) anwenden und mit den KI-Befunden (findings.json) vergleichen.

Aufruf: python3 build/catalog_sim.py [input/_all]
Ausgabe: out/catalog-sim.json, Zusammenfassung auf stdout.

Absichtlich schlank: Textparser für nmap/testssl, JSON für header_check/httpx/
dns_records/dns_security/zap/shodan/wpscan. Keine KI. Ziel ist nicht der fertige
Regelkatalog, sondern die Frage: Wie viele Sachverhaltsfamilien gibt es, wie viele
Regeln decken sie ab, was bleibt übrig.
"""
import json, os, re, sys, collections

ROOT = sys.argv[1] if len(sys.argv) > 1 else "input/_all"
ANSI = re.compile(r"\x1b\[[0-9;]*m")

# ---------------------------------------------------------------- Fakten
def parse_nmap(host_ip, raw):
    services = []
    cur = None
    for line in raw.splitlines():
        m = re.match(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)\s+\S+\s*(.*)$", line)
        if m:
            port, proto, svc, ver = int(m.group(1)), m.group(2), m.group(3), m.group(4).strip()
            cur = dict(host=host_ip, port=port, proto=proto, service=svc, version=ver,
                       tls=svc.startswith("ssl/") or "requires SSL" in ver,
                       starttls=False, cert_cn=None, cert_after=None, caps="")
            services.append(cur)
            continue
        if cur is None:
            continue
        if "capabilities:" in line or "smtp-commands:" in line:
            cur["caps"] = line
            if "STARTTLS" in line or "STLS" in line:
                cur["starttls"] = True
        m = re.search(r"commonName=([^\s,]+)", line)
        if m and cur["cert_cn"] is None:
            cur["cert_cn"] = m.group(1)
        m = re.search(r"Not valid after:\s+(\S+)", line)
        if m:
            cur["cert_after"] = m.group(1)
    up = "Host is up" in raw
    return services, up

def parse_testssl(raw):
    t = ANSI.sub("", raw or "")
    m = re.search(r"-->> ([\d.:a-f]+):(\d+) \(([^)]*)\)", t)
    if not m or "Fatal error" in t or "Can't connect" in t:
        return None
    f = dict(host=m.group(1), port=int(m.group(2)), name=m.group(3), protos={}, weak=[], vulns=[], cert={})
    for p in ("SSLv2", "SSLv3", "TLS 1", "TLS 1.1", "TLS 1.2", "TLS 1.3"):
        mm = re.search(r"^\s*" + re.escape(p) + r"\s{2,}(not offered|offered)", t, re.M)
        if mm:
            f["protos"][p] = mm.group(1) == "offered"
    for cat, key in (("NULL ciphers", "null"), ("Anonymous NULL", "anon"), ("Export ciphers", "export"),
                     ("LOW: 64 Bit", "low"), ("Triple DES Ciphers / IDEA", "3des")):
        mm = re.search(r"^\s*" + re.escape(cat) + r".*?\s(offered|not offered)", t, re.M)
        if mm and mm.group(1) == "offered":
            f["weak"].append(key)
    for v in ("Heartbleed", "CCS", "Ticketbleed", "ROBOT", "CRIME", "BREACH", "POODLE", "SWEET32",
              "FREAK", "DROWN", "LOGJAM", "BEAST", "LUCKY13", "RC4"):
        mm = re.search(r"^\s*" + v + r"\b.*?(?:potentially )?VULNERABLE", t, re.M)
        if mm:
            sev = "potential" if "potentially" in mm.group(0) else "vulnerable"
            f["vulns"].append((v, sev))
    mm = re.search(r"Trust \(hostname\)\s+(.*)", t); f["cert"]["hostname_ok"] = bool(mm and mm.group(1).strip().startswith("Ok"))
    mm = re.search(r"Chain of trust\s+(.*)", t); f["cert"]["chain_ok"] = bool(mm and mm.group(1).strip().startswith("Ok"))
    mm = re.search(r"Certificate Validity \(UTC\)\s+(.*)", t)
    val = mm.group(1) if mm else ""
    f["cert"]["expired"] = "expired" in val
    mm2 = re.search(r"expires < (\d+) days \((\d+)\)", val)
    f["cert"]["days_left"] = int(mm2.group(2)) if mm2 else None
    f["cert"]["self_signed"] = "self signed" in t.lower() or "self-signed" in t.lower()
    return f

def parse_json(raw):
    try:
        return json.loads(raw)
    except Exception:
        return None

def parse_httpx(raw):
    out = []
    for line in (raw or "").splitlines():
        d = parse_json(line)
        if d and isinstance(d, dict) and d.get("url"):
            out.append(d)
    return out

def extract_facts(order_dir):
    rows = json.load(open(os.path.join(order_dir, "results.json")))["data"]["results"]
    od = json.load(open(os.path.join(order_dir, "order.json")))["data"]
    dnsf = ((od.get("progress") or {}).get("discoveredHosts") or {}).get("dns_findings") or {}
    dnss = (od.get("passiveIntelSummary") or {}).get("dns_security") or {}
    F = dict(services=[], hosts_up={}, tls=[], http=[], httpx=[], dns={}, dnssec={}, zap=[], shodan_ports=[],
             wp=[], coverage=collections.Counter(), tool_status=collections.Counter(), urlhaus=False, feserver=[], php=[])
    if dnsf:
        F["dns"] = dict(spf=dnsf.get("spf"), mx=dnsf.get("mx"), dkim=dnsf.get("dkim"),
                        dmarc_policy=dnss.get("dmarc") or ({"dmarc_present": bool(dnsf.get("dmarc")), "p": (re.search(r"p=(\w+)", dnsf.get("dmarc") or "") or [None, None])[1]}),
                        zone_transfer=dnsf.get("zone_transfer"), dangling=dnsf.get("dangling_cnames") or [])
    if dnss:
        F["dnssec"] = dnss
    for r in rows:
        t, raw, ip = r["toolName"], r["rawOutput"] or "", r["hostIp"]
        st = r.get("status") or ("ok" if raw.strip() and not raw.startswith("SKIPPED") else "empty")
        F["tool_status"][(t, st)] += 1
        if t == "nmap":
            svcs, up = parse_nmap(ip, raw)
            F["services"] += svcs
            F["hosts_up"][ip] = up
            if up and not svcs:
                F["coverage"]["nmap_no_open_ports"] += 1
        elif t == "testssl":
            f = parse_testssl(raw)
            if f: F["tls"].append(f)
            else: F["coverage"]["testssl_unreachable"] += 1
        elif t == "header_check":
            d = parse_json(raw)
            if d and d.get("result"):
                res = d["result"]
                if res.get("reachable") is False:
                    F["coverage"]["vhost_unreachable"] += 1
                else:
                    hdr = {k.lower(): v for k, v in (res.get("headers") or {}).items()}
                    F["http"].append(dict(vhost=d.get("vhost"), url=res.get("url"), headers=hdr,
                                          sec=res.get("security_headers") or {}, score=res.get("score")))
                    if hdr.get("x-feserver"): F["feserver"].append((d.get("vhost"), hdr["x-feserver"]))
                    m = re.search(r"PHP/(\d+)\.(\d+)", hdr.get("x-powered-by") or "")
                    if m: F["php"].append((d.get("vhost"), f"{m.group(1)}.{m.group(2)}"))
        elif t == "httpx":
            F["httpx"] += parse_httpx(raw)
        elif t == "dns_records":
            d = parse_json(raw)
            if d and not F["dns"]: F["dns"] = d
        elif t == "dns_security":
            d = parse_json(raw)
            if d and not F["dnssec"]: F["dnssec"] = d
        elif t == "zap":
            d = parse_json(raw)
            if d and d.get("top_alerts"):
                for a in d["top_alerts"]:
                    F["zap"].append(dict(name=a.get("name"), risk=a.get("risk"), url=a.get("url"), host=ip))
            elif st == "ok":
                F["coverage"]["zap_empty"] += 1
        elif t == "shodan":
            d = parse_json(raw)
            if d:
                for hip, hd in (d.get("shodan_host") or {}).items() if isinstance(d.get("shodan_host"), dict) else []:
                    for p in (hd.get("ports") or []):
                        F["shodan_ports"].append((hip, p))
        elif t == "wpscan" and raw.startswith("{"):
            d = parse_json(raw)
            if d: F["wp"].append(d)
        elif t == "urlhaus" and "OK: no_data" not in raw and raw.strip() and not raw.startswith("SKIPPED"):
            F["urlhaus"] = True
        if st in ("skipped", "failed"):
            F["coverage"][f"{t}_{st}"] += 1
    return F

# ---------------------------------------------------------------- Katalog (Entwurf)
DB_PORTS = {3306: "MySQL/MariaDB", 5432: "PostgreSQL", 1433: "MSSQL", 27017: "MongoDB", 6379: "Redis", 9200: "Elasticsearch", 5984: "CouchDB", 1521: "Oracle"}
ADMIN_PORTS = {8443: "Plesk/Admin-HTTPS", 8880: "Plesk", 10000: "Webmin", 9443: "Portainer", 9000: "Portainer/Admin", 8006: "Proxmox", 3128: "Proxy/Proxmox-API",
               2083: "cPanel", 2087: "WHM", 4433: "Firewall-Mgmt", 5060: "SIP", 111: "rpcbind", 2222: "SSH-alt", 8080: "HTTP-alt", 8000: "HTTP-alt",
               1000: "Mgmt", 1001: "Mgmt", 1002: "Mgmt", 444: "Mgmt", 9929: "Nping", 31337: "Unbekannt"}
KNOWN_PORTS = {21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3389, 139, 445, 106} | set(DB_PORTS) | set(ADMIN_PORTS)
ADMIN_TITLES = re.compile(r"plesk|cpanel|portainer|proxmox|webmin|phpmyadmin|fortigate|fortinet|sonicwall|jitsi|rustdesk|gitlab|jenkins|grafana|kibana", re.I)
LOGIN_TITLES = re.compile(r"outlook|\bowa\b|roundcube|webmail|nextcloud|openotp|bitwarden|remote desktop|rd web|citrix|vpn|sslvpn", re.I)
DEFAULT_TITLES = re.compile(r"default page|default web|iis windows|apache2 .* default|welcome to nginx|froxlor|plesk default|web server's default|it works|test page", re.I)

def norm_version(product, ver):
    """Versions-Normalisierung mit Plausibilität: (familie, version) oder (familie, None)."""
    v = ver or ""
    if "or later" in v or "or newer" in v:
        return product, None
    m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", v)
    return product, (m.group(0) if m else None)

def eol_check(svc):
    """Sehr kleine EOL-Tabelle, nur eindeutige Fälle. Liefert (produkt, version, eol_grund) oder None."""
    ver = svc["version"]
    if "MariaDB" in ver:
        m = re.search(r"(\d+\.\d+\.\d+)-MariaDB", ver)
        if m:
            mv = m.group(1)
            major = tuple(int(x) for x in mv.split(".")[:2])
            if major < (10, 5): return ("MariaDB", mv, "MariaDB < 10.5")
        return None
    if svc["service"] == "mysql" and re.search(r"MySQL 5\.[0-6]\b", ver) and "MariaDB" not in ver:
        return ("MySQL", re.search(r"5\.\d", ver).group(0), "MySQL 5.x")
    m = re.search(r"PostgreSQL DB (\d+)\.(\d+)", ver)
    if m and "or later" not in ver and int(m.group(1)) < 13:
        return ("PostgreSQL", m.group(0), "PostgreSQL < 13")
    m = re.search(r"Microsoft Exchange .*?15\.(\d)\.", ver)
    if m and m.group(1) == "1":
        return ("Exchange 2016", "15.1", "Exchange 2016 EOL 2025-10")
    m = re.search(r"Apache httpd 2\.2\b", ver)
    if m: return ("Apache", "2.2", "Apache 2.2")
    m = re.search(r"PHP/?(\d)\.(\d)", ver)
    if m and (int(m.group(1)), int(m.group(2))) < (8, 1):
        return ("PHP", f"{m.group(1)}.{m.group(2)}", "PHP < 8.1")
    return None

def apply_rules(F, domain):
    R = []   # (rule_id, family, scale, level, affected)
    P = []   # (rule_id, positive text)
    unproc = []   # unverarbeitete Beobachtungen
    notes = []    # Inventarnotizen (kein Befund)
    def add(rid, fam, scale, level, aff): R.append(dict(rule=rid, family=fam, scale=scale, level=level, affected=aff))
    S = F["services"]
    byport = collections.defaultdict(list)
    for s in S: byport[s["port"]].append(s)
    # Exposure
    aff = [f"{s['host']}:{s['port']} ({DB_PORTS[s['port']]})" for s in S if s["port"] in DB_PORTS]
    if aff: add("R-DB-EXPOSED", "db_exposed", "exposure", "kritisch", aff)
    aff = [f"{s['host']}:{s['port']}" for s in S if s["port"] in (139, 445)]
    if aff: add("R-SMB-EXPOSED", "smb_exposed", "exposure", "kritisch", aff)
    aff = [f"{s['host']}:3389" for s in S if s["port"] == 3389]
    if aff: add("R-RDP-EXPOSED", "rdp_exposed", "exposure", "erhöht", aff)
    aff = [f"{s['host']}:{s['port']} ({ADMIN_PORTS[s['port']]})" for s in S if s["port"] in ADMIN_PORTS]
    aff += [f"{h.get('host')} {h.get('url')} ({h.get('title','')[:30]})" for h in F["httpx"] if ADMIN_TITLES.search(h.get("title") or "")]
    if aff: add("R-ADMIN-EXPOSED", "admin_service_exposed", "exposure", "erhöht", aff)
    ftp = [s for s in S if s["port"] == 21]
    plain = [f"{s['host']}:21" for s in ftp if not s["tls"] and not s["starttls"]]
    tlsftp = [f"{s['host']}:21 (TLS erzwungen)" for s in ftp if s["tls"] or s["starttls"]]
    if plain: add("R-FTP-PLAIN", "ftp_exposed", "exposure", "erhöht", plain)
    if tlsftp: notes.append(("ftp_tls_only", tlsftp))
    mail = [s for s in S if s["port"] in (110, 143)]
    mp = [f"{s['host']}:{s['port']}" for s in mail if not s["starttls"] and not s["tls"]]
    ms = [f"{s['host']}:{s['port']} (STARTTLS)" for s in mail if s["starttls"] or s["tls"]]
    if mp: add("R-MAIL-PLAIN", "mail_plaintext", "exposure", "erhöht", mp)
    if ms: notes.append(("mail_starttls", ms))
    hosts80 = {s["host"] for s in S if s["port"] == 80}; hosts443 = {s["host"] for s in S if s["port"] == 443}
    aff = sorted(hosts80 - hosts443)
    if aff: add("R-HTTP-NO-TLS", "http_no_tls", "exposure", "erhöht", aff)
    eol = []
    for s in S:
        e = eol_check(s)
        if e: eol.append(f"{s['host']}:{s['port']} {e[0]} {e[1]} ({e[2]})")
    for vh, fe in F["feserver"]:
        if re.search(r"2013|2016|2019", fe): eol.append(f"{vh} Exchange (Hostname {fe}, Build prüfen)")
    for vh, v in F["php"]:
        if tuple(int(x) for x in v.split(".")) < (8, 1): eol.append(f"{vh} PHP {v}")
    eol = sorted(set(eol))
    if eol: add("R-EOL", "software_eol", "exposure", "erhöht", eol)
    if F["urlhaus"]: add("R-URLHAUS", "urlhaus_compromise", "exposure", "kritisch", [domain])
    for w in F["wp"]:
        vp = [p for p, d in (w.get("plugins") or {}).items() if d.get("vulnerabilities")]
        if vp: add("R-WP-PLUGIN-VULN", "wordpress_plugin_vulnerable", "exposure", "erhöht", vp)
        users = list((w.get("users") or {}).keys())
        if users: add("R-WP-USER-ENUM", "user_enumeration", "hygiene", "niedrig", users[:5])
        ver = (w.get("version") or {})
        if ver.get("status") == "insecure": add("R-WP-CORE-OLD", "wordpress_core_outdated", "exposure", "erhöht", [ver.get("number")])
    # TLS / Zertifikate
    T = F["tls"]
    aff = [f"{t['name']}:{t['port']} ({', '.join(p for p,o in t['protos'].items() if o and p in ('SSLv2','SSLv3','TLS 1','TLS 1.1'))})" for t in T if any(o for p,o in t["protos"].items() if p in ("SSLv2","SSLv3","TLS 1","TLS 1.1"))]
    if aff: add("R-TLS-LEGACY", "tls_legacy_protocols", "hygiene", "hoch", aff)
    aff = [f"{t['name']}:{t['port']} ({','.join(t['weak'])})" for t in T if t["weak"]]
    if aff: add("R-TLS-WEAK-CIPHERS", "tls_weak_ciphers", "hygiene", "mittel", aff)
    hard = [f"{t['name']}:{t['port']} {v}" for t in T for v, s in t["vulns"] if v in ("Heartbleed","CCS","ROBOT","POODLE","DROWN","FREAK","LOGJAM","Ticketbleed") and s == "vulnerable"]
    if hard: add("R-TLS-VULN", "tls_known_vulnerability", "exposure", "erhöht", hard)
    soft = [f"{t['name']}:{t['port']} {v}" for t in T for v, s in t["vulns"] if v in ("BREACH","SWEET32","LUCKY13","BEAST","RC4","CRIME")]
    if soft: add("R-TLS-VULN-SOFT", "tls_weakness", "hygiene", "niedrig", soft)
    aff = [f"{t['name']}:{t['port']}" for t in T if t["cert"].get("expired")]
    if aff: add("R-CERT-EXPIRED", "cert_expired", "exposure", "erhöht", aff)
    aff = [f"{t['name']}:{t['port']} ({t['cert']['days_left']} Tage)" for t in T if t["cert"].get("days_left") is not None and t["cert"]["days_left"] <= 30 and not t["cert"].get("expired")]
    if aff: add("R-CERT-EXPIRING", "cert_expiring", "hygiene", "hoch", aff)
    aff = [f"{t['name']}:{t['port']}" for t in T if t["cert"].get("hostname_ok") is False]
    if aff: add("R-CERT-MISMATCH", "cert_hostname_mismatch", "hygiene", "hoch", aff)
    aff = [f"{t['name']}:{t['port']}" for t in T if t["cert"].get("chain_ok") is False]
    if aff: add("R-CERT-CHAIN", "cert_chain_incomplete", "hygiene", "mittel", aff)
    # Header je vHost, konsolidiert
    H = F["http"]
    def sec(h, k): return (h["sec"].get(k) or {})
    aff = [h["vhost"] for h in H if (h["url"] or "").startswith("https") and not sec(h, "strict-transport-security").get("present")]
    if aff: add("R-HDR-HSTS-MISSING", "hsts_missing", "hygiene", "mittel", aff)
    aff = []
    for h in H:
        v = sec(h, "strict-transport-security").get("value") or ""
        m = re.search(r"max-age=(\d+)", v)
        if m and int(m.group(1)) < 15552000: aff.append(f"{h['vhost']} (max-age={m.group(1)})")
    if aff: add("R-HDR-HSTS-SHORT", "hsts_short", "hygiene", "niedrig", aff)
    aff = [h["vhost"] for h in H if not sec(h, "content-security-policy").get("present")]
    if aff: add("R-HDR-CSP-MISSING", "csp_missing", "hygiene", "mittel", aff)
    aff = [h["vhost"] for h in H if re.search(r"unsafe-inline|unsafe-eval|\*", sec(h, "content-security-policy").get("value") or "")]
    if aff: add("R-HDR-CSP-WEAK", "csp_weak", "hygiene", "mittel", aff)
    aff = [f"{h['vhost']} ({h['score']})" for h in H if any(not sec(h, k).get("present") for k in ("x-frame-options","x-content-type-options","referrer-policy","permissions-policy"))]
    if aff: add("R-HDR-INCOMPLETE", "security_headers_incomplete", "hygiene", "niedrig", aff)
    aff = [f"{h['vhost']} ({h['headers'].get('Server') or h['headers'].get('server')})" for h in H if re.search(r"\d+\.\d+", (h["headers"].get("server") or ""))]
    aff += [f"{s['host']}:{s['port']} ({s['version'][:40]})" for s in S if re.search(r"\d+\.\d+", s["version"]) and s["port"] not in (443, 80)]
    if aff: add("R-BANNER-VERSION", "banner_version_disclosure", "hygiene", "niedrig", aff)
    # Web-Oberflächen
    aff = [f"{h.get('input')} ({(h.get('title') or '')[:40]})" for h in F["httpx"] if DEFAULT_TITLES.search(h.get("title") or "")]
    if aff: add("R-DEFAULT-PAGE", "default_page_exposed", "hygiene", "niedrig", aff)
    aff = [f"{h.get('input')} ({(h.get('title') or '')[:40]})" for h in F["httpx"] if LOGIN_TITLES.search(h.get("title") or "") and not ADMIN_TITLES.search(h.get("title") or "")]
    if aff: add("R-LOGIN-PORTAL", "login_portal_exposed", "hygiene", "mittel", aff)
    aff = [h.get("input") for h in F["httpx"] if re.match(r"^(dev|test|staging|stage|demo|old|alt)\.", h.get("input") or "") and h.get("status_code") == 200]
    if aff: add("R-DEV-HOST", "dev_host_public", "hygiene", "mittel", aff)
    # DNS / Mail
    D = F["dns"]; DS = F["dnssec"]
    if D:
        mx = bool(D.get("mx"))
        spf = D.get("spf")
        if not spf: add("R-SPF-MISSING", "spf_missing", "hygiene", "hoch", [domain])
        elif re.search(r"\+all", spf): add("R-SPF-PLUSALL", "spf_permissive", "hygiene", "hoch", [domain])
        elif re.search(r"~all|\?all", spf): add("R-SPF-SOFT", "spf_softfail", "hygiene", "niedrig", [domain])
        else: P.append(("R-SPF-OK", "SPF mit -all"))
        dp = (D.get("dmarc_policy") or {})
        if not dp.get("dmarc_present"): add("R-DMARC-MISSING", "dmarc_missing", "hygiene", "hoch", [domain])
        elif dp.get("p") == "none": add("R-DMARC-NONE", "dmarc_none", "hygiene", "mittel", [domain])
        elif dp.get("p") == "quarantine": add("R-DMARC-QUAR", "dmarc_quarantine", "hygiene", "niedrig", [domain])
        else: P.append(("R-DMARC-OK", "DMARC reject"))
        if mx and not D.get("dkim"): add("R-DKIM-MISSING", "dkim_missing", "hygiene", "mittel", [domain])
        elif mx: P.append(("R-DKIM-OK", "DKIM vorhanden"))
    if DS:
        if not (DS.get("dnssec") or {}).get("dnssec_signed"): add("R-DNSSEC-MISSING", "dnssec_missing", "hygiene", "niedrig", [domain])
        else: P.append(("R-DNSSEC-OK", "DNSSEC signiert"))
        if not (DS.get("caa") or {}).get("has_caa"): add("R-CAA-MISSING", "caa_missing", "hygiene", "niedrig", [domain])
        else: P.append(("R-CAA-OK", "CAA vorhanden"))
        if D.get("mx") and not (DS.get("mta_sts") or {}).get("has_policy"): add("R-MTASTS-MISSING", "mta_sts_missing", "hygiene", "niedrig", [domain])
    # ZAP (Werkzeugbefunde)
    Z = F["zap"]
    zmap = [
        (r"cookie.*(secure|httponly|samesite)", "cookie_flags", "niedrig"),
        (r"private ip|timestamp|suspicious comments|information disclosure|debug error|application error", "info_disclosure", "niedrig"),
        (r"csrf|anti-csrf", "csrf_token_missing", "niedrig"),
        (r"vulnerable js|outdated|library", "js_library_outdated", "mittel"),
        (r"sql injection|remote code|command injection|path traversal|xss|cross site scripting|xxe|ssrf", "web_vulnerability_active", "erhöht"),
        (r"directory browsing|directory listing", "directory_listing", "mittel"),
        (r"session id in url|session.*url", "session_in_url", "mittel"),
        (r"cors", "cors_misconfiguration", "mittel"),
        (r"integrity|sri", "sri_missing", "niedrig"),
        (r"multiple x-frame-options|multiple .* header entries", "header_duplicate", "niedrig"),
        (r"x-aspnet-version|in page banner|cross-domain javascript", "info_disclosure", "niedrig"),
    ]
    zhit = collections.defaultdict(set); zrest = collections.Counter()
    for a in Z:
        n = (a["name"] or "").lower()
        if re.search(r"header not set|clickjacking|content security policy|strict-transport|x-content-type|server leaks|x-powered-by|cache-control|permissions policy|referrer|^csp:", n):
            continue  # durch Header-Regeln abgedeckt (CSP-Unteralerts gehen in csp_weak)
        if re.search(r"modern web application|session management response|retrieved from cache|authentication request identified|user controllable|charset|loosely scoped", n):
            continue  # ZAP-Informationsalerts ohne Sicherheitsaussage: Ignorierliste
        for pat, fam, lvl in zmap:
            if re.search(pat, n):
                zhit[(fam, lvl)].add(a["url"] or a["host"]); break
        else:
            zrest[a["name"]] += 1
    for (fam, lvl), urls in zhit.items():
        add("R-ZAP-" + fam.upper(), fam, "exposure" if lvl == "erhöht" else "hygiene", lvl, sorted(urls)[:5])
    for n, c in zrest.items(): unproc.append(("zap_alert", n, c))
    # Positiv
    if T and all(not any(o for p,o in t["protos"].items() if p in ("SSLv2","SSLv3","TLS 1","TLS 1.1")) for t in T): P.append(("R-TLS-MODERN", "nur TLS 1.2/1.3"))
    if H and all(sec(h,"strict-transport-security").get("present") for h in H): P.append(("R-HSTS-OK", "HSTS überall"))
    # Unverarbeitet: Ports außerhalb der Listen, Shodan-only-Ports
    for s in S:
        if s["port"] not in KNOWN_PORTS: unproc.append(("service_unknown_port", f"{s['port']}/{s['service']} {s['version'][:30]}", 1))
    nm = {(h, p) for h in F["hosts_up"] for p in byport if any(x["host"] == h for x in byport[p])}
    for h, p in F["shodan_ports"]:
        if (h, p) not in nm: unproc.append(("shodan_only_port", f"{h}:{p}", 1))
    # Dangling CNAME / AXFR
    if F["dns"].get("dangling"): add("R-DNS-DANGLING", "dns_dangling", "hygiene", "mittel", F["dns"]["dangling"])
    if F["dns"].get("zone_transfer"): add("R-DNS-AXFR", "dns_axfr", "exposure", "erhöht", [domain])
    elif F["dns"]: P.append(("R-AXFR-OK", "Zonentransfer unterbunden"))
    return R, P, unproc, notes

# ---------------------------------------------------------------- KI-Befunde -> Familien
KI_FAMILY = [
    (r"datenbank|database|mysql|mariadb|postgres|3306|5432", "db_exposed"),
    (r"smb|samba", "smb_exposed"), (r"\brdp\b|3389|remote desktop", "rdp_exposed"),
    (r"ftp", "ftp_exposed"), (r"pop3|imap|mail-?dienste|maildienste|mail-ports|klartext-mail", "mail_service_exposed"),
    (r"plesk|webmin|portainer|proxmox|rpcbind|management|admin|fortinet|verwaltungs|icecast|ports? .*exponiert|port-exposition|dienst-exposition|nping|31337|smtp.*port 26", "admin_service_exposed"),
    (r"exchange|end[- ]of[- ]life|eol|veraltet|end of support|outdated|nginx 1\.|apache 2\.", "software_eol"),
    (r"3des|idea|cipher", "tls_weak_ciphers"), (r"tr-03116|tls 1\.0|tls 1\.1|tls-konfiguration|legacy", "tls_legacy_protocols"),
    (r"zertifikatskette|chain", "cert_chain_incomplete"), (r"passt nicht|mismatch|sni", "cert_hostname_mismatch"),
    (r"abgelaufen|expired", "cert_expired"), (r"läuft .* ab|expiring|30 tage", "cert_expiring"), (r"breach|kompression", "tls_weakness"),
    (r"hsts.*max-age|max-age", "hsts_short"), (r"hsts", "hsts_missing"),
    (r"csp.*(unsafe|wildcard|schwäch|schwaech|permissiv|direktiv)|content-security-policy.*(unsafe|wildcard|schwäch|permissiv|direktiv)", "csp_weak"),
    (r"content-security-policy fehlt|csp fehlt|csp_missing", "csp_missing"),
    (r"x-frame-options|security-header|sicherheits-?header|permissions-policy|x-content-type|referrer", "security_headers_incomplete"),
    (r"banner|versions-info|version information", "banner_version_disclosure"),
    (r"csrf", "csrf_token_missing"), (r"cookie", "cookie_flags"), (r"private ip|timestamp|suspicious|disclosure|phpinfo|error", "info_disclosure"),
    (r"javascript|js-bibliothek|library|jquery", "js_library_outdated"), (r"subresource|sri", "sri_missing"), (r"cors", "cors_misconfiguration"),
    (r"directory listing|verzeichnisauflistung", "directory_listing"), (r"session-id|jsessionid", "session_in_url"),
    (r"spf.*(softfail|~all)", "spf_softfail"), (r"spf", "spf_missing"), (r"dmarc.*none", "dmarc_none"), (r"dmarc.*quarantine", "dmarc_quarantine"),
    (r"dmarc", "dmarc_missing"), (r"dkim", "dkim_missing"), (r"dnssec", "dnssec_missing"), (r"caa", "caa_missing"), (r"mta-sts|tls-rpt|tlsrpt", "mta_sts_missing"),
    (r"wordpress.*plugin|plugin.*wordpress|wp-plugin", "wordpress_plugin_vulnerable"), (r"xmlrpc|rest-api", "wp_xmlrpc"), (r"wordpress|benutzer-enumeration|user enumeration|enumeration", "user_enumeration"),
    (r"urlhaus|kompromittiert|malware", "urlhaus_compromise"), (r"cve-|schwachstelle in openssh|openssh", "cve_claim"),
    (r"ssh.*brute|brute-force", "ssh_no_bruteforce"), (r"kein https|keine transportverschl|http statt https", "http_no_tls"),
    (r"dangling|verwaist", "dns_dangling"), (r"standardseite|default|parking|welcome", "default_page_exposed"),
    (r"webmail|roundcube|owa|login", "login_portal_exposed"), (r"dev-|test-|subdomain-exposition|entwicklungs", "dev_host_public"),
    (r"nicht scanbar|gefiltert|timeout", "coverage_note"), (r"doppelte|mehrfache|duplicate", "header_duplicate"),
]
TYPE_FAMILY = {
    "database_port_exposed": "db_exposed", "server_banner_with_version": "banner_version_disclosure", "server_banner_no_version": "banner_version_disclosure",
    "csp_missing": "csp_missing", "csp_unsafe_inline": "csp_weak", "csp_wildcard_source": "csp_weak", "csrf_token_missing": "csrf_token_missing",
    "software_eol": "software_eol", "spf_softfail": "spf_softfail", "spf_missing": "spf_missing", "dnssec_missing": "dnssec_missing",
    "wordpress_plugin_vulnerability": "wordpress_plugin_vulnerable", "xfo_missing": "security_headers_incomplete", "permissions_policy_missing": "security_headers_incomplete",
    "private_ip_disclosure": "info_disclosure", "phpinfo_exposed": "info_disclosure", "js_library_vulnerable": "js_library_outdated", "tls_below_tr03116_minimum": "tls_legacy_protocols",
    "hsts_missing": "hsts_missing", "hsts_short_maxage": "hsts_short", "hsts_no_includesubdomains": "hsts_short", "urlhaus_compromise_detected": "urlhaus_compromise",
    "tls_weak_cipher_suites": "tls_weak_ciphers", "user_enumeration": "user_enumeration", "wordpress_user_enumeration": "user_enumeration", "dmarc_p_none": "dmarc_none",
    "dmarc_p_quarantine": "dmarc_quarantine", "dmarc_pct_partial": "dmarc_quarantine", "sri_missing": "sri_missing", "tls_rpt_missing": "mta_sts_missing", "mta_sts_missing": "mta_sts_missing",
    "dkim_missing": "dkim_missing", "cookie_no_secure": "cookie_flags", "cookie_no_samesite": "cookie_flags", "cors_misconfiguration": "cors_misconfiguration",
    "tls_certificate_expiring_30d": "cert_expiring", "tls_certificate_expired": "cert_expired", "cve_finding": "cve_claim", "ssh_no_brute_force_protection": "ssh_no_bruteforce",
    "directory_listing_enabled": "directory_listing",
}

def ki_family(f):
    ft = f.get("finding_type"); title = (f.get("title") or "").lower()
    for pat, fam in KI_FAMILY:
        if re.search(pat, title): return fam
    if ft in TYPE_FAMILY:
        return TYPE_FAMILY[ft]
    return "unclassified:" + title[:40]

# ---------------------------------------------------------------- Lauf
def main():
    orders = {o["id"]: o for o in json.load(open(os.path.join(ROOT, "orders.json")))["data"]["orders"]}
    out = []
    for oid, o in sorted(orders.items(), key=lambda kv: kv[1]["createdAt"]):
        d = os.path.join(ROOT, oid)
        if not os.path.exists(os.path.join(d, "findings.json")) or "vectiscan-demo" in (o.get("domain") or ""):
            continue
        dom = o.get("domain") or ""
        if o.get("targets") and len(o["targets"]) > 1: dom = "+".join(t["canonical"] for t in o["targets"])
        F = extract_facts(d)
        R, P, U, N = apply_rules(F, dom.split("+")[0])
        ki = json.load(open(os.path.join(d, "findings.json")))["data"].get("findings") or []
        kif = collections.Counter(ki_family(f) for f in ki)
        rf = collections.Counter(r["family"] for r in R)
        out.append(dict(order=oid, domain=dom, created=o["createdAt"][:10], package=o["package"],
                        n_services=len(F["services"]), n_tls=len(F["tls"]), n_http=len(F["http"]), n_zap=len(F["zap"]),
                        coverage=dict(F["coverage"]), rules=R, positives=P, unprocessed=U, notes=N,
                        ki_families=dict(kif), rule_families=dict(rf),
                        both=sorted(set(kif) & set(rf)), ki_only=sorted(set(kif) - set(rf)), rule_only=sorted(set(rf) - set(kif)),
                        ki_fallback=sum(1 for f in ki if f.get("policy_id") == "SP-FALLBACK"), ki_n=len(ki)))
    os.makedirs("out", exist_ok=True)
    json.dump(out, open("out/catalog-sim.json", "w"), ensure_ascii=False, indent=1)
    # Zusammenfassung
    print(f"Orders: {len(out)}")
    allr = collections.Counter(); allk = collections.Counter(); newr = []; seen = set(); seenk = set(); newk = []
    for o in out:
        for fam in o["rule_families"]: allr[fam] += 1
        for fam in o["ki_families"]: allk[fam] += 1
        nr = set(o["rule_families"]) - seen; seen |= set(o["rule_families"]); newr.append(len(nr))
        nk = set(o["ki_families"]) - seenk; seenk |= set(o["ki_families"]); newk.append(len(nk))
    print(f"Regel-Familien gesamt: {len(allr)}  KI-Familien gesamt: {len(allk)} (davon unclassified: {sum(1 for k in allk if k.startswith('unclassified'))})")
    print("Neue Familien je Order (chronologisch), Regeln:", newr)
    print("Neue Familien je Order (chronologisch), KI:   ", newk)
    print("\nFamilie                         Regel  KI")
    for fam in sorted(set(allr) | set(allk), key=lambda f: -(allr[f] + allk[f])):
        if fam.startswith("unclassified"): continue
        print(f"{fam:32} {allr[fam]:4} {allk[fam]:4}")
    print("\nunclassified KI-Titel:")
    for k, v in allk.items():
        if k.startswith("unclassified"): print("  ", v, k)
    up = collections.Counter()
    for o in out:
        for kind, what, c in o["unprocessed"]: up[(kind, what)] += c
    print(f"\nUnverarbeitete Beobachtungen: {sum(up.values())} Vorkommen, {len(up)} verschiedene")
    for (k, w), c in up.most_common(40): print(f"  {c:3} {k:20} {w}")
    tot_both = sum(len(o["both"]) for o in out); tot_ki = sum(len(o["ki_only"]) for o in out); tot_r = sum(len(o["rule_only"]) for o in out)
    print(f"\nFamilien je Order: in beiden {tot_both}, nur KI {tot_ki}, nur Regeln {tot_r}")
    print("\nnur-KI-Familien (Regel hat nichts erzeugt):", collections.Counter(f for o in out for f in o["ki_only"]).most_common(25))
    print("\nnur-Regel-Familien (KI hat nichts erzeugt):", collections.Counter(f for o in out for f in o["rule_only"]).most_common(25))

if __name__ == "__main__":
    main()
