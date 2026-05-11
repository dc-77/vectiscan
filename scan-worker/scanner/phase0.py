"""Phase 0: DNS-Reconnaissance — Subdomain-Enumeration und Host-Gruppierung."""

import hashlib
import json
import os
import signal
import socket
import subprocess
import tempfile
import time
from collections import defaultdict
from typing import Any, Optional
from urllib.parse import urlparse

import structlog

from scanner.tools import run_tool
from scanner.progress import publish_event

log = structlog.get_logger()

PHASE0_TIMEOUT = 600  # 10 Minuten Gesamt-Timeout
MAX_HOSTS = 10

# ---------------------------------------------------------------------------
# Dangling CNAME risk classification
# ---------------------------------------------------------------------------
# Services where subdomain takeover IS possible (attacker can claim the name)
_TAKEOVER_POSSIBLE: list[tuple[str, str]] = [
    # Azure
    (".azurewebsites.net", "Azure App Service"),
    (".cloudapp.azure.com", "Azure Cloud App"),
    (".cloudapp.net", "Azure Cloud App"),
    (".azureedge.net", "Azure CDN"),
    (".trafficmanager.net", "Azure Traffic Manager"),
    (".blob.core.windows.net", "Azure Blob Storage"),
    (".azure-api.net", "Azure API Management"),
    (".azurefd.net", "Azure Front Door"),
    (".azurestaticapps.net", "Azure Static Web Apps"),
    # AWS
    (".s3.amazonaws.com", "AWS S3"),
    (".s3-website", "AWS S3 Website"),
    (".elasticbeanstalk.com", "AWS Elastic Beanstalk"),
    (".cloudfront.net", "AWS CloudFront"),
    # GitHub
    (".github.io", "GitHub Pages"),
    (".githubusercontent.com", "GitHub"),
    # Heroku
    (".herokuapp.com", "Heroku"),
    (".herokudns.com", "Heroku DNS"),
    (".herokussl.com", "Heroku SSL"),
    # Diverse
    (".shopify.com", "Shopify"),
    (".myshopify.com", "Shopify"),
    (".pantheonsite.io", "Pantheon"),
    (".netlify.app", "Netlify"),
    (".netlify.com", "Netlify"),
    (".vercel.app", "Vercel"),
    (".fly.dev", "Fly.io"),
    (".surge.sh", "Surge"),
    (".bitbucket.io", "Bitbucket"),
    (".ghost.io", "Ghost"),
    (".helpjuice.com", "Helpjuice"),
    (".helpscoutdocs.com", "HelpScout"),
    (".zendesk.com", "Zendesk"),
    (".teamwork.com", "Teamwork"),
    (".freshdesk.com", "Freshdesk"),
    (".unbounce.com", "Unbounce"),
    (".tictail.com", "Tictail"),
    (".cargocollective.com", "Cargo"),
    (".tumblr.com", "Tumblr"),
    (".wordpress.com", "WordPress.com"),
    (".readthedocs.io", "ReadTheDocs"),
]

# Services where takeover is NOT possible (provider-controlled infrastructure)
_TAKEOVER_NOT_POSSIBLE: list[tuple[str, str]] = [
    # Microsoft 365 / Lync / Skype for Business
    (".online.lync.com", "Microsoft Lync/SfB (abgeschaltet)"),
    (".lync.com", "Microsoft Lync"),
    (".outlook.com", "Microsoft 365"),
    (".microsoftonline.com", "Microsoft Entra ID"),
    (".sharepoint.com", "SharePoint Online"),
    (".office.com", "Microsoft 365"),
    (".onmicrosoft.com", "Microsoft 365 Tenant"),
    (".msappproxy.net", "Azure AD App Proxy"),
    # Google
    (".google.com", "Google Workspace"),
    (".googlemail.com", "Google Mail"),
    (".ghs.googlehosted.com", "Google Hosted"),
    # Andere kontrollierte Infrastruktur
    (".microsoft.com", "Microsoft"),
    (".windows.net", "Microsoft Azure (intern)"),
    (".office365.com", "Microsoft 365"),
]


# ---------------------------------------------------------------------------
# Generated takeover indicators (EdOverflow can-i-take-over-xyz, F-P0B-006)
# ---------------------------------------------------------------------------
# Geladen aus `data/takeover_data_generated.py` (Sync-Skript
# `scripts/sync-takeover-list.py`). Bei fehlendem Generated-File (z.B. frischer
# Checkout vor erstem Sync-Lauf) leeres Dict — Klassifikation faellt dann
# komplett auf die Manual-Listen zurueck.
try:
    from data.takeover_data_generated import (  # type: ignore[import-not-found]
        TAKEOVER_INDICATORS_GENERATED as _GENERATED_TAKEOVER,
    )
except Exception:  # noqa: BLE001 — generated-File optional zur Build-Zeit
    _GENERATED_TAKEOVER: dict[str, dict] = {}


def _build_takeover_indicators() -> list[tuple[str, str]]:
    """Kombiniert Generated-Eintraege mit Manual-Liste.

    Reihenfolge: erst Manual (`_TAKEOVER_POSSIBLE`), dann Generated.
    Suffix-Match in `_classify_dangling_cname` greift first-hit, dadurch
    haben Manual-Kuratierte automatisch Vorrang bei Suffix-Kollisionen
    (analog `saas_heuristic._build_combined_ranges()`). Pro Generated-Eintrag
    werden alle `cname_patterns` als eigenstaendige Suffixe (`.<pattern>`)
    eingetragen.
    """
    out: list[tuple[str, str]] = list(_TAKEOVER_POSSIBLE)
    seen_suffixes = {suffix for suffix, _ in _TAKEOVER_POSSIBLE}
    for slug, info in (_GENERATED_TAKEOVER or {}).items():
        service_label = info.get("service") or slug
        for cname in info.get("cname_patterns", []) or []:
            if not isinstance(cname, str) or not cname:
                continue
            suffix = cname if cname.startswith(".") else f".{cname}"
            suffix = suffix.lower()
            if suffix in seen_suffixes:
                continue
            seen_suffixes.add(suffix)
            out.append((suffix, service_label))
    return out


# Kombinierte Liste — beim Modul-Load einmal gebaut, danach read-only.
_TAKEOVER_POSSIBLE_COMBINED: list[tuple[str, str]] = _build_takeover_indicators()


def _classify_dangling_cname(cname_target: str) -> tuple[str, str]:
    """Classify a dangling CNAME target by subdomain takeover risk.

    Returns:
        (risk_level, reason) where risk_level is "high", "low", or "info".
    """
    target = cname_target.lower()

    for suffix, service in _TAKEOVER_POSSIBLE_COMBINED:
        if target.endswith(suffix):
            return "high", f"Subdomain-Takeover möglich ({service})"

    for suffix, service in _TAKEOVER_NOT_POSSIBLE:
        if target.endswith(suffix):
            return "info", f"Verwaister DNS-Eintrag, kein Takeover-Risiko ({service})"

    # Unknown target — conservative medium/low classification
    if not target:
        return "low", "CNAME-Ziel unbekannt"
    return "low", f"Verwaister DNS-Eintrag (Ziel: {cname_target})"


def run_crtsh(domain: str, scan_dir: str, order_id: str) -> list[str]:
    """Query crt.sh for certificate transparency subdomains. Timeout 60s.

    Mit 3-Stufen-Self-Retry: crt.sh ist berüchtigt instabil (HTTP 502 / leere
    Antworten trotz HTTP 200). curl `--retry 2` zaehlt nur Connection-Fehler,
    nicht „leerer Response trotz 200". Wir wiederholen daher bis zu 3x mit
    exponentiellem Backoff (5s, 15s, 30s) und akzeptieren erst wenn JSON
    parsbar UND len(entries) > 0 ist.

    Falls am Ende dennoch leer: leere Liste zurueckgeben — der Caller
    (run_certificate_transparency) ruft dann certspotter als Fallback.
    """
    publish_event(order_id, {"type": "tool_starting", "tool": "crtsh", "host": domain})
    output_path = os.path.join(scan_dir, "phase0", "crtsh_raw.json")
    parsed_path = os.path.join(scan_dir, "phase0", "crtsh.json")
    subdomains: list[str] = []

    # 3-Stufen-Self-Retry mit exponentiellem Backoff. Erfolg = JSON parsbar
    # UND mindestens ein Eintrag (entries > 0). curl `--retry` zaehlt nur
    # Connection-Fehler, nicht „leere Antwort trotz HTTP 200" — daher hier
    # in Python.
    backoffs = [0, 5, 15]  # erste Sekunde sofort, dann 5s, dann 15s
    last_attempt = 0
    for attempt, sleep_s in enumerate(backoffs, start=1):
        if sleep_s:
            log.info("crtsh_retry_backoff", attempt=attempt, sleep_s=sleep_s)
            time.sleep(sleep_s)
        last_attempt = attempt

        cmd = [
            "curl", "-s",
            "--max-time", "30",
            "--retry", "1",
            "--retry-delay", "3",
            "--retry-connrefused",
            "-A", "Mozilla/5.0 vectiscan",
            "-o", output_path,
            f"https://crt.sh/?q=%.{domain}&output=json",
        ]
        exit_code, duration_ms = run_tool(
            cmd=cmd,
            timeout=60,
            output_path=output_path,
            order_id=order_id,
            phase=0,
            tool_name="crtsh" if attempt == 1 else f"crtsh_retry{attempt}",
        )

        if exit_code != 0:
            log.warning("crtsh_curl_failed", attempt=attempt, exit_code=exit_code)
            continue

        try:
            with open(output_path, "r") as f:
                raw = f.read().strip()
            if not raw:
                log.warning("crtsh_empty_response", attempt=attempt)
                continue
            entries = json.loads(raw)
            if not entries:
                log.warning("crtsh_zero_entries", attempt=attempt)
                continue
            seen: set[str] = set()
            for entry in entries:
                name_value = entry.get("name_value", "")
                for name in name_value.split("\n"):
                    name = name.strip().lower()
                    if name.startswith("*."):
                        name = name[2:]
                    if name and (name.endswith(f".{domain}") or name == domain):
                        seen.add(name)
            subdomains = sorted(seen)
            with open(parsed_path, "w") as f:
                json.dump({"subdomains": subdomains, "raw_count": len(entries)}, f, indent=2)
            log.info("crtsh_complete", subdomains_found=len(subdomains), attempts_used=attempt)
            break  # Erfolg
        except (json.JSONDecodeError, FileNotFoundError, Exception) as e:
            log.warning("crtsh_parse_error", attempt=attempt, error=str(e))
            continue

    if not subdomains:
        log.warning("crtsh_all_attempts_failed", attempts=last_attempt)

    return subdomains


# F-P0A-004 (Mai 2026): `run_securitytrails_subdomains` entfernt.
# Phase 0a uebernimmt SecurityTrails-Aufrufe (parallel zu shodan/whois);
# die Subdomains kommen ueber `seed_subdomains` an `run_phase0`.
# Doppel-Call gegen SecurityTrails-Free-Tier (50 Calls/mo) entfernt.


def run_certspotter(domain: str, scan_dir: str, order_id: str) -> list[str]:
    """Cert-Transparency-Fallback ueber SSLMate certspotter API.

    Wird aufgerufen wenn crt.sh komplett leer geblieben ist. Liefert in der
    Regel dasselbe Subdomain-Set, in seltenen Faellen mehr (certspotter
    indexiert auch Issuances die crt.sh noch nicht eingelesen hat).
    """
    publish_event(order_id, {"type": "tool_starting", "tool": "certspotter", "host": domain})
    output_path = os.path.join(scan_dir, "phase0", "certspotter.json")
    started = time.monotonic()

    subdomains: list[str] = []
    error: Optional[str] = None
    try:
        from scanner.passive.certspotter_client import CertSpotterClient
        client = CertSpotterClient()
        subdomains = client.get_subdomains(domain)
        log.info("certspotter_complete", subdomains_found=len(subdomains))
    except Exception as e:
        error = str(e)
        log.warning("certspotter_error", error=error)

    duration_ms = int((time.monotonic() - started) * 1000)
    # Persistiere als scan_results-Eintrag fuer Audit
    try:
        payload = {"subdomains": subdomains, "error": error}
        with open(output_path, "w") as f:
            json.dump(payload, f, indent=2)
        from scanner.tools import _save_result
        _save_result(
            order_id=order_id, host_ip=None, phase=0,
            tool_name="certspotter",
            raw_output=json.dumps(payload, ensure_ascii=False),
            exit_code=0 if not error else 1,
            duration_ms=duration_ms,
        )
    except Exception as e:
        log.warning("certspotter_save_error", error=str(e))

    return subdomains


def run_subfinder(domain: str, scan_dir: str, order_id: str) -> list[str]:
    """Run subfinder for passive subdomain enumeration. Timeout 120s."""
    publish_event(order_id, {"type": "tool_starting", "tool": "subfinder", "host": domain})
    output_path = os.path.join(scan_dir, "phase0", "subfinder.json")
    subdomains: list[str] = []

    # F-P0B-002 (Mai 2026): `-all` durch explizite `-sources`-Liste mit
    # Free-Providern ersetzen. Begruendung: Container hat keinen
    # provider-config.yaml — Premium-Provider (Chaos, BinaryEdge, Censys,
    # GitHub, ZoomEye, Shodan, SecurityTrails) wurden silent geskippt.
    # Explizite Liste macht Coverage sichtbar und audit-faehig. Premium-
    # Provider werden orthogonal ueber Phase 0a abgedeckt.
    # Quelle: docs/scan-flow/Scan-Optimierung.md §3.3.1 (F-P0B-002).
    _SUBFINDER_FREE_SOURCES = ",".join([
        "crtsh", "hackertarget", "wayback", "dnsdumpster", "alienvault",
        "anubis", "bevigil", "bufferover", "cero", "certspotter",
        "commoncrawl", "digitorus", "dnsrepo", "fofa", "fullhunt",
        "hudsonrock", "leakix", "passivetotal", "quake", "rapiddns",
        "sitedossier", "subdomaincenter", "threatbook", "virustotal",
        "waybackarchive", "whoisxmlapi", "zoomeyeapi",
    ])
    cmd = [
        "subfinder", "-d", domain,
        "-silent", "-json",
        "-disable-update-check",
        "-sources", _SUBFINDER_FREE_SOURCES,
        # `-recursive` enumeriert auch Subdomains-of-Subdomains
        # (z.B. wenn `mail.example.com` gefunden, sucht nach `*.mail.example.com`).
        "-recursive",
        # Mehr Threads → schneller bei vielen Sources
        "-t", "50",
        # Timeout pro Provider in Sekunden — verhindert Haenger
        "-timeout", "15",
        "-o", output_path,
    ]
    exit_code, duration_ms = run_tool(
        cmd=cmd,
        timeout=180,
        output_path=output_path,
        order_id=order_id,
        phase=0,
        tool_name="subfinder",
    )

    if exit_code not in (0,):
        log.warning("subfinder_failed", exit_code=exit_code)

    # Parse JSON lines output
    try:
        if os.path.exists(output_path):
            with open(output_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        host = entry.get("host", "").strip().lower()
                        if host:
                            subdomains.append(host)
                    except json.JSONDecodeError:
                        continue
            log.info("subfinder_complete", subdomains_found=len(subdomains))
    except Exception as e:
        log.warning("subfinder_parse_error", error=str(e))

    return subdomains


# F-P0B-003 (2026-05-07): amass v5 entfernt.
# Begruendung: Hard-Cap-Bottleneck (300s in 1/30 Aufrufen) + redundant zu
# `gobuster_dns` durch `-brute`-Workaround fuer den v5-Race-Bug. Der
# `gobuster_dns`-Pfad nutzt jetzt eine ~30k-Merged-Wordlist (F-P0B-004),
# womit die Permutation-/Brute-Force-Coverage deutlich groesser ist als
# die ~5k von amass-`-brute`. Erwarteter Subdomain-Coverage-Verlust <5%
# (nur amass-Permutation-Heuristiken wie ALTRA/dns-permute fallen weg).
# Snapshot-Schema (Migration 019) bleibt kompatibel — bestehende
# `tool_sources["amass"]`-Eintraege koennen liegen bleiben, neue
# Snapshots haben den Key nicht mehr.


# F-P0B-004 (2026-05-07): Merged-Subdomain-Wordlist
# SecLists-20k + bitquark-10k + n0kovo-small werden zur Build-Zeit im
# Dockerfile gemerged + dedupliziert (~30k Eintraege). Loest die
# zu enge `subdomains-top5000.txt` ab — moderne SaaS-/DevOps-Patterns
# (api-v2, argocd, vault, webhook, staging-eu, ...) sind jetzt drin.
GOBUSTER_DNS_WORDLIST_PATH = "/opt/wordlists/dns-merged-30k.txt"


def run_gobuster_dns(domain: str, scan_dir: str, order_id: str) -> list[str]:
    """Run gobuster DNS brute-force. Timeout 180s (3 Min).

    F-P0B-004 (2026-05-07): nutzt die zur Build-Zeit gemergte ~30k-Wordlist
    (`/opt/wordlists/dns-merged-30k.txt`), Threads 30 (statt 50) +
    Per-Query-Timeout 3s (statt 5s) als Compromise zwischen Speed und
    Customer-NS-Friendliness.
    """
    publish_event(order_id, {"type": "tool_starting", "tool": "gobuster_dns", "host": domain})
    output_path = os.path.join(scan_dir, "phase0", "gobuster_dns.txt")
    subdomains: list[str] = []

    cmd = [
        "gobuster", "dns",
        "--domain", domain,
        "--wordlist", GOBUSTER_DNS_WORDLIST_PATH,
        # Wildcard-DNS (Domain antwortet auf *.domain mit gleicher IP) bricht
        # gobuster sonst ab. Mit `--wildcard` versucht gobuster trotzdem zu
        # enumerieren und filtert die Wildcard-IP heraus. Bergersysteme.com
        # ist genau so ein Fall (alles 176.9.21.52).
        "--wildcard",
        # F-P0B-004: 30 Threads (statt 50) + 3s Per-Query-Timeout (statt 5s).
        # Compromise zwischen Speed (~500 Q/s) und Customer-NS-Friendliness.
        # Bei ~30k Wordlist-Groesse bleibt Worst-Case ~50-90s, max ~120-150s
        # bei langsamen NS — unter dem 180s Wrapper-Timeout.
        "--threads", "30",
        "--timeout", "3s",
        "-q",
        "-o", output_path,
    ]
    exit_code, duration_ms = run_tool(
        cmd=cmd,
        timeout=180,
        output_path=output_path,
        order_id=order_id,
        phase=0,
        tool_name="gobuster_dns",
    )

    if exit_code not in (0,):
        log.warning("gobuster_dns_failed", exit_code=exit_code)

    # Parse text output: "Found: sub.example.com" or just "sub.example.com"
    try:
        if os.path.exists(output_path):
            with open(output_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    # gobuster output: "Found: subdomain.example.com"
                    if line.startswith("Found:"):
                        host = line.split("Found:")[-1].strip().lower()
                    else:
                        host = line.strip().lower()
                    if host:
                        subdomains.append(host)
            log.info("gobuster_dns_complete", subdomains_found=len(subdomains))
    except Exception as e:
        log.warning("gobuster_dns_parse_error", error=str(e))

    return subdomains


def run_zone_transfer(domain: str, scan_dir: str, order_id: str) -> dict[str, Any]:
    """Attempt DNS zone transfer via AXFR. Timeout 30s per NS."""
    publish_event(order_id, {"type": "tool_starting", "tool": "axfr", "host": domain})
    output_path = os.path.join(scan_dir, "phase0", "zone_transfer.txt")
    result_data: dict[str, Any] = {"success": False, "data": {}}
    all_output: list[str] = []

    # Step 1: resolve NS records
    try:
        # @1.1.1.1 — fixierter Resolver, siehe scanner/resolvers.txt.
        # Ohne Fixierung wechselt System-DNS zwischen Resolvern und liefert
        # bei manchen Domains leicht andere NS-Listen pro Lauf.
        ns_result = subprocess.run(
            ["dig", "@1.1.1.1", "NS", domain, "+short", "+tries=2", "+time=5"],
            capture_output=True, text=True, timeout=15,
            start_new_session=True,
        )
        nameservers = [
            ns.strip().rstrip(".")
            for ns in ns_result.stdout.strip().split("\n")
            if ns.strip()
        ]
    except Exception as e:
        log.warning("zone_transfer_ns_lookup_failed", error=str(e))
        return result_data

    if not nameservers:
        log.info("zone_transfer_no_ns", domain=domain)
        return result_data

    log.info("zone_transfer_attempting", nameservers=nameservers)

    # Step 2: try AXFR against each NS
    for ns in nameservers:
        cmd = ["dig", f"@{ns}", domain, "AXFR", "+tries=1", "+time=10"]

        try:
            axfr_proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, start_new_session=True,
            )
            output, _ = axfr_proc.communicate(timeout=30)
            all_output.append(f"=== NS: {ns} ===\n{output}\n")

            # Check if transfer succeeded (contains actual records, not just SOA)
            lines = [
                l for l in output.split("\n")
                if l.strip() and not l.startswith(";")
            ]
            if len(lines) > 2:  # More than just SOA records = successful transfer
                result_data["success"] = True
                result_data["data"][ns] = output
                log.warning("zone_transfer_success", ns=ns, domain=domain)
        except subprocess.TimeoutExpired:
            if axfr_proc is not None:
                try:
                    os.killpg(axfr_proc.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    axfr_proc.kill()
                axfr_proc.wait()
            all_output.append(f"=== NS: {ns} === TIMEOUT\n")
            log.warning("zone_transfer_timeout", ns=ns)
        except Exception as e:
            all_output.append(f"=== NS: {ns} === ERROR: {e}\n")
            log.warning("zone_transfer_error", ns=ns, error=str(e))

    # Save all output
    try:
        with open(output_path, "w") as f:
            f.write("\n".join(all_output))
    except Exception as e:
        log.warning("zone_transfer_save_error", error=str(e))

    return result_data


def run_dnsx(subdomains: list[str], scan_dir: str, order_id: str) -> list[dict[str, Any]]:
    """Validate subdomains with dnsx and resolve IPs. Timeout 60s."""
    publish_event(order_id, {"type": "tool_starting", "tool": "dnsx", "host": ""})
    output_path = os.path.join(scan_dir, "phase0", "dnsx_validation.json")
    validated: list[dict[str, Any]] = []

    if not subdomains:
        log.info("dnsx_skip", reason="no subdomains to validate")
        return validated

    # Write subdomains to temp file
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
            tmp.write("\n".join(subdomains))
            tmp_path = tmp.name
    except Exception as e:
        log.error("dnsx_tempfile_error", error=str(e))
        return validated

    # Fixierte Resolver-Liste eliminiert die Resolver-Wahl-Drift
    # (System-Default kann zwischen 8.8.8.8 / 1.1.1.1 / 9.9.9.9
    # rotieren → unterschiedliche Antwort-Sets pro Lauf).
    resolvers_path = os.path.join(os.path.dirname(__file__), "resolvers.txt")
    try:
        cmd = [
            "dnsx",
            "-l", tmp_path,
            # Erweitertes Record-Set: MX/NS/TXT brauchen wir fuer
            # Email-Security-Findings ohnehin in dns_records — hier
            # konsolidieren statt extra `dig`-Calls.
            "-a", "-aaaa", "-cname", "-mx", "-ns", "-txt",
            "-resp", "-json",
            # Fixierte Resolver (siehe Kommentar oben)
            "-r", resolvers_path,
            # Rate-Limit pro Sekunde — bei 200+ Subdomains wuerde
            # Default-Speed Resolver throtteln.
            "-rl", "100",
            # Retry pro Query: bei UDP-Packet-Loss kein false-negative
            "-retry", "2",
            "-o", output_path,
        ]
        exit_code, duration_ms = run_tool(
            cmd=cmd,
            timeout=60,
            output_path=output_path,
            order_id=order_id,
            phase=0,
            tool_name="dnsx",
        )

        if exit_code not in (0,):
            log.warning("dnsx_failed", exit_code=exit_code)

        # Parse JSON lines output
        if os.path.exists(output_path):
            with open(output_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        validated.append(entry)
                    except json.JSONDecodeError:
                        continue

        log.info("dnsx_complete", validated_count=len(validated))

    except Exception as e:
        log.warning("dnsx_parse_error", error=str(e))
    finally:
        # Clean up temp file
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    return validated


def collect_dns_records(domain: str, scan_dir: str, order_id: str) -> dict[str, Any]:
    """Collect SPF, DMARC, DKIM, MX, NS records via dig. Saves to dns_records.json."""
    output_path = os.path.join(scan_dir, "phase0", "dns_records.json")
    records: dict[str, Any] = {
        "spf": None,
        "dmarc": None,
        "dmarc_policy": None,  # strukturierter DMARC-Parser (F-P0A-002)
        "dkim": False,
        "dkim_selectors": [],
        "mx": [],
        "ns": [],
    }

    def _dig_query(qname: str, qtype: str, timeout: int = 10) -> str:
        """Run a dig query and return stdout."""
        try:
            # @1.1.1.1 — fixierter Resolver fuer SPF/DMARC/MX/NS. Diese
            # Werte sind autoritativ, aber System-DNS kann gecachte stale
            # Antworten liefern. Cloudflare-DNS ist global konsistent.
            result = subprocess.run(
                ["dig", "@1.1.1.1", qname, qtype, "+short", "+tries=2", "+time=5"],
                capture_output=True, text=True, timeout=timeout,
                start_new_session=True,
            )
            return result.stdout.strip()
        except Exception as e:
            log.warning("dig_query_error", qname=qname, qtype=qtype, error=str(e))
            return ""

    # SPF (TXT record)
    try:
        txt_output = _dig_query(domain, "TXT")
        for line in txt_output.split("\n"):
            line = line.strip().strip('"')
            if "v=spf1" in line.lower():
                records["spf"] = line
                break
    except Exception as e:
        log.warning("spf_lookup_error", error=str(e))

    # DMARC — F-P0A-002: structured parser via mail_security_parsers.
    # Wir behalten das raw-`dmarc`-Feld (rueckwaertskompatibel fuer Reporter
    # und Phase-3-Korrelation), ergaenzen aber `dmarc_policy` mit
    # strukturierten Feldern (p, sp, pct, rua, ruf, aspf, adkim).
    try:
        from scanner.passive.mail_security_parsers import (
            check_dmarc_policy,
        )
        dmarc_policy = check_dmarc_policy(domain)
        if dmarc_policy.get("dmarc_present"):
            records["dmarc"] = dmarc_policy.get("raw")
        records["dmarc_policy"] = dmarc_policy
    except Exception as e:
        log.warning("dmarc_lookup_error", error=str(e))
        records.setdefault("dmarc_policy", None)

    # DKIM — F-P0B-001 (2026-05-07): Selektoren-Probe parallel
    # (ThreadPoolExecutor max_workers=10) + erweiterte Liste fuer
    # ESP/SaaS und DE-Provider (SES, Postmark, Mailgun, Mailjet, Brevo,
    # Zoho, IONOS, STRATO, T-Online, GMX, ...).
    # Vorher (2026-05-03 FIX): 25 Selektoren sequenziell — `for sel in
    # DKIM_SELECTORS` Worst-Case 5-12s. Jetzt: ~44 Selektoren parallel,
    # Worst-Case <2s gegen FIXED_NAMESERVERS (Cloudflare/Google/Quad9).
    # Liste deduplizieren (Set) — manche Selektoren tauchen in mehreren
    # Provider-Categories auf (z.B. selector1/selector2 fuer M365 + IONOS).
    DKIM_SELECTORS = sorted({
        # Klassisch / generisch
        "default", "selector", "mail", "dkim", "email",
        "key1", "key2", "primary", "secondary",
        # Microsoft 365
        "selector1", "selector2",
        # Google Workspace
        "google", "googledomains",
        # Mailchimp
        "k1", "k2", "mandrill",
        # SendGrid
        "s1", "s2", "smtpapi", "s2048", "s1024",
        # Hornetsecurity
        "hse1", "hse2",
        # Amazon SES
        "amazonses", "mxvault",
        # Postmark
        "pm", "postmark",
        # Mailgun
        "mg", "mailgun", "mailo", "smtp",
        # Mailjet
        "mailjet", "mj",
        # Brevo (ehem. Sendinblue)
        "brevo", "sib", "mailin", "sendinblue",
        # Zoho
        "zoho", "zmail",
        # SparkPost
        "scph", "scph0123", "scph0124", "pf2014",
        # IONOS / 1&1
        "1und1", "ionos1", "ionos2",
        # STRATO
        "strato1", "strato2",
        # DE-Mailprovider
        "t-online", "gmx",
        # Konvention numbered selectors
        "dkim1", "dkim-1", "dkim01", "dkim2", "dkim-2",
        # Postfix-Variation
        "mta", "mta1", "mta2", "fd", "fd2",
        # PGP-style sigs
        "sig1", "sig2",
    })
    found_selectors: list[str] = []

    def _probe_dkim(sel: str) -> str | None:
        try:
            out = _dig_query(f"{sel}._domainkey.{domain}", "TXT")
            if out and "v=dkim1" in out.lower():
                return sel
        except Exception:
            return None
        return None

    try:
        from concurrent.futures import ThreadPoolExecutor, as_completed
        with ThreadPoolExecutor(
            max_workers=10, thread_name_prefix="dkim_probe",
        ) as pool:
            futures = {pool.submit(_probe_dkim, sel): sel for sel in DKIM_SELECTORS}
            for fut in as_completed(futures):
                try:
                    sel = fut.result()
                except Exception:
                    sel = None
                if sel:
                    found_selectors.append(sel)
    except Exception as e:
        log.warning("dkim_parallel_error", error=str(e))

    # Deterministisches Sort (parallel-Order ist nicht stable).
    found_selectors = sorted(set(found_selectors))
    records["dkim"] = bool(found_selectors)
    records["dkim_selectors"] = found_selectors
    if found_selectors:
        log.info("dkim_selectors_found", domain=domain, selectors=found_selectors)
    else:
        log.info("dkim_no_selectors_found", domain=domain,
                 probed=len(DKIM_SELECTORS))

    # MX records
    try:
        mx_output = _dig_query(domain, "MX")
        for line in mx_output.split("\n"):
            line = line.strip()
            if line:
                # MX output: "10 mx1.example.com."
                parts = line.split()
                if len(parts) >= 2:
                    records["mx"].append(parts[-1].rstrip("."))
                else:
                    records["mx"].append(line.rstrip("."))
    except Exception as e:
        log.warning("mx_lookup_error", error=str(e))

    # NS records
    try:
        ns_output = _dig_query(domain, "NS")
        for line in ns_output.split("\n"):
            line = line.strip().rstrip(".")
            if line:
                records["ns"].append(line)
    except Exception as e:
        log.warning("ns_lookup_error", error=str(e))

    # Save result and log to DB
    try:
        with open(output_path, "w") as f:
            json.dump(records, f, indent=2)
    except Exception as e:
        log.warning("dns_records_save_error", error=str(e))

    run_tool(
        cmd=["echo", "dns_records_collected"],
        timeout=5,
        order_id=order_id,
        phase=0,
        tool_name="dns_records",
    )

    log.info("dns_records_complete", records=records)
    return records


_MAIL_PREFIXES = ("mail.", "email.", "mx.", "smtp.", "imap.", "pop.",
                   "autodiscover.", "exchange.", "webmail.", "fin-mail.")


def _sort_fqdns_by_relevance(fqdns: list[str], domain: str) -> list[str]:
    """Sort FQDNs by scanning relevance: base domain first, www second, mail last."""
    domain_lower = domain.lower()

    def priority(fqdn: str) -> int:
        f = fqdn.lower()
        if f == domain_lower:
            return 0  # Base domain always first
        if f == f"www.{domain_lower}":
            return 1  # www second
        if any(f.startswith(p) for p in _MAIL_PREFIXES):
            return 9  # Mail FQDNs last
        return 5  # Everything else in the middle

    return sorted(fqdns, key=lambda f: (priority(f), f))


def _is_mail_only_fqdn(fqdn: str) -> bool:
    """Check if an FQDN is purely mail-related."""
    return any(fqdn.lower().startswith(p) for p in _MAIL_PREFIXES)


def _collapse_cdn_edge_ips(hosts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """B2: Kollabiert IPs gleicher CDN/Cloud-Range mit identischem FQDN-Set
    zu einem logischen Host.

    Beispiel: Cloudflare-Round-Robin fuer online.heuel.com liefert mal
    104.16.10.6, mal 104.16.11.6. Beide sind CF-Edges fuer denselben
    Service → werden zu einem Host mit primary_ip + edge_ips-Liste.

    Heuristik (F-P0B-005, Mai 2026 angepasst): rdns-Suffix-Match VOR
    IP-Range-Pruefung — damit Fastly/Akamai-Edges deren IP-Ranges nicht in
    `_STATIC_RANGES` stehen (oder rotieren) trotzdem korrekt dedupliziert
    werden. Suffix-Match statt Substring-Match (endswith) verhindert
    False-Positives bei Customer-rdns wie `cdn-cloudflare-failover.kunde.de`.

    Mergen NUR wenn:
      (a) selber Provider (rdns-Suffix-Match ODER IP-Range-Match)
      (b) gleicher fqdn-Set
      (c) Maschinen-rdns (kein Provider-Match) → nicht mergen
    """
    try:
        from scanner.precheck.saas_heuristic import (
            detect_cloud_provider,
            detect_provider_by_rdns,
        )
    except Exception:
        return hosts

    # Gruppiere nach (provider, frozenset(fqdns))
    groups: dict[tuple[str, frozenset], list[dict[str, Any]]] = {}
    standalone: list[dict[str, Any]] = []
    for h in hosts:
        rdns = (h.get("rdns") or "").lower().rstrip(".")
        # 1) rdns-Suffix-Match zuerst — deckt Fastly/Akamai-Edges ab,
        #    deren IP nicht in `_STATIC_RANGES` ist.
        provider: Optional[str] = detect_provider_by_rdns(rdns) if rdns else None

        # 2) Fallback: IP-Range-Match (nur wenn rdns leer ODER kein
        #    Provider-Suffix-Match). Eine eigene Maschinen-rdns
        #    (`webserver01.kunde.de`) verhindert den Merge — die IP gehoert
        #    moeglicherweise einer Cloud-Range, aber der Server hat eigene
        #    Identitaet.
        if not provider and not rdns:
            provider = detect_cloud_provider(h.get("ip", ""))

        if not provider:
            standalone.append(h)
            continue

        key = (provider, frozenset(f.lower() for f in (h.get("fqdns") or [])))
        groups.setdefault(key, []).append(h)

    out: list[dict[str, Any]] = list(standalone)
    for (provider, _fqdns), group in groups.items():
        if len(group) == 1:
            out.append(group[0])
            continue
        # Mehrere IPs gleicher Range + gleicher FQDNs → kollabieren
        primary = group[0]  # erste IP als kanonisch
        edge_ips = sorted(h["ip"] for h in group)
        primary["edge_ips"] = edge_ips
        primary["cdn_provider"] = provider
        log.info("cdn_edge_collapse", provider=provider,
                 primary_ip=primary["ip"], edge_count=len(edge_ips),
                 fqdns=list(primary.get("fqdns", []))[:3])
        out.append(primary)
    return out


def merge_and_group(
    domain: str,
    all_subdomains: list[str],
    dnsx_results: list[dict[str, Any]],
    dns_records: dict[str, Any],
    zone_transfer: dict[str, Any],
    scan_dir: str,
    max_hosts: int = 10,
) -> dict[str, Any]:
    """Deduplicate subdomains, group by IP, create host_inventory.json."""
    output_path = os.path.join(scan_dir, "phase0", "host_inventory.json")

    # Deduplicate subdomains and filter invalid DNS labels (>63 chars per label)
    unique_subs = sorted(set(s.lower().rstrip(".") for s in all_subdomains if s))
    invalid = [s for s in unique_subs if any(len(label) > 63 for label in s.split("."))]
    if invalid:
        log.warning("invalid_dns_labels_filtered", count=len(invalid), examples=invalid[:3])
        unique_subs = [s for s in unique_subs if not any(len(label) > 63 for label in s.split("."))]
    log.info("merge_dedup", total_raw=len(all_subdomains), unique=len(unique_subs))

    # Group by IP from dnsx results
    ip_to_fqdns: dict[str, set[str]] = defaultdict(set)
    dnsx_resolved: set[str] = set()  # Track which FQDNs dnsx handled
    dangling_candidates: list[dict[str, Any]] = []  # {fqdn, cname_target}

    for entry in dnsx_results:
        host = entry.get("host", "").lower().rstrip(".")
        if not host:
            continue
        dnsx_resolved.add(host)

        # Collect A record IPs
        a_records = entry.get("a", [])
        aaaa_records = entry.get("aaaa", [])
        cname = entry.get("cname", [])

        ips = (a_records or []) + (aaaa_records or [])

        if ips:
            for ip in ips:
                ip_to_fqdns[ip].add(host)
        elif cname and not ips:
            # CNAME exists but dnsx didn't return the final A record —
            # resolve via socket fallback instead of discarding the FQDN
            target = cname[0].lower().rstrip(".") if cname else ""
            dangling_candidates.append({"fqdn": host, "cname_target": target})

    # --- Socket fallback for dangling CNAMEs ---
    # dnsx sometimes returns CNAME without following it to the A record.
    # Resolve these via socket so FQDNs are correctly assigned to hosts.
    resolved_danglings = 0
    true_danglings: list[dict[str, Any]] = []
    for entry in dangling_candidates:
        fqdn = entry["fqdn"]
        # Skip FQDNs with invalid DNS labels (>63 chars) — getaddrinfo
        # uses IDNA encoding which raises UnicodeError for these
        if any(len(label) > 63 for label in fqdn.split(".")):
            true_danglings.append(entry)
            continue
        old_timeout = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(5)
            infos = socket.getaddrinfo(fqdn, None, proto=socket.IPPROTO_TCP)
            resolved_ips = sorted({info[4][0] for info in infos})
            for ip in resolved_ips:
                ip_to_fqdns[ip].add(fqdn)
            resolved_danglings += 1
        except (socket.gaierror, socket.timeout, OSError, UnicodeError):
            true_danglings.append(entry)  # Truly unresolvable
        finally:
            socket.setdefaulttimeout(old_timeout)

    # Classify dangling CNAMEs by takeover risk
    dangling_cnames: list[dict[str, Any]] = []
    for entry in true_danglings:
        target = entry["cname_target"]
        risk, reason = _classify_dangling_cname(target)
        dangling_cnames.append({
            "fqdn": entry["fqdn"],
            "cname_target": target,
            "takeover_risk": risk,
            "reason": reason,
        })

    if resolved_danglings:
        log.info("dangling_cname_resolved", count=resolved_danglings,
                 still_dangling=len(dangling_cnames))

    # --- Socket fallback for subdomains dnsx missed entirely ---
    # dnsx may skip subdomains due to timeout or rate-limiting.
    # Resolve any enumerated subdomains that aren't in dnsx output.
    missed_subs = [s for s in unique_subs if s not in dnsx_resolved]
    resolved_missed = 0
    if missed_subs:
        for fqdn in missed_subs:
            if any(len(label) > 63 for label in fqdn.split(".")):
                continue
            old_timeout = socket.getdefaulttimeout()
            try:
                socket.setdefaulttimeout(5)
                infos = socket.getaddrinfo(fqdn, None, proto=socket.IPPROTO_TCP)
                resolved_ips = sorted({info[4][0] for info in infos})
                for ip in resolved_ips:
                    ip_to_fqdns[ip].add(fqdn)
                resolved_missed += 1
            except (socket.gaierror, socket.timeout, OSError, UnicodeError):
                pass  # Subdomain doesn't resolve — expected for stale entries
            finally:
                socket.setdefaulttimeout(old_timeout)
        if resolved_missed:
            log.info("missed_subs_resolved", total_missed=len(missed_subs),
                     resolved=resolved_missed)

    # Ensure base domain is present — fallback via socket if still missing
    domain_in_results = any(
        domain.lower() in (h.lower().rstrip(".") for h in fqdns)
        for fqdns in ip_to_fqdns.values()
    )
    if not domain_in_results:
        old_timeout = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(10)
            infos = socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP)
            fallback_ips = sorted({info[4][0] for info in infos})
            for fb_ip in fallback_ips:
                ip_to_fqdns[fb_ip].add(domain.lower())
            log.info("base_domain_fallback", domain=domain, ips=fallback_ips)
        except (socket.gaierror, socket.timeout, OSError, UnicodeError) as e:
            log.warning("base_domain_resolve_failed", domain=domain, error=str(e))
        finally:
            socket.setdefaulttimeout(old_timeout)

    # ── Deduplicate IPs sharing the same FQDN set ─────────────
    # Multiple IPs (especially IPv6 variants) often serve the same FQDNs.
    # Group by FQDN set, keep one representative IP per group (prefer IPv4).
    fqdn_groups: dict[frozenset[str], list[str]] = defaultdict(list)
    for ip, fqdns in ip_to_fqdns.items():
        fqdn_groups[frozenset(fqdns)].append(ip)

    deduped_ip_to_fqdns: dict[str, set[str]] = {}
    deduped_count = 0
    for fqdn_set, ips in fqdn_groups.items():
        if len(ips) == 1:
            deduped_ip_to_fqdns[ips[0]] = set(fqdn_set)
        else:
            # Prefer IPv4 over IPv6, then alphabetisch sortiert.
            # CloudFlare/AnyCast-Dienste rotieren die DNS-Antwort-
            # Reihenfolge bei jeder Anfrage (z.B. 104.16.10.6 in R1,
            # 104.16.11.6 in R2). Ohne Sortierung waere die "Repraesentanten-
            # IP" damit nicht-deterministisch und das gesamte host_inventory
            # driftet. Mit `sorted(ipv4)[0]` haben wir immer die kleinste
            # IP als Repraesentant.
            ipv4 = sorted(ip for ip in ips if ":" not in ip)
            representative = ipv4[0] if ipv4 else sorted(ips, key=len)[0]
            deduped_ip_to_fqdns[representative] = set(fqdn_set)
            deduped_count += len(ips) - 1

    if deduped_count:
        log.info("hosts_deduped", removed=deduped_count,
                 before=len(ip_to_fqdns), after=len(deduped_ip_to_fqdns))

    # Build hosts list
    hosts: list[dict[str, Any]] = []
    for ip, fqdns in sorted(deduped_ip_to_fqdns.items()):
        # Attempt reverse DNS (with 5s timeout to prevent hangs)
        rdns = ""
        old_timeout = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(5)
            rdns = socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, socket.timeout, OSError):
            pass
        finally:
            socket.setdefaulttimeout(old_timeout)

        hosts.append({
            "ip": ip,
            "fqdns": _sort_fqdns_by_relevance(list(fqdns), domain),
            "rdns": rdns,
        })

    # B2 (Mai 2026): CDN-Edge-IPs gleichen Providers + gleicher FQDN-Set zu
    # einem logischen Host kollabieren. Verhindert Round-Robin-Drift wie
    # Cloudflare 104.16.10.6 vs 104.16.11.6 fuer denselben Service.
    hosts = _collapse_cdn_edge_ips(hosts)

    # Prioritize hosts: base domain first, unique services high, cloud noise low
    _CLOUD_ONLY_PREFIXES = (
        "autodiscover.", "enterpriseregistration.", "enterpriseenrollment.",
        "lyncdiscover.", "sip.", "msoid.", "selector1._domainkey.",
        "selector2._domainkey.", "_dmarc.",
    )

    def _host_priority(host: dict[str, Any]) -> tuple[int, int, str]:
        fqdns_lower = [f.lower() for f in host["fqdns"]]
        num_fqdns = len(fqdns_lower)

        # Priority 0: host that serves the base domain itself
        if domain.lower() in fqdns_lower:
            return (0, -num_fqdns, host["ip"])
        # Priority 1: www subdomain
        if f"www.{domain.lower()}" in fqdns_lower:
            return (1, -num_fqdns, host["ip"])

        # Priority 4: pure cloud/MDM service hosts (all FQDNs are cloud prefixes)
        if all(any(f.startswith(p) for p in _CLOUD_ONLY_PREFIXES) for f in fqdns_lower):
            return (4, -num_fqdns, host["ip"])

        # Priority 3: mail/autodiscover/mx — deprioritize
        mail_keywords = ("mail.", "mx.", "smtp.", "imap.", "pop.", "autodiscover.", "exchange.")
        if all(any(f.startswith(kw) for kw in mail_keywords) for f in fqdns_lower):
            return (3, -num_fqdns, host["ip"])

        # Priority 2: business hosts — more FQDNs = more important (negative for ascending sort)
        return (2, -num_fqdns, host["ip"])

    hosts.sort(key=_host_priority)

    # Limit to max_hosts
    skipped_hosts: list[dict[str, Any]] = []
    if len(hosts) > max_hosts:
        log.warning("hosts_limited", total=len(hosts), max=max_hosts,
                    kept=[h["ip"] for h in hosts[:max_hosts]],
                    skipped=[h["ip"] for h in hosts[max_hosts:]])
        skipped_hosts = hosts[max_hosts:]
        hosts = hosts[:max_hosts]

    inventory: dict[str, Any] = {
        "domain": domain,
        "hosts": hosts,
        "dns_findings": {
            "zone_transfer": zone_transfer.get("success", False),
            "spf": dns_records.get("spf"),
            "dmarc": dns_records.get("dmarc"),
            "dkim": dns_records.get("dkim", False),
            "mx": dns_records.get("mx", []),
            "ns": dns_records.get("ns", []),
            "dangling_cnames": dangling_cnames,
        },
        "skipped_hosts": skipped_hosts,
    }

    # Save host_inventory.json
    try:
        with open(output_path, "w") as f:
            json.dump(inventory, f, indent=2)
        log.info(
            "host_inventory_saved",
            hosts=len(hosts),
            skipped=len(skipped_hosts),
            dangling_cnames=len(dangling_cnames),
        )
    except Exception as e:
        log.error("host_inventory_save_error", error=str(e))

    return inventory


def _canonicalize_vhosts(host: dict[str, Any], scope_root: str) -> None:
    """Klassifiziert _raw_probes in primary-VHosts + Aliase und schreibt
    host['vhosts'] + host['web_probe'] (Compat).

    Aliase entstehen durch (a) HTTP-Redirect zu einer anderen FQDN auf
    derselben IP, (b) identischer body_hash mit einem anderen primary.
    Externe Redirects (final_url-host gehoert nicht zu fqdns dieses
    Hosts UND nicht zur scope_root) werden als 'skip-extern' markiert.
    """
    raw_probes = host.pop("_raw_probes", []) or []
    if not raw_probes:
        host["vhosts"] = []
        host["web_probe"] = {
            "has_web": False, "status": None, "final_url": None,
            "title": None, "web_fqdn": None,
        }
        return

    own_fqdns = {f.lower() for f in host.get("fqdns", [])}
    scope_root_lc = (scope_root or "").lower().lstrip(".")

    # Schritt 1: Klassifiziere jede Probe
    primaries: dict[str, dict[str, Any]] = {}
    aliases: list[dict[str, Any]] = []  # {to_fqdn?, fqdn, status, reason}
    skipped: list[dict[str, Any]] = []
    by_body_hash: dict[str, str] = {}  # body_hash → primary fqdn

    for probe in raw_probes:
        fqdn = probe["fqdn"].lower()
        final_url = probe["final_url"] or ""
        try:
            fu_host = (urlparse(final_url).hostname or "").lower()
        except Exception:
            fu_host = ""

        # (a) HTTP-Redirect zu anderer eigener FQDN auf demselben Host
        if fu_host and fu_host != fqdn and fu_host in own_fqdns:
            aliases.append({
                "fqdn": fqdn, "to_fqdn": fu_host,
                "status": probe["status"], "reason": "redirect",
            })
            continue

        # (b) Externer Redirect zu out-of-scope Domain
        if fu_host and fu_host != fqdn and scope_root_lc and \
                not fu_host.endswith(scope_root_lc) and fu_host not in own_fqdns:
            skipped.append({
                "fqdn": fqdn, "final_url": final_url,
                "reason": f"redirect-extern → {fu_host}",
            })
            continue

        # (c) Body-Hash-Dup: identischer Inhalt wie ein bereits gesehener primary
        bh = probe["body_hash"]
        if bh and bh in by_body_hash and by_body_hash[bh] != fqdn:
            aliases.append({
                "fqdn": fqdn, "to_fqdn": by_body_hash[bh],
                "status": probe["status"], "reason": "body-hash-dup",
            })
            continue

        # (d) Parking-Page → kein primary, aber web_probe zeigt es
        if probe["parking"]:
            skipped.append({
                "fqdn": fqdn, "status": probe["status"],
                "title": probe["title"], "reason": "parking",
            })
            continue

        # → echter primary VHost
        primaries[fqdn] = {
            "fqdn": fqdn,
            "status": probe["status"],
            "title": probe["title"],
            "final_url": probe["final_url"],
            "body_hash": bh,
            "is_primary": True,
            "aliases": [],
        }
        if bh:
            by_body_hash[bh] = fqdn

    # Schritt 2: Aliase ihren primaries zuordnen (sofern Ziel ein primary ist)
    for al in aliases:
        target = al.get("to_fqdn")
        if target and target in primaries:
            primaries[target]["aliases"].append({
                "fqdn": al["fqdn"], "status": al["status"], "reason": al["reason"],
            })
        else:
            # Ziel selbst kein primary (z.B. eigene FQDN nicht geprobt) →
            # als skipped fuehren, damit es im Frontend sichtbar bleibt
            skipped.append({
                "fqdn": al["fqdn"], "status": al["status"],
                "reason": f"redirect → {target or '?'} (kein primary)",
            })

    # Sortierung: 200er zuerst (echter Content), dann andere Stati,
    # dann kuerzeste FQDN. Sodass web_probe (= vhosts[0]) den besten
    # Kandidaten zeigt — Cloudflare-WAF-403 verliert gegen 200 OK.
    def _sort_key(v: dict[str, Any]) -> tuple:
        status = v.get("status") or 0
        is_2xx = 0 if 200 <= status < 300 else 1
        is_3xx = 0 if 300 <= status < 400 else 1
        return (is_2xx, is_3xx, len(v["fqdn"]), v["fqdn"])

    vhosts = sorted(primaries.values(), key=_sort_key)
    host["vhosts"] = vhosts
    host["vhost_skipped"] = skipped

    # Backwards-Compat: web_probe aus erstem primary
    if vhosts:
        v0 = vhosts[0]
        host["web_probe"] = {
            "has_web": True,
            "status": v0["status"],
            "final_url": v0["final_url"],
            "title": v0["title"],
            "web_fqdn": v0["fqdn"],
        }
    else:
        # Kein primary → nutze ersten skipped (z.B. parking) als Compat-Probe
        first_sk = skipped[0] if skipped else {}
        host["web_probe"] = {
            "has_web": False,
            "status": first_sk.get("status"),
            "final_url": None,
            "title": first_sk.get("title"),
            "web_fqdn": first_sk.get("fqdn"),
            "parking": first_sk.get("reason") == "parking" or None,
        }


_PARKING_PATTERNS = [
    "domain not configured", "nicht konfiguriert",
    "froxlor", "plesk", "cpanel", "ispconfig",
    "this domain is parked", "domain parking",
    "coming soon", "under construction",
    "default web page", "apache2 debian default",
    "welcome to nginx", "test page for",
]

# Probe-Cap pro Host (Schutz gegen IP mit 50+ FQDNs)
MAX_VHOSTS_PROBED = int(os.environ.get("MAX_VHOSTS_PROBED", "10"))


def _parse_httpx_probe_line(data: dict[str, Any]) -> dict[str, Any] | None:
    """Parsed eine httpx-NDJSON-Zeile in das probe-Dict-Format.

    Returns None wenn Status fehlt oder ausserhalb 200-499 — analog zum
    alten `_probe_single_fqdn`. Liefert Schluessel:
      {fqdn, status, title, final_url, body_hash, parking}
    """
    status = data.get("status_code") or data.get("status-code") or 0
    try:
        status = int(status)
    except (TypeError, ValueError):
        return None

    if not status or not (200 <= status < 500):
        return None

    # httpx liefert die Eingabe-URL unter 'input'/'url'; den Hostnamen
    # extrahieren wir daraus.
    #
    # PR-G (Mai 2026): Wenn `-l <file>` mit nackten Hostnamen (ohne Scheme)
    # benutzt wird, ist `input` haeufig nur der Hostname (z.B. "heuel.com").
    # ``urlparse("heuel.com").hostname`` gibt dann None zurueck. Fallback in
    # mehreren Stufen: input-als-URL → input-als-Hostname → url-Feld → host.
    url_in = data.get("input") or data.get("url", "") or ""
    try:
        fqdn = (urlparse(url_in).hostname or "").lower()
    except Exception:
        fqdn = ""
    if not fqdn and url_in:
        # Kein Scheme → urlparse-fail. Wenn `input` wie ein blanker Hostname
        # aussieht (kein '/' und max ein Doppelpunkt fuer Port), nimm es direkt.
        candidate = url_in.strip().lower()
        if candidate and "/" not in candidate and candidate.count(":") <= 1:
            # Strip optional :port
            fqdn = candidate.split(":")[0]
    if not fqdn:
        # Fallback: separates Feld aus httpx-Output
        fqdn = (data.get("host") or "").lower()
    if not fqdn:
        # Letzter Versuch: aus url-Feld (mit Scheme)
        url_full = data.get("url", "") or ""
        try:
            fqdn = (urlparse(url_full).hostname or "").lower()
        except Exception:
            fqdn = ""
    if not fqdn:
        return None

    title = (data.get("title") or "")[:100]
    final_url = data.get("final_url") or data.get("url", "") or ""
    # httpx liefert hash entweder direkt als 'hash' Feld oder unter
    # 'body_hash'; der genaue Key variiert je httpx-Version.
    h = data.get("hash") or data.get("body_hash") or {}
    if isinstance(h, dict):
        body_hash = h.get("body_sha256") or h.get("sha256") or ""
    else:
        body_hash = str(h or "")

    title_lower = title.lower()
    is_parking = any(p in title_lower for p in _PARKING_PATTERNS)

    return {
        "fqdn": fqdn,
        "status": status,
        "title": title,
        "final_url": final_url,
        "body_hash": body_hash or "",
        "parking": is_parking,
    }


def _probe_single_fqdn(fqdn: str, ip: str) -> dict[str, Any] | None:
    """Probt EINE FQDN via httpx und liefert Roh-Probe-Dict zurueck.

    Wird seit F-P0B-007 (Mai 2026) im Hauptpfad nicht mehr benutzt —
    `_probe_web_hosts` macht einen einzigen batch-httpx-Aufruf. Funktion
    bleibt fuer Tests/Fallbacks erhalten.

    Returns None bei Fehler/keine Antwort. Bei Erfolg:
      {fqdn, status, title, final_url, body_hash, parking}
    """
    cmd = [
        "httpx", "-u", fqdn, "-json", "-silent",
        "-follow-redirects", "-status-code", "-title", "-timeout", "5",
        "-retries", "1",
        # body_hash bekommen wir via httpx -hash sha256 (Standard-Body-Hash)
        "-hash", "sha256",
        # `-fr` = meta-refresh-follow
        "-fr",
    ]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=10,
            start_new_session=True,
        )
    except (subprocess.TimeoutExpired, Exception) as e:
        log.debug("web_probe_error", ip=ip, fqdn=fqdn, error=str(e))
        return None

    if not (result.stdout and result.stdout.strip()):
        return None

    try:
        data = json.loads(result.stdout.strip().split("\n")[0])
    except (json.JSONDecodeError, IndexError):
        return None

    probe = _parse_httpx_probe_line(data)
    if probe is None:
        return None
    # `_parse_httpx_probe_line` extrahiert fqdn aus URL; bei Single-Probe
    # mit Hostname-only (kein Schema) kann das Feld leer sein → setze hier
    # den explizit uebergebenen FQDN als Quelle.
    probe["fqdn"] = probe["fqdn"] or fqdn.lower()
    return probe


def _probe_web_hosts(hosts: list[dict[str, Any]], order_id: str, scan_dir: str,
                     domain: str = "") -> list[dict[str, Any]]:
    """Quick HTTP probe per host — probt ALLE FQDNs (capped MAX_VHOSTS_PROBED).

    F-P0B-007 (Mai 2026): batch-httpx via `-l <file> -threads 30` statt
    eines subprocess-Aufrufs pro FQDN. Bei 25 FQDNs faellt Wall-Time von
    ~50s auf ~5-10s. Schema-Auswahl uebernimmt httpx selbst (probiert
    https → http). NDJSON-Output wird per `_parse_httpx_probe_line`
    gemappt; pro FQDN gewinnt das erste 2xx-Result (Sort: Status-Klasse).
    Schreibt host['vhosts'] (canonicalized primary + Aliase) und
    host['web_probe'] (Backwards-Compat = vhosts[0]).
    """
    from scanner.tools import _save_result

    # Sammle alle FQDNs (deterministisch sortiert, gecappt pro Host).
    fqdn_to_host: dict[str, dict[str, Any]] = {}
    all_fqdns: list[str] = []
    for host in hosts:
        for fqdn in host.get("fqdns", [])[:MAX_VHOSTS_PROBED]:
            fl = fqdn.lower()
            if fl in fqdn_to_host:
                # FQDN bereits einer anderen Host-IP zugewiesen — bei
                # CDN-Round-Robin moeglich. Erste Zuordnung gewinnt;
                # Probe-Ergebnis wird allen Hosts derselben FQDN zugeordnet,
                # aber wir tracken nur die erste hier.
                continue
            fqdn_to_host[fl] = host
            all_fqdns.append(fl)

    # Map: fqdn → probe-Dict (None wenn kein 2xx-3xx-4xx Result)
    probes_by_fqdn: dict[str, dict[str, Any]] = {}

    if all_fqdns:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, encoding="utf-8",
        ) as tf:
            for f in sorted(set(all_fqdns)):
                tf.write(f + "\n")
            list_path = tf.name

        cmd = [
            "httpx", "-l", list_path, "-json", "-silent",
            "-follow-redirects", "-status-code", "-title",
            "-timeout", "5", "-retries", "1",
            "-hash", "sha256",
            "-fr",  # meta-refresh-follow
            "-threads", "30",
        ]
        # Worst-Case-Timeout: pro FQDN ~5s × ceil(N/30) + Overhead;
        # konservativ auf 90s gecappt damit ein einziger Hang nicht das
        # ganze Phase 0b haengen laesst.
        batch_timeout = min(
            90,
            10 + 5 * (len(all_fqdns) // 30 + 1),
        )
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=batch_timeout,
                start_new_session=True,
            )
            stdout = result.stdout or ""
            stderr = result.stderr or ""
            exit_code = result.returncode
        except subprocess.TimeoutExpired:
            log.warning("web_probe_batch_timeout", fqdns=len(all_fqdns),
                        timeout_s=batch_timeout)
            stdout, stderr, exit_code = "", "", -1
        except Exception as e:
            log.warning("web_probe_batch_error", error=str(e))
            stdout, stderr, exit_code = "", "", -2
        finally:
            try:
                os.unlink(list_path)
            except OSError:
                pass

        # Diagnostik (PR-G Mai 2026): Bei leerem stdout immer stderr + exit_code
        # loggen — sonst stillschweigender has_web=false fuer alle Hosts.
        if not stdout.strip():
            log.warning(
                "web_probe_batch_empty_stdout",
                exit_code=exit_code,
                stderr=stderr[:500],
                fqdns_count=len(all_fqdns),
                fqdns_sample=all_fqdns[:5],
                cmd=" ".join(cmd[:5]) + " ...",
            )
        else:
            log.info(
                "web_probe_batch_done",
                exit_code=exit_code,
                stdout_bytes=len(stdout),
                stderr_bytes=len(stderr),
                stderr_head=stderr[:200] if stderr else "",
                fqdns=len(all_fqdns),
            )

        # NDJSON parsen — pro FQDN das erste Ergebnis behalten.
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            probe = _parse_httpx_probe_line(data)
            if probe is None:
                continue
            fqdn_lc = probe["fqdn"]
            # Erstes Result pro FQDN gewinnt (httpx-Output ist bei Threads
            # nicht garantiert sortiert — eine deterministische Sortierung
            # findet `_canonicalize_vhosts` ueber Status-Klasse).
            probes_by_fqdn.setdefault(fqdn_lc, probe)

    # Pro Host die zugehoerigen Probes einsammeln.
    for host in hosts:
        raw_probes: list[dict[str, Any]] = []
        for fqdn in host.get("fqdns", [])[:MAX_VHOSTS_PROBED]:
            fl = fqdn.lower()
            probe = probes_by_fqdn.get(fl)
            if probe is None:
                continue
            raw_probes.append(probe)
            if probe["parking"]:
                log.info("web_probe_parking_detected", ip=host["ip"],
                         fqdn=fl, title=probe["title"][:50])
            else:
                log.info("web_probe_found", ip=host["ip"], fqdn=fl,
                         status=probe["status"], title=probe["title"][:50])

        host["_raw_probes"] = raw_probes
        _canonicalize_vhosts(host, scope_root=domain)

    # Save probe results: pro Host vhosts + Compat-web_probe
    probe_summary = {
        h["ip"]: {
            "web_probe": h.get("web_probe", {}),
            "vhosts": h.get("vhosts", []),
            "vhost_skipped": h.get("vhost_skipped", []),
        } for h in hosts
    }
    _save_result(
        order_id=order_id, host_ip=None, phase=0,
        tool_name="web_probe",
        raw_output=json.dumps(probe_summary, indent=2, ensure_ascii=False),
        exit_code=0, duration_ms=0,
    )

    web_count = sum(1 for h in hosts if h.get("web_probe", {}).get("has_web"))
    vhost_count = sum(len(h.get("vhosts", [])) for h in hosts)
    log.info("web_probe_complete", total=len(hosts), with_web=web_count,
             primary_vhosts=vhost_count)

    return hosts


def run_phase0(domain: str, scan_dir: str, order_id: str, config: dict[str, Any] | None = None,
               seed_subdomains: list[str] | None = None) -> dict[str, Any]:
    """
    Orchestrate Phase 0: DNS Reconnaissance.

    Runs all enumeration tools, collects and deduplicates subdomains,
    validates with dnsx, and creates the host inventory.

    Overall timeout: 10 minutes.

    PR-M4 (2026-05-02): Falls fuer dieselbe Domain ein frischer
    Subdomain-Snapshot existiert (TTL 24h, ueber `scan_targets.canonical`),
    wird die Subdomain-Discovery-Phase (crt.sh / subfinder /
    gobuster_dns / axfr) uebersprungen und das gecachte Subdomain-Set
    direkt an dnsx weitergereicht. Externe Drift-Quellen werden so
    eliminiert; Re-Scans innerhalb der TTL haben ein deterministisches
    Subdomain-Inventar.

    F-P0B-003 (2026-05-07): amass v5 wurde komplett entfernt
    (Hard-Cap-Bottleneck + `-brute`-Doppelarbeit zu gobuster_dns).

    F-P0A-004 (Mai 2026): `seed_subdomains` ist eine optionale
    Subdomain-Liste aus Phase 0a (Shodan-DNS + SecurityTrails-Subdomains).
    Die Eintraege werden dem Discovery-Pool hinzugefuegt und mit ihrer
    Quelle in `tool_sources["phase0a_passive"]` gespeichert. Ersetzt den
    bisherigen `run_securitytrails_subdomains`-Call in Phase 0b
    (Doppel-Call gegen SecurityTrails-API entfernt).
    """
    # Use config if provided, otherwise default to professional
    # v2 uses phase0b_tools/phase0b_timeout; fall back to v1 keys for compat
    if config:
        phase0_timeout = config.get("phase0b_timeout", config.get("phase0_timeout", PHASE0_TIMEOUT))
        max_hosts = config["max_hosts"]
        phase0_tools = config.get("phase0b_tools", config.get("phase0_tools",
                                  ["crtsh", "subfinder", "gobuster_dns", "axfr", "dnsx"]))
    else:
        phase0_timeout = PHASE0_TIMEOUT
        max_hosts = MAX_HOSTS
        phase0_tools = ["crtsh", "subfinder", "gobuster_dns", "axfr", "dnsx"]

    phase0_start = time.monotonic()
    phase0_dir = os.path.join(scan_dir, "phase0")
    os.makedirs(phase0_dir, exist_ok=True)

    log.info("phase0_start", domain=domain, order_id=order_id)

    all_subdomains: list[str] = []
    tool_sources: dict[str, list[str]] = {}

    def _time_remaining() -> float:
        elapsed = time.monotonic() - phase0_start
        return max(0, phase0_timeout - elapsed)

    # --- Snapshot als ZUSAETZLICHER Seed (Mai 2026, securess.de-Drift-Fix) ---
    # Frueher (PR-M4) hat ein <24h-Snapshot die Discovery-Tools komplett
    # uebersprungen ("SKIPPED"-Marker). Resultat: ein einmaliger Magerlauf
    # (crt.sh leer, subfinder 8 statt 33 Subs) wurde 24h lang perpetuiert.
    # Jetzt: Snapshot-Subs werden ergaenzend gemerged, Discovery-Tools
    # laufen IMMER. snapshot_store.save_for_target nutzt MERGE-Semantik
    # (kein Shrinkage). ENV `SUBDOMAIN_SNAPSHOT_DISABLED=1` deaktiviert den
    # Seed komplett (Notausgang fuer komplettes Cold-Start).
    snapshot_seed: list[str] = []
    snapshot_target_id: Optional[str] = None
    snapshot_age_min: Optional[int] = None
    if os.environ.get("SUBDOMAIN_SNAPSHOT_DISABLED", "").lower() not in ("1", "true", "yes"):
        try:
            from scanner.precheck import snapshot_store
            snap = snapshot_store.find_fresh_for_domain(domain)
            if snap and snap.get("subdomains"):
                snapshot_seed = list(snap["subdomains"])
                all_subdomains.extend(snapshot_seed)
                tool_sources["snapshot"] = list(snapshot_seed)
                snapshot_target_id = snap.get("scan_target_id")
                snapshot_age_min = (snap.get("age_seconds") or 0) // 60
                log.info(
                    "phase0_snapshot_seed_loaded",
                    domain=domain, order_id=order_id,
                    subdomains=len(snapshot_seed),
                    age_minutes=snapshot_age_min,
                    target_id=snapshot_target_id,
                )
                publish_event(order_id, {
                    "type": "phase0_snapshot_seed_loaded",
                    "orderId": order_id,
                    "domain": domain,
                    "subdomains": len(snapshot_seed),
                    "ageMinutes": snapshot_age_min,
                })
        except Exception as exc:
            log.warning("phase0_snapshot_lookup_failed", error=str(exc))

    # --- F-P0A-004: Phase-0a-Passive-Subdomains als Seed mergen ---
    # Phase 0a hat Shodan-DNS und SecurityTrails-Subdomains schon gesammelt.
    # Wir nehmen sie hier in den Discovery-Pool mit auf und entfernen damit
    # den SecurityTrails-Doppelcall in Phase 0b. Die Quelle wird unter
    # `phase0a_passive` in tool_sources gespeichert (Audit-Trail).
    seed_passive: list[str] = []
    if seed_subdomains:
        seed_passive = sorted({
            str(s).strip().lower().rstrip(".")
            for s in seed_subdomains
            if s and str(s).strip()
        })
        if seed_passive:
            all_subdomains.extend(seed_passive)
            tool_sources["phase0a_passive"] = list(seed_passive)
            log.info(
                "phase0_phase0a_seed_loaded",
                domain=domain, order_id=order_id,
                subdomains=len(seed_passive),
            )

    # --- Stufe 1: Subdomain Discovery + DNS Records (parallel) ---
    # Bei Snapshot-Reuse nur DNS-Records + axfr neu, weil diese fuer
    # Email-Security/Compliance-Reports relevant sind und billig.
    from concurrent.futures import ThreadPoolExecutor, as_completed

    zone_transfer: dict[str, Any] = {"success": False, "data": {}}
    dns_records: dict[str, Any] = {"spf": None, "dmarc": None, "dkim": False, "dkim_selectors": [], "mx": [], "ns": []}

    discovery_futures: dict[Any, str] = {}
    with ThreadPoolExecutor(max_workers=8, thread_name_prefix="phase0b") as pool:
        # Discovery-Tools laufen IMMER (Snapshot ist nur Seed, nicht Skip).
        # F-P0B-008 (Mai 2026): crt.sh + certspotter werden PARALLEL
        # angestossen statt certspotter als Fallback bei leerem crt.sh-Result.
        # Beide CT-Logs werden anschliessend per Set-Vereinigung gemerged
        # (`merge_and_group` deduppt sowieso). Coverage-Plus: certspotter
        # indexiert frische Issuances die crt.sh manchmal noch nicht hat;
        # kostet ~0.5s parallel, kein zusaetzlicher Wall-Time-Druck.
        if "crtsh" in phase0_tools:
            discovery_futures[pool.submit(run_crtsh, domain, scan_dir, order_id)] = "crtsh"
            discovery_futures[pool.submit(run_certspotter, domain, scan_dir, order_id)] = "certspotter"
        if "subfinder" in phase0_tools:
            discovery_futures[pool.submit(run_subfinder, domain, scan_dir, order_id)] = "subfinder"
        # F-P0B-003 (2026-05-07): amass v5 wurde entfernt (Hard-Cap-Bottleneck +
        # `-brute`-Doppelarbeit zu gobuster_dns). Wenn Configs `"amass"` noch
        # in `phase0b_tools` listen, wird der Eintrag stillschweigend ignoriert.
        if "gobuster_dns" in phase0_tools:
            discovery_futures[pool.submit(run_gobuster_dns, domain, scan_dir, order_id)] = "gobuster_dns"
        # F-P0A-004 (Mai 2026): SecurityTrails-Doppelcall in Phase 0b entfernt.
        # Phase 0a ruft SecurityTrails bereits auf (parallel zu shodan/whois);
        # die Subdomains kommen ueber `seed_subdomains` (= passive_subdomains)
        # in den Discovery-Pool. webcheck-Paket nutzt SecurityTrails ohnehin
        # nicht (phase0a_tools=["whois"]) — kein Verlust.
        if "axfr" in phase0_tools:
            discovery_futures[pool.submit(run_zone_transfer, domain, scan_dir, order_id)] = "axfr"
        discovery_futures[pool.submit(collect_dns_records, domain, scan_dir, order_id)] = "dns_records"

        for future in as_completed(discovery_futures, timeout=_time_remaining()):
            tool_name = discovery_futures[future]
            try:
                result = future.result()
                if tool_name == "axfr":
                    zone_transfer = result
                    log.info("phase0_zone_transfer_done", success=zone_transfer["success"])
                elif tool_name == "dns_records":
                    dns_records = result
                    log.info("phase0_dns_records_done")
                else:
                    # Subdomain enumeration tools return list[str]
                    subs = result if isinstance(result, list) else []
                    all_subdomains.extend(subs)
                    tool_sources[tool_name] = list(subs)
                    log.info(f"phase0_{tool_name}_done", found=len(subs))
            except Exception as e:
                log.error(f"phase0_{tool_name}_error", error=str(e))

    # Always include the base domain
    all_subdomains.append(domain)

    # --- dnsx validation ---
    dnsx_results: list[dict[str, Any]] = []
    if _time_remaining() > 0 and "dnsx" in phase0_tools:
        try:
            unique_subs = sorted(set(s.lower() for s in all_subdomains if s))
            dnsx_results = run_dnsx(unique_subs, scan_dir, order_id)
            log.info("phase0_dnsx_done", validated=len(dnsx_results))
        except Exception as e:
            log.error("phase0_dnsx_error", error=str(e))

    # --- Merge and group ---
    inventory = merge_and_group(
        domain=domain,
        all_subdomains=all_subdomains,
        dnsx_results=dnsx_results,
        dns_records=dns_records,
        zone_transfer=zone_transfer,
        scan_dir=scan_dir,
        max_hosts=max_hosts,
    )

    # --- Web probe: quick HTTP check per host ---
    inventory["hosts"] = _probe_web_hosts(inventory.get("hosts", []), order_id, scan_dir,
                                          domain=domain)

    # --- Snapshot persistieren (immer; MERGE-Semantik in save_for_target) ---
    # Mai 2026: Snapshot wird nicht mehr als Skip-Schalter benutzt, sondern
    # als Seed + dauerhafter Speicher. save_for_target merget mit dem
    # bestehenden Set (kein Shrinkage) — auch ein Magerlauf bringt also
    # nichts mehr durcheinander.
    try:
        from scanner.precheck import snapshot_store
        target_id = snapshot_target_id or _resolve_scan_target_id(order_id, domain)
        if target_id and all_subdomains:
            snapshot_store.save_for_target(
                scan_target_id=target_id,
                all_subdomains=all_subdomains,
                tool_sources=tool_sources,
            )
            log.info(
                "phase0_subdomain_snapshot_saved",
                target_id=target_id,
                subdomains=len(set(all_subdomains)),
            )
    except Exception as exc:
        log.warning("phase0_snapshot_save_failed", error=str(exc))

    elapsed_ms = int((time.monotonic() - phase0_start) * 1000)
    snapshot_seeded = bool(snapshot_seed)
    log.info(
        "phase0_complete",
        domain=domain,
        hosts_found=len(inventory.get("hosts", [])),
        skipped=len(inventory.get("skipped_hosts", [])),
        duration_ms=elapsed_ms,
        snapshot_seeded=snapshot_seeded,
        snapshot_seed_count=len(snapshot_seed),
    )

    # Discovery-Health: pro Tool wieviele Subdomains kamen — fuer
    # Abbruch-Logik in worker.py + UI-Sichtbarkeit. Snapshot ist eine
    # Quelle wie jede andere; ct_sources_empty bezieht sich nur auf die
    # heutigen externen API-Treffer (crtsh + certspotter).
    snapshot_set = set(snapshot_seed)
    discovery_set: set[str] = set()
    for tool, subs in tool_sources.items():
        if tool == "snapshot":
            continue
        discovery_set.update(s for s in (subs or []) if s)
    discovery_added = sorted(discovery_set - snapshot_set)
    discovery_health: dict[str, Any] = {
        "snapshot_seeded": snapshot_seeded,
        "snapshot_age_minutes": snapshot_age_min,
        "snapshot_seed_count": len(snapshot_seed),
        "discovery_added_count": len(discovery_added),
        "tool_counts": {tool: len(set(subs)) for tool, subs in tool_sources.items()},
        "tools_with_zero_results": sorted(
            tool for tool, subs in tool_sources.items()
            if tool != "snapshot" and not subs
        ),
        "total_subdomains": len(set(all_subdomains)),
        "ct_sources_empty": (
            not tool_sources.get("crtsh")
            and not tool_sources.get("certspotter")
        ),
    }
    inventory["discovery_health"] = discovery_health

    # Wenn alle CT-Quellen leer waren UND wir keinen Snapshot-Seed haben,
    # warnen wir explizit — das ist verdaechtig (Domain hat normalerweise
    # mindestens 2-3 Subdomains in CT-Logs).
    if (discovery_health["ct_sources_empty"] and not snapshot_seeded
            and discovery_health["total_subdomains"] < 3):
        log.warning(
            "phase0_discovery_thin",
            domain=domain,
            total_subdomains=discovery_health["total_subdomains"],
            tool_counts=discovery_health["tool_counts"],
        )
        publish_event(order_id, {
            "type": "phase0_discovery_warning",
            "orderId": order_id,
            "domain": domain,
            "message": "Alle CT-Quellen leer und sehr wenige Subdomains — Discovery moeglicherweise eingeschraenkt.",
            "subdomainCount": discovery_health["total_subdomains"],
        })

    return inventory


def _resolve_scan_target_id(order_id: str, domain: str) -> Optional[str]:
    """Findet die `scan_target_id` zur aktuellen Domain dieser Order.

    Match-Regel: erst exakter `canonical`-Hit fuer die Order, dann
    Fallback ueber alle approved Targets der Subscription. Gibt
    ``None`` zurueck wenn kein Treffer (Single-Target-Legacy-Order
    ohne `scan_targets`-Eintrag).
    """
    try:
        import psycopg2
        import psycopg2.extras
        conn = psycopg2.connect(
            os.environ.get("DATABASE_URL", "postgresql://localhost:5432/vectiscan"),
            connect_timeout=5,
            options="-c statement_timeout=10000",
        )
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                # 1. Direkt ueber Order
                cur.execute(
                    """SELECT t.id FROM scan_targets t
                        WHERE t.order_id = %s AND LOWER(t.canonical) = %s
                        LIMIT 1""",
                    (order_id, (domain or "").lower()),
                )
                row = cur.fetchone()
                if row:
                    return str(row["id"])
                # 2. Ueber Subscription der Order
                cur.execute(
                    """SELECT t.id FROM scan_targets t
                        JOIN orders o ON o.subscription_id = t.subscription_id
                       WHERE o.id = %s AND LOWER(t.canonical) = %s
                         AND t.status = 'approved'
                       LIMIT 1""",
                    (order_id, (domain or "").lower()),
                )
                row = cur.fetchone()
                if row:
                    return str(row["id"])
        finally:
            conn.close()
    except Exception:
        return None
    return None
