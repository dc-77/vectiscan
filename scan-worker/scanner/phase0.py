"""Phase 0: DNS-Reconnaissance — Subdomain-Enumeration und Host-Gruppierung."""

import json
import os
import signal
import socket
import subprocess
import tempfile
import time
from collections import defaultdict
from typing import Any, Optional

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


def _classify_dangling_cname(cname_target: str) -> tuple[str, str]:
    """Classify a dangling CNAME target by subdomain takeover risk.

    Returns:
        (risk_level, reason) where risk_level is "high", "low", or "info".
    """
    target = cname_target.lower()

    for suffix, service in _TAKEOVER_POSSIBLE:
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


def run_securitytrails_subdomains(domain: str, scan_dir: str, order_id: str) -> list[str]:
    """SecurityTrails-Subdomain-Liste als 4. CT-Quelle in Phase 0b.

    SecurityTrails liefert oft hunderte Subdomains (historische DNS-Daten),
    die crt.sh + subfinder + amass nicht haben. Nur aktiv wenn
    `SECURITYTRAILS_API_KEY` gesetzt ist — sonst stiller Skip.
    """
    publish_event(order_id, {"type": "tool_starting", "tool": "securitytrails", "host": domain})
    output_path = os.path.join(scan_dir, "phase0", "securitytrails.json")
    started = time.monotonic()

    subdomains: list[str] = []
    error: Optional[str] = None
    try:
        from scanner.passive.securitytrails_client import SecurityTrailsClient
        client = SecurityTrailsClient()
        if not client.available:
            log.info("securitytrails_skipped", reason="no_api_key")
            return []
        subdomains = client.get_subdomains(domain)
        log.info("securitytrails_complete", subdomains_found=len(subdomains))
    except Exception as e:
        error = str(e)
        log.warning("securitytrails_error", error=error)

    duration_ms = int((time.monotonic() - started) * 1000)
    try:
        payload = {"subdomains": subdomains, "error": error}
        with open(output_path, "w") as f:
            json.dump(payload, f, indent=2)
        from scanner.tools import _save_result
        _save_result(
            order_id=order_id, host_ip=None, phase=0,
            tool_name="securitytrails",
            raw_output=json.dumps(payload, ensure_ascii=False),
            exit_code=0 if not error else 1,
            duration_ms=duration_ms,
        )
    except Exception as e:
        log.warning("securitytrails_save_error", error=str(e))

    return subdomains


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

    cmd = [
        "subfinder", "-d", domain,
        "-silent", "-json",
        "-disable-update-check",
        # `-all` aktiviert ALLE Source-Plugins (chaos, binaryedge,
        # securitytrails, ...) statt nur Default-Set. Liefert deutlich
        # mehr Subdomains. API-Keys via ~/.config/subfinder/provider-config.yaml.
        "-all",
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


def run_amass(domain: str, scan_dir: str, order_id: str) -> list[str]:
    """Run amass v5 passive enumeration in 2 stages. Timeout 300s (5 Min).

    amass v5 hat eine voellig andere Architektur als v4:
    1. Engine + Asset-DB (Graph-Datenbank), nicht mehr stdout/file
    2. `enum` befuellt die DB; **kein** `-json`/`-o`-Flag fuer die
       Subdomains (wie in v4).
    3. `-passive` ist **deprecated** — passive ist seit v5 der Default.
    4. `-o <file>` in v5 schreibt **nur den CLI-Log** (Banner, Source-
       Status), NICHT die gefundenen FQDNs.
    5. Subdomains kommen erst ueber das **`subs`-Subcommand** raus:
       `amass subs -d <domain> -dir <db> -names -nocolor`.

    Bisherige Versuche schlugen fehl, weil:
    - v4-Code (`-json`): "flag provided but not defined: -json"
    - v5-Code mit `-o` als Subdomain-Quelle: nur CLI-Log gelesen → 0 Subs

    Workflow jetzt: dedizierte Per-Order-DB (`<scan_dir>/phase0/amass-db`)
    fuer Isolation; enum schreibt rein; subs -names liest raus.
    """
    publish_event(order_id, {"type": "tool_starting", "tool": "amass", "host": domain})
    db_dir = os.path.join(scan_dir, "phase0", "amass-db")
    log_path = os.path.join(scan_dir, "phase0", "amass.log")
    subs_path = os.path.join(scan_dir, "phase0", "amass-subs.txt")
    os.makedirs(db_dir, exist_ok=True)
    subdomains: list[str] = []

    # --- Stufe 1: enum (befuellt Graph-DB) ---
    enum_cmd = [
        "amass", "enum",
        "-d", domain,
        "-nocolor",
        "-dir", db_dir,
        "-o", log_path,
        # `-timeout` in Minuten — wir cappen weicher als run_tool-Timeout.
        "-timeout", "4",
    ]
    enum_exit, enum_duration = run_tool(
        cmd=enum_cmd,
        timeout=270,
        output_path=log_path,
        order_id=order_id,
        phase=0,
        tool_name="amass",
    )

    if enum_exit not in (0,):
        log.warning("amass_enum_failed", exit_code=enum_exit)
        # Trotzdem versuchen `subs` zu lesen — eventuell sind partial-results da

    # --- Stufe 2: subs -names (Subdomains aus DB lesen) ---
    subs_cmd = [
        "amass", "subs",
        "-d", domain,
        "-dir", db_dir,
        "-names",
        "-nocolor",
        "-o", subs_path,
    ]
    subs_exit, subs_duration = run_tool(
        cmd=subs_cmd,
        timeout=60,
        output_path=subs_path,
        order_id=order_id,
        phase=0,
        tool_name="amass_subs",
    )

    if subs_exit not in (0,):
        log.warning("amass_subs_failed", exit_code=subs_exit)

    # --- Parse: subs -o schreibt CLI-Log; subs Output geht auf stdout. ---
    # Wir lesen den raw_output aus scan_results (run_tool persistiert stdout
    # bei `tool_complete`), aber praktischer: wir laufen subs nochmal mit
    # File-Capture via Output-Redirect. ABER: `-o` macht stdout-Mirror,
    # nicht Subdomain-File. Pragmatisch: wir lesen die DB selbst nicht,
    # sondern nutzen die Tatsache dass subs auf stdout listet — und stdout
    # wird von run_tool in scan_results.raw_output persistiert.
    # Deshalb hier: zweiter Aufruf direkt mit subprocess.run um stdout zu
    # capturen und daraus FQDNs zu extrahieren (run_tool wirft stdout weg
    # nach DB-Persistierung).
    domain_lower = domain.lower()
    try:
        result = subprocess.run(
            ["amass", "subs", "-d", domain, "-dir", db_dir, "-names", "-nocolor"],
            capture_output=True, text=True, timeout=60,
            start_new_session=True,
        )
        for line in (result.stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue
            # Erste Spalte = FQDN-Kandidat (subs -names druckt `name FQDN`
            # oder einfach FQDN; defensiv beide Faelle handhaben)
            candidate = line.split()[-1].lower().strip(".,;:")
            if candidate == domain_lower or candidate.endswith("." + domain_lower):
                subdomains.append(candidate)
        # Dedup + sort
        subdomains = sorted(set(subdomains))
        log.info("amass_complete", subdomains_found=len(subdomains))
    except subprocess.TimeoutExpired:
        log.warning("amass_subs_stdout_timeout")
    except Exception as e:
        log.warning("amass_parse_error", error=str(e))

    return subdomains


def run_gobuster_dns(domain: str, scan_dir: str, order_id: str) -> list[str]:
    """Run gobuster DNS brute-force. Timeout 180s (3 Min)."""
    publish_event(order_id, {"type": "tool_starting", "tool": "gobuster_dns", "host": domain})
    output_path = os.path.join(scan_dir, "phase0", "gobuster_dns.txt")
    subdomains: list[str] = []

    cmd = [
        "gobuster", "dns",
        "--domain", domain,
        "--wordlist", "/usr/share/wordlists/subdomains-top5000.txt",
        # Wildcard-DNS (Domain antwortet auf *.domain mit gleicher IP) bricht
        # gobuster sonst ab. Mit `--wildcard` versucht gobuster trotzdem zu
        # enumerieren und filtert die Wildcard-IP heraus. Bergersysteme.com
        # ist genau so ein Fall (alles 176.9.21.52).
        "--wildcard",
        # Default 10 threads → 50; bei 5000-Wort-Liste in 180s Timeout
        # sonst nicht durchgekommen.
        "--threads", "50",
        # Timeout pro DNS-Request — bei langsamen Resolvern sonst Haenger
        "--timeout", "5s",
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
        "dkim": False,
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

    # DMARC
    try:
        dmarc_output = _dig_query(f"_dmarc.{domain}", "TXT")
        for line in dmarc_output.split("\n"):
            line = line.strip().strip('"')
            if "v=dmarc1" in line.lower():
                records["dmarc"] = line
                break
    except Exception as e:
        log.warning("dmarc_lookup_error", error=str(e))

    # DKIM (check default._domainkey)
    try:
        dkim_output = _dig_query(f"default._domainkey.{domain}", "TXT")
        records["dkim"] = bool(dkim_output and "v=dkim1" in dkim_output.lower())
    except Exception as e:
        log.warning("dkim_lookup_error", error=str(e))

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


def _probe_web_hosts(hosts: list[dict[str, Any]], order_id: str, scan_dir: str) -> list[dict[str, Any]]:
    """Quick HTTP probe per host — determines which FQDNs serve web content.

    Adds a 'web_probe' dict to each host with has_web, status, final_url, title, web_fqdn.
    Uses httpx for fast probing (~1-5s per FQDN).
    """
    from scanner.tools import _save_result

    for host in hosts:
        probe: dict[str, Any] = {
            "has_web": False, "status": None, "final_url": None,
            "title": None, "web_fqdn": None,
        }

        for fqdn in host.get("fqdns", [])[:3]:
            cmd = [
                "httpx", "-u", fqdn, "-json", "-silent",
                "-follow-redirects", "-status-code", "-title", "-timeout", "5",
                # Bei Packet-Loss/transient-Fehler 1 Retry — sonst false-negative
                "-retries", "1",
                # `-fr` ist meta-refresh-follow zusaetzlich zu HTTP-Redirects;
                # bei SPAs/CMS-Wartungsseiten oft notwendig.
                "-fr",
            ]
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=10,
                    start_new_session=True,
                )
                if result.stdout and result.stdout.strip():
                    line = result.stdout.strip().split("\n")[0]
                    data = json.loads(line)
                    status = data.get("status_code") or data.get("status-code") or 0
                    if status and 200 <= int(status) < 500:
                        title = (data.get("title") or "")[:100]
                        final_url = data.get("final_url") or data.get("url", "")

                        # Detect parking/hosting panel pages — not real web content
                        _PARKING_PATTERNS = [
                            "domain not configured", "nicht konfiguriert",
                            "froxlor", "plesk", "cpanel", "ispconfig",
                            "this domain is parked", "domain parking",
                            "coming soon", "under construction",
                            "default web page", "apache2 debian default",
                            "welcome to nginx", "test page for",
                        ]
                        title_lower = title.lower()
                        is_parking = any(p in title_lower for p in _PARKING_PATTERNS)

                        if is_parking:
                            probe["has_web"] = False
                            probe["status"] = int(status)
                            probe["title"] = title
                            probe["parking"] = True
                            log.info("web_probe_parking_detected", ip=host["ip"],
                                     fqdn=fqdn, title=title[:50])
                            break

                        probe["has_web"] = True
                        probe["status"] = int(status)
                        probe["final_url"] = final_url
                        probe["title"] = title
                        probe["web_fqdn"] = fqdn
                        log.info("web_probe_found", ip=host["ip"], fqdn=fqdn,
                                 status=status, title=title[:50])
                        break
            except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception) as e:
                log.debug("web_probe_error", ip=host["ip"], fqdn=fqdn, error=str(e))
                continue

        host["web_probe"] = probe

    # Save probe results as a scan_result for debug visibility
    probe_summary = {h["ip"]: h.get("web_probe", {}) for h in hosts}
    _save_result(
        order_id=order_id, host_ip=None, phase=0,
        tool_name="web_probe",
        raw_output=json.dumps(probe_summary, indent=2, ensure_ascii=False),
        exit_code=0, duration_ms=0,
    )

    web_count = sum(1 for h in hosts if h.get("web_probe", {}).get("has_web"))
    log.info("web_probe_complete", total=len(hosts), with_web=web_count)

    return hosts


def run_phase0(domain: str, scan_dir: str, order_id: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
    """
    Orchestrate Phase 0: DNS Reconnaissance.

    Runs all enumeration tools, collects and deduplicates subdomains,
    validates with dnsx, and creates the host inventory.

    Overall timeout: 10 minutes.

    PR-M4 (2026-05-02): Falls fuer dieselbe Domain ein frischer
    Subdomain-Snapshot existiert (TTL 24h, ueber `scan_targets.canonical`),
    wird die Subdomain-Discovery-Phase (crt.sh / subfinder / amass /
    gobuster_dns / axfr) uebersprungen und das gecachte Subdomain-Set
    direkt an dnsx weitergereicht. Externe Drift-Quellen werden so
    eliminiert; Re-Scans innerhalb der TTL haben ein deterministisches
    Subdomain-Inventar.
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

    # --- PR-M4: Snapshot-Reuse vor Discovery ---
    # ENV `SUBDOMAIN_SNAPSHOT_DISABLED=1` deaktiviert den Reuse explizit.
    snapshot_used = False
    snapshot_target_id: Optional[str] = None
    if os.environ.get("SUBDOMAIN_SNAPSHOT_DISABLED", "").lower() not in ("1", "true", "yes"):
        try:
            from scanner.precheck import snapshot_store
            snap = snapshot_store.find_fresh_for_domain(domain)
            if snap and snap.get("subdomains"):
                all_subdomains.extend(snap["subdomains"])
                tool_sources = dict(snap.get("tool_sources") or {})
                snapshot_target_id = snap.get("scan_target_id")
                snapshot_used = True
                age_min = snap.get("age_seconds", 0) // 60
                log.info(
                    "phase0_subdomain_snapshot_reused",
                    domain=domain, order_id=order_id,
                    subdomains=len(snap["subdomains"]),
                    age_minutes=age_min,
                    target_id=snapshot_target_id,
                )
                publish_event(order_id, {
                    "type": "phase0_snapshot_reused",
                    "orderId": order_id,
                    "domain": domain,
                    "subdomains": len(snap["subdomains"]),
                    "ageMinutes": age_min,
                })
                # Skip-Marker pro uebersprungenem Tool im scan_results
                # persistieren — sonst sieht der User im Tool-Trace einfach
                # "kein amass/crtsh/subfinder" und denkt es ist kaputt.
                from scanner.tools import _save_result
                skip_msg = (
                    f"SKIPPED: Subdomain-Snapshot vom {snap.get('snapshot_ts')} "
                    f"(Alter: {age_min} Min, TTL: {snap.get('ttl_hours', 24)}h) "
                    f"wiederverwendet — {len(snap['subdomains'])} Subdomains aus "
                    f"vorherigem Lauf. Re-Enumeration via Admin: "
                    f"POST /api/admin/targets/{snapshot_target_id}/restart-precheck"
                )
                for skipped_tool in ("crtsh", "subfinder", "amass", "gobuster_dns"):
                    if skipped_tool in (phase0_tools or []):
                        try:
                            _save_result(
                                order_id=order_id, host_ip=None, phase=0,
                                tool_name=skipped_tool,
                                raw_output=skip_msg,
                                exit_code=0, duration_ms=0,
                            )
                        except Exception:
                            pass
        except Exception as exc:
            log.warning("phase0_snapshot_lookup_failed", error=str(exc))

    # --- Stufe 1: Subdomain Discovery + DNS Records (parallel) ---
    # Bei Snapshot-Reuse nur DNS-Records + axfr neu, weil diese fuer
    # Email-Security/Compliance-Reports relevant sind und billig.
    from concurrent.futures import ThreadPoolExecutor, as_completed

    zone_transfer: dict[str, Any] = {"success": False, "data": {}}
    dns_records: dict[str, Any] = {"spf": None, "dmarc": None, "dkim": False, "mx": [], "ns": []}

    discovery_futures: dict[Any, str] = {}
    with ThreadPoolExecutor(max_workers=8, thread_name_prefix="phase0b") as pool:
        if not snapshot_used:
            if "crtsh" in phase0_tools:
                discovery_futures[pool.submit(run_crtsh, domain, scan_dir, order_id)] = "crtsh"
            if "subfinder" in phase0_tools:
                discovery_futures[pool.submit(run_subfinder, domain, scan_dir, order_id)] = "subfinder"
            if "amass" in phase0_tools:
                discovery_futures[pool.submit(run_amass, domain, scan_dir, order_id)] = "amass"
            if "gobuster_dns" in phase0_tools:
                discovery_futures[pool.submit(run_gobuster_dns, domain, scan_dir, order_id)] = "gobuster_dns"
            # SecurityTrails als 4. CT-Quelle, parallel. Nur wenn API-Key
            # gesetzt — sonst Skip ohne Aufwand.
            if os.environ.get("SECURITYTRAILS_API_KEY"):
                discovery_futures[pool.submit(
                    run_securitytrails_subdomains, domain, scan_dir, order_id,
                )] = "securitytrails"
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

    # --- certspotter-Fallback wenn crt.sh leer geblieben ist ---
    # crt.sh ist die haeufigste Drift-/Ausfall-Quelle in Phase 0. Wenn es
    # 0 Subdomains liefert, fragen wir certspotter (SSLMate) als zweite
    # CT-Quelle. Beide CT-Logs indexieren denselben Bestand.
    if not snapshot_used:
        crtsh_results = tool_sources.get("crtsh") or []
        if not crtsh_results:
            try:
                cs_subs = run_certspotter(domain, scan_dir, order_id)
                if cs_subs:
                    all_subdomains.extend(cs_subs)
                    tool_sources["certspotter"] = list(cs_subs)
                    log.info("phase0_certspotter_fallback_used",
                             subdomains_found=len(cs_subs))
            except Exception as e:
                log.warning("phase0_certspotter_fallback_error", error=str(e))

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
    inventory["hosts"] = _probe_web_hosts(inventory.get("hosts", []), order_id, scan_dir)

    # --- PR-M4: Snapshot persistieren (nur wenn neu enumeriert) ---
    if not snapshot_used:
        try:
            from scanner.precheck import snapshot_store
            target_id = _resolve_scan_target_id(order_id, domain)
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
    log.info(
        "phase0_complete",
        domain=domain,
        hosts_found=len(inventory.get("hosts", [])),
        skipped=len(inventory.get("skipped_hosts", [])),
        duration_ms=elapsed_ms,
        snapshot_used=snapshot_used,
    )

    # Discovery-Health: pro Tool wieviele Subdomains kamen — fuer
    # Abbruch-Logik in worker.py + UI-Sichtbarkeit. Bei Snapshot-Reuse
    # markieren wir die Quelle als "snapshot".
    discovery_health: dict[str, Any] = {
        "snapshot_used": snapshot_used,
        "tool_counts": {tool: len(set(subs)) for tool, subs in tool_sources.items()},
        "total_subdomains": len(set(all_subdomains)),
        "ct_sources_empty": (
            not snapshot_used
            and not tool_sources.get("crtsh")
            and not tool_sources.get("certspotter")
        ),
    }
    inventory["discovery_health"] = discovery_health

    # Wenn alle CT-Quellen leer waren UND wir nicht aus Snapshot kommen,
    # warnen wir explizit — das ist verdaechtig (Domain hat normalerweise
    # mindestens 2-3 Subdomains in CT-Logs).
    if discovery_health["ct_sources_empty"] and discovery_health["total_subdomains"] < 3:
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
