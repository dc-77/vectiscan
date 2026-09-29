"""Coverage (spec/05 M5): was wurde geprueft, was nicht, und warum.

Quelle sind die ``scan_results``-Zeilen (``record_tool_run``), ergaenzt um
Sonderfaelle, die nur aus dem Werkzeug-Output erkennbar sind:
- nmap ohne gescanntes Ziel (IPv6 ohne ``-6``): Status ``ok``, aber ``hosts total=0``.
- testssl ``Can't connect``: Status ``failed`` mit Grund ``connect``.
- Web-Werkzeuge ohne Inhalt bei erreichbarem Host: ``empty``; bei blockiertem Host
  ``blocked`` (Blockade aus Inventar, ``scan_results`` oder abgeleitet).
Legacy-Zeilen ohne ``status`` werden nach ``exit_code`` und Ausgabe klassifiziert;
parsebare Ausgabe gewinnt (testssl exit 10/246 mit vollstaendigem Lauf ist ``ok``).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from typing import Any

from reporter.facts.nmap_parse import NmapHost, NmapRun
from reporter.facts.schema import (
    CONFIDENCE_DERIVED, CONFIDENCE_TOOL, Blocked, CoverageFact, Evidence, ProviderBlock,
)
from reporter.facts.serialize import excerpt, sort_key
from reporter.facts.sources import NON_TOOL_ROWS, ScanBundle, ToolRun, is_testssl_tool

# S6d (A8): Grund einer Sperre laut Sperrerkennung nach dem Portscan (S6c provider_block_probe).
PROVIDER_BLOCK_REASON = "provider_block_after_portscan"

WEB_TOOLS = frozenset({
    "header_check", "httpx", "testssl", "zap", "zap_spider", "zap_active", "zap_ajax_spider",
    "feroxbuster", "ffuf_param", "ffuf_sensitive", "ffuf_dir", "ffuf_vhost", "wpscan", "webtech",
    "nikto", "nuclei", "katana", "dalfox", "gowitness",
})
WEB_PORTS = frozenset({80, 443, 8080, 8443, 8000, 8888})
TOOL_OK_EXIT_CODES = {
    "testssl": (0, 1), "wpscan": (0, 4, 5), "ffuf_param": (0, 1), "ffuf_sensitive": (0, 1),
    "ffuf_dir": (0, 1), "ffuf_vhost": (0, 1), "feroxbuster": (0, 1),
}
EXIT_TIMEOUT, EXIT_ERROR, EXIT_SKIPPED = -1, -2, -3
# Grund fuer eine Zeile, deren Rohtext der Lader wegen der Groessengrenze
# weggelassen hat (``worker._load_tool_runs``, S5b). Die Zeile bleibt in der
# Abdeckung sichtbar, statt still als leeres Ergebnis zu erscheinen.
RAW_NOT_LOADED = "rohtext_nicht_geladen"
# S6b-3 (spec/10 R4): eine Sperre gilt nur mit Beleg in der Rohausgabe: Status 403 oder 429
# oder eine Abwehr- bzw. Challenge-Seite. Der Scanner markiert Zeilen auch dann ``blocked``,
# wenn nur ein Textmerkmal einer WAF-Seite im Koerper stand (``waf_body_marker``, bergersysteme
# 198.202.211.1 mit normalen 200- und 404-Antworten); das ist keine Sperre (S6c: Scanner).
_BLOCK_STATUS_RE = re.compile(r'"status(?:_code)?"\s*:\s*(403|429)\b')
# Nur Kopf- und Titelmerkmale einer Abwehrseite; Woerter wie "captcha" stehen auch in den
# Pfaden der Wortlisten (ffuf "captcha.php") und belegen nichts.
_CHALLENGE_RE = re.compile(r"x-vercel-mitigated|cf-mitigated|attention required|just a moment|"
                           r"security checkpoint", re.I)


def block_evidenced(run: ToolRun) -> bool:
    """Belegt die Rohausgabe oder der Grund einer ``blocked``-Zeile eine Sperre?"""
    reason = str(run.reason or "")
    if re.search(r"(?<!\d)(403|429)(?!\d)|challenge|rate.?limit", reason, re.I):
        return True
    raw = run.raw_output or ""
    if not raw.strip():
        # Ohne Rohtext bleibt es bei der Angabe des Scanners.
        return not run.raw_known
    return bool(_BLOCK_STATUS_RE.search(raw) or _CHALLENGE_RE.search(raw))


@dataclass
class HostSignals:
    ip: str
    nmap_run: Optional[NmapRun] = None
    nmap_host: Optional[NmapHost] = None
    web_ports_open: bool = False
    open_port_count: int = 0
    headers_reachable: dict[str, Optional[bool]] = field(default_factory=dict)
    httpx_has_output: Optional[bool] = None
    testssl_connect_failed: Optional[bool] = None
    testssl_has_data: bool = False
    zap_spider_urls: Optional[int] = None
    zap_alerts_total: Optional[int] = None
    inventory_blocked: Optional[Blocked] = None
    # S6d (A8): Sperrerkennung nach dem Portscan; (A2) Zustand je zusaetzlichem testssl-Lauf
    # (Werkzeugname -> "ok" oder Grund, siehe ``testssl_run_state``).
    provider_block: Optional[ProviderBlock] = None
    testssl_runs: dict[str, str] = field(default_factory=dict)


def testssl_run_state(ts: Any) -> str:
    """Zustand eines testssl-Laufs aus seiner Ausgabe (S6d, A2, C4).

    testssl gibt als Exit-Code eine Befundzahl zurueck; die Zeile steht deshalb bei einem
    vollstaendigen Lauf mit Befunden auf ``failed`` (dortmund-beach testssl_587: Exit 8, 235
    Eintraege). Massgeblich ist die Ausgabe: ``ok`` bei Protokollergebnissen ohne Abbruch; sonst
    der Grund (``tls_connect_refused``, ``no_tls_on_port``, ``starttls_failed``, ``incomplete``)."""
    if ts is None:
        return "no_output"
    for e in getattr(ts, "entries", []) or []:
        if e.get("id") == "scanProblem" or str(e.get("severity") or "").upper() == "FATAL":
            f = str(e.get("finding") or "").lower()
            if "starttls" in f:
                return "starttls_failed"
            if "tls/ssl enabled" in f or "doesn't seem" in f or "no ssl/tls" in f:
                return "no_tls_on_port"
            return "tls_connect_refused"
    if getattr(ts, "connect_failed", False):
        return "tls_connect_refused"
    if not ts.has_data or not any(v is not None for v in ts.protocols.values()):
        return "incomplete"
    return "ok"


def _looks_complete(run: ToolRun) -> bool:
    raw = (run.raw_output or "").strip()
    if not raw:
        return False
    if raw.startswith(("SKIPPED", "FAILED", "TIMEOUT")):
        return False
    tool = run.tool_norm
    if is_testssl_tool(tool):
        return "Done 20" in raw or " Done " in raw or "Testing protocols" in raw
    if tool == "nmap":
        return "Nmap scan report" in raw or "Nmap done" in raw
    if raw[0] in "[{":
        return True
    return len(raw) > 40


def classify_run(run: ToolRun) -> tuple[str, Optional[str], Optional[str]]:
    """(status, reason, raw_status) fuer eine Zeile, ohne Host-Kontext.

    ``run.raw_known`` unterscheidet "leer gelaufen" von "nicht geladen" (S5b).
    Eine Zeile ohne geladenen Rohtext behaelt ihren Status; sie als ``empty`` zu
    fuehren hiesse, ueber ein Werkzeug zu urteilen, dessen Ausgabe nie gelesen
    wurde. Wurde der Rohtext wegen der Groessengrenze weggelassen, steht das als
    Grund in der Abdeckung.
    """
    raw_status = run.status
    reason = run.reason
    if run.raw_omitted and not reason:
        reason = RAW_NOT_LOADED
    raw = (run.raw_output or "").strip()
    if raw_status == "blocked" and not block_evidenced(run):
        # S6b-3 (spec/10 R4): Sperre ohne Beleg ist ein normaler Lauf.
        return ("ok" if raw else "empty"), reason, raw_status
    if raw_status in ("ok", "skipped", "failed", "blocked"):
        status = raw_status
        if status == "ok" and not raw and run.raw_known \
                and run.tool_norm not in ("ai_host_strategy",):
            status = "empty"
        return status, reason, raw_status
    if raw_status == "timeout":
        return "failed", reason or "timeout", raw_status
    # Legacy ohne status: Ausgabe zuerst, dann exit_code.
    if raw.startswith("SKIPPED:"):
        return "skipped", reason or raw[len("SKIPPED:"):].strip()[:160], None
    if raw.startswith("TIMEOUT"):
        return "failed", reason or "timeout", None
    if raw.startswith("FAILED:"):
        return "failed", reason or raw[len("FAILED:"):].strip()[:160], None
    if raw.startswith("OK:"):
        return "ok", reason or raw[3:].strip()[:160], None
    if run.exit_code == EXIT_SKIPPED:
        return "skipped", reason, None
    if run.exit_code == EXIT_TIMEOUT:
        return "failed", reason or "timeout", None
    if _looks_complete(run):
        return "ok", reason, None
    if run.exit_code == EXIT_ERROR:
        return "failed", reason, None
    if run.exit_code is not None and run.exit_code > 0:
        ok_codes = TOOL_OK_EXIT_CODES.get(run.tool_norm, (0,))
        if run.exit_code in ok_codes:
            return ("ok" if raw or not run.raw_known else "empty"), reason, None
        return "failed", reason or f"exit_{run.exit_code}", None
    if not raw:
        if not run.raw_known:
            return "unknown", reason or RAW_NOT_LOADED, None
        return "empty", reason, None
    return "ok", reason, None


def derive_blocked(sig: HostSignals, runs: list[ToolRun]) -> Blocked:
    """Blockade in fester Reihenfolge: Inventar, Sperrerkennung, scan_results, abgeleitet."""
    if sig.inventory_blocked and sig.inventory_blocked.detected:
        return sig.inventory_blocked
    # S6d (A8): die Sperrerkennung nach dem Portscan (S6c) ist ein Messfakt, keine Ableitung.
    # Gesperrte Hosts ueberspringen Phase 2; die Ableitung unten griffe dort nie.
    if sig.provider_block is not None and sig.provider_block.blocked is True:
        return Blocked(detected=True, reason=PROVIDER_BLOCK_REASON, source="scan_results")
    for r in runs:
        if r.host_ip == sig.ip and r.status == "blocked" and block_evidenced(r):
            return Blocked(detected=True, reason=r.reason or "blocked", source="scan_results")
    if sig.web_ports_open and sig.headers_reachable and all(
            v is False for v in sig.headers_reachable.values()) \
            and (sig.testssl_connect_failed or not sig.testssl_has_data) \
            and not sig.httpx_has_output:
        return Blocked(detected=True, reason="web_unreachable_after_portscan", source="derived")
    return Blocked(detected=False)


def build_coverage(bundle: ScanBundle, signals: dict[str, HostSignals],
                   blocked: dict[str, Blocked], scan_finished: Optional[str],
                   primary_domain: Optional[str], extra_domains: list[str]) -> list[CoverageFact]:
    facts: list[CoverageFact] = []
    seen_ids: dict[str, int] = {}

    def make(scope: str, tool: str, status: str, *, host_ip=None, fqdn=None, domain=None,
             phase=None, raw_status=None, reason=None, exit_code=None, duration_ms=None,
             observed_at=None, evidence=None, confidence=CONFIDENCE_TOOL, source="scan_results",
             target=None, run_status=None):
        key = f"cov:{phase if phase is not None else '-'}:{tool}:{_scope_key(scope, host_ip, fqdn, domain)}"
        n = seen_ids.get(key, 0)
        seen_ids[key] = n + 1
        fid = key if n == 0 else f"{key}#{n + 1}"
        facts.append(CoverageFact(
            id=fid, source=source, mode="active", observed_at=observed_at or scan_finished,
            confidence=confidence, evidence=evidence or [], scope=scope, domain=domain,
            host_ip=host_ip, fqdn=fqdn, phase=phase, tool=tool, status=status,
            raw_status=raw_status, reason=reason, exit_code=exit_code, duration_ms=duration_ms,
            target=target, run_status=run_status,
        ))

    if not bundle.tool_runs:
        make("scan", "scan_results", "unknown", reason="no_tool_runs", domain=primary_domain,
             confidence=CONFIDENCE_DERIVED, source="facts_builder")
        for ip, sig in sorted(signals.items(), key=lambda kv: sort_key(kv[0])):
            _special_rows(make, bundle, ip, sig, blocked.get(ip), None)
        for dom in extra_domains:
            make("domain", "dns", "unknown", domain=dom, reason="second_target_unlabeled",
                 confidence=CONFIDENCE_DERIVED, source="facts_builder")
        return facts

    for run in bundle.tool_runs:
        if run.tool in NON_TOOL_ROWS or run.is_ai or run.is_debug:
            continue
        status, reason, raw_status = classify_run(run)
        tool = run.tool_norm
        ip = run.host_ip
        fqdn = run.vhost() if tool in ("header_check", "httpx") else None
        if fqdn is None and tool == "wafw00f":
            fqdn = _wafw00f_vhost(run)
        ev = [Evidence(tool=run.tool, ref=run.ref, excerpt=excerpt(run.raw_output, 160))]
        sig = signals.get(ip) if ip else None
        # Sonderfaelle aus dem Werkzeug-Output
        if ip and sig is not None:
            status, reason = _adjust_with_signals(tool, status, reason, sig, fqdn, blocked.get(ip))
        scope = "host" if ip else "scan"
        if fqdn:
            scope = "fqdn"
        # Issue #12: traegt die Zeile ein Domain-Etikett, ist ihr Geltungsbereich
        # genau diese Domain. Ohne Etikett bleibt es beim bisherigen Verhalten:
        # domainweite Zeilen zaehlen zum Primaerziel.
        row_domain = run.domain() if not ip else None
        if row_domain:
            scope = "domain"
        make(scope, tool, status, host_ip=ip, fqdn=fqdn,
             domain=None if ip else (row_domain or primary_domain),
             phase=run.phase, raw_status=raw_status,
             reason=reason, exit_code=run.exit_code, duration_ms=run.duration_ms,
             observed_at=run.created_at, evidence=ev, target=_run_target(run),
             run_status=_run_status(run))
    # Domains, die eigene domainweite Zeilen mitgebracht haben, brauchen den
    # Platzhalter nicht mehr. Fuer die historischen Tars (Junkerwerk) bleibt er
    # erreichbar, deshalb wird der Grund nicht entfernt.
    labeled = {f.domain for f in facts if f.scope == "domain" and f.domain}
    for dom in extra_domains:
        if dom in labeled:
            continue
        make("domain", "dns", "unknown", domain=dom, reason="second_target_unlabeled",
             confidence=CONFIDENCE_DERIVED, source="facts_builder")
    facts.sort(key=lambda f: sort_key(f.phase, f.tool, f.host_ip, f.fqdn, f.domain, f.id))
    return facts


def _run_target(run: ToolRun) -> Optional[str]:
    """Ziel einer zap_active-Zeile laut Rohausgabe (spec/10 R3)."""
    if run.tool_norm != "zap_active":
        return None
    data = run.json()
    if isinstance(data, dict) and data.get("target"):
        return str(data["target"])[:300]
    m = re.search(r"'url':\s*'([^']+)'", run.raw_output or "")
    return m.group(1)[:300] if m else None


def _run_status(run: ToolRun) -> Optional[str]:
    """Abschluss einer zap_active-Zeile laut Rohausgabe (``status: complete``, spec/11 N13)."""
    if run.tool_norm != "zap_active":
        return None
    data = run.json()
    if isinstance(data, dict) and data.get("status"):
        return str(data["status"])[:40]
    return None


def _scope_key(scope: str, host_ip, fqdn, domain) -> str:
    from reporter.facts.serialize import ip_token
    if scope == "fqdn":
        return f"{ip_token(host_ip)}:{fqdn}"
    if scope == "host":
        return ip_token(host_ip)
    if scope == "domain":
        return str(domain)
    return "scan"


def _wafw00f_vhost(run: ToolRun) -> Optional[str]:
    import re
    m = re.search(r"Checking https?://([^\s/]+)", run.raw_output or "")
    return m.group(1) if m else None


def _adjust_with_signals(tool: str, status: str, reason: Optional[str], sig: HostSignals,
                         fqdn: Optional[str], blocked: Optional[Blocked]) -> tuple[str, Optional[str]]:
    if tool == "nmap":
        run = sig.nmap_run
        if run is not None and not run.hosts and not run.hosts_total:
            if run.targets_skipped or ":" in sig.ip:
                return "failed", "target_invalid_ipv6" if ":" in sig.ip else "target_skipped"
            return "empty", reason or "no_output"
        if run is not None and sig.nmap_host is not None and sig.open_port_count == 0 \
                and status == "ok":
            return "ok", reason or "no_open_ports"
        return status, reason
    if tool == "testssl":
        if sig.testssl_connect_failed:
            status, reason = "failed", "connect"
        elif status == "failed" and sig.testssl_has_data and not sig.testssl_connect_failed:
            status, reason = "ok", reason
    elif is_testssl_tool(tool) and status in ("ok", "failed"):
        # S6d (A2): die Ausgabe des Laufs entscheidet, nicht der Exit-Code (Befundzahl).
        state = sig.testssl_runs.get(tool)
        if state == "ok":
            status, reason = "ok", None
        elif state:
            status, reason = "failed", reason or state
    if tool == "header_check" and fqdn is not None:
        reach = sig.headers_reachable.get(fqdn)
        if reach is False and status == "ok":
            status, reason = "empty", reason or "unreachable"
    if tool == "httpx" and status == "ok" and sig.httpx_has_output is False:
        status, reason = "empty", reason or "no_output"
    if tool in ("zap", "zap_spider") and status == "ok" and sig.zap_spider_urls == 0:
        status, reason = "empty", reason or "no_urls_spidered"
    # Issue #13: ZAP hat gespidert, aber keine einzige Meldung geliefert.
    # Junkerwerk Lauf 2 (2572eebc) steht so auf "ok" bei 50/34/4 gespiderten
    # URLs und total_alerts 0, waehrend Lauf 1 fuer dieselben Hosts 127/19/55
    # Alerts hat. Als "ok" gelesen hiesse das "keine Befunde"; die Wahrheit ist
    # "nicht belastbar" und gehoert in die Abdeckung, nicht in eine
    # Auffangregel des Katalogs. Nur `zap` (die passive Analyse) wird
    # herabgestuft: der Spider zaehlt URLs, nicht Alerts, und zap_active hat
    # seine eigene Abdeckung.
    if tool == "zap" and status == "ok" and sig.zap_alerts_total == 0:
        status, reason = "empty", reason or "zap_no_alerts"
    if blocked is not None and blocked.detected and (tool in WEB_TOOLS or is_testssl_tool(tool)) \
            and status in ("empty", "failed"):
        return "blocked", blocked.reason
    return status, reason


def _special_rows(make, bundle: ScanBundle, ip: str, sig: HostSignals,
                  blocked: Optional[Blocked], observed_at: Optional[str]) -> None:
    """Ohne tool_runs nur die Faelle, die der Werkzeug-Output selbst belegt."""
    h = bundle.hosts.get(ip)
    run = sig.nmap_run
    if run is not None and not run.hosts and not run.hosts_total:
        ref = (h.refs.get("nmap.xml") if h else None) or "hosts/%s/phase1/nmap.xml" % ip
        make("host", "nmap", "failed", host_ip=ip, phase=1,
             reason="target_invalid_ipv6" if ":" in ip else "target_skipped",
             evidence=[Evidence(tool="nmap", ref=ref, excerpt=excerpt(run.summary or "0 hosts scanned", 160))],
             confidence=CONFIDENCE_DERIVED, source="nmap")
    if sig.testssl_connect_failed:
        ref = (h.refs.get("testssl.json") if h else None) or "hosts/%s/phase2/testssl.json" % ip
        make("host", "testssl", "blocked" if blocked and blocked.detected else "failed",
             host_ip=ip, phase=2, reason=(blocked.reason if blocked and blocked.detected else "connect"),
             evidence=[Evidence(tool="testssl", ref=ref, excerpt="Can't connect")],
             confidence=CONFIDENCE_DERIVED, source="testssl")
