"""C3 — Abdeckungs-Aggregation: "Was wurde geprueft — und was nicht".

Reine Aggregation ohne ReportLab-Abhaengigkeit (analog ``v2_data.py`` /
``befund_landschaft.py``). Wandelt die autoritativen ``scan_results``-Zeilen
(durchgereicht als ``scan_meta["toolRuns"]``) plus die KI-#1-Host-Strategie
(``scan_meta["hostStrategy"]``), das Host-Inventar und die Findings in eine
deterministische Datenstruktur fuer den v2-Renderer um.

Drei Host-Zustaende:
  - ``befund``          — Host hat >= 1 Finding.
  - ``unauffaellig``    — >= 1 erfolgreicher Tool-Lauf in Phase 1/2, kein Finding.
  - ``nicht_pruefbar``  — kein erfolgreicher Phase-1/2-Lauf ODER KI-Skip ODER
                          host["status"]=="skipped" ODER Host-Limit erreicht.

Fail-open: jeder unerwartete Input wird abgefangen, im Zweifel liefert die
Funktion ``None`` und der Renderer ueberspringt das Kapitel — ein Fehler hier
darf den Report niemals kippen.
"""
from __future__ import annotations

import re
from typing import Any

import structlog

log = structlog.get_logger()


# --------------------------------------------------------------------------
# Konstanten
# --------------------------------------------------------------------------

STATE_BEFUND = "befund"
STATE_CLEAN = "unauffaellig"
STATE_NOT_TESTABLE = "nicht_pruefbar"

_STATE_LABELS: dict[str, str] = {
    STATE_BEFUND: "Befund",
    STATE_CLEAN: "unauffällig",
    STATE_NOT_TESTABLE: "nicht prüfbar",
}

# Zell-Zustaende der Tool-x-Host-Matrix.
CELL_OK = "ok"
CELL_FAIL = "fail"
CELL_SKIP = "skip"
CELL_NA = "n/a"

# Spalten-Schluessel fuer scan-weite (host_ip IS NULL) Laeufe.
SCANWIDE_KEY = "scanweit"

# Zeilen in scan_results, die keine Tools sind und aus der Matrix fliegen.
_NON_TOOL_NAMES: frozenset[str] = frozenset({
    "report_cost",
    "ai_host_strategy",
    "ai_host_skip",
    "ai_tech_analysis",
    "ai_phase2_config",
    "ai_phase2_config_rule_based",
    "phase3_correlation",
})


# --------------------------------------------------------------------------
# Schwachstellen-Scanner vs. reine Detektion (BEFUND 5)
# --------------------------------------------------------------------------
# Tools, deren ERFOLGREICHER Lauf eine echte Schwachstellen-/Sicherheitspruefung
# belegt.  Nur wenn mindestens eines davon auf einem Host erfolgreich lief, darf
# der Host ohne Finding als "unauffaellig" (STATE_CLEAN) gelten.  Reine
# Detektions-/Fingerprint-Tools (nmap, webtech, wafw00f, cms_fingerprint,
# httpx) und Content-Discovery (gobuster, ffuf, feroxbuster, katana, gowitness)
# sagen NICHTS ueber die Abwesenheit von Schwachstellen aus — laeuft nur so
# etwas, ist die Schwachstellenpruefung nicht abgeschlossen.
_VULN_SCAN_TOOLS: frozenset[str] = frozenset({
    "testssl", "nikto", "nuclei", "dalfox", "wpscan", "sslscan", "sslyze",
})


def _is_vuln_scan_tool(norm: str) -> bool:
    """True, wenn der (normalisierte) Tool-Name ein echter Schwachstellenscan ist.

    ZAP laeuft in mehreren Modi (``zap_active``/``zap_spider``/``zap_passive``/
    ``zap_ajax_spider``) — alle gelten als DAST-Schwachstellenscan und werden
    ueber das ``zap``-Praefix erfasst.
    """
    if not norm:
        return False
    if norm in _VULN_SCAN_TOOLS:
        return True
    if norm.startswith("zap"):
        return True
    return False


def _normalize_tool_name(name: str) -> str:
    """Retry-/Varianten-Suffixe auf den Basis-Tool-Namen zuruecckfuehren.

    ``crtsh_retry2`` -> ``crtsh``, ``ffuf_sensitive``/``ffuf_param`` -> ``ffuf``.
    """
    if not name:
        return ""
    n = name.strip()
    # ``_retry<N>``-Suffix (phase0.py schreibt crtsh_retry2 etc.)
    n = re.sub(r"_retry\d+$", "", n)
    # ffuf laeuft in mehreren Modi (param/sensitive/...) — alle auf ffuf.
    if n.startswith("ffuf_"):
        n = "ffuf"
    return n


def _is_tool_row(tool_name: str) -> bool:
    """True, wenn die scan_results-Zeile ein echtes Tool ist (keine KI/Meta)."""
    if not tool_name:
        return False
    if tool_name in _NON_TOOL_NAMES:
        return False
    # *_debug-Zeilen (ai_strategy.py) sind Debug-Dumps, keine Tools.
    if tool_name.endswith("_debug"):
        return False
    return True


def _run_state(run: dict[str, Any]) -> str:
    """Ein Tool-Lauf -> Zell-Zustand. DREISTUFIG, Reihenfolge zwingend:

    (1) ``status`` (A7) wenn gesetzt -> autoritativ.
    (2) sonst Ableitung aus ``exit_code`` (Legacy), -3 explizit als Skip.
    (3) im Zweifel ``fail`` (nie werfend).
    """
    status = run.get("status")
    if status:
        s = str(status).strip().lower()
        if s == "ok":
            return CELL_OK
        if s in ("skipped", "blocked"):
            return CELL_SKIP
        if s in ("failed", "timeout"):
            return CELL_FAIL
        return CELL_FAIL

    ec = run.get("exit_code")
    if ec is None:
        return CELL_FAIL
    try:
        ec_int = int(ec)
    except (TypeError, ValueError):
        return CELL_FAIL
    if ec_int == 0:
        return CELL_OK
    if ec_int == -3:          # EXIT_CODE_SKIPPED
        return CELL_SKIP
    # -1 (Timeout) / -2 (Error) / sonstige != 0 -> fehlgeschlagen.
    return CELL_FAIL


def _cell_merge(states: list[str]) -> str:
    """Mehrere Laeufe pro (Tool, Host) zu EINER Zelle verdichten.

    Praezedenz ``ok > fail > skip``: ein erfolgreicher Lauf (auch nur auf einem
    VHost) macht die Zelle gruen; sonst zaehlt der Fehlschlag vor dem Skip.
    """
    if not states:
        return CELL_NA
    if CELL_OK in states:
        return CELL_OK
    if CELL_FAIL in states:
        return CELL_FAIL
    if CELL_SKIP in states:
        return CELL_SKIP
    return CELL_NA


def _finding_id(finding: dict[str, Any]) -> str:
    return str(finding.get("external_id") or finding.get("id") or "").strip()


# IPv4 + FQDN-Extraktion aus freien affected-Strings. Der von der KI erzeugte
# affected-Text kommt in wechselnder Reihenfolge — "fqdn (ip:port)",
# "ip:port (fqdn)", "fqdn:port", "ip", "fqdn a, fqdn b". Ein reines
# split(":")[0] zerbricht an "fqdn (ip:port)" (liefert "fqdn (ip" statt fqdn
# ODER ip) und die Finding->Host-Zuordnung schlaegt fehl — der Host erschiene
# faelschlich als "unauffaellig", obwohl Befunde vorliegen. Deshalb ziehen wir
# jede IPv4- und FQDN-artige Teilzeichenkette reihenfolgeunabhaengig heraus.
_IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_FQDN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z][a-z0-9-]*[a-z0-9]\b",
    re.IGNORECASE,
)


def _tokens_from_affected(aff: str) -> set[str]:
    """Zieht alle Host-Identifier (IPv4 + FQDNs) aus einem affected-String."""
    out: set[str] = set()
    for m in _IPV4_RE.findall(aff):
        out.add(m.lower())
    for m in _FQDN_RE.findall(aff):
        out.add(m.lower())
    return out


def _host_candidates(finding: dict[str, Any]) -> set[str]:
    """Host-Bezeichner, auf die ein Finding zeigen kann (ip/fqdn/affected).

    Wiederverwendung der Zuordnungslogik aus appendix._findings_by_port_host,
    aber ReportLab-frei und als Menge normalisierter Kleinbuchstaben. Der
    ``affected``-Freitext wird per Regex zerlegt (siehe _tokens_from_affected),
    damit sowohl "fqdn (ip:port)" als auch "ip:port (fqdn)" korrekt auf Host-IP
    und -FQDN abgebildet werden.
    """
    out: set[str] = set()
    for k in ("vhost", "fqdn", "host", "host_ip", "ip"):
        v = finding.get(k)
        if v:
            out.add(str(v).strip().lower())
    aff = finding.get("affected")
    if isinstance(aff, str):
        out |= _tokens_from_affected(aff)
    elif isinstance(aff, list):
        for a in aff:
            if isinstance(a, str):
                out |= _tokens_from_affected(a)
    out.discard("")
    return out


def _host_label(ip: str, fqdns: list[str]) -> str:
    """Host-Label exakt wie v2_data.build_tech_table_v2:314."""
    first = fqdns[0] if fqdns else ip
    return f"{first} - {ip}".strip(" -")


def _host_match_keys(ip: str, fqdns: list[str]) -> set[str]:
    keys: set[str] = set()
    if ip:
        keys.add(str(ip).strip().lower())
    for fq in fqdns or []:
        if fq:
            keys.add(str(fq).strip().lower())
    keys.discard("")
    return keys


def build_scan_coverage(
    host_inventory: dict[str, Any] | None,
    tool_runs: list[dict[str, Any]] | None,
    host_strategy: dict[str, Any] | None,
    findings: list[dict[str, Any]] | None,
    tech_profiles: list[dict[str, Any]] | None,
    package: str | None,
) -> dict[str, Any] | None:
    """Aggregiert die Abdeckungs-Sicht fuer das C3-Kapitel.

    Returns ein deterministisches dict (Stable-Sort, ``ip`` als Tiebreaker)::

        {
          "hosts":  [{ip, host_label, fqdns, state, state_label, reason,
                      finding_ids, finding_count, tools_run, tools_failed}],
          "matrix": {"tools": [name...], "tool_phase": {name: phase},
                     "hosts": [colkey...], "host_labels": {colkey: label},
                     "cells": {name: {colkey: "ok"|"fail"|"skip"|"n/a"}}},
          "totals": {hosts_total, hosts_with_findings, hosts_clean,
                     hosts_not_testable, tools_total, tool_runs_total,
                     tool_runs_failed},
        }

    ``None``, wenn es keine Host-Grundgesamtheit gibt (leeres Inventar) — der
    Renderer ueberspringt das Kapitel dann komplett. Fail-open: jede Exception
    wird geloggt und fuehrt zu ``None``.
    """
    try:
        return _build_scan_coverage_impl(
            host_inventory or {},
            tool_runs or [],
            host_strategy or {},
            findings or [],
            tech_profiles or [],
            package or "",
        )
    except Exception as exc:  # pragma: no cover - reine Absicherung
        log.warning("build_scan_coverage_failed", error=str(exc))
        return None


def _build_scan_coverage_impl(
    host_inventory: dict[str, Any],
    tool_runs: list[dict[str, Any]],
    host_strategy: dict[str, Any],
    findings: list[dict[str, Any]],
    tech_profiles: list[dict[str, Any]],
    package: str,
) -> dict[str, Any] | None:
    # -- Host-Grundgesamtheit: aktive Hosts + Limit-uebersprungene Hosts ----
    inv_hosts = host_inventory.get("hosts") or []
    skipped_hosts = host_inventory.get("skipped_hosts") or []

    host_entries: list[dict[str, Any]] = []
    seen_ips: set[str] = set()
    for h in inv_hosts:
        if not isinstance(h, dict):
            continue
        ip = str(h.get("ip") or "").strip()
        if not ip or ip in seen_ips:
            continue
        seen_ips.add(ip)
        host_entries.append({"raw": h, "ip": ip, "limit_skipped": False})
    for h in skipped_hosts:
        if not isinstance(h, dict):
            continue
        ip = str(h.get("ip") or "").strip()
        if not ip or ip in seen_ips:
            continue
        seen_ips.add(ip)
        host_entries.append({"raw": h, "ip": ip, "limit_skipped": True})

    if not host_entries:
        # Keine Hosts -> kein Kapitel (Degradation).
        return None

    # -- KI-#1-Strategie nach IP indizieren ---------------------------------
    strategy_by_ip: dict[str, dict[str, Any]] = {}
    for sh in host_strategy.get("hosts") or []:
        if isinstance(sh, dict) and sh.get("ip"):
            strategy_by_ip[str(sh["ip"]).strip()] = sh

    # -- Tool-Laeufe: filtern (echte Tools) + normalisieren -----------------
    # runs_by_col_tool[(colkey, tool)] = [state, ...]
    filtered_runs: list[dict[str, Any]] = []
    for r in tool_runs:
        if not isinstance(r, dict):
            continue
        raw_name = str(r.get("tool_name") or "")
        if not _is_tool_row(raw_name):
            continue
        norm = _normalize_tool_name(raw_name)
        if not norm:
            continue
        host_ip = r.get("host_ip")
        colkey = str(host_ip).strip() if host_ip else SCANWIDE_KEY
        try:
            phase = int(r.get("phase")) if r.get("phase") is not None else None
        except (TypeError, ValueError):
            phase = None
        filtered_runs.append({
            "tool": norm,
            "colkey": colkey,
            "phase": phase,
            "state": _run_state(r),
        })

    # Aggregation der Zellen + Tool-Phasen.
    cell_states: dict[str, dict[str, list[str]]] = {}
    tool_phase: dict[str, int] = {}
    for fr in filtered_runs:
        tool = fr["tool"]
        cell_states.setdefault(tool, {}).setdefault(fr["colkey"], []).append(fr["state"])
        ph = fr["phase"]
        if ph is not None:
            prev = tool_phase.get(tool)
            tool_phase[tool] = ph if prev is None else min(prev, ph)

    # Per-Host-Aggregation der Laeufe fuer die Zustandslogik.
    # host_ok_p12[ip] = True, wenn >=1 erfolgreicher Phase-1/2-Lauf.
    host_ok_p12: dict[str, bool] = {}
    host_ran_p12: dict[str, bool] = {}
    host_tools_ok: dict[str, set[str]] = {}
    host_tools_failed: dict[str, set[str]] = {}
    host_ai_skip_reason: dict[str, str] = {}
    for r in tool_runs:
        if not isinstance(r, dict):
            continue
        host_ip = r.get("host_ip")
        if not host_ip:
            continue
        ip = str(host_ip).strip()
        raw_name = str(r.get("tool_name") or "")
        # A7-Host-Skip traegt die autoritative Skip-Begruendung.
        if raw_name == "ai_host_skip":
            reason = r.get("skip_reason")
            if reason:
                host_ai_skip_reason[ip] = str(reason).strip()
            continue
        if not _is_tool_row(raw_name):
            continue
        try:
            phase = int(r.get("phase")) if r.get("phase") is not None else None
        except (TypeError, ValueError):
            phase = None
        if phase not in (1, 2):
            continue
        norm = _normalize_tool_name(raw_name)
        state = _run_state(r)
        host_ran_p12[ip] = True
        if state == CELL_OK:
            host_ok_p12[ip] = True
            host_tools_ok.setdefault(ip, set()).add(norm)
        elif state == CELL_FAIL:
            host_tools_failed.setdefault(ip, set()).add(norm)

    # -- Findings -> Hosts zuordnen -----------------------------------------
    # Vorab die Match-Keys pro Host bilden.
    host_match: dict[str, set[str]] = {}
    for he in host_entries:
        raw = he["raw"]
        fqdns = raw.get("fqdns") or []
        host_match[he["ip"]] = _host_match_keys(he["ip"], fqdns)

    findings_for_host: dict[str, list[str]] = {he["ip"]: [] for he in host_entries}
    for f in findings:
        if not isinstance(f, dict):
            continue
        fid = _finding_id(f)
        if not fid:
            continue
        cand = _host_candidates(f)
        if not cand:
            continue
        for ip, keys in host_match.items():
            if keys & cand and fid not in findings_for_host[ip]:
                findings_for_host[ip].append(fid)

    # -- Host-Zustaende + Begruendung ---------------------------------------
    hosts_out: list[dict[str, Any]] = []
    for he in host_entries:
        ip = he["ip"]
        raw = he["raw"]
        fqdns = [str(x) for x in (raw.get("fqdns") or [])]
        fids = sorted(findings_for_host.get(ip, []))
        is_explicit_skip = (
            (strategy_by_ip.get(ip, {}).get("action") == "skip")
            or (str(raw.get("status") or "").lower() == "skipped")
            or he["limit_skipped"]
        )
        has_ok = host_ok_p12.get(ip, False)
        # BEFUND 5: "unauffaellig" nur, wenn mindestens ein ECHTER Schwachstellen-
        # /Pruef-Lauf erfolgreich war.  Lief nur Detektion/Fingerprinting
        # erfolgreich (und die echten Schwachstellen-Scans schlugen fehl), ist
        # die Pruefung nicht abgeschlossen -> nicht_pruefbar statt unauffaellig.
        has_vuln_scan_ok = any(
            _is_vuln_scan_tool(t) for t in host_tools_ok.get(ip, ()))

        if fids:
            state = STATE_BEFUND
        elif is_explicit_skip or not has_ok or not has_vuln_scan_ok:
            state = STATE_NOT_TESTABLE
        else:
            state = STATE_CLEAN

        reason = ""
        if state == STATE_NOT_TESTABLE:
            reason = _reason_for_not_testable(
                ip, raw, he, strategy_by_ip, host_ai_skip_reason,
                host_ran_p12.get(ip, False),
                has_ok=has_ok, vuln_scan_ok=has_vuln_scan_ok,
            )

        hosts_out.append({
            "ip": ip,
            "host_label": _host_label(ip, fqdns),
            "fqdns": fqdns,
            "state": state,
            "state_label": _STATE_LABELS[state],
            "reason": reason,
            "finding_ids": fids,
            "finding_count": len(fids),
            "tools_run": sorted(host_tools_ok.get(ip, set())),
            "tools_failed": sorted(host_tools_failed.get(ip, set())),
        })

    # Stable-Sort: nicht_pruefbar/befund zuerst waere Wertung — wir sortieren
    # rein deterministisch nach IP (Tiebreaker laut Determinismus-Block).
    hosts_out.sort(key=lambda h: h["ip"])

    # -- Matrix zusammenbauen -----------------------------------------------
    col_order: list[str] = [h["ip"] for h in hosts_out]
    has_scanwide = any(
        SCANWIDE_KEY in cols for cols in cell_states.values()
    )
    if has_scanwide:
        col_order.append(SCANWIDE_KEY)

    host_labels: dict[str, str] = {h["ip"]: h["host_label"] for h in hosts_out}
    if has_scanwide:
        host_labels[SCANWIDE_KEY] = "scanweit"

    matrix_tools = sorted(
        cell_states.keys(),
        key=lambda t: (tool_phase.get(t, 99), t),
    )
    cells: dict[str, dict[str, str]] = {}
    for tool in matrix_tools:
        per_col = cell_states.get(tool, {})
        cells[tool] = {}
        for col in col_order:
            cells[tool][col] = _cell_merge(per_col.get(col, []))

    matrix = {
        "tools": matrix_tools,
        "tool_phase": {t: tool_phase.get(t, 0) for t in matrix_tools},
        "hosts": col_order,
        "host_labels": host_labels,
        "cells": cells,
    }

    # -- Totals --------------------------------------------------------------
    tool_runs_failed = sum(1 for fr in filtered_runs if fr["state"] == CELL_FAIL)
    totals = {
        "hosts_total": len(hosts_out),
        "hosts_with_findings": sum(1 for h in hosts_out if h["state"] == STATE_BEFUND),
        "hosts_clean": sum(1 for h in hosts_out if h["state"] == STATE_CLEAN),
        "hosts_not_testable": sum(1 for h in hosts_out if h["state"] == STATE_NOT_TESTABLE),
        "tools_total": len(matrix_tools),
        "tool_runs_total": len(filtered_runs),
        "tool_runs_failed": tool_runs_failed,
    }

    return {"hosts": hosts_out, "matrix": matrix, "totals": totals}


def _reason_for_not_testable(
    ip: str,
    raw: dict[str, Any],
    host_entry: dict[str, Any],
    strategy_by_ip: dict[str, dict[str, Any]],
    host_ai_skip_reason: dict[str, str],
    ran_p12: bool,
    has_ok: bool = False,
    vuln_scan_ok: bool = True,
) -> str:
    """Begruendungs-Prioritaet fuer ``nicht_pruefbar``.

    skip_reason (A7) > host_strategy.reasoning > host["_reasoning"]
    (Redirect-Dedup) > "Host-Limit des Pakets erreicht" (skipped_hosts) >
    "Schwachstellenpruefung nicht abgeschlossen" (BEFUND 5 — Detektion lief,
    aber kein echter Schwachstellenscan) > "alle Tool-Laeufe fehlgeschlagen" >
    "Grund nicht protokolliert" (Alt-Orders vor A7 — niemals behaupten, es sei
    alles geprueft worden).
    """
    a7 = host_ai_skip_reason.get(ip)
    if a7:
        return a7
    strat = strategy_by_ip.get(ip, {}).get("reasoning")
    if strat:
        return str(strat).strip()
    reasoning = raw.get("_reasoning")
    if reasoning:
        return str(reasoning).strip()
    if host_entry.get("limit_skipped"):
        return "Host-Limit des Pakets erreicht"
    # BEFUND 5: erfolgreiche Detektion, aber kein echter Schwachstellenscan.
    # "alle Tool-Laeufe fehlgeschlagen" waere hier falsch (es gab erfolgreiche
    # Laeufe) — der Host ist nur nicht abschliessend geprueft.
    if has_ok and not vuln_scan_ok:
        return "Schwachstellenprüfung nicht abgeschlossen"
    if ran_p12:
        return "alle Tool-Läufe fehlgeschlagen"
    return "Grund nicht protokolliert"


__all__ = [
    "build_scan_coverage",
    "STATE_BEFUND",
    "STATE_CLEAN",
    "STATE_NOT_TESTABLE",
    "CELL_OK",
    "CELL_FAIL",
    "CELL_SKIP",
    "CELL_NA",
    "SCANWIDE_KEY",
]
