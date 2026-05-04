"""Tool-Output-Normalizer (PR-ABC, 2026-05-02).

Strippt volatile Felder aus Tool-Outputs vor der Persistierung in
`scan_results.raw_output`, damit gleicher Server-Zustand zu identischen
Bytes fuehrt — Cache-Hash auf KI-Inputs wird wirksam.

Hintergrund TIEFENANALYSE-RUN-DRIFT-2026-05-02.md:
- httpx schreibt `timestamp` (Wall-Clock) und `time` (Real-Latency-ms) in
  jede Output-Zeile → bricht Bytehash zwischen identischen Server-
  Antworten.
- wafw00f rotiert seine ASCII-Art-Banner (W00f vs Wave) und fuegt
  ANSI-Farb-Codes ein → 1097 vs 622 Bytes bei selber Detection.
- dnsx-Output sortiert nach Resolver-Antwort-Reihenfolge → CloudFlare-
  IPv6-Reihenfolge variiert pro Anfrage.

Design: nicht-destruktiv. Original wird in-place gestrippt; Tool-Funktion
bleibt erhalten. KI sieht stabilere Inputs, im UI/Debug-Tab ist die
inhaltsrelevante Information weiter da.
"""

from __future__ import annotations

import json
import re
from typing import Optional


# httpx schreibt JSON-Lines mit "timestamp", "time", evtl. "tls.not_after_days"
_HTTPX_VOLATILE_KEYS = ("timestamp", "time", "csp", "tls", "host_ip")
_HTTPX_TIMESTAMP_RE = re.compile(r'"timestamp":"[^"]*",?')
_HTTPX_TIME_RE = re.compile(r'"time":"[^"]*",?')

# ANSI-Farb-Codes: ESC [ ... m
_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[mGKHJ]')


def normalize_httpx(raw: Optional[str]) -> Optional[str]:
    """JSON-Lines: pro Zeile timestamp + time-Felder entfernen.

    Wir parsen nicht, um robust gegen halb-kaputte Outputs zu sein —
    pures Regex-Strippen reicht.
    """
    if not raw:
        return raw
    out_lines: list[str] = []
    for line in raw.splitlines():
        s = _HTTPX_TIMESTAMP_RE.sub('', line)
        s = _HTTPX_TIME_RE.sub('', s)
        # Komma-Spuren bereinigen: ",}" → "}", "{," → "{"
        s = re.sub(r',\s*}', '}', s)
        s = re.sub(r'{\s*,', '{', s)
        s = re.sub(r',\s*,', ',', s)
        out_lines.append(s)
    return '\n'.join(out_lines)


_WAFWOOF_BANNER_RE = re.compile(
    r'(\s*[~?\\\/_\(\)\.\,\|\'\"\`\-\*\=\:\;\^]+\s*)+\n',
)
_WAFWOOF_BANNER_END_RE = re.compile(
    r'(?im)^\s*~\s*WAFW00F\b.*$|^\s*~\s*Sniffing.*$',
)


def normalize_wafw00f(raw: Optional[str]) -> Optional[str]:
    """Strippt das wechselnde Banner; behaelt nur die Detection-Block-Zeilen.

    wafw00f-Output beginnt mit ASCII-Art (W00f / Wave / etc.) gefolgt von
    `[*] Checking ...` + `[+] Generic Detection results:` + `[-] No WAF detected ...`
    Wir behalten alle Zeilen ab dem ersten `[*]` / `[+]` / `[-]` / `[~]`.
    """
    if not raw:
        return raw
    # Erstmal ANSI-Codes weg
    s = _ANSI_RE.sub('', raw)
    # Splitten und ab erster Detection-Zeile behalten
    lines = s.splitlines()
    start = 0
    for i, line in enumerate(lines):
        if re.match(r'^\s*\[[\*\+\-\!~]\]', line):
            start = i
            break
    kept = lines[start:]
    # "Number of requests: N" am Ende ist ein Counter; weg.
    kept = [l for l in kept if not re.match(r'^\s*\[~\]\s*Number of requests', l)]
    return '\n'.join(kept)


def normalize_dnsx(raw: Optional[str]) -> Optional[str]:
    """JSON-Lines: pro Zeile sortieren wir IP-Listen + Resolver-Listen alphabetisch.

    Plus Sortierung der Zeilen selbst nach `host`.
    """
    if not raw:
        return raw
    parsed_lines: list[tuple[str, dict]] = []
    other_lines: list[str] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            other_lines.append(line)
            continue
        # IP-Felder sortieren
        for k in ('a', 'aaaa', 'cname', 'mx', 'ns', 'ptr', 'soa', 'txt', 'resolver'):
            v = obj.get(k)
            if isinstance(v, list):
                obj[k] = sorted(v)
        host = obj.get('host', '')
        parsed_lines.append((host, obj))
    parsed_lines.sort(key=lambda x: x[0])
    out = [json.dumps(o, sort_keys=True, ensure_ascii=False) for _, o in parsed_lines]
    out.extend(sorted(other_lines))
    return '\n'.join(out)


# ============================================================
# nmap (XML-Output): sortiert nach Port; strippt Laufzeit-Felder
# ============================================================
_NMAP_VOLATILE_ATTRS = re.compile(
    r'\s+(?:start|startstr|end|endstr|elapsed|reason_ttl|extrareasons|'
    r'extraports|scaninfo)="[^"]*"'
)


def normalize_nmap(raw: Optional[str]) -> Optional[str]:
    """nmap-XML: strippt zeitabhaengige Attribute (start/end/elapsed/ttl).

    Sortiert <port>-Elemente nicht (XML-Reihenfolge ist semantisch).
    Fuer JSON-konvertierte Outputs siehe parser.py — diese Funktion arbeitet
    nur am rohen XML/Text-Output von `nmap -oX`.
    """
    if not raw:
        return raw
    s = _NMAP_VOLATILE_ATTRS.sub('', raw)
    # nmap-Header "Starting Nmap 7.94 ( https://nmap.org ) at 2026-..."
    s = re.sub(r'\s+at\s+\d{4}-\d{2}-\d{2}[^\n"]*', '', s)
    # Footer "Nmap done: 1 IP address (1 host up) scanned in 4.23 seconds"
    s = re.sub(r'(?im)^.*scanned in\s+\d+\.\d+\s+seconds\s*$\n?', '', s)
    return s


# ============================================================
# zap (JSON-Alerts): sortiert nach (pluginId, url, riskcode); strippt IDs
# ============================================================
_ZAP_VOLATILE_KEYS = ("alertId", "sourceid", "messageId", "id", "alertRef")


def normalize_zap(raw: Optional[str]) -> Optional[str]:
    """ZAP-JSON-Alerts: sortiert nach (pluginId, url, riskcode); strippt
    scan-spezifische IDs (alertId, sourceid, messageId).
    """
    if not raw:
        return raw
    try:
        data = json.loads(raw)
    except Exception:
        return raw

    def _scrub(item: dict) -> dict:
        out = {k: v for k, v in item.items() if k not in _ZAP_VOLATILE_KEYS}
        return out

    if isinstance(data, list):
        scrubbed = [_scrub(it) if isinstance(it, dict) else it for it in data]
        scrubbed.sort(
            key=lambda x: (
                str(x.get("pluginId", "")) if isinstance(x, dict) else "",
                str(x.get("url", "")) if isinstance(x, dict) else "",
                int(x.get("riskcode", 0)) if isinstance(x, dict) else 0,
            )
        )
        return json.dumps(scrubbed, indent=2, sort_keys=True, ensure_ascii=False)
    if isinstance(data, dict):
        # Top-Level "alerts"-Wrapper
        if isinstance(data.get("alerts"), list):
            data["alerts"] = sorted(
                [_scrub(it) if isinstance(it, dict) else it for it in data["alerts"]],
                key=lambda x: (
                    str(x.get("pluginId", "")) if isinstance(x, dict) else "",
                    str(x.get("url", "")) if isinstance(x, dict) else "",
                ),
            )
        return json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False)
    return raw


# ============================================================
# nuclei (JSONL): sortiert nach (template-id, matched-at); strippt timestamp
# ============================================================
_NUCLEI_VOLATILE_KEYS = ("timestamp", "curl-command", "request-id")


def normalize_nuclei(raw: Optional[str]) -> Optional[str]:
    """nuclei-JSONL: pro Zeile timestamp/curl-command strippen, dann
    Zeilen nach (template-id, matched-at) sortieren.
    """
    if not raw:
        return raw
    parsed: list[tuple[tuple[str, str], dict]] = []
    other: list[str] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            other.append(line)
            continue
        for k in _NUCLEI_VOLATILE_KEYS:
            obj.pop(k, None)
        # info.timestamp etc. auch
        if isinstance(obj.get("info"), dict):
            obj["info"].pop("timestamp", None)
        key = (str(obj.get("template-id", "")), str(obj.get("matched-at", "")))
        parsed.append((key, obj))
    parsed.sort(key=lambda x: x[0])
    out = [json.dumps(o, sort_keys=True, ensure_ascii=False) for _, o in parsed]
    out.extend(sorted(other))
    return '\n'.join(out)


# ============================================================
# nikto (JSON oder Plain-Text): sortiert nach (id, url)
# ============================================================
_NIKTO_VOLATILE_KEYS = ("scanstart", "scanend", "elapsed", "errors")


def normalize_nikto(raw: Optional[str]) -> Optional[str]:
    """nikto-Output: bei JSON sortiere `vulnerabilities` nach (id, url),
    strippt scanstart/scanend/elapsed.
    """
    if not raw:
        return raw
    # Versuche JSON-Parse (nikto -Format json)
    try:
        data = json.loads(raw)
    except Exception:
        # Plain-Text-Fallback: Findings sortieren, Zeitstempel-Zeilen weg
        lines = raw.splitlines()
        # ALLE Zeilen die wie Zeitstempel/Statistik aussehen vorab raus
        time_re = re.compile(r'(?i)\b(start time|end time|elapsed|host\(s\) tested)\b')
        clean = [l for l in lines if not time_re.search(l)]
        finding_lines = sorted(l for l in clean if l.startswith('+ '))
        other_lines = [l for l in clean if not l.startswith('+ ')]
        return '\n'.join(other_lines + finding_lines)

    # JSON-Pfad
    if isinstance(data, dict):
        for k in _NIKTO_VOLATILE_KEYS:
            data.pop(k, None)
        vulns = data.get("vulnerabilities")
        if isinstance(vulns, list):
            data["vulnerabilities"] = sorted(
                vulns,
                key=lambda v: (
                    str(v.get("id", "")) if isinstance(v, dict) else "",
                    str(v.get("url", "")) if isinstance(v, dict) else "",
                ),
            )
        return json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False)
    return raw


# ============================================================
# wpscan (JSON): sortiert plugins/themes/users nach Slug
# ============================================================
_WPSCAN_VOLATILE_KEYS = ("start_time", "stop_time", "elapsed", "requests_done",
                          "cached_requests", "data_sent", "data_received",
                          "used_memory", "scan_aborted")


def normalize_wpscan(raw: Optional[str]) -> Optional[str]:
    """wpscan-JSON: strippt Laufzeit-Statistiken; sortiert plugins/themes
    alphabetisch nach Slug.
    """
    if not raw:
        return raw
    try:
        data = json.loads(raw)
    except Exception:
        return raw
    if not isinstance(data, dict):
        return raw

    for k in _WPSCAN_VOLATILE_KEYS:
        data.pop(k, None)

    # plugins/themes sind {slug: {...}} → konvertiere zu sortierter Liste-im-Dict
    for collection in ("plugins", "themes"):
        coll = data.get(collection)
        if isinstance(coll, dict):
            # Sortiert serialisieren via sort_keys (json.dumps mit sort_keys=True)
            # zusaetzlich strippen wir interne timestamps in nested dicts
            for slug, info in coll.items():
                if isinstance(info, dict):
                    info.pop("found_by", None)  # variiert pro Lauf

    return json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False)


# Mapping tool_name -> normalizer
_NORMALIZERS = {
    'httpx': normalize_httpx,
    'wafw00f': normalize_wafw00f,
    'dnsx': normalize_dnsx,
    'nmap': normalize_nmap,
    'zap': normalize_zap,
    'zap_active': normalize_zap,
    'zap_alerts': normalize_zap,
    'zap_passive': normalize_zap,
    'nuclei': normalize_nuclei,
    'nikto': normalize_nikto,
    'wpscan': normalize_wpscan,
}


def normalize(tool_name: str, raw: Optional[str]) -> Optional[str]:
    """Wendet den Normalizer fuer ein Tool an, falls vorhanden.

    Unbekannte Tools werden unveraendert zurueckgegeben.
    """
    fn = _NORMALIZERS.get(tool_name)
    if fn is None:
        return raw
    try:
        return fn(raw)
    except Exception:
        # Bei Normalisierungs-Fehler: lieber Original behalten als Daten verlieren
        return raw


__all__ = [
    "normalize",
    "normalize_httpx",
    "normalize_wafw00f",
    "normalize_dnsx",
    "normalize_nmap",
    "normalize_zap",
    "normalize_nuclei",
    "normalize_nikto",
    "normalize_wpscan",
]
