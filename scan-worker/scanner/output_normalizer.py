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


# Mapping tool_name -> normalizer
_NORMALIZERS = {
    'httpx': normalize_httpx,
    'wafw00f': normalize_wafw00f,
    'dnsx': normalize_dnsx,
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
]
