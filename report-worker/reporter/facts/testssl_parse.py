"""testssl-Leser: JSON-Eintraege aus dem Tar plus ANSI-Rohtext aus scan_results.

Datenfalle (spec/07 S1, Scanner-Befund 2): testssl laeuft im Perimeter-Paket mit
``--severity MEDIUM``. Das JSON im Tar enthaelt deshalb nur Eintraege ab MEDIUM;
Protokollzeilen wie "TLS 1 offered (deprecated)" (LOW) fehlen. Der vollstaendige
Rohtext steht nur in der ``scan_results``-Zeile. Beide Quellen werden hier
zusammengefuehrt; ohne Rohtext bleiben nicht belegte Protokolle ``None`` und
``json_filtered`` wird gesetzt.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional

from reporter.facts.schema import TLS_PROTOCOL_KEYS
from reporter.facts.serialize import iso_utc, strip_ansi

_PROTO_IDS = {
    "SSLv2": "SSLv2", "SSLv3": "SSLv3", "TLS1": "TLS1.0", "TLS1_1": "TLS1.1",
    "TLS1_2": "TLS1.2", "TLS1_3": "TLS1.3",
}
_PROTO_TEXT = {
    "SSLv2": "SSLv2", "SSLv3": "SSLv3", "TLS 1": "TLS1.0", "TLS 1.1": "TLS1.1",
    "TLS 1.2": "TLS1.2", "TLS 1.3": "TLS1.3",
}
_CIPHER_IDS = {
    "cipherlist_NULL": "null", "cipherlist_aNULL": "anon", "cipherlist_EXPORT": "export",
    "cipherlist_LOW": "low", "cipherlist_3DES_IDEA": "3des", "cipherlist_OBSOLETED": "cbc",
    "cipherlist_AVERAGE": "cbc",
}
_CIPHER_TEXT = (
    ("NULL ciphers", "null"), ("Anonymous NULL", "anon"), ("Export ciphers", "export"),
    ("LOW: 64 Bit", "low"), ("Triple DES Ciphers / IDEA", "3des"),
    ("Obsoleted CBC ciphers", "cbc"),
)
_VULN_IDS = {
    "heartbleed": "Heartbleed", "CCS": "CCS", "ticketbleed": "Ticketbleed", "ROBOT": "ROBOT",
    "secure_renego": "Secure Renegotiation", "secure_client_renego": "Secure Client-Initiated Renegotiation",
    "CRIME_TLS": "CRIME", "BREACH": "BREACH", "POODLE_SSL": "POODLE", "SWEET32": "SWEET32",
    "FREAK": "FREAK", "DROWN": "DROWN", "LOGJAM": "LOGJAM", "LOGJAM-common_primes": "LOGJAM",
    "BEAST_CBC_TLS1": "BEAST", "BEAST": "BEAST", "LUCKY13": "LUCKY13", "winshock": "Winshock",
    "RC4": "RC4",
}
_VULN_TEXT = (
    ("Heartbleed", "Heartbleed"), ("CCS", "CCS"), ("Ticketbleed", "Ticketbleed"), ("ROBOT", "ROBOT"),
    ("Secure Client-Initiated Renegotiation", "Secure Client-Initiated Renegotiation"),
    ("Secure Renegotiation", "Secure Renegotiation"), ("CRIME, TLS", "CRIME"), ("BREACH", "BREACH"),
    ("POODLE, SSL", "POODLE"), ("SWEET32", "SWEET32"), ("FREAK", "FREAK"), ("DROWN", "DROWN"),
    ("LOGJAM", "LOGJAM"), ("BEAST", "BEAST"), ("LUCKY13", "LUCKY13"), ("Winshock", "Winshock"),
    ("RC4", "RC4"),
)
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
# Severities, mit denen testssl ein Urteil "verwundbar" ausspricht. ``OK`` und
# ``INFO`` sind Entwarnungen und tragen trotzdem oft eine CVE-Nummer im Feld
# ``cve`` (die CVE, gegen die geprueft wurde). Wer sie als Fund liest, schreibt
# Heartbleed in den Bericht eines Hosts, der nicht betroffen ist (S5b).
VULN_SEVERITIES = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})
# S6b-3 (spec/10 R1, R4): testssl ruft "/" des gepruften Namens ab und nennt Status und
# gesetzte Sicherheits-Header; fehlt ein Header, steht er nicht in der Liste
# ("security_headers --" heisst: keiner gesetzt). Kanonische Namen wie im HTTP-Kopf.
HTTP_HEADER_IDS = {
    "X-Frame-Options": "x-frame-options", "X-Content-Type-Options": "x-content-type-options",
    "Content-Security-Policy": "content-security-policy", "Referrer-Policy": "referrer-policy",
    "Permissions-Policy": "permissions-policy", "X-XSS-Protection": "x-xss-protection",
}
_START_RE = re.compile(r"Start (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+-->> ([^\s:]+):(\d+) \(([^)]*)\) <<--")


@dataclass
class TestsslResult:
    fqdn: Optional[str] = None
    host_ip: Optional[str] = None
    port: int = 443
    protocols: dict[str, Optional[bool]] = field(default_factory=lambda: {k: None for k in TLS_PROTOCOL_KEYS})
    ciphers_weak: list[str] = field(default_factory=list)
    vulns: dict[str, str] = field(default_factory=dict)
    cert: dict[str, Any] = field(default_factory=dict)
    hsts: Optional[dict[str, Any]] = None
    fallback_scsv: Optional[bool] = None
    grade: Optional[str] = None
    entries: list[dict[str, Any]] = field(default_factory=list)
    duplicate_headers: list[str] = field(default_factory=list)
    connect_failed: bool = False
    json_filtered: bool = False
    started_at: Optional[str] = None
    json_parsed: bool = False
    text_parsed: bool = False
    # S6b-3: HTTP-Status und Sicherheits-Header der Antwort auf "/" (spec/10 R1, R4),
    # "Obsoleted CBC ciphers" angeboten (R6) und Fingerabdruck des Zertifikats (R4).
    http_status: Optional[int] = None
    http_headers: dict[str, str] = field(default_factory=dict)
    http_headers_listed: bool = False
    cbc_obsoleted: Optional[bool] = None

    @property
    def has_data(self) -> bool:
        return self.json_parsed or self.text_parsed


def _vuln_state(finding: str) -> Optional[str]:
    f = (finding or "").strip()
    low = f.lower()
    if low.startswith("not vulnerable") or " not vulnerable" in low or low.startswith("no ") \
            or low.startswith("supported (ok)") or low.startswith("no fallback") or "(ok)" in low and "vulnerable" not in low:
        return None
    if "potentially" in low:
        return "potential"
    if "vulnerable" in low:
        return "vulnerable"
    return None


def _offered(finding: str) -> Optional[bool]:
    low = (finding or "").strip().lower()
    if low.startswith("not offered"):
        return False
    if low.startswith("offered"):
        return True
    return None


def _parse_hsts_text(text: str) -> dict[str, Any]:
    low = text.lower()
    info: dict[str, Any] = {"present": None, "max_age": None, "include_subdomains": None,
                            "preload": None, "raw": text.strip()[:200]}
    if low.startswith("not offered") or low.startswith("--"):
        info["present"] = False
        return info
    m = re.search(r"(\d+)\s*s\b", text)
    if m:
        info["present"] = True
        info["max_age"] = int(m.group(1))
    elif re.search(r"\d+ days", low):
        info["present"] = True
    if "includes subdomains" in low:
        info["include_subdomains"] = True
    elif "just this domain" in low or "only this domain" in low:
        info["include_subdomains"] = False
    if "preload" in low:
        info["preload"] = "not" not in low.split("preload", 1)[0][-12:]
    return info


# ------------------------------------------------------------------ JSON

def apply_json(result: TestsslResult, entries: list[dict[str, Any]] | None) -> None:
    if not isinstance(entries, list):
        return
    saw_protocol = False
    for e in entries:
        if not isinstance(e, dict):
            continue
        eid = str(e.get("id") or "")
        finding = str(e.get("finding") or "")
        sev = str(e.get("severity") or "")
        if not eid:
            continue
        ipfield = str(e.get("ip") or "")
        if ipfield and "/" in ipfield and not result.fqdn:
            fq, ip = ipfield.split("/", 1)
            result.fqdn = fq or None
            result.host_ip = result.host_ip or ip or None
        try:
            result.port = int(e.get("port") or result.port)
        except (TypeError, ValueError):
            pass
        result.json_parsed = True
        # S6 (spec/08 Punkt 18): testssl nennt je Test mehrere CVE-Kennungen
        # ("CVE-2013-2566 CVE-2015-2808" bei RC4, neun bei ROBOT). Bisher stand
        # nur die erste im Fakt, und Anhang A.3 liess die uebrigen weg.
        cves = _CVE_RE.findall(str(e.get("cve") or ""))
        result.entries.append({"id": eid, "severity": sev, "finding": finding[:300],
                               "cve": cves[0] if cves else None,
                               "cves": cves})
        if eid == "scanProblem" or (sev == "FATAL" and "connect" in finding.lower()):
            result.connect_failed = True
            continue
        if eid in _PROTO_IDS:
            saw_protocol = True
            result.protocols[_PROTO_IDS[eid]] = _offered(finding)
        elif eid in _CIPHER_IDS:
            if _offered(finding):
                _add(result.ciphers_weak, _CIPHER_IDS[eid])
            if eid == "cipherlist_OBSOLETED":
                result.cbc_obsoleted = _offered(finding)
        elif eid == "fallback_SCSV":
            result.fallback_scsv = _fallback_state(finding)
        elif eid in _VULN_IDS:
            st = _vuln_state(finding)
            if st is None and sev.upper() in VULN_SEVERITIES \
                    and "not vulnerable" not in finding.lower():
                # testssl-JSON nennt bei Treffern oft nur die Cipher-Liste; die Severity traegt das Urteil.
                st = "potential" if "potentially" in finding.lower() else "vulnerable"
            if st is None and sev.upper() == "WARN":
                # WARN heisst "konnte nicht geprueft werden" (Zeitueberschreitung,
                # Verbindungsfehler). Weder Fund noch Entwarnung.
                st = "not_tested"
            if st:
                _worst(result.vulns, _VULN_IDS[eid], st)
        elif eid == "overall_grade":
            result.grade = finding.strip() or None
        elif eid == "cert_commonName":
            result.cert.setdefault("cn", finding.strip())
        elif eid == "cert_subjectAltName":
            result.cert.setdefault("san", sorted(set(finding.split())))
        elif eid == "cert_caIssuers":
            result.cert.setdefault("issuer", finding.strip())
        elif eid == "cert_notBefore":
            result.cert.setdefault("not_before", iso_utc(finding.strip().replace(" ", "T") + ":00"))
        elif eid == "cert_notAfter":
            result.cert.setdefault("not_after", iso_utc(finding.strip().replace(" ", "T") + ":00"))
        elif eid == "cert_expirationStatus":
            result.cert["expired"] = finding.strip().lower().startswith("expired")
        elif eid == "cert_trust":
            result.cert["mismatch"] = _trust_mismatch(finding)
        elif eid == "cert_chain_of_trust":
            low = finding.lower()
            result.cert["chain_ok"] = low.startswith("passed") or low.startswith("ok")
            if "self signed" in low or "self-signed" in low:
                result.cert["self_signed"] = True
        elif eid == "HSTS":
            result.hsts = result.hsts or {"present": None, "max_age": None, "include_subdomains": None,
                                          "preload": None, "raw": finding[:200]}
            result.hsts["present"] = _offered(finding)
        elif eid == "HSTS_time":
            result.hsts = result.hsts or {"present": True, "max_age": None, "include_subdomains": None,
                                          "preload": None, "raw": finding[:200]}
            m = re.search(r"=\s*(\d+)\s*seconds", finding)
            if m:
                result.hsts["max_age"] = int(m.group(1))
                result.hsts["present"] = True
        elif eid == "HSTS_subdomains":
            if result.hsts is not None:
                result.hsts["include_subdomains"] = "includes" in finding.lower()
        elif eid == "HSTS_preload":
            if result.hsts is not None:
                result.hsts["preload"] = "not" not in finding.lower()
        elif eid.endswith("_multiple"):
            _add(result.duplicate_headers, eid[: -len("_multiple")].lower())
        elif eid == "HTTP_status_code":
            m = re.match(r"\s*(\d{3})\b", finding)
            result.http_status = int(m.group(1)) if m else None
        elif eid == "security_headers":
            result.http_headers_listed = True
        elif eid in HTTP_HEADER_IDS:
            result.http_headers_listed = True
            result.http_headers.setdefault(HTTP_HEADER_IDS[eid], finding.strip())
        elif eid == "cert_fingerprintSHA256":
            result.cert.setdefault("fingerprint_sha256", finding.strip().lower() or None)
    if result.json_parsed and not saw_protocol:
        result.json_filtered = True


def _fallback_state(finding: str) -> Optional[bool]:
    low = (finding or "").lower()
    if low.startswith("not supported") or "not supported" in low or "no protection" in low:
        return False
    if "no fallback possible" in low or low.startswith("supported") or "(ok)" in low:
        return True
    return None


def _trust_mismatch(finding: str) -> Optional[bool]:
    low = (finding or "").lower()
    if "does not match" in low or "mismatch" in low:
        return True
    if low.startswith("ok"):
        return False
    return None


def _add(lst: list[str], item: str) -> None:
    if item not in lst:
        lst.append(item)


_VULN_RANK = {"not_tested": 0, "potential": 1, "vulnerable": 2}


def _worst(vulns: dict[str, str], name: str, state: str) -> None:
    """Das schwerere Urteil gewinnt; "nicht getestet" ueberschreibt nie einen Fund."""
    if _VULN_RANK.get(vulns.get(name, ""), -1) >= _VULN_RANK.get(state, -1):
        return
    vulns[name] = state


# ------------------------------------------------------------------ Text

def apply_text(result: TestsslResult, raw: str | None) -> None:
    if not raw:
        return
    text = strip_ansi(raw).replace("\r", "")
    if not text.strip():
        return
    if text.lstrip().startswith(("SKIPPED", "FAILED", "TIMEOUT", "OK:")):
        return
    m = _START_RE.search(text)
    if not m and "Testing" not in text and "Can't connect" not in text and "Fatal error" not in text:
        return
    if m:
        result.started_at = iso_utc(m.group(1).replace(" ", "T"))
        result.host_ip = result.host_ip or m.group(2)
        try:
            result.port = int(m.group(3))
        except ValueError:
            pass
        result.fqdn = result.fqdn or (m.group(4) or None)
    if "Can't connect" in text or "Fatal error" in text or "TCP connect problem" in text:
        result.connect_failed = True
    result.text_parsed = True
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        s = line.strip()
        if not s:
            continue
        for label, key in _PROTO_TEXT.items():
            if re.match(rf"^{re.escape(label)}\s{{2,}}", s):
                val = _offered(re.split(r"\s{2,}", s, maxsplit=1)[1] if re.search(r"\s{2,}", s) else "")
                if val is not None and result.protocols.get(key) is None:
                    result.protocols[key] = val
                break
        for label, key in _CIPHER_TEXT:
            if s.startswith(label):
                rest = re.split(r"\s{2,}", s, maxsplit=1)
                if len(rest) == 2 and _offered(rest[1]) and key not in result.ciphers_weak:
                    result.ciphers_weak.append(key)
                if len(rest) == 2 and label == "Obsoleted CBC ciphers" and result.cbc_obsoleted is None:
                    result.cbc_obsoleted = _offered(rest[1])
        for label, name in _VULN_TEXT:
            if s.startswith(label):
                parts = re.split(r"\s{2,}", s, maxsplit=1)
                if len(parts) == 2:
                    st = _vuln_state(parts[1])
                    if st:
                        _worst(result.vulns, name, st)
                break
        if s.startswith("TLS_FALLBACK_SCSV"):
            parts = re.split(r"\s{2,}", s, maxsplit=1)
            if len(parts) == 2 and result.fallback_scsv is None:
                result.fallback_scsv = _fallback_state(parts[1])
        elif s.startswith("Common Name (CN)"):
            result.cert.setdefault("cn", _after(s))
        elif s.startswith("subjectAltName (SAN)"):
            result.cert.setdefault("san", sorted(set(_after(s).split())))
        elif s.startswith("Issuer"):
            result.cert.setdefault("issuer", _after(s))
        elif s.startswith("Trust (hostname)"):
            result.cert.setdefault("mismatch", _trust_mismatch(_after(s)))
        elif s.startswith("Chain of trust"):
            val = _after(s).lower()
            result.cert.setdefault("chain_ok", val.startswith("ok") or val.startswith("passed"))
            if "self signed" in val or "self-signed" in val:
                result.cert["self_signed"] = True
        elif s.startswith("Certificate Validity (UTC)"):
            val = _after(s)
            result.cert.setdefault("expired", val.lower().startswith("expired"))
            m2 = re.search(r"\((\d{4}-\d{2}-\d{2} \d{2}:\d{2}) --> (\d{4}-\d{2}-\d{2} \d{2}:\d{2})\)", val)
            if m2:
                result.cert.setdefault("not_before", iso_utc(m2.group(1).replace(" ", "T") + ":00"))
                result.cert.setdefault("not_after", iso_utc(m2.group(2).replace(" ", "T") + ":00"))
        elif s.startswith("Strict Transport Security"):
            if result.hsts is None or result.hsts.get("max_age") is None:
                result.hsts = _parse_hsts_text(_after(s))
        elif s.startswith("Overall Grade"):
            result.grade = result.grade or _after(s) or None
    if result.text_parsed:
        result.json_filtered = False


def _after(line: str) -> str:
    parts = re.split(r"\s{2,}", line.strip(), maxsplit=1)
    return parts[1].strip() if len(parts) == 2 else ""


# ------------------------------------------------------------------ Einstieg

def parse_testssl(entries: list[dict[str, Any]] | None, raw_text: str | None,
                  *, host_ip: str | None = None, fqdn: str | None = None) -> TestsslResult:
    result = TestsslResult(fqdn=fqdn, host_ip=host_ip)
    apply_json(result, entries)
    apply_text(result, raw_text)
    if result.json_parsed and not result.text_parsed and not any(
            v is not None for v in result.protocols.values()):
        result.json_filtered = True
    if result.cert.get("cn") and "wildcard" not in result.cert:
        result.cert["wildcard"] = str(result.cert["cn"]).startswith("*.")
    return result
