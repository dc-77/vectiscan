"""BSI TR-03116-4 TLS-Checkliste Compliance Checker.

Nimmt geparste testssl.sh-Ergebnisse und prüft sie gegen die
BSI TLS-Checkliste für Diensteanbieter (Abschnitte 2.1–2.6).

Jeder Check gibt zurück:
  - check_id: z.B. "2.1.1"
  - title: Beschreibung auf Deutsch
  - section: "2.1" bis "2.6"
  - required: True (Pflicht 2.1-2.5) oder False (Empfehlung 2.6)
  - status: "PASS" | "FAIL" | "WARN" | "N/A"
  - detail: Erklärung was gefunden wurde
  - evidence: relevanter testssl-Output
"""

from __future__ import annotations

from datetime import datetime
from typing import Any


# ---------------------------------------------------------------------------
# TR-02102-2 Allowlists
# ---------------------------------------------------------------------------

TR_02102_2_ALLOWED_CIPHERS = [
    # TLS 1.3 (alle konform)
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    # TLS 1.2 — ECDHE
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    # TLS 1.2 — DHE
    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA384",
]

TR_02102_2_ALLOWED_CURVES = [
    # Brainpool (BSI-bevorzugt)
    "brainpoolP256r1",
    "brainpoolP384r1",
    "brainpoolP512r1",
    # NIST
    "secp256r1",   # = P-256 / prime256v1
    "secp384r1",   # = P-384
    "secp521r1",   # = P-521
    # TLS 1.3
    "x25519",
    "x448",
]

# Aliases that testssl might use for the same curves
_CURVE_ALIASES: dict[str, str] = {
    "prime256v1": "secp256r1",
    "P-256": "secp256r1",
    "P-384": "secp384r1",
    "P-521": "secp521r1",
    "X25519": "x25519",
    "X448": "x448",
}


# ---------------------------------------------------------------------------
# Helper: lookup testssl finding by id
# ---------------------------------------------------------------------------

def _find(findings: list[dict[str, Any]], target_id: str) -> dict[str, Any] | None:
    """Find a testssl entry by id (case-insensitive).

    Handles testssl.sh's multi-cert suffix format where IDs like
    ``cert_notAfter`` become ``cert_notAfter <hostCert#1>``.
    First tries exact match, then prefix match (id starts with target).
    """
    target_lower = target_id.lower()
    # Exact match first
    for f in findings:
        if f.get("id", "").lower() == target_lower:
            return f
    # Prefix match (handles " <hostCert#N>" suffixes)
    for f in findings:
        fid = f.get("id", "").lower()
        if fid.startswith(target_lower) and (len(fid) == len(target_lower) or fid[len(target_lower)] in (" ", "_")):
            return f
    return None


def _find_all(findings: list[dict[str, Any]], target_id: str) -> list[dict[str, Any]]:
    """Find all testssl entries whose id starts with target_id (case-insensitive)."""
    target_lower = target_id.lower()
    return [f for f in findings if f.get("id", "").lower().startswith(target_lower)]


def _evidence_str(entry: dict[str, Any] | None) -> str:
    """Build evidence string from a testssl entry."""
    if not entry:
        return ""
    return f"{entry.get('id', '')}: {entry.get('finding', '')} ({entry.get('severity', '')})"


def _check(
    check_id: str,
    title: str,
    status: str,
    detail: str,
    evidence: str = "",
) -> dict[str, Any]:
    return {
        "check_id": check_id,
        "title": title,
        "status": status,
        "detail": detail,
        "evidence": evidence,
    }


# ---------------------------------------------------------------------------
# Section 2.1: TLS-Versionen
# ---------------------------------------------------------------------------

def _check_tls_versions(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []

    # 2.1.1 TLS 1.2 offered
    entry = _find(findings, "TLS1_2")
    if entry:
        offered = "offered" in entry.get("finding", "").lower()
        checks.append(_check(
            "2.1.1", "TLS 1.2 wird unterstützt",
            "PASS" if offered else "FAIL",
            "TLS 1.2 wird angeboten" if offered else "TLS 1.2 wird NICHT angeboten — Pflichtverstoß",
            _evidence_str(entry),
        ))
    else:
        checks.append(_check("2.1.1", "TLS 1.2 wird unterstützt", "N/A",
                             "Keine testssl-Daten für TLS 1.2 vorhanden"))

    # 2.1.2 TLS 1.3 offered (WARN if not, since recommended)
    entry = _find(findings, "TLS1_3")
    if entry:
        offered = "offered" in entry.get("finding", "").lower()
        checks.append(_check(
            "2.1.2", "TLS 1.3 wird unterstützt",
            "PASS" if offered else "WARN",
            "TLS 1.3 wird angeboten" if offered else "TLS 1.3 wird nicht angeboten (empfohlen)",
            _evidence_str(entry),
        ))
    else:
        checks.append(_check("2.1.2", "TLS 1.3 wird unterstützt", "N/A",
                             "Keine testssl-Daten für TLS 1.3 vorhanden"))

    # 2.1.3-2.1.6: Legacy protocols must NOT be offered
    legacy_checks = [
        ("2.1.3", "SSLv2", "SSLv2 deaktiviert"),
        ("2.1.4", "SSLv3", "SSLv3 deaktiviert"),
        ("2.1.5", "TLS1", "TLS 1.0 deaktiviert"),
        ("2.1.6", "TLS1_1", "TLS 1.1 deaktiviert"),
    ]
    for cid, tid, title in legacy_checks:
        entry = _find(findings, tid)
        if entry:
            finding_text = entry.get("finding", "").lower()
            not_offered = "not offered" in finding_text
            checks.append(_check(
                cid, title,
                "PASS" if not_offered else "FAIL",
                f"{tid} ist deaktiviert" if not_offered else f"{tid} ist noch aktiv — Pflichtverstoß",
                _evidence_str(entry),
            ))
        else:
            checks.append(_check(cid, title, "N/A",
                                 f"Keine testssl-Daten für {tid} vorhanden"))

    return checks


# ---------------------------------------------------------------------------
# Section 2.2: Cipher Suites
# ---------------------------------------------------------------------------

def _check_cipher_suites(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []

    # 2.2.1-2.2.5: Weak ciphers must NOT be offered
    # testssl.sh uses "cipherlist_" prefix for cipher group tests:
    # cipherlist_NULL, cipherlist_aNULL, cipherlist_EXPORT, cipherlist_3DES_IDEA
    # RC4 is a standalone vulnerability check (no prefix)
    weak_checks = [
        ("2.2.1", "RC4", "Keine RC4-Cipher"),
        ("2.2.2", "cipherlist_3DES_IDEA", "Keine 3DES/IDEA-Cipher"),
        ("2.2.3", "cipherlist_NULL", "Keine NULL-Cipher"),
        ("2.2.4", "cipherlist_EXPORT", "Keine EXPORT-Cipher"),
        ("2.2.5", "cipherlist_aNULL", "Keine anonymen Cipher"),
    ]
    for cid, tid, title in weak_checks:
        entry = _find(findings, tid)
        if entry:
            finding_text = entry.get("finding", "").lower()
            not_offered = "not offered" in finding_text or "not vulnerable" in finding_text
            sev = entry.get("severity", "").upper()
            is_ok = not_offered or sev == "OK"
            checks.append(_check(
                cid, title,
                "PASS" if is_ok else "FAIL",
                f"{tid} wird nicht angeboten" if is_ok else f"{tid}-Cipher aktiv — Pflichtverstoß",
                _evidence_str(entry),
            ))
        else:
            checks.append(_check(cid, title, "N/A",
                                 f"Keine testssl-Daten für {tid} vorhanden"))

    # 2.2.6: PFS offered (testssl uses "FS" as jsonID)
    entry = _find(findings, "FS") or _find(findings, "PFS")
    if entry:
        finding_text = entry.get("finding", "").lower()
        not_offered = "not offered" in finding_text
        offered = ("offered" in finding_text and not not_offered) or entry.get("severity", "").upper() == "OK"
        checks.append(_check(
            "2.2.6", "Perfect Forward Secrecy (PFS) unterstützt",
            "PASS" if offered else "FAIL",
            "PFS wird unterstützt" if offered else "PFS wird NICHT unterstützt — Pflichtverstoß",
            _evidence_str(entry),
        ))
    else:
        checks.append(_check("2.2.6", "Perfect Forward Secrecy (PFS) unterstützt", "N/A",
                             "Keine testssl-Daten für PFS vorhanden"))

    # 2.2.7: AES-GCM preferred (first cipher in order)
    cipher_order_entries = _find_all(findings, "cipher_order")
    if cipher_order_entries:
        first_cipher = cipher_order_entries[0].get("finding", "")
        gcm_preferred = "GCM" in first_cipher.upper()
        checks.append(_check(
            "2.2.7", "AES-GCM bevorzugt",
            "PASS" if gcm_preferred else "WARN",
            "AES-GCM ist bevorzugte Cipher Suite" if gcm_preferred
            else f"Erste Cipher ist nicht GCM: {first_cipher[:60]}",
            _evidence_str(cipher_order_entries[0]),
        ))
    else:
        checks.append(_check("2.2.7", "AES-GCM bevorzugt", "N/A",
                             "Keine Cipher-Order-Daten vorhanden"))

    # 2.2.8: All ciphers TR-02102-2 compliant
    cipher_entries = [f for f in findings
                      if f.get("id", "").startswith("cipher_")
                      or f.get("id", "").startswith("cipher_order")]
    if cipher_entries:
        allowed_set = set(TR_02102_2_ALLOWED_CIPHERS)
        non_compliant = []
        for ce in cipher_entries:
            cipher_name = ce.get("finding", "").strip()
            # Extract IANA cipher name from testssl output
            # testssl format can be: "TLS_RSA_WITH_AES_128_CBC_SHA" or include extra info
            parts = cipher_name.split()
            if parts:
                name = parts[0]
                if name.startswith("TLS_") and name not in allowed_set:
                    non_compliant.append(name)
        if non_compliant:
            checks.append(_check(
                "2.2.8", "Alle Cipher Suites TR-02102-2-konform",
                "FAIL",
                f"{len(non_compliant)} nicht-konforme Cipher: {', '.join(non_compliant[:3])}",
                f"Nicht-konform: {', '.join(non_compliant[:5])}",
            ))
        else:
            checks.append(_check(
                "2.2.8", "Alle Cipher Suites TR-02102-2-konform",
                "PASS", "Alle angebotenen Cipher Suites sind TR-02102-2-konform",
            ))
    else:
        checks.append(_check("2.2.8", "Alle Cipher Suites TR-02102-2-konform", "N/A",
                             "Keine Cipher-Daten vorhanden"))

    return checks


# ---------------------------------------------------------------------------
# Section 2.3: Serverzertifikat
# ---------------------------------------------------------------------------

def _check_certificate(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []

    # 2.3.1: Key size RSA >= 2048 or EC >= 256
    entry = _find(findings, "cert_keySize")
    if entry:
        finding_text = entry.get("finding", "")
        import re
        numbers = re.findall(r"(\d+)", finding_text)
        key_size = int(numbers[0]) if numbers else 0
        is_ec = "ec" in finding_text.lower() or "ecdsa" in finding_text.lower()
        min_size = 256 if is_ec else 2048
        ok = key_size >= min_size
        checks.append(_check(
            "2.3.1", f"Schlüssellänge {'EC' if is_ec else 'RSA'} ≥ {min_size} Bit",
            "PASS" if ok else "FAIL",
            f"Schlüssellänge: {key_size} Bit" if ok
            else f"Schlüssellänge {key_size} Bit zu kurz (Minimum: {min_size})",
            _evidence_str(entry),
        ))
    else:
        checks.append(_check("2.3.1", "Schlüssellänge ausreichend", "N/A",
                             "Keine Daten zur Schlüssellänge vorhanden"))

    # 2.3.2: Signature algorithm >= SHA-256
    entry = _find(findings, "cert_signatureAlgorithm")
    if entry:
        finding_text = entry.get("finding", "").lower()
        weak = "sha1" in finding_text or "md5" in finding_text or "md2" in finding_text
        checks.append(_check(
            "2.3.2", "Signaturalgorithmus ≥ SHA-256",
            "FAIL" if weak else "PASS",
            "Schwacher Signaturalgorithmus (SHA-1 oder MD5)" if weak
            else f"Signaturalgorithmus: {entry.get('finding', '')}",
            _evidence_str(entry),
        ))
    else:
        checks.append(_check("2.3.2", "Signaturalgorithmus ≥ SHA-256", "N/A",
                             "Keine Daten zum Signaturalgorithmus vorhanden"))

    # 2.3.3: Certificate not expired
    entry = _find(findings, "cert_notAfter")
    if entry:
        finding_text = entry.get("finding", "")
        sev = entry.get("severity", "").upper()
        expired = sev in ("CRITICAL", "HIGH") or "expired" in finding_text.lower()
        checks.append(_check(
            "2.3.3", "Zertifikat nicht abgelaufen",
            "FAIL" if expired else "PASS",
            "Zertifikat ist abgelaufen" if expired else f"Gültig bis: {finding_text[:40]}",
            _evidence_str(entry),
        ))
    else:
        checks.append(_check("2.3.3", "Zertifikat nicht abgelaufen", "N/A",
                             "Keine Daten zum Ablaufdatum vorhanden"))

    # 2.3.4: Certificate chain complete
    entry = _find(findings, "cert_chain_of_trust")
    if entry:
        sev = entry.get("severity", "").upper()
        ok = sev == "OK"
        checks.append(_check(
            "2.3.4", "Zertifikatskette vollständig",
            "PASS" if ok else "FAIL",
            "Zertifikatskette ist vollständig und vertrauenswürdig" if ok
            else f"Zertifikatskette unvollständig: {entry.get('finding', '')[:80]}",
            _evidence_str(entry),
        ))
    else:
        checks.append(_check("2.3.4", "Zertifikatskette vollständig", "N/A",
                             "Keine Daten zur Zertifikatskette vorhanden"))

    # 2.3.5: CN/SAN matches domain
    cn_entry = _find(findings, "cert_commonName")
    san_entry = _find(findings, "cert_subjectAltName")
    if cn_entry or san_entry:
        sev_cn = (cn_entry or {}).get("severity", "").upper()
        sev_san = (san_entry or {}).get("severity", "").upper()
        ok = sev_cn == "OK" or sev_san == "OK"
        detail_parts = []
        if cn_entry:
            detail_parts.append(f"CN: {cn_entry.get('finding', '')[:50]}")
        if san_entry:
            detail_parts.append(f"SAN: {san_entry.get('finding', '')[:50]}")
        checks.append(_check(
            "2.3.5", "CN/SAN stimmt mit Domain überein",
            "PASS" if ok else "FAIL",
            "; ".join(detail_parts) if ok
            else f"CN/SAN-Mismatch: {'; '.join(detail_parts)}",
            _evidence_str(cn_entry) + (" | " + _evidence_str(san_entry) if san_entry else ""),
        ))
    else:
        checks.append(_check("2.3.5", "CN/SAN stimmt mit Domain überein", "N/A",
                             "Keine Daten zu CN/SAN vorhanden"))

    # 2.3.6: Trusted CA
    entry = _find(findings, "cert_trust")
    if entry:
        finding_text = entry.get("finding", "").lower()
        trusted = "trusted" in finding_text or entry.get("severity", "").upper() == "OK"
        checks.append(_check(
            "2.3.6", "Vertrauenswürdige CA",
            "PASS" if trusted else "FAIL",
            "Zertifikat wurde von vertrauenswürdiger CA ausgestellt" if trusted
            else f"Zertifikat nicht vertrauenswürdig: {entry.get('finding', '')[:80]}",
            _evidence_str(entry),
        ))
    else:
        checks.append(_check("2.3.6", "Vertrauenswürdige CA", "N/A",
                             "Keine Daten zum Vertrauensstatus vorhanden"))

    # 2.3.7: OCSP URL present
    entry = _find(findings, "cert_ocspURL")
    if entry:
        has_url = bool(entry.get("finding", "").strip()) and entry.get("finding", "").strip() != "--"
        checks.append(_check(
            "2.3.7", "OCSP-URL vorhanden",
            "PASS" if has_url else "WARN",
            f"OCSP-URL: {entry.get('finding', '')[:60]}" if has_url
            else "Keine OCSP-URL im Zertifikat",
            _evidence_str(entry),
        ))
    else:
        checks.append(_check("2.3.7", "OCSP-URL vorhanden", "N/A",
                             "Keine Daten zur OCSP-URL vorhanden"))

    return checks


# ---------------------------------------------------------------------------
# Section 2.4: Schlüsselaustausch
# ---------------------------------------------------------------------------

def _check_key_exchange(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []

    # 2.4.1: ECDHE supported
    pfs_entry = _find(findings, "FS") or _find(findings, "PFS")
    cipher_entries = _find_all(findings, "cipher_order")
    has_ecdhe = False
    if pfs_entry:
        has_ecdhe = "ecdhe" in pfs_entry.get("finding", "").lower()
    if not has_ecdhe:
        for ce in cipher_entries:
            if "ecdhe" in ce.get("finding", "").lower():
                has_ecdhe = True
                break
    if pfs_entry or cipher_entries:
        checks.append(_check(
            "2.4.1", "ECDHE wird unterstützt",
            "PASS" if has_ecdhe else "FAIL",
            "ECDHE-Schlüsselaustausch wird unterstützt" if has_ecdhe
            else "Kein ECDHE-Schlüsselaustausch verfügbar",
            _evidence_str(pfs_entry),
        ))
    else:
        checks.append(_check("2.4.1", "ECDHE wird unterstützt", "N/A",
                             "Keine Daten zum Schlüsselaustausch vorhanden"))

    # 2.4.2: Elliptic curves compliant
    entry = _find(findings, "FS_ECDHE_curves") or _find(findings, "PFS_ECDHE_curves")
    if entry:
        curves_str = entry.get("finding", "")
        curves = [c.strip() for c in curves_str.replace(",", " ").split() if c.strip()]
        # Normalize aliases
        normalized = []
        non_compliant = []
        has_brainpool = False
        for c in curves:
            norm = _CURVE_ALIASES.get(c, c)
            normalized.append(norm)
            if norm not in TR_02102_2_ALLOWED_CURVES:
                non_compliant.append(c)
            if "brainpool" in norm.lower():
                has_brainpool = True

        if non_compliant:
            checks.append(_check(
                "2.4.2", "Elliptische Kurven TR-02102-2-konform",
                "WARN",
                f"Nicht-konforme Kurven: {', '.join(non_compliant)}",
                _evidence_str(entry),
            ))
        else:
            detail = "Alle Kurven sind TR-02102-2-konform"
            if has_brainpool:
                detail += " (inkl. BSI-empfohlene Brainpool-Kurven)"
            checks.append(_check(
                "2.4.2", "Elliptische Kurven TR-02102-2-konform",
                "PASS", detail, _evidence_str(entry),
            ))
    else:
        checks.append(_check("2.4.2", "Elliptische Kurven TR-02102-2-konform", "N/A",
                             "Keine Daten zu elliptischen Kurven vorhanden"))

    # 2.4.3: DH groups >= 2048 bit
    dh_entry = _find(findings, "DH_groups")
    logjam_entry = _find(findings, "LOGJAM")
    if dh_entry or logjam_entry:
        ok = True
        detail = ""
        if logjam_entry:
            sev = logjam_entry.get("severity", "").upper()
            if sev in ("CRITICAL", "HIGH"):
                ok = False
                detail = f"LOGJAM-Schwachstelle: {logjam_entry.get('finding', '')[:80]}"
        if ok and dh_entry:
            import re
            numbers = re.findall(r"(\d+)", dh_entry.get("finding", ""))
            if numbers:
                min_dh = min(int(n) for n in numbers if int(n) > 100)
                if min_dh < 2048:
                    ok = False
                    detail = f"DH-Gruppe nur {min_dh} Bit (Minimum: 2048)"
                else:
                    detail = f"DH-Gruppen: {min_dh}+ Bit"
        if not detail:
            detail = "DH-Parameter ausreichend" if ok else "Schwache DH-Parameter"
        checks.append(_check(
            "2.4.3", "DH-Gruppen ≥ 2048 Bit",
            "PASS" if ok else "FAIL", detail,
            _evidence_str(dh_entry or logjam_entry),
        ))
    else:
        checks.append(_check("2.4.3", "DH-Gruppen ≥ 2048 Bit", "N/A",
                             "Keine Daten zu DH-Gruppen vorhanden"))

    # 2.4.4: Secure Renegotiation
    entry = _find(findings, "secure_renego")
    if entry:
        finding_text = entry.get("finding", "").lower()
        ok = "supported" in finding_text or entry.get("severity", "").upper() == "OK"
        checks.append(_check(
            "2.4.4", "Secure Renegotiation unterstützt",
            "PASS" if ok else "FAIL",
            "Secure Renegotiation wird unterstützt" if ok
            else "Secure Renegotiation wird NICHT unterstützt",
            _evidence_str(entry),
        ))
    else:
        checks.append(_check("2.4.4", "Secure Renegotiation unterstützt", "N/A",
                             "Keine Daten zu Secure Renegotiation vorhanden"))

    # 2.4.5: No client-initiated renegotiation
    entry = _find(findings, "secure_client_renego")
    if entry:
        finding_text = entry.get("finding", "").lower()
        ok = "not vulnerable" in finding_text or entry.get("severity", "").upper() == "OK"
        checks.append(_check(
            "2.4.5", "Client-initiierte Renegotiation deaktiviert",
            "PASS" if ok else "FAIL",
            "Client-initiierte Renegotiation ist deaktiviert" if ok
            else "Client-initiierte Renegotiation ist aktiv — Sicherheitsrisiko",
            _evidence_str(entry),
        ))
    else:
        checks.append(_check("2.4.5", "Client-initiierte Renegotiation deaktiviert", "N/A",
                             "Keine Daten zur Client-Renegotiation vorhanden"))

    return checks


# ---------------------------------------------------------------------------
# Section 2.5: Extensions
# ---------------------------------------------------------------------------

def _check_extensions(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []

    # 2.5.1: TLS Compression disabled (CRIME)
    entry = _find(findings, "CRIME_TLS")
    if entry:
        sev = entry.get("severity", "").upper()
        ok = sev == "OK" or "not vulnerable" in entry.get("finding", "").lower()
        checks.append(_check(
            "2.5.1", "TLS-Kompression deaktiviert (CRIME)",
            "PASS" if ok else "FAIL",
            "TLS-Kompression ist deaktiviert" if ok
            else "TLS-Kompression aktiv — CRIME-Angriff möglich",
            _evidence_str(entry),
        ))
    else:
        checks.append(_check("2.5.1", "TLS-Kompression deaktiviert (CRIME)", "N/A",
                             "Keine Daten zur TLS-Kompression vorhanden"))

    # 2.5.2: Heartbleed not vulnerable
    entry = _find(findings, "heartbleed")
    if entry:
        sev = entry.get("severity", "").upper()
        ok = sev == "OK" or "not vulnerable" in entry.get("finding", "").lower()
        checks.append(_check(
            "2.5.2", "Heartbleed-Schwachstelle nicht vorhanden",
            "PASS" if ok else "FAIL",
            "Nicht verwundbar für Heartbleed" if ok
            else "VERWUNDBAR für Heartbleed (CVE-2014-0160) — Kritisch!",
            _evidence_str(entry),
        ))
    else:
        checks.append(_check("2.5.2", "Heartbleed-Schwachstelle nicht vorhanden", "N/A",
                             "Keine Daten zu Heartbleed vorhanden"))

    return checks


# ---------------------------------------------------------------------------
# Section 2.6: Empfehlungen (optional)
# ---------------------------------------------------------------------------

def _check_recommendations(
    findings: list[dict[str, Any]],
    header_data: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []

    # 2.6.1: Only PFS cipher suites
    cipher_entries = _find_all(findings, "cipher_order")
    if cipher_entries:
        non_pfs = []
        for ce in cipher_entries:
            cipher_name = ce.get("finding", "").upper()
            if cipher_name and not any(kw in cipher_name for kw in ("ECDHE", "DHE", "TLS_AES", "TLS_CHACHA")):
                non_pfs.append(ce.get("finding", "")[:40])
        if non_pfs:
            checks.append(_check(
                "2.6.1", "Ausschließlich PFS-Cipher Suites",
                "WARN",
                f"{len(non_pfs)} Cipher ohne PFS: {', '.join(non_pfs[:3])}",
            ))
        else:
            checks.append(_check(
                "2.6.1", "Ausschließlich PFS-Cipher Suites",
                "PASS", "Alle angebotenen Cipher verwenden PFS",
            ))
    else:
        checks.append(_check("2.6.1", "Ausschließlich PFS-Cipher Suites", "N/A",
                             "Keine Cipher-Daten vorhanden"))

    # 2.6.2: OCSP Stapling
    entry = _find(findings, "OCSP_stapling")
    if entry:
        finding_text = entry.get("finding", "").lower()
        not_offered = "not offered" in finding_text
        offered = ("offered" in finding_text and not not_offered) or entry.get("severity", "").upper() == "OK"
        checks.append(_check(
            "2.6.2", "OCSP-Stapling aktiviert",
            "PASS" if offered else "WARN",
            "OCSP-Stapling ist aktiviert" if offered
            else "OCSP-Stapling ist nicht aktiviert (empfohlen)",
            _evidence_str(entry),
        ))
    else:
        checks.append(_check("2.6.2", "OCSP-Stapling aktiviert", "N/A",
                             "Keine Daten zu OCSP-Stapling vorhanden"))

    # 2.6.3: HSTS active (from header_data)
    if header_data:
        present = header_data.get("present", [])
        missing = header_data.get("missing", [])
        hsts_present = "strict-transport-security" in present
        hsts_missing = "strict-transport-security" in missing
        if hsts_present:
            # Check max-age
            details = header_data.get("details", {})
            hsts_info = details.get("security_headers", {}).get("Strict-Transport-Security", {})
            value = hsts_info.get("value", "") if isinstance(hsts_info, dict) else ""
            checks.append(_check(
                "2.6.3", "HSTS aktiviert",
                "PASS", f"HSTS aktiv: {value[:60]}" if value else "HSTS ist aktiviert",
            ))
        elif hsts_missing:
            checks.append(_check(
                "2.6.3", "HSTS aktiviert",
                "WARN", "HSTS-Header fehlt (empfohlen: max-age ≥ 15768000)",
            ))
        else:
            checks.append(_check("2.6.3", "HSTS aktiviert", "N/A",
                                 "Keine Header-Daten verfügbar"))
    else:
        checks.append(_check("2.6.3", "HSTS aktiviert", "N/A",
                             "Keine Header-Daten verfügbar"))

    return checks


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

SECTIONS = [
    ("2.1", "TLS-Versionen", True),
    ("2.2", "Cipher Suites", True),
    ("2.3", "Serverzertifikat", True),
    ("2.4", "Schlüsselaustausch", True),
    ("2.5", "Extensions", True),
    ("2.6", "Empfehlungen", False),
]


def check_tr03116_compliance(
    testssl_findings: list[dict[str, Any]],
    header_data: dict[str, Any] | None = None,
    host: str = "",
) -> dict[str, Any]:
    """Run all TR-03116-4 checks against testssl findings for a single host.

    Args:
        testssl_findings: Raw testssl.sh JSON entries (ALL severities incl. OK/INFO).
        header_data: Parsed security headers dict (optional, for HSTS check).
        host: Hostname/FQDN for labeling.

    Returns:
        Dict with overall_status, score, mandatory_pass, and per-section checks.
    """
    section_checks = {
        "2.1": _check_tls_versions(testssl_findings),
        "2.2": _check_cipher_suites(testssl_findings),
        "2.3": _check_certificate(testssl_findings),
        "2.4": _check_key_exchange(testssl_findings),
        "2.5": _check_extensions(testssl_findings),
        "2.6": _check_recommendations(testssl_findings, header_data),
    }

    # Build sections dict
    sections: dict[str, dict[str, Any]] = {}
    total_checks = 0
    passed_checks = 0
    has_mandatory_fail = False
    has_warn = False

    for sec_id, sec_title, required in SECTIONS:
        checks = section_checks[sec_id]
        sections[sec_id] = {
            "title": sec_title,
            "required": required,
            "checks": checks,
        }
        for c in checks:
            status = c["status"]
            if status != "N/A":
                total_checks += 1
                if status == "PASS":
                    passed_checks += 1
                elif status == "FAIL" and required:
                    has_mandatory_fail = True
                elif status == "WARN":
                    has_warn = True

    # Determine overall status
    if has_mandatory_fail:
        overall_status = "FAIL"
    elif has_warn:
        overall_status = "PARTIAL"
    else:
        overall_status = "PASS"

    return {
        "host": host,
        "overall_status": overall_status,
        "score": f"{passed_checks}/{total_checks}",
        "mandatory_pass": not has_mandatory_fail,
        "sections": sections,
    }
