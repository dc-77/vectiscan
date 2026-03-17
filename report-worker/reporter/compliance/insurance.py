"""Insurance questionnaire generator.

Generates cybersecurity insurance questionnaire answers from scan findings.
Used in the InsuranceReport variant.
"""

from __future__ import annotations

from typing import Any

import structlog

log = structlog.get_logger()

# Standard insurance questionnaire questions
INSURANCE_QUESTIONS: list[dict[str, Any]] = [
    {
        "id": "INS-01",
        "question": "Ist die Website per HTTPS erreichbar?",
        "category": "encryption",
        "keywords": ["ssl", "tls", "https", "certificate"],
        "positive_keywords": ["tls 1.2", "tls 1.3", "https"],
    },
    {
        "id": "INS-02",
        "question": "Werden aktuelle TLS-Versionen verwendet?",
        "category": "encryption",
        "keywords": ["tls", "ssl", "cipher"],
        "positive_keywords": ["tls 1.2", "tls 1.3"],
        "negative_keywords": ["tls 1.0", "tls 1.1", "sslv3"],
    },
    {
        "id": "INS-03",
        "question": "Sind bekannte Schwachstellen (CVEs) vorhanden?",
        "category": "vulnerability",
        "keywords": ["cve-", "vulnerability", "schwachstelle"],
    },
    {
        "id": "INS-04",
        "question": "Ist ein Web Application Firewall (WAF) im Einsatz?",
        "category": "protection",
        "keywords": ["waf", "firewall", "web application firewall"],
        "positive_keywords": ["waf erkannt", "waf detected", "cloudflare", "akamai"],
    },
    {
        "id": "INS-05",
        "question": "Sind Remote-Zugriffsdienste exponiert?",
        "category": "access",
        "keywords": ["rdp", "ssh", "vnc", "remote desktop", "3389", "5900"],
    },
    {
        "id": "INS-06",
        "question": "Ist Multi-Faktor-Authentifizierung erkennbar?",
        "category": "authentication",
        "keywords": ["mfa", "2fa", "multi-faktor", "totp"],
    },
    {
        "id": "INS-07",
        "question": "Werden E-Mails durch SPF/DMARC/DKIM geschützt?",
        "category": "email",
        "keywords": ["spf", "dmarc", "dkim"],
        "positive_keywords": ["spf pass", "dmarc reject", "dkim"],
        "negative_keywords": ["kein spf", "kein dmarc", "no spf", "no dmarc"],
    },
    {
        "id": "INS-08",
        "question": "Sind Backup-Systeme von außen erreichbar?",
        "category": "backup",
        "keywords": ["backup", "rsync", "ftp", "storage"],
    },
    {
        "id": "INS-09",
        "question": "Existieren exponierte Datenbank-Ports?",
        "category": "database",
        "keywords": ["mysql", "postgresql", "mongodb", "redis", "3306", "5432", "27017", "6379"],
    },
    {
        "id": "INS-10",
        "question": "Sind CMS-Systeme aktuell gepatcht?",
        "category": "cms",
        "keywords": ["wordpress", "joomla", "drupal", "typo3", "shopware", "cms"],
    },
]

# Ransomware risk ports
RANSOMWARE_PORTS = {3389, 445, 139, 5900, 5985, 5986}


def generate_questionnaire(
    findings: list[dict[str, Any]],
    positive_findings: list[dict[str, Any]],
    tech_profiles: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Generate insurance questionnaire answers from scan findings.

    Returns list of question-answer dicts.
    """
    all_text = ""
    for f in findings:
        all_text += f" {f.get('title', '')} {f.get('description', '')} {f.get('evidence', '')}"
    for pf in positive_findings:
        all_text += f" {pf.get('title', '')} {pf.get('description', '')}"
    all_text = all_text.lower()

    questionnaire: list[dict[str, Any]] = []

    for q in INSURANCE_QUESTIONS:
        answer = "NOT_ASSESSED"
        detail = "Konnte aus den Scan-Ergebnissen nicht bewertet werden."
        risk_impact = "unknown"

        has_keyword = any(kw in all_text for kw in q["keywords"])
        has_positive = any(kw in all_text for kw in q.get("positive_keywords", []))
        has_negative = any(kw in all_text for kw in q.get("negative_keywords", []))

        if has_keyword:
            if has_positive and not has_negative:
                answer = "PASS"
                detail = "Scan-Ergebnisse bestätigen eine korrekte Konfiguration."
                risk_impact = "low"
            elif has_negative:
                answer = "FAIL"
                detail = "Scan-Ergebnisse zeigen Verbesserungsbedarf."
                risk_impact = "high"
            else:
                answer = "PARTIAL"
                detail = "Teilweise implementiert, Optimierung empfohlen."
                risk_impact = "medium"

        questionnaire.append({
            "id": q["id"],
            "question": q["question"],
            "answer": answer,
            "detail": detail,
            "risk_impact": risk_impact,
            "category": q["category"],
        })

    return questionnaire


def calculate_risk_score(
    findings: list[dict[str, Any]],
    questionnaire: list[dict[str, Any]],
    tech_profiles: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Calculate insurance risk score (0-100, lower = better).

    Returns risk score dict with rating and recommendations.
    """
    score = 50  # Start at neutral

    # Deductions for positive findings
    pass_count = sum(1 for q in questionnaire if q["answer"] == "PASS")
    score -= pass_count * 5

    # Additions for negative findings
    fail_count = sum(1 for q in questionnaire if q["answer"] == "FAIL")
    score += fail_count * 8

    # Critical/High findings increase score
    for f in findings:
        sev = f.get("severity", "").upper()
        if sev == "CRITICAL":
            score += 15
        elif sev == "HIGH":
            score += 8
        elif sev == "MEDIUM":
            score += 3

    # Ransomware indicator
    ransomware_indicator = "LOW"
    all_text = " ".join(f.get("title", "") + " " + f.get("description", "")
                        for f in findings).lower()
    if any(str(p) in all_text for p in RANSOMWARE_PORTS) or "rdp" in all_text or "smb" in all_text:
        ransomware_indicator = "HIGH"
        score += 20
    elif "ssh" in all_text and "password" in all_text:
        ransomware_indicator = "MEDIUM"
        score += 10

    # Clamp to 0-100
    score = max(0, min(100, score))

    # Rating
    if score <= 25:
        rating = "LOW"
    elif score <= 50:
        rating = "MEDIUM"
    elif score <= 75:
        rating = "HIGH"
    else:
        rating = "CRITICAL"

    # Premium reduction actions
    actions: list[str] = []
    for q in questionnaire:
        if q["answer"] == "FAIL":
            if q["category"] == "protection":
                actions.append("WAF implementieren (geschätzt -10% Prämie)")
            elif q["category"] == "authentication":
                actions.append("MFA für alle Remote-Zugänge aktivieren (geschätzt -15% Prämie)")
            elif q["category"] == "encryption":
                actions.append("TLS-Konfiguration aktualisieren (geschätzt -5% Prämie)")
            elif q["category"] == "email":
                actions.append("SPF/DMARC/DKIM vollständig konfigurieren (geschätzt -5% Prämie)")
            elif q["category"] == "access":
                actions.append("Remote-Zugriffsdienste absichern oder deaktivieren (geschätzt -10% Prämie)")

    return {
        "score": score,
        "rating": rating,
        "ransomware_indicator": ransomware_indicator,
        "premium_reduction_actions": actions[:5],
    }
