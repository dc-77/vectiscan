"""Layer-1-Aggregation fuer v2-Renderer (Doc 02 Seite 2 "Auf einen Blick").

Spec: docs/report-erstellung/02_Report_Aufbau_Neudesign.md
Plan: ~/.claude/plans/ich-m-chte-gerne-das-iterative-nova.md (M3 Aggregator-Agent)

Outputs:
  - risk_ampel: 5 Risikokategorien mit Level (hoch/mittel-hoch/mittel/niedrig-mittel/niedrig/info)
  - top_hebel: 3 kombinierte Massnahmen die maximal viele Findings adressieren
                (NICHT Top-3-CVSS - Geschaeftsfuehrer-relevant: groesste Wirkung pro Aktion)
  - overall_level: aggregierte Gesamtbewertung
  - hygiene_split: Liste der Findings, die in Anhang A.2 (Hygiene-Skala) gehoeren,
                   getrennt von Anhang A.1 (CVSS).
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any

logger = logging.getLogger(__name__)


# ====================================================================
# DOC-02-RISIKOKATEGORIEN (Frontpage-Buckets)
# ====================================================================
# Genau 5 Buckets analog Doc 02 Seite 2:
#   - Perimeter-Exposition  (RDP, DB-Ports, dev-Umgebung, FTP, alte SSH...)
#   - Patch- & EOL-Status   (EOL-Software, outdated, bekannte CVEs)
#   - E-Mail-Authentizitaet (SPF/DKIM/DMARC/DNSSEC/MTA-STS/TLS-RPT)
#   - Web-Hygiene           (HSTS/CSP/Cookies/Header)
#   - Konfigurations-Hygiene (Info-Disclosure, schwache TLS, CORS, SRI)
RISK_CATEGORIES = (
    "perimeter_exposition",
    "patch_eol",
    "mail_authenticity",
    "web_hygiene",
    "config_hygiene",
)

RISK_CATEGORY_LABELS_DE = {
    "perimeter_exposition": "Perimeter-Exposition",
    "patch_eol": "Patch- & EOL-Status",
    "mail_authenticity": "E-Mail-Authentizitaet",
    "web_hygiene": "Web-Hygiene",
    "config_hygiene": "Konfigurations-Hygiene",
}

# Mapping: policy_id-Prefix -> Risikokategorie
POLICY_PREFIX_TO_RISK_CATEGORY: dict[str, str] = {
    # Perimeter
    "SP-RDP": "perimeter_exposition",
    "SP-DB":  "perimeter_exposition",
    "SP-FTP": "perimeter_exposition",
    "SP-SSH": "perimeter_exposition",
    # Patch/EOL
    "SP-EOL": "patch_eol",
    "SP-CVE": "patch_eol",
    "SP-WP":  "patch_eol",
    "SP-JS":  "patch_eol",
    # Mail
    "SP-DNS": "mail_authenticity",
    # Web-Hygiene
    "SP-HDR":  "web_hygiene",
    "SP-CSP":  "web_hygiene",
    "SP-COOK": "web_hygiene",
    "SP-CSRF": "web_hygiene",
    # Config-Hygiene
    "SP-DISC":    "config_hygiene",
    "SP-TLS":     "config_hygiene",
    "SP-CORS":    "config_hygiene",
    "SP-SRI":     "config_hygiene",
    "SP-ENUM":    "config_hygiene",
    "SP-URLHAUS": "config_hygiene",
}


# Severity-Rang fuer Level-Aggregation
_SEVERITY_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}


# Mapping von Severity-Histogramm-Schwerpunkt zur Frontpage-Level-Bezeichnung
def _level_from_max_severity(max_sev: str, count: int) -> str:
    """Frontpage-Level aus Max-Severity + Anzahl."""
    if count == 0:
        return "info"
    sev = max_sev.upper()
    if sev == "CRITICAL":
        return "hoch"
    if sev == "HIGH":
        return "mittel-hoch" if count <= 1 else "hoch"
    if sev == "MEDIUM":
        return "niedrig-mittel" if count <= 1 else "mittel"
    if sev == "LOW":
        return "niedrig"
    return "info"


def _category_for_finding(finding: dict) -> str | None:
    """Welcher 5-Bucket-Risikokategorie gehoert das Finding?"""
    pid = (finding.get("policy_id") or "").strip()
    if not pid:
        return None
    # Longest-prefix-match: "SP-DISC" muss vor "SP-DB" geprueft werden falls
    # beide passen (heute nicht der Fall, aber sicherer). sorted() liefert
    # determinstische Reihenfolge — wir bevorzugen den laengsten Match.
    best_prefix: str | None = None
    for prefix in POLICY_PREFIX_TO_RISK_CATEGORY:
        if pid.startswith(prefix):
            if best_prefix is None or len(prefix) > len(best_prefix):
                best_prefix = prefix
    if best_prefix is None:
        return None
    return POLICY_PREFIX_TO_RISK_CATEGORY[best_prefix]


# ====================================================================
# TOP-3-HEBEL-CLUSTERING
# ====================================================================
# Massnahmen-Taxonomie: Cluster-Regeln die mehrere Findings zu einer Massnahme bundlen.
# Doc 02 Seite 2: "kombinierte Massnahmen, die maximal viele/schwerste Findings
# gleichzeitig abdecken (NICHT Top-CVSS)".

MASSNAHMEN_CLUSTER: list[dict[str, Any]] = [
    # Cluster #1: Perimeter-Firewall - schliesst alle ungewollt exponierten Dienste
    {
        "title": "Datenbank-, RDP- und Dev-Ports per Firewall sperren",
        "matches_policy_prefixes": ("SP-DB", "SP-RDP"),
        "matches_finding_types": ("database_port_exposed", "rdp_exposed"),
        "effect": "Schliesst die schwersten Einzelrisiken auf einen Schlag.",
        "priority_boost": 30,
    },
    # Cluster #2: Mail-Authentifizierung vervollstaendigen
    {
        "title": "E-Mail-Authentifizierung vervollstaendigen (SPF + DKIM + DMARC reject)",
        "matches_policy_prefixes": ("SP-DNS",),
        "matches_finding_types": ("mail_security_missing", "mail_security_missing_spf",
                                  "mail_security_missing_dkim",
                                  "mail_security_missing_dmarc",
                                  "mail_security_dmarc_none"),
        "effect": "Reduziert Identitaetsdiebstahl im Kundenkontakt erheblich.",
        "priority_boost": 15,
    },
    # Cluster #3: EOL-Migration
    {
        "title": "EOL-Software auf supportete Version migrieren",
        "matches_policy_prefixes": ("SP-EOL",),
        "matches_finding_types": ("software_eol",),
        "effect": "Beendet kumulierte unpatched CVEs, schliesst bekannte RCE-Pfade.",
        "priority_boost": 25,
    },
    # Cluster #4: Web-Patching (CMS/Plugin/Theme)
    {
        "title": "CMS / Plugin / Theme aktualisieren",
        "matches_policy_prefixes": ("SP-WP",),
        "matches_finding_types": ("wordpress_plugin_vulnerability",
                                  "wordpress_user_enumeration",
                                  "outdated_software"),
        "effect": "Adressiert den Hauptangriffsweg auf die Web-Praesenz.",
        "priority_boost": 12,
    },
    # Cluster #5: TLS / Klartext beenden
    {
        "title": "Klartext-Protokolle abschalten (FTP, HTTP-Login, SMTP ohne STARTTLS)",
        "matches_policy_prefixes": ("SP-TLS",),
        "matches_finding_types": ("ftp_cleartext", "cleartext_login",
                                  "tls_weak_cipher", "tls_obsolete_version"),
        "effect": "Verhindert Credential-Sniffing und MitM-Angriffe.",
        "priority_boost": 10,
    },
    # Cluster #6: Security-Header haerten
    {
        "title": "Sicherheitsheader haerten (HSTS, CSP, Cookies)",
        "matches_policy_prefixes": ("SP-HDR", "SP-CSP", "SP-COOK", "SP-CSRF"),
        "matches_finding_types": (),
        "effect": "Reduziert XSS-, CSRF- und Session-Hijack-Risiken.",
        "priority_boost": 5,
    },
    # Cluster #7: Information-Disclosure schliessen
    {
        "title": "Server-Banner, Generator-Tags und Konfig-Lecks unterdruecken",
        "matches_policy_prefixes": ("SP-DISC",),
        "matches_finding_types": ("info_disclosure_banner",
                                  "info_disclosure_meta_generator"),
        "effect": "Erschwert Footprinting durch Angreifer.",
        "priority_boost": 3,
    },
    # Cluster #8: CVE-Patches mit aktivem Ausnutzungs-Bezug
    {
        "title": "CVEs aus CISA-KEV / hohem EPSS unverzueglich patchen",
        "matches_policy_prefixes": ("SP-CVE",),
        "matches_finding_types": ("cve_finding",),
        "effect": "Adressiert aktiv ausgenutzte Schwachstellen.",
        "priority_boost": 28,
    },
]


def _match_findings_to_cluster(cluster: dict, findings: list[dict]) -> list[dict]:
    """Welche Findings passen in dieses Cluster?"""
    matched: list[dict] = []
    prefixes = cluster.get("matches_policy_prefixes") or ()
    ftypes = set(cluster.get("matches_finding_types") or ())
    for f in findings:
        pid = (f.get("policy_id") or "").strip()
        ftype = (f.get("finding_type") or "").strip().lower()
        if prefixes and any(pid.startswith(p) for p in prefixes):
            matched.append(f)
            continue
        if ftypes and ftype in ftypes:
            matched.append(f)
    return matched


def _score_cluster(findings: list[dict], cluster: dict) -> float:
    """Cluster-Score = Sum(severity-Rang) * Anzahl + priority_boost.

    So gewinnt ein Cluster, das viele Findings UND hohe Severities abdeckt.
    Single-CRITICAL faellt durch wenn ein anderes Cluster 3xHIGH liefert.
    """
    if not findings:
        return 0.0
    severity_sum = sum(_SEVERITY_RANK.get((f.get("severity") or "INFO").upper(), 0)
                       for f in findings)
    return severity_sum * len(findings) + cluster.get("priority_boost", 0)


# ====================================================================
# HYGIENE-SPLIT (Anhang A.1 CVSS vs A.2 Hygiene)
# ====================================================================
def split_findings_by_scale(findings: list[dict]) -> dict[str, list[dict]]:
    """Trennt Findings nach scale ('cvss' vs 'hygiene') fuer Anhang A.1/A.2.

    Erwartet: findings sind durch cvss_consistency.apply_consistency gelaufen
    (M2 Track 2a) und tragen entweder scale="cvss" oder scale="hygiene".
    Fallback fuer Pre-M2-Findings: ohne scale-Feld -> cvss.
    """
    cvss_list: list[dict] = []
    hygiene_list: list[dict] = []
    for f in findings:
        scale = (f.get("scale") or "cvss").lower()
        if scale == "hygiene":
            hygiene_list.append(f)
        else:
            cvss_list.append(f)
    return {"cvss": cvss_list, "hygiene": hygiene_list}


# ====================================================================
# HAUPT-FUNKTION
# ====================================================================
def build_layer1(findings: list[dict],
                 recommendations: list[dict] | None = None,
                 host_inventory: dict | None = None,
                 package: str = "perimeter") -> dict[str, Any]:
    """Baut den Layer-1-Aggregations-Output fuer den v2-Renderer.

    Returns Dict mit:
      - risk_ampel: list[{label, level, count}]
      - top_hebel: list[{rank, title, effect, finding_ids}]
      - overall_level: str
      - hygiene_split: {cvss: [...], hygiene: [...]}
    """
    findings = findings or []

    # --------- 1. Risiko-Ampel ----------
    findings_by_cat: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        cat = _category_for_finding(f)
        if cat:
            findings_by_cat[cat].append(f)
        # findings ohne policy_id (SP-FALLBACK oder leer) gehen in keine
        # Frontpage-Kategorie - sie bleiben in der Befund-Landschaft sichtbar.

    risk_ampel: list[dict[str, Any]] = []
    for cat in RISK_CATEGORIES:
        fs = findings_by_cat.get(cat, [])
        max_sev = "INFO"
        for f in fs:
            sev = (f.get("severity") or "INFO").upper()
            if _SEVERITY_RANK.get(sev, 0) > _SEVERITY_RANK.get(max_sev, 0):
                max_sev = sev
        level = _level_from_max_severity(max_sev, len(fs))
        risk_ampel.append({
            "label": RISK_CATEGORY_LABELS_DE[cat],
            "key": cat,
            "level": level,
            "count": len(fs),
            "max_severity": max_sev,
        })

    # --------- 2. Top-3-Hebel ----------
    cluster_scores: list[tuple[float, dict, list[dict]]] = []
    for cluster in MASSNAHMEN_CLUSTER:
        matched = _match_findings_to_cluster(cluster, findings)
        score = _score_cluster(matched, cluster)
        if score > 0:
            cluster_scores.append((score, cluster, matched))

    cluster_scores.sort(key=lambda x: -x[0])
    top_hebel: list[dict[str, Any]] = []
    used_findings: set[str] = set()
    for score, cluster, matched in cluster_scores:
        # vermeide Cluster-Ueberlappung - wenn ein Cluster nur Findings enthaelt,
        # die schon vom hoeher-rankenden Cluster adressiert wurden, skip
        new_matched = [f for f in matched
                       if (f.get("id") or f.get("finding_id"))
                       not in used_findings]
        if not new_matched:
            continue
        rank = len(top_hebel) + 1
        finding_ids = sorted({
            (f.get("id") or f.get("finding_id") or "?")
            for f in matched
        })
        top_hebel.append({
            "rank": rank,
            "title": cluster["title"],
            "effect": cluster["effect"],
            "finding_ids": finding_ids,
            "cluster_score": score,
        })
        used_findings.update(finding_ids)
        if len(top_hebel) >= 3:
            break

    # --------- 3. Gesamt-Level ----------
    if not findings:
        overall = "info"
    else:
        max_sev_overall = "INFO"
        for f in findings:
            sev = (f.get("severity") or "INFO").upper()
            if _SEVERITY_RANK.get(sev, 0) > _SEVERITY_RANK.get(max_sev_overall, 0):
                max_sev_overall = sev
        overall = _level_from_max_severity(max_sev_overall, len(findings))

    # --------- 4. Hygiene-Split fuer Anhang A.1/A.2 ----------
    hygiene_split = split_findings_by_scale(findings)

    logger.info("layer1_built package=%s findings=%d top_hebel=%d hygiene=%d",
                package, len(findings), len(top_hebel),
                len(hygiene_split["hygiene"]))

    return {
        "risk_ampel": risk_ampel,
        "top_hebel": top_hebel,
        "overall_level": overall,
        "hygiene_split": hygiene_split,
    }


__all__ = [
    "RISK_CATEGORIES",
    "RISK_CATEGORY_LABELS_DE",
    "POLICY_PREFIX_TO_RISK_CATEGORY",
    "MASSNAHMEN_CLUSTER",
    "build_layer1",
    "split_findings_by_scale",
]
