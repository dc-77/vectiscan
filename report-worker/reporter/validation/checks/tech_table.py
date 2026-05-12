"""Tech-Table-Check: prueft Detection-Quality in der Tech-Tabelle.

Adressiert aus Doc 01 (Fehleranalyse_und_Korrekturplan.md):
- P1-05: Kernel-/internal-Detection-Strings sickern in die Tabelle
  (z.B. "HTTPAPI/2.0", "http.sys" — das ist Windows-Kernel, kein Produkt).
- P2-04: Versions-Falscherkennung, die der Public-Reality widerspricht
  (z.B. "Bootstrap 0.x" — Bootstrap 1 wurde nie released, ab 2.0 public).

Defensive: Wenn Tech-Tabelle nicht zugaenglich, return [] mit Warning-Log.
"""
from __future__ import annotations

import re
from typing import Any

import structlog

from reporter.validation.gate import ValidationIssue

log = structlog.get_logger()


# Strings die in der Tech-Tabelle als Produktname NIE auftauchen duerfen
# (Kernel-Komponenten von Windows, keine Software-Produkte zum patchen).
_KERNEL_BLACKLIST = (
    "httpapi",
    "http.sys",
    "microsoft httpapi httpd",
    "microsoft-httpapi",
)

# Minimum-Public-Version pro Tech-Produkt (Major-Version unter dieser Grenze
# existiert nicht in der Realitaet → Detection-Bug).
MIN_PUBLIC_VERSIONS: dict[str, int] = {
    "bootstrap": 2,    # 1.x nie released, 2.0 ist erste public Version
    "angular": 1,      # AngularJS war 1.x, Angular ab 2.x
    "react": 0,        # 0.x existiert (Pre-1.0-Phase)
    "jquery": 1,       # 1.x ist die erste Generation
    "tailwind": 1,
    "tailwindcss": 1,
    "vue": 1,
    "vue.js": 1,
    "ember": 1,
    "ember.js": 1,
    "next.js": 1,
    "nextjs": 1,
    "nuxt": 1,
    "nuxt.js": 1,
    "wordpress": 1,
    "drupal": 4,       # Drupal 4 ist aelteste relevant aktive Linie
    "joomla": 1,
    "django": 1,
    "rails": 1,
    "ruby on rails": 1,
    "spring": 1,
    "php": 4,          # PHP 4 ist EOL, aber existiert; <4 nicht
    "apache": 1,
    "nginx": 0,        # 0.x existierte
    "iis": 1,
}


def _get_tech_rows(
    report_data: dict[str, Any], context: dict[str, Any],
) -> list[dict[str, Any]]:
    """Hole alle Tech-Tabellen-Zeilen aus context.tech_profiles.

    Defense-in-Depth: prueft sowohl die *rohen* technologies[] aus
    tech_profiles ALS AUCH die per build_tech_table_for_host gebauten Rows.
    Seit M2 Track 2c filtert der Builder Kernel-Detections + sub-MinVersion-
    Treffer raus — der Check muss aber dennoch melden wenn die ROHEN
    Detection-Strings problematisch sind (sonst geht die Pipeline silent
    durch und wir verlieren das Audit-Signal).
    """
    rows: list[dict[str, Any]] = []
    profiles = context.get("tech_profiles") or []
    if not profiles or not isinstance(profiles, list):
        return rows

    # 1. Raw technologies[] aus tech_profiles — kein Builder, kein Filter.
    #    So sehen wir auch das, was der Builder rauswirft (Kernel/MinVer).
    for p in profiles:
        if not isinstance(p, dict):
            continue
        host_ip = p.get("ip")
        for tech in (p.get("technologies") or []):
            if not isinstance(tech, dict):
                continue
            name = tech.get("name") or ""
            if not name:
                continue
            rows.append({
                "name": name,
                "version": tech.get("version") or "",
                "_host_ip": host_ip,
                "_source": "raw_profile",
            })
        # Server-Banner ebenfalls als raw-row (z.B. "HTTPAPI/2.0")
        server = p.get("server")
        if server:
            rows.append({
                "name": str(server).split("/")[0].strip(),
                "version": (str(server).split("/", 1)[1].strip()
                            if "/" in str(server) else ""),
                "_host_ip": host_ip,
                "_source": "raw_profile_server",
            })

    # 2. Gebaute Rows als zweite Datenquelle (Defense-in-Depth — falls
    #    spaeter andere Tools direkt rows befuellen).
    try:
        from reporter.tech_table_builder import build_tech_table_for_host
    except ImportError:
        log.warning("tech_table_builder_unavailable_in_check")
        return rows

    for p in profiles:
        if not isinstance(p, dict):
            continue
        try:
            host_rows = build_tech_table_for_host(p)
        except Exception as e:
            log.warning("tech_table_build_failed",
                        ip=p.get("ip"), error=str(e))
            continue
        for r in host_rows:
            r = dict(r)
            r["_host_ip"] = p.get("ip")
            r["_source"] = "built_row"
            rows.append(r)
    return rows


def _major_version(version: str) -> int | None:
    """Extrahiere den Major-Version-Integer."""
    if not version:
        return None
    m = re.match(r"\s*(\d+)", version)
    if not m:
        return None
    try:
        return int(m.group(1))
    except ValueError:
        return None


def check(
    findings_data: dict,
    report_data: dict,
    context: dict,
) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    rows = _get_tech_rows(report_data or {}, context or {})

    if not rows:
        # Pragmatisch: kein Tech-Profile in context → moeglicherweise legitim
        # (z.B. tlscompliance-Paket ohne Phase 1). Warning, kein Error.
        issues.append(ValidationIssue(
            check="tech_table",
            severity="warning",
            finding_id=None,
            message=(
                "Tech-Tabelle ist leer oder nicht aufloesbar — Detection-"
                "Quality-Checks (Kernel/MinVersion) wurden uebersprungen"
            ),
            detail={"source": "context.tech_profiles"},
        ))
        return issues

    for r in rows:
        name = (r.get("name") or "").strip()
        name_lower = name.lower()
        version = (r.get("version") or "").strip()
        host_ip = r.get("_host_ip")

        # P1-05: Kernel-Blacklist
        for bad in _KERNEL_BLACKLIST:
            if bad in name_lower:
                issues.append(ValidationIssue(
                    check="tech_table",
                    severity="error",
                    finding_id=None,
                    message=(
                        f"Tech-Tabelle enthaelt Kernel-/Internal-Detection: "
                        f"{name!r}"
                    ),
                    detail={
                        "tech_name": name,
                        "host_ip": host_ip,
                        "blacklisted_token": bad,
                    },
                ))
                break

        # P2-04: Min-Public-Version
        if version:
            major = _major_version(version)
            # Match auf den ersten Whitespace-getrennten Token in name (z.B.
            # "Apache HTTP Server" → "apache") fuer den Lookup
            lookup_keys = [name_lower] + name_lower.split()
            for key in lookup_keys:
                if key in MIN_PUBLIC_VERSIONS:
                    min_v = MIN_PUBLIC_VERSIONS[key]
                    if major is not None and major < min_v:
                        issues.append(ValidationIssue(
                            check="tech_table",
                            severity="error",
                            finding_id=None,
                            message=(
                                f"{name} {version}: Major-Version {major} "
                                f"unterhalb der Min-Public-Version {min_v}"
                            ),
                            detail={
                                "tech_name": name,
                                "version": version,
                                "major": major,
                                "min_public": min_v,
                                "host_ip": host_ip,
                            },
                        ))
                    break

    return issues
