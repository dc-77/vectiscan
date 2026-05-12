"""Geschaeftskontext (Doc 02 Seite 3 — Schicht 1.2).

Erzeugt einen kundenspezifischen Kontext-Block ("In Ihrem Geschaeft sind ...
besonders sensibel."), zugeschnitten auf eine Branche und die im Scan
beobachteten Anwendungen.

Quellen (in dieser Reihenfolge — erste Treffer gewinnt):
  1. Order-Metadaten (scan_meta["industry_vertical"]) — manuell vom Wizard gesetzt
  2. Branchen-Heuristik aus erkannten Tech-Stacks (CRM, Shop, WordPress, ...)
  3. Domain-TLD-Heuristik (.health, .legal, ...)
  4. Generic-Fallback

Output ist explizit ein Plain-Dict (kein ReportLab-Flowable), damit die
Daten testbar bleiben und Renderer austauschbar sind. Render-Logik liegt in
``reporter/pdf/v2/layers/strategy.py``.

Doc 02 Leitsatz: "Diese Seite wird semi-statisch generiert: Templates pro
Branchencluster + Einfuegung der konkret betroffenen Datenarten. Keine
generischen Floskeln." Wenn kein Branchencluster identifizierbar ist,
wird ein neutraler, datenarten-gebundener Text gerendert — kein
generisches Marketing-Sprech.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


# ====================================================================
# BRANCHENCLUSTER-TEMPLATES
# ====================================================================
# Jeder Cluster: Schluessel, Match-Heuristik, Storytext (mit Platzhaltern),
# typische Datenarten + Compliance-Bezug.
#
# Doc 02-Beispiele:
#   - trunk (Makler):    "Kundenstammdaten, KYC-Unterlagen, Geldwaeschepruefdaten"
#                        Bezug: DSGVO Art. 32/33
#   - secumetrix (Cyber): "Strengere Eigen-Posture als Branchenschnitt;
#                          Findings sind Vertriebs-/Reputationsthema."

INDUSTRY_CLUSTERS: dict[str, dict[str, Any]] = {
    "real_estate": {
        "label": "Immobilienwirtschaft / Makler",
        "data_kinds": [
            "Kundenstammdaten",
            "Kontaktinformationen",
            "Vertragshistorie",
            "KYC-/Geldwaeschepruefdaten",
        ],
        "narrative": (
            "In Ihrem Geschaeft sind Kundenstammdaten, KYC-Unterlagen und "
            "Geldwaesche-Pruefdaten besonders sensibel. Eine kompromittierte "
            "Datenbank- oder Anwendungs-Instanz, die direkt aus dem Internet "
            "erreichbar ist, gefaehrdet diese Bestaende unmittelbar. Im "
            "Schadensfall greift die Meldepflicht nach Art. 33 DSGVO "
            "innerhalb von 72 Stunden."
        ),
        "compliance_focus": ("DSGVO Art. 32/33", "BSI-Grundschutz Basis"),
    },
    "cybersecurity": {
        "label": "Cybersecurity- / IT-Sicherheits-Anbieter",
        "data_kinds": [
            "Kunden-Auditdaten",
            "interne Threat-Intelligence",
            "Kundenkontakte aus Vertraulichkeitsvertraegen",
        ],
        "narrative": (
            "Ihre Position als Anbieter von Sicherheitsleistungen verlangt "
            "eine deutlich strengere Eigen-Posture als der Branchenschnitt. "
            "Findings dieser Art sind nicht nur ein IT-Problem, sondern "
            "unmittelbar Vertriebs- und Reputationsthema, insbesondere im "
            "Versicherungs- und KRITIS-Umfeld."
        ),
        "compliance_focus": ("ISO 27001", "NIS2 §30 BSIG", "Branchen-Reputation"),
    },
    "healthcare": {
        "label": "Gesundheitswesen / MedTech",
        "data_kinds": [
            "Patientenstammdaten",
            "Diagnose- und Behandlungsdaten",
            "Abrechnungsdaten",
        ],
        "narrative": (
            "Im Gesundheitswesen verlangt Art. 9 DSGVO besonderen Schutz "
            "fuer Gesundheitsdaten. Eine externe Angriffsflaeche, die "
            "Patienten- oder Abrechnungssysteme erreicht, ist nicht nur "
            "ein IT-Risiko, sondern ein Meldetatbestand nach Art. 33 DSGVO "
            "und je nach Versorgungsrolle nach §30 BSIG / KRITIS-Verordnung."
        ),
        "compliance_focus": ("DSGVO Art. 9/32/33", "B3S Krankenhaus", "KRITIS"),
    },
    "legal_services": {
        "label": "Rechtsanwaltskanzlei / Notariat",
        "data_kinds": [
            "Mandantendaten",
            "Akten",
            "Verschwiegenheits-pflichtige Korrespondenz",
        ],
        "narrative": (
            "Die anwaltliche Verschwiegenheitspflicht (§203 StGB / §43a BRAO) "
            "wirkt auch auf die IT-Sicherheit: Eine offene Datenbank oder "
            "eine unzureichend gehaertete Anwendungsumgebung ist ein "
            "berufsrechtliches Risiko, das ueber den Datenschutz hinausgeht. "
            "Im Vorfallsfall sind sowohl Mandanten als auch die zustaendige "
            "Rechtsanwaltskammer in Kenntnis zu setzen."
        ),
        "compliance_focus": ("DSGVO Art. 32", "§203 StGB", "§43a BRAO"),
    },
    "ecommerce": {
        "label": "Online-Handel / E-Commerce",
        "data_kinds": [
            "Kundenkonten",
            "Bestell- und Adressdaten",
            "Zahlungsdaten",
        ],
        "narrative": (
            "Im Online-Handel ist die externe Angriffsflaeche der Vertriebs"
            "kanal — eine erfolgreiche Kompromittierung trifft unmittelbar "
            "Umsatz und Kundenkontakt. Zusaetzlich greift PCI-DSS, sobald "
            "Kreditkartendaten verarbeitet werden, sowie Art. 32 DSGVO fuer "
            "alle Kundenstammdaten."
        ),
        "compliance_focus": ("DSGVO Art. 32", "PCI-DSS", "TKG/TMG"),
    },
    "industrial": {
        "label": "Industrie / Maschinenbau",
        "data_kinds": [
            "Konstruktionsdaten",
            "Lieferantenketten-Informationen",
            "Steuerungs- und Produktionsdaten",
        ],
        "narrative": (
            "Industrieunternehmen sind regelmaessig Ziel von Wirtschafts"
            "spionage und Lieferketten-Angriffen. Eine offene Angriffs"
            "flaeche kann Konstruktions-, Produktions- und Lieferanten"
            "informationen exponieren — Werte, die sich nach einem Vorfall "
            "nicht zurueckholen lassen."
        ),
        "compliance_focus": (
            "TISAX (bei Automotive)", "NIS2 §30 BSIG", "Geschaeftsgeheimnis-Gesetz",
        ),
    },
    "financial_services": {
        "label": "Finanzdienstleister",
        "data_kinds": [
            "Kundenkonten",
            "Transaktionsdaten",
            "Vertragsstamm",
        ],
        "narrative": (
            "Finanzdienstleister unterliegen sektorspezifischen Aufsichts"
            "regimen (BaFin / MaRisk / DORA) mit hohen Anforderungen an "
            "Schwachstellenmanagement und Vorfallmeldung. Bereits einzelne "
            "exponierte Datenbank- oder Verwaltungs-Endpoints sind in der "
            "Pruefung relevant."
        ),
        "compliance_focus": ("DORA", "BaFin/MaRisk", "DSGVO Art. 32"),
    },
    "public_sector": {
        "label": "Oeffentliche Verwaltung",
        "data_kinds": [
            "Buergerdaten",
            "Verfahrensakten",
            "Verwaltungs-internes IT-Inventar",
        ],
        "narrative": (
            "In der oeffentlichen Verwaltung gelten BSI-Grundschutz und das "
            "Online-Zugangsgesetz (OZG) als Pruefungsmassstab. Eine "
            "exponierte Angriffsflaeche gegen Buergerportale oder "
            "Verwaltungsfachverfahren ist sowohl Datenschutz- als auch "
            "Aufsichtsthema."
        ),
        "compliance_focus": ("BSI-Grundschutz", "OZG", "DSGVO Art. 32"),
    },
}


# Default-Cluster wenn nichts matcht — KEINE generischen Floskeln, sondern
# datenarten-fokussierter, neutraler Text.
GENERIC_CLUSTER: dict[str, Any] = {
    "label": "Allgemeine Geschaefts-IT",
    "data_kinds": [
        "Kundenkontakte",
        "Geschaeftskorrespondenz",
        "Auftragsdaten",
    ],
    "narrative": (
        "Auch ohne branchen-spezifischen Sonderschutz greift Art. 32 DSGVO "
        "fuer jede Verarbeitung personenbezogener Daten. Eine exponierte "
        "Angriffsflaeche gefaehrdet typischerweise Kundenkontakte und "
        "Geschaeftskorrespondenz und ist damit unmittelbar Datenschutz-"
        "relevant."
    ),
    "compliance_focus": ("DSGVO Art. 32",),
}


# ====================================================================
# HEURISTIK: Tech-Stack -> Branche
# ====================================================================
# Wenn keine Branche im Order-Wizard gesetzt wurde, wird aus erkannten
# Anwendungen heraus geraten. Bewusst konservativ — bei Unsicherheit
# faellt es auf GENERIC zurueck.
_TECH_HINTS: tuple[tuple[str, str], ...] = (
    # E-Commerce-Plattformen
    ("shopware",       "ecommerce"),
    ("magento",        "ecommerce"),
    ("woocommerce",    "ecommerce"),
    ("shopify",        "ecommerce"),
    ("xtcommerce",     "ecommerce"),
    ("oxid",           "ecommerce"),
    # Health
    ("medatixx",       "healthcare"),
    ("turbomed",       "healthcare"),
    # Legal-typische Software
    ("ranet",          "legal_services"),
    ("advoware",       "legal_services"),
    ("rena2",          "legal_services"),
    # Industrie-typische Systeme
    ("sap",            "industrial"),
    ("siemens",        "industrial"),
    ("rockwell",       "industrial"),
)


def _detect_industry_from_techs(tech_profiles: list[dict]) -> str | None:
    """Branchen-Heuristik anhand der im Scan erkannten Tech-Stacks."""
    if not tech_profiles:
        return None
    blob_parts: list[str] = []
    for p in tech_profiles:
        if not isinstance(p, dict):
            continue
        if p.get("cms"):
            blob_parts.append(str(p["cms"]))
        if p.get("server"):
            blob_parts.append(str(p["server"]))
        for tech in p.get("technologies") or []:
            if isinstance(tech, dict) and tech.get("name"):
                blob_parts.append(str(tech["name"]))
    blob = " ".join(blob_parts).lower()
    if not blob:
        return None
    for needle, cluster_key in _TECH_HINTS:
        if needle in blob:
            return cluster_key
    return None


def _detect_industry_from_domain(domain: str | None) -> str | None:
    """TLD- / Subdomain-Heuristik. Sehr konservativ — viele Branchen-TLDs
    sind faktisch leer geworden, sind also nur ein schwaches Signal.
    """
    if not domain:
        return None
    d = str(domain).lower()
    # Domains mit eindeutigen Branchen-Hinweisen
    if any(token in d for token in ("anwalt", "kanzlei", "notar")):
        return "legal_services"
    if any(token in d for token in ("immobilien", "makler", "haus-")):
        return "real_estate"
    if any(token in d for token in ("klinik", "praxis", "arzt", "med-")):
        return "healthcare"
    if any(token in d for token in ("bank", "versicher", "finanz")):
        return "financial_services"
    if d.endswith((".gov.de", ".bund.de")):
        return "public_sector"
    return None


# ====================================================================
# DATENARTEN-HEURISTIK
# ====================================================================
# Zusaetzlich zu den Cluster-Default-Datenarten werden konkret beobachtete
# Anwendungen in eine "vermutete Datenart" uebersetzt — Doc 02:
# "Datenart-Vermutung aus erkannten Anwendungen (WordPress mit Contact
# Form 7 -> Kontaktdaten; CRM-Hostname -> Kundendaten; etc.)."

_APP_DATA_HINTS: tuple[tuple[str, str], ...] = (
    ("contact form 7", "Kontaktanfragen ueber Web-Formulare"),
    ("contact-form-7", "Kontaktanfragen ueber Web-Formulare"),
    ("wpforms",        "Kontaktanfragen ueber Web-Formulare"),
    ("woocommerce",    "Bestell- und Zahlungsdaten (WooCommerce-Shop)"),
    ("phpmyadmin",     "direkter Datenbankzugriff"),
    ("roundcube",      "E-Mail-Postfaecher"),
    ("nextcloud",      "Dateifreigaben und Kalenderdaten"),
    ("owncloud",       "Dateifreigaben und Kalenderdaten"),
    ("mautic",         "Marketing-Kontaktdatenbank"),
    ("matomo",         "Web-Analyse-/Besucherdaten"),
    ("piwik",          "Web-Analyse-/Besucherdaten"),
)


def _observed_data_kinds(tech_profiles: list[dict]) -> list[str]:
    """Datenarten, die sich aus den konkret erkannten Anwendungen ergeben.

    Nur 'gesehene' Datenarten — der Cluster-Default kommt aus den
    Branchen-Templates oben.
    """
    if not tech_profiles:
        return []
    blob_parts: list[str] = []
    for p in tech_profiles:
        if not isinstance(p, dict):
            continue
        if p.get("cms"):
            blob_parts.append(str(p["cms"]))
        for tech in p.get("technologies") or []:
            if isinstance(tech, dict) and tech.get("name"):
                blob_parts.append(str(tech["name"]))
    blob = " ".join(blob_parts).lower()
    seen: list[str] = []
    for needle, label in _APP_DATA_HINTS:
        if needle in blob and label not in seen:
            seen.append(label)
    return seen


# ====================================================================
# HAUPT-FUNKTION
# ====================================================================
def build_business_context(
    scan_meta: dict[str, Any] | None,
    host_inventory: dict[str, Any] | None,
    claude_output: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Baut den Geschaeftskontext-Block (Doc 02 Seite 3).

    Args:
        scan_meta: Erwartet optional ``industry_vertical``, ``domain``, ``techProfiles``.
        host_inventory: Erwartet ``domain`` als Fallback.
        claude_output: aktuell ungenutzt, reserviert fuer KI-Verfeinerung.

    Returns:
        Dict mit Schluesseln:
            ``cluster_key``    — z.B. 'real_estate' | 'cybersecurity' | 'generic'
            ``cluster_label``  — angezeigter Branchen-Titel
            ``data_kinds``     — Cluster-Default-Datenarten + erkannte App-spezifische
            ``narrative``      — Fliesstext-Block (kein HTML)
            ``compliance_focus`` — Tuple mit ein bis drei Anker-Frameworks
            ``observed_apps``  — Liste konkret beobachteter Apps + abgeleiteter Datenart
                                 (fuer einen Bullet-Block, Doc 02 ``Datenarten:`` Zeile)
            ``source``         — 'override' | 'tech_heuristic' | 'domain_heuristic' | 'generic'
    """
    scan_meta = scan_meta or {}
    host_inventory = host_inventory or {}
    tech_profiles = scan_meta.get("techProfiles") or []
    domain = scan_meta.get("domain") or host_inventory.get("domain")

    cluster_key: str | None = (
        (scan_meta.get("industry_vertical") or "").strip().lower() or None
    )
    source = "override" if cluster_key else None
    if cluster_key and cluster_key not in INDUSTRY_CLUSTERS:
        logger.info(
            "business_context_unknown_override",
            extra={"override": cluster_key},
        )
        cluster_key = None
        source = None

    if not cluster_key:
        cluster_key = _detect_industry_from_techs(tech_profiles)
        if cluster_key:
            source = "tech_heuristic"

    if not cluster_key:
        cluster_key = _detect_industry_from_domain(domain)
        if cluster_key:
            source = "domain_heuristic"

    if not cluster_key:
        cluster = GENERIC_CLUSTER
        cluster_key = "generic"
        source = "generic"
    else:
        cluster = INDUSTRY_CLUSTERS[cluster_key]

    observed_apps = _observed_data_kinds(tech_profiles)

    # Datenarten = Cluster-Default + konkret beobachtete (dedupliziert)
    data_kinds = list(cluster["data_kinds"])
    for kind in observed_apps:
        if kind not in data_kinds:
            data_kinds.append(kind)

    logger.info(
        "business_context_built",
        extra={
            "cluster_key": cluster_key,
            "source": source,
            "observed_apps": len(observed_apps),
            "domain": domain,
        },
    )

    return {
        "cluster_key": cluster_key,
        "cluster_label": cluster["label"],
        "data_kinds": data_kinds,
        "narrative": cluster["narrative"],
        "compliance_focus": tuple(cluster.get("compliance_focus", ())),
        "observed_apps": observed_apps,
        "source": source,
    }


__all__ = [
    "INDUSTRY_CLUSTERS",
    "GENERIC_CLUSTER",
    "build_business_context",
]
