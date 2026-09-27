# -*- coding: utf-8 -*-
"""Erzähltexte des Reports: deterministisch, aus Vorlagen und Zahlen.

Der Prototyp hat diese Absätze von Hand geschrieben. Sie gehören nicht in den
Prüfkatalog (sie beschreiben nicht einen Sachverhalt, sondern den Bericht) und sie
gehören nicht zur KI (sie enthalten Zahlen und Zusagen, die stimmen müssen). Deshalb
stehen sie hier als Vorlage mit Zahlen-Slots.

Regeln wie im Katalog: Deutsch mit echten Umlauten, Sie-Form, keine Gedankenstriche,
keine Zusagen zu Prüfstandards, zur Rolle von Sprachmodellen oder zur Vollständigkeit,
keine Aufwände und keine Kosten. Die Liste der verbotenen Begriffe steht in
``orthography.FORBIDDEN_CLAIMS``, der Wächter dazu in ``tests/test_no_legacy_claims.py``.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Counts:
    """Zahlen, die in den Erzähltexten vorkommen dürfen; alle aus Fakten und Katalog."""

    domains: list[str] = field(default_factory=list)
    scan_date: str = ""
    hosts_total: int = 0
    # Nachtrag 3: Systeme (IPv4 und IPv6 mit gleichem rDNS sind eines) und die
    # Adressen der Systeme mit Luecke.
    systems_total: int = 0
    gap_addresses: int = 0
    hosts_ipv4: int = 0
    hosts_ipv6: int = 0
    fqdns_total: int = 0
    runs: int = 1
    tool_runs: int = 0
    # S6b-3 (spec/10 R14): aus der Bilanz der Phase-3-Korrelation (``total_findings`` und die
    # Dedup-Gruende); ohne Bilanz 0, und die Zahl steht nicht im Bericht.
    raw_findings: int = 0
    findings: int = 0
    positives: int = 0
    categories: int = 5
    coverage_full: int = 0
    coverage_partial: int = 0
    coverage_none: int = 0
    duplicates: int = 0
    not_testable: int = 0
    # S6b-3 (spec/10 R5): ermittelte Namen (Inventar und Hostsuche mit Adresse) und davon geprueft.
    names_found: int = 0
    names_checked: int = 0
    # S6b-3 (spec/10 R13): Betriebsformen der eigenen Systeme (rechenzentrum, anschluss, plattform).
    betriebsformen: list[str] = field(default_factory=list)
    # S6b-4 (spec/11 T8): mindestens eine belastbare Pfadsuche; ``path_search_known`` ohne Fakten
    # aelterer Laeufe bleibt der bisherige Text.
    path_search_ok: bool = False
    path_search_known: bool = False
    # S6b-4n (spec/11 N13): Adressen nur aus DNS (AAAA, weitere A-Eintraege) oder ohne Antwort;
    # sie zaehlen in der Zahl der Adressen mit, geprueft sind sie nicht.
    hosts_dns_only: int = 0
    # S6b-4n (spec/11 N12): Doppelmeldungen je Grund der Korrelation (``fp_by_reason``).
    duplicates_by: dict[str, int] = field(default_factory=dict)


def _join(names: list[str]) -> str:
    if not names:
        return "der beauftragten Domain"
    if len(names) == 1:
        return names[0]
    return ", ".join(names[:-1]) + " und " + names[-1]


def _plural(n: int, one: str, many: str) -> str:
    return one if n == 1 else many


# ---------------------------------------------------------------- Kapitel 1

def adressen(c: Counts) -> str:
    """"9 IP-Adressen" oder "9 IP-Adressen, davon 3 nur aus DNS oder ohne Antwort" (spec/11 N13)."""
    text = f"{c.hosts_total} {_plural(c.hosts_total, 'IP-Adresse', 'IP-Adressen')}"
    if c.hosts_dns_only and c.hosts_total > 1:
        text += f", davon {c.hosts_dns_only} nur aus DNS oder ohne Antwort"
    return text


def context(c: Counts) -> str:
    runs = (f" Die Ergebnisse aus {c.runs} Scandurchgängen sind zu einem Bericht "
            "zusammengeführt." if c.runs > 1 else "")
    return (
        f"Geprüft wurde die von außen erreichbare Angriffsfläche von {_join(c.domains)} "
        f"am {c.scan_date}: {c.fqdns_total} "
        f"{_plural(c.fqdns_total, 'Hostname', 'Hostnamen')} auf {adressen(c)}."
        f"{runs} Die Innenperspektive, Mitarbeiterszenarien und Social Engineering sind "
        "nicht Teil dieser Prüfung."
    )


def _system_label(ips: list[str]) -> str:
    return ips[0] + (f" mit {_join(ips[1:])}" if len(ips) > 1 else "")


def _gap_kind(c: Counts) -> tuple[str, str]:
    """(Satzteil Kapitel 2, Satzteil Hinweis) nach Art der Luecken."""
    if c.coverage_partial and not c.coverage_none:
        return "nur teilweise möglich", "nur eine teilweise aktive Prüfung"
    if c.coverage_none and not c.coverage_partial:
        return "nicht möglich", "keine aktive Prüfung"
    return "nur teilweise oder gar nicht möglich", "keine oder nur eine teilweise aktive Prüfung"


def coverage_warning(c: Counts, systems: list[list[str]]) -> str:
    """Hinweis auf Seite 2: je System mit seinen Adressen (Nachtrag 3, Q16).

    S6b-4 (spec/11 Teil 3 LW): gefundene, aber nicht geprüfte Namen stehen mit ihrer Zahl im
    Hinweis; vorher nannte ihn nur Kapitel 2."""
    offen = max(c.names_found - c.names_checked, 0)
    # S6b-4n (spec/11 N15): "1 weiterer gefundener Name ist", nicht "1 weitere gefundene Name".
    namen = ((f"{offen} weiterer gefundener Name ist nicht geprüft." if offen == 1 else
              f"{offen} weitere gefundene Namen sind nicht geprüft.") if offen else "")
    if not systems:
        return (f"{namen} Die Gründe stehen in Kapitel 2; die Ergebnisse dieses Berichts sind "
                "entsprechend zu lesen.") if namen else ""
    _, art = _gap_kind(c)
    labels = _join([_system_label(ips) for ips in systems])
    return (
        f"Für {len(systems)} {_plural(len(systems), 'System', 'Systeme')} ({labels}) liegt "
        f"{art} vor." + (f" {namen}" if namen else "") + " Die Einschränkungen und ihre Gründe "
        "stehen in Kapitel 2; die Ergebnisse dieses Berichts sind entsprechend zu lesen."
    )


BUSINESS_LEAD = (
    "Was der Scan über das Unternehmen sichtbar macht, bestimmt, welche Befunde wirklich "
    "zählen. Maßgeblich ist nicht die Zahl der Meldungen, sondern welche Systeme am "
    "Perimeter stehen und wofür sie gebraucht werden."
)

BUSINESS_IMPLICATION_GENERIC = (
    "Die Befunde dieses Berichts sind danach geordnet, wie nah sie an den Zugangswegen in "
    "das Unternehmensnetz liegen. Ein Dienst, über den sich jemand anmelden kann, wiegt "
    "schwerer als eine Abweichung an einer reinen Auslieferungsseite. Bei einem Vorfall mit "
    "personenbezogenen Daten gilt die Meldepflicht nach Art. 33 DSGVO innerhalb von "
    "72 Stunden."
)

# S6b-3 (spec/10 R13, Entscheidung E9): "Unternehmensnetz" nur, wenn ein System am eigenen
# Anschluss steht; bei gemieteten Servern im Rechenzentrum und Plattformen sind es die
# Zugangswege zu den Servern und Diensten.
BUSINESS_IMPLICATION_SERVER = (
    "Die Befunde dieses Berichts sind danach geordnet, wie nah sie an den Zugangswegen zu den "
    "betriebenen Servern und Diensten liegen. Ein Dienst, über den sich jemand anmelden kann, "
    "wiegt schwerer als eine Abweichung an einer reinen Auslieferungsseite. Bei einem Vorfall "
    "mit personenbezogenen Daten gilt die Meldepflicht nach Art. 33 DSGVO innerhalb von "
    "72 Stunden."
)


def business_implication(betriebsformen: list[str]) -> str:
    return BUSINESS_IMPLICATION_GENERIC if "anschluss" in betriebsformen else BUSINESS_IMPLICATION_SERVER


# ---------------------------------------------------------------- Kapitel 2

def scope_lead(c: Counts) -> str:
    """Einleitungssatz Kapitel 2; Einheit ist das System (Nachtrag 3, Entscheidung DC)."""
    gaps = c.coverage_partial + c.coverage_none
    systems = c.systems_total or c.hosts_total
    art, _ = _gap_kind(c)
    tail = (
        f" Für {gaps} {_plural(gaps, 'System', 'Systeme')} ({c.gap_addresses} "
        f"{_plural(c.gap_addresses, 'Adresse', 'Adressen')}) war die aktive Prüfung {art}; "
        f"{_plural(gaps, 'diese Lücke ist', 'diese Lücken sind')} unten benannt, damit die "
        "Ergebnisse nicht vollständiger wirken, als sie sind."
        if gaps else
        " Alle Systeme konnten aktiv geprüft werden."
    )
    # Der Einschub "davon m nur aus DNS oder ohne Antwort" schliesst mit Komma vor "und".
    einschub = "," if ", davon " in adressen(c) else ""
    return (
        f"Der Scan hat {systems} {_plural(systems, 'System', 'Systeme')} mit {adressen(c)}{einschub} "
        f"und {c.fqdns_total} {_plural(c.fqdns_total, 'Hostname', 'Hostnamen')} erfasst.{tail}"
    )


OUT_OF_SCOPE_BASE: list[str] = [
    "Interne Netzsegmente, Arbeitsplätze und mobile Geräte hinter der Firewall.",
    "Prüfungen mit Anmeldung (kein Login in Portale oder Verwaltungsoberflächen).",
    "Social Engineering, Phishing-Simulationen, physische Sicherheit.",
]

STANDARD_NOTE = (
    "Einordnung: automatisierte externe Schwachstellenanalyse, angelehnt an die Prüfphasen "
    "Aufklärung, Schwachstellenanalyse und Bericht. Kein Penetrationstest, keine Ausnutzung "
    "gefundener Schwachstellen, keine Prüfung mit Zugangsdaten."
)

AI_NOTE = (
    "Die Befunde dieses Berichts entstehen regelbasiert aus den Ausgaben der eingesetzten "
    "Werkzeuge: ein Prüfkatalog wertet die erhobenen Fakten aus, jede Einstufung folgt einer "
    "hinterlegten Regel. Ein Sprachmodell formuliert einzelne erläuternde Absätze und "
    "steuert im Scanner die Reihenfolge und die Konfiguration der Werkzeuge. Es entscheidet "
    "weder über Befunde noch über deren Einstufung."
)

CAN = [
    "erreichbare Dienste, Versionen und Konfigurationsschwächen aus Angreifersicht",
    "E-Mail- und DNS-Authentizität, Transportverschlüsselung, Sicherheits-Header",
    "bekannte Schwachstellenmuster ohne Anmeldung",
]
CANNOT = [
    "Schwachstellen hinter einer Anmeldung",
    "Versionsstände, die sich nicht in der Antwort eines Dienstes zeigen",
    "Fehlkonfigurationen im Inneren, Berechtigungen, Sicherungen, Notfallprozesse",
]
ADVICE = (
    "Für die Zugangs-Infrastruktur empfehlen wir ergänzend eine Konfigurationsprüfung mit "
    "administrativem Zugang."
)


def method_phases(c: Counts) -> list[tuple[str, str, str]]:
    return [
        ("0", "Aufklärung (passiv)",
         "Ermittlung der Hostnamen aus öffentlichen Quellen, DNS- und E-Mail-Einträge, "
         f"Reputationsdienste. Ergebnis: {c.fqdns_total} "
         f"{_plural(c.fqdns_total, 'Hostname', 'Hostnamen')} auf {adressen(c)}."
         + names_sentence(c)),
        ("1", "Technologie-Erkennung",
         "Portscan der häufigsten TCP-Ports mit Versionserkennung, Erkennung der "
         "Web-Technologien und vorgelagerter Schutzsysteme."),
        ("2", "Tiefenprüfung",
         "Analyse der Transportverschlüsselung, der Sicherheits-Header und der "
         "HTTP-Antworten je virtuellem Host, "
         + ("Verzeichnis-Enumeration und passive Webanalyse."
            if c.path_search_ok or not c.path_search_known else
            # S6b-4 (spec/11 T8): ohne belastbaren Lauf steht die Enumeration nicht als durchgeführt.
            "passive Webanalyse; die Suche nach nicht verlinkten Pfaden war nicht belastbar "
            "(siehe Einschränkungen).")),
        ("3", "Auswertung",
         "Zusammenführung über Werkzeuge und Durchgänge, Abgleich mit Fremdquellen zu "
         f"Schwachstellen, Auswertung des Prüfkatalogs. Ergebnis: {c.findings} "
         f"{_plural(c.findings, 'Befund', 'Befunde')} und {c.positives} positive "
         f"{_plural(c.positives, 'Feststellung', 'Feststellungen')}."),
    ]


def names_sentence(c: Counts) -> str:
    """S6b-3 (spec/10 R5): "n von m ermittelten Namen geprüft", solange die Hostsuche Namen verliert."""
    if c.names_found <= c.names_checked:
        return ""
    return (f" Geprüft wurden {c.names_checked} von {c.names_found} ermittelten Namen; die übrigen "
            "stehen in Kapitel 2 unter den Einschränkungen.")


def numbers(c: Counts) -> list[tuple[str, str]]:
    out = [
        (str(c.runs), _plural(c.runs, "Scandurchgang", "Scandurchgänge")),
        (str(c.tool_runs), _plural(c.tool_runs, "Werkzeuglauf", "Werkzeugläufe")),
    ]
    if c.raw_findings:
        out.append((str(c.raw_findings), _plural(c.raw_findings, "Einzelmeldung",
                                                 "Einzelmeldungen")))
    out.append((str(c.findings), _plural(c.findings, "Befund im Bericht", "Befunde im Bericht")))
    return out


# ---------------------------------------------------------------- Kapitel 3

def architecture_lead(systems: int, roles: list[str]) -> str:
    """Einleitung Kapitel 3, gezaehlt in Systemen wie Kapitel 2.1 (S6b-2)."""
    einheit = _plural(systems, "System", "Systeme")
    if roles:
        return (
            f"Die geprüfte Angriffsfläche verteilt sich auf {systems} {einheit} mit folgenden "
            f"Aufgaben: {_join(roles)}. Die Tabellen dieses Kapitels zeigen je Adresse die "
            "erkannte Software, die erreichbaren Dienste und den Stand der wichtigsten "
            "Schutzmaßnahmen."
        )
    return (
        f"Die geprüfte Angriffsfläche umfasst {systems} {einheit}. Die Tabellen dieses Kapitels "
        "zeigen je Adresse die erkannte Software, die erreichbaren Dienste und den Stand der "
        "wichtigsten Schutzmaßnahmen."
    )


# S6b-1 (spec/09 Teil 3): Legende nach Ampel. Die Farbe eines Ports ist die Ampel des
# schwersten Befunds, der ihn nennt (auch VHost-Befunde auf dem Webport); Blau hiess
# vorher "Altprotokoll" und stand auch an Webports mit niedrigem Befund.
SERVICES_NOTE = (
    "Farbe je Port nach Ampel des schwersten Befunds: Rot unverzüglich · Gelb in Kürze · "
    "Blau geplante Verbesserung · Grün: kein Befund · Grau: nur aus einer Passivquelle bekannt, ohne Befund."
)

SCREENS_LEAD = "Sichtprüfung der erreichbaren Web-Oberflächen der geprüften Hosts."


def reputation_line(clean: bool, sources: list[str], not_rated: list[str] | None = None,
                    reported: list[tuple[str, int]] | None = None) -> str:
    """S6b-3 (spec/10 R6): "keine Meldungen" nur, wenn alle gemessenen Adressen einschließlich
    der Plattform- und CDN-Adressen ohne Meldung sind; Adressen mit Meldungen stehen mit Zahl da.

    ``not_rated``: Adressen von Plattformen und Inhaltsnetzen (S6b-2, spec/09 Q12), die der
    Kunde mit anderen teilt; ``reported``: (Adresse, Zahl der AbuseIPDB-Meldungen)."""
    if not sources:
        return "Reputationsquellen wurden für diesen Auftrag nicht abgefragt."
    src = _join(sources)
    fremd = list(not_rated or [])
    if clean:
        text = f"Reputation: keine Meldungen zu den geprüften Adressen in {src}."
        if fremd:
            text += (" Das gilt auch für die Adressen von Plattformen und Inhaltsnetzen, die auch "
                     f"andere Kunden nutzen: {_join(fremd)}.")
        return text
    if reported:
        namen = _join([f"{ip} ({n} {_plural(n, 'Meldung', 'Meldungen')})" for ip, n in reported])
        text = f"Reputation: in AbuseIPDB liegen Meldungen zu {namen} vor."
    else:
        text = f"Reputation: zu mindestens einer der geprüften Adressen liegt in {src} eine Meldung vor."
    geteilt = [ip for ip, _ in (reported or []) if ip in fremd]
    if geteilt:
        text += (f" {_join(geteilt)} {_plural(len(geteilt), 'gehört', 'gehören')} zu einer Plattform "
                 "oder einem Inhaltsnetz, das auch andere Kunden nutzen; die Meldungen stammen nicht "
                 "zwingend aus Ihren Diensten.")
    return text


# ---------------------------------------------------------------- Befundlandschaft

def landscape_lead(c: Counts) -> str:
    # S6b-4 (spec/11 T10): die Zahl der Kategorien mit Befund, nicht immer fünf (LW: drei).
    return (
        f"{c.findings} {_plural(c.findings, 'Befund', 'Befunde')} in {c.categories} von 5 "
        "Kategorien. Die Kategorien entsprechen der Ampel auf Seite 2; die Reihenfolge folgt "
        "der Einstufung, nicht der Reihenfolge der Entdeckung."
    )


# ---------------------------------------------------------------- Maßnahmenplan

# S6b-2 (spec/09 Q6): der Effekt einer Planzeile kommt aus ``texts.plan.effect`` der Regel.
# Die Tabelle je Kategorie entfaellt; sie setzte "Schützt die Authentizität der eigenen
# E-Mail" auch an DNSSEC und CAA. Geblieben ist der Satz vor der ersten roten Zeile.
PLAN_EFFECT_TOP = "Beseitigt das dringlichste Risiko dieses Berichts"


# ---------------------------------------------------------------- Anhang

# S6b-4n (spec/11 N12): Herkunft der Doppelmeldungen je Grund der Korrelation.
DEDUP_QUELLEN = {"header-dedup": "der Webanalyse", "ssl-dedup": "der TLS-Prüfung"}


def _doppelt(c: Counts) -> str:
    """", davon 531 gleiche Meldungen der Webanalyse zusammengeführt" (spec/11 N12); vorher stand
    "Doppelmeldungen mehrerer Werkzeuge und Durchgänge" bei einem Durchgang und nur ZAP-Dubletten."""
    if not c.duplicates:
        return ""
    teile = [(n, DEDUP_QUELLEN.get(k.lower(), "der Werkzeuge")) for k, n in sorted(c.duplicates_by.items())]
    if not teile:
        teile = [(c.duplicates, "der Werkzeuge")]
    erste_n, erste_q = teile[0]
    text = f"{erste_n} gleiche {_plural(erste_n, 'Meldung', 'Meldungen')} {erste_q}"
    rest = [f"{n} {q}" for n, q in teile[1:]]
    if rest:
        text += " und " + " und ".join(rest)
    return f", davon {text} zusammengeführt"


def filtering(c: Counts) -> str:
    """Anhang D. S6b-3 (spec/10 R12, R14): Zahlen nur aus der Korrelationsbilanz, keine Zusage."""
    bilanz = ""
    if c.raw_findings:
        bilanz = (f"Die Korrelation hat {c.raw_findings} "
                  f"{_plural(c.raw_findings, 'Einzelmeldung', 'Einzelmeldungen')} der Werkzeuge erfasst"
                  + _doppelt(c) + ". ")
    return (
        f"{bilanz}Nach Zusammenführung gleicher Meldungen und Bündelung nach Sachverhalt "
        f"verbleiben {c.findings} {_plural(c.findings, 'Befund', 'Befunde')} und {c.positives} "
        f"positive {_plural(c.positives, 'Feststellung', 'Feststellungen')}. Beobachtungen ohne "
        "Regeltreffer erscheinen nicht als Befund. Grundlage sind die vollständigen "
        "Werkzeugausgaben."
    )


def repeat(c: Counts, has_red: bool, has_gaps: bool) -> list[str]:
    out: list[str] = []
    if has_red:
        out.append("Nachprüfung der Sofortmaßnahmen nach ihrer Umsetzung, gezielt auf die "
                   "betroffenen Dienste.")
    out.append("Wiederholung des Scans nach Abschluss der Maßnahmen der Stufe In Kürze, "
               "spätestens in zwölf Monaten.")
    out.append("Zusätzlich nach jeder größeren Änderung an der Zugangs-Infrastruktur und bei "
               "jedem Verdacht auf einen Vorfall.")
    if has_gaps:
        out.append("Freischaltung der Scanner-Adresse beim Betreiber der blockierenden Systeme, "
                   "damit die offenen Prüfungen im nächsten Durchgang nachgeholt werden können.")
    return out


def disclaimer(scan_date: str, provider: str) -> str:
    return (
        f"Dieser Bericht bildet den von außen sichtbaren Zustand der genannten Systeme am "
        f"{scan_date} ab. Er beruht auf automatisierten Prüfungen ohne Zugangsdaten und "
        "ersetzt weder einen manuellen Penetrationstest noch eine Konfigurationsprüfung mit "
        "administrativen Rechten. Bereits am Folgetag können neue Schwachstellen bekannt "
        "werden oder Konfigurationen sich ändern. Aussagen aus Passivquellen sind als solche "
        f"gekennzeichnet und nicht durch eine eigene Messung bestätigt. Die {provider} "
        "übernimmt keine Gewähr dafür, dass jede vorhandene Schwäche erfasst wurde; die "
        "Umsetzung der Empfehlungen liegt in der Verantwortung des Auftraggebers und seiner "
        "Dienstleister. Der Bericht ist vertraulich und ausschließlich für den Auftraggeber "
        "bestimmt."
    )
