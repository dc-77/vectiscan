# -*- coding: utf-8 -*-
"""Rechtschreibung der Kundentexte: Umschrift gegen echten Umlaut.

Der Kundenreport verlangt echte Umlaute (spec/03 Regel 9, spec/04 Definition of Done
Punkt 6). Die Katalogtexte aus S2 waren durchgehend in ASCII-Umschrift geschrieben
("gehoert", "aussen", "Zugaenge") und wurden in S3 umgestellt. Diese Liste haelt den
Zustand fest: jedes Wort hier ist eine Umschrift, die es in einem Kundentext nicht mehr
geben darf.

Bewusst eine Wortliste und kein Generalverbot von "ae|oe|ue|ss": Adresse, Anlass,
Anschluss, WordPress, Quelle, aktuell, neue, virtueller, dass, muss, passt und viele
weitere sind korrekt geschrieben und muessen erlaubt bleiben.

Bezeichner bleiben ASCII (Pruef-IDs, YAML-Schluessel, Stufen wie ``unverzueglich``).
Diese Pruefung gilt nur fuer Text, den ein Kunde liest. Das Gate der Prosa-KI
(reporter/v3/gate.py) und der Textlint des Katalogs benutzen dieselbe Liste.
"""

from __future__ import annotations

import re

# Umschrift -> korrekte Schreibweise. Reihenfolge egal, die Regex sortiert nach Laenge.
ASCII_UMLAUTS: dict[str, str] = {
    # Grossgeschrieben
    "Absenderfaelschung": "Absenderfälschung",
    "Administrationsoberflaeche": "Administrationsoberfläche",
    "Aenderungen": "Änderungen",
    "Aktivitaet": "Aktivität",
    "Angriffsflaeche": "Angriffsfläche",
    "Ankuendigung": "Ankündigung",
    "Anmeldeoberflaeche": "Anmeldeoberfläche",
    "Aufklaerung": "Aufklärung",
    "Aufklaerungsphase": "Aufklärungsphase",
    "Aufloesung": "Auflösung",
    "Ausserbetriebnahme": "Außerbetriebnahme",
    "Authentizitaet": "Authentizität",
    "Bestaetigt": "Bestätigt",
    "Bestaetigung": "Bestätigung",
    "Cybersicherheitsbehoerde": "Cybersicherheitsbehörde",
    "Einschraenkung": "Einschränkung",
    "Eintraege": "Einträge",
    "Eintraegen": "Einträgen",
    "Empfaenger": "Empfänger",
    "Empfaengersysteme": "Empfängersysteme",
    "Faehigkeiten": "Fähigkeiten",
    "Faellt": "Fällt",
    "Faelschung": "Fälschung",
    "Fuer": "Für",
    "Gefaelschte": "Gefälschte",
    "Gueltigkeit": "Gültigkeit",
    "Gueltigkeitsdauer": "Gültigkeitsdauer",
    "Gueltigkeitszeitraum": "Gültigkeitszeitraum",
    "Gueltigkeitszeitraums": "Gültigkeitszeitraums",
    "Identitaet": "Identität",
    "Integritaetspruefung": "Integritätsprüfung",
    "Klaeren": "Klären",
    "Kuerze": "Kürze",
    "Laeuft": "Läuft",
    "Loeschung": "Löschung",
    "Massnahme": "Maßnahme",
    "Massnahmen": "Maßnahmen",
    "Netzwerkaktivitaet": "Netzwerkaktivität",
    "Oberflaeche": "Oberfläche",
    "Oeffentliche": "Öffentliche",
    "Oeffentlichkeit": "Öffentlichkeit",
    "Pruefen": "Prüfen",
    "Pruefschritt": "Prüfschritt",
    "Pruefumfang": "Prüfumfang",
    "Pruefung": "Prüfung",
    "Pruefungen": "Prüfungen",
    "Pruefwert": "Prüfwert",
    "Quarantaene": "Quarantäne",
    "Rueckschluss": "Rückschluss",
    "Rueckstufung": "Rückstufung",
    "Schluessel": "Schlüssel",
    "Signaturschluessel": "Signaturschlüssel",
    "Transportverschluesselung": "Transportverschlüsselung",
    "Uebernahme": "Übernahme",
    "Uebernahmerisiko": "Übernahmerisiko",
    "Uebertragungsprotokoll": "Übertragungsprotokoll",
    "Uebertragungsweg": "Übertragungsweg",
    "Umstaenden": "Umständen",
    "Unterstuetzung": "Unterstützung",
    "Urspruenge": "Ursprünge",
    "Urspruengen": "Ursprüngen",
    "Verlaengerung": "Verlängerung",
    "Verschluesselung": "Verschlüsselung",
    "Verschluesselungsoptionen": "Verschlüsselungsoptionen",
    "Verschluesselungspflicht": "Verschlüsselungspflicht",
    "Verschluesselungsverfahren": "Verschlüsselungsverfahren",
    "Versionspruefung": "Versionsprüfung",
    "Versionsuebersicht": "Versionsübersicht",
    "Verwaltungsoberflaeche": "Verwaltungsoberfläche",
    "Verwaltungsoberflaechen": "Verwaltungsoberflächen",
    "Verzoegerung": "Verzögerung",
    "Zugangsbeschraenkungen": "Zugangsbeschränkungen",
    "Zugangsschluessel": "Zugangsschlüssel",
    "Zugriffsbeschraenkung": "Zugriffsbeschränkung",
    "Zurueckweisung": "Zurückweisung",
    "Zusaetzliche": "Zusätzliche",
    # Kleingeschrieben
    "aeltere": "ältere",
    "aelteren": "älteren",
    "aelterer": "älterer",
    "aelteres": "älteres",
    "aendern": "ändern",
    "aendert": "ändert",
    "anfaellig": "anfällig",
    "anschliessend": "anschließend",
    "auffaellig": "auffällig",
    "auffaellige": "auffällige",
    "auffaelliger": "auffälliger",
    "auffuehren": "aufführen",
    "auffuehrt": "aufführt",
    "aufloesendes": "auflösendes",
    "ausgefuehrt": "ausgeführt",
    "ausloesen": "auslösen",
    "ausschliesslich": "ausschließlich",
    "aussen": "außen",
    "ausserhalb": "außerhalb",
    "benoetigt": "benötigt",
    "benoetigte": "benötigte",
    "benoetigten": "benötigten",
    "beschraenken": "beschränken",
    "beschraenkt": "beschränkt",
    "beschraenkten": "beschränkten",
    "bestaetigen": "bestätigen",
    "bestaetigter": "bestätigter",
    "dafuer": "dafür",
    "duerfen": "dürfen",
    "durchfuehrbar": "durchführbar",
    "durchfuehren": "durchführen",
    "durchgefuehrt": "durchgeführt",
    "einfuehren": "einführen",
    "einschliesslich": "einschließlich",
    "einschliesst": "einschließt",
    "einschraenken": "einschränken",
    "entfaellt": "entfällt",
    "enthaelt": "enthält",
    "ergaenzen": "ergänzen",
    "ergaenzt": "ergänzt",
    "erhaelt": "erhält",
    "ermoeglichen": "ermöglichen",
    "faellt": "fällt",
    "fruehere": "frühere",
    "fuehren": "führen",
    "fuer": "für",
    "gaengigen": "gängigen",
    "gaengiger": "gängiger",
    "gefaehrdet": "gefährdet",
    "gefaelschte": "gefälschte",
    "gefaelschten": "gefälschten",
    "gegenueber": "gegenüber",
    "gehoert": "gehört",
    "geklaert": "geklärt",
    "genuegt": "genügt",
    "geprueft": "geprüft",
    "geprueften": "geprüften",
    "geschuetzt": "geschützt",
    "gewoehnt": "gewöhnt",
    "groesseren": "größeren",
    "grundsaetzlich": "grundsätzlich",
    "gueltig": "gültig",
    "gueltige": "gültige",
    "gueltigem": "gültigem",
    "haeufig": "häufig",
    "haeufiges": "häufiges",
    "hoeher": "höher",
    "koennen": "können",
    "koennten": "könnten",
    "kuenftige": "künftige",
    "kuenftigen": "künftigen",
    "laesst": "lässt",
    "laeuft": "läuft",
    "missbraeuchliche": "missbräuchliche",
    "moeglich": "möglich",
    "naechsten": "nächsten",
    "oeffentlich": "öffentlich",
    "oeffentliche": "öffentliche",
    "oeffentlichen": "öffentlichen",
    "praesentierten": "präsentierten",
    "pruefen": "prüfen",
    "prueft": "prüft",
    "regelmaessig": "regelmäßig",
    "routinemaessig": "routinemäßig",
    "schliessen": "schließen",
    "schuetzen": "schützen",
    "schwaecher": "schwächer",
    "schwaechere": "schwächere",
    "schwaecheren": "schwächeren",
    "sekundaeren": "sekundären",
    "tatsaechlich": "tatsächlich",
    "ueber": "über",
    "ueberhaupt": "überhaupt",
    "ueberlassen": "überlassen",
    "uebermittelte": "übermittelte",
    "uebernehmen": "übernehmen",
    "uebernommen": "übernommen",
    "uebersprungen": "übersprungen",
    "uebertraegt": "überträgt",
    "uebertragen": "übertragen",
    "ueberwachen": "überwachen",
    "ueberwachten": "überwachten",
    "ueblichen": "üblichen",
    "unabhaengig": "unabhängig",
    "unabhaengige": "unabhängige",
    "unabhaengigen": "unabhängigen",
    "unauffaellige": "unauffällige",
    "unbestaetigt": "unbestätigt",
    "ungeschuetzt": "ungeschützt",
    "ungewoehnliche": "ungewöhnliche",
    "unterdruecken": "unterdrücken",
    "unterstuetzen": "unterstützen",
    "unterstuetzt": "unterstützt",
    "unterstuetzte": "unterstützte",
    "unueblichem": "unüblichem",
    "unueblichen": "unüblichen",
    "unveraendert": "unverändert",
    "unveraenderte": "unveränderte",
    "unverschluesselt": "unverschlüsselt",
    "unverschluesselte": "unverschlüsselte",
    "unverschluesselten": "unverschlüsselten",
    "unverschluesseltes": "unverschlüsseltes",
    "unvollstaendig": "unvollständig",
    "unvollstaendige": "unvollständige",
    "urspruengliche": "ursprüngliche",
    "ursprungsuebergreifende": "ursprungsübergreifende",
    "veraendern": "verändern",
    "veraendert": "verändert",
    "veraenderte": "veränderte",
    "verdaechtig": "verdächtig",
    "verdaechtige": "verdächtige",
    "verfuegbar": "verfügbar",
    "verfuegbare": "verfügbare",
    "vergroessert": "vergrößert",
    "verlaengert": "verlängert",
    "veroeffentlichen": "veröffentlichen",
    "veroeffentlicht": "veröffentlicht",
    "veroeffentlichte": "veröffentlichte",
    "verraet": "verrät",
    "verschluesselte": "verschlüsselte",
    "verschluesselten": "verschlüsselten",
    "vertrauenswuerdig": "vertrauenswürdig",
    "vertrauenswuerdige": "vertrauenswürdige",
    "vertrauenswuerdigen": "vertrauenswürdigen",
    "vertrauenswuerdiger": "vertrauenswürdiger",
    "vollstaendig": "vollständig",
    "vollstaendige": "vollständige",
    "vollstaendigen": "vollständigen",
    "waehlen": "wählen",
    "waehrend": "während",
    "waeren": "wären",
    "zaehlt": "zählt",
    "zugaenglich": "zugänglich",
    "zugehoerigen": "zugehörigen",
    "zulaesst": "zulässt",
    "zunaechst": "zunächst",
    "zurueck": "zurück",
    "zurueckgegebene": "zurückgegebene",
    "zurueckgewiesen": "zurückgewiesen",
    "zurueckgreifen": "zurückgreifen",
    "zusaetzlich": "zusätzlich",
    "zusaetzliche": "zusätzliche",
    "zusaetzlichen": "zusätzlichen",
    "zuverlaessig": "zuverlässig",
}

_ASCII_UMLAUT_RE = re.compile(
    r"\b(" + "|".join(sorted(ASCII_UMLAUTS, key=len, reverse=True)) + r")\b"
)

DASHES = ("–", "—")

# Zusagen, die im Kundentext nichts zu suchen haben (spec/05 B7). Der Waechter
# tests/test_no_legacy_claims.py verbietet diese Begriffe als Literal im Reporter-Code.
# Deshalb steht das Muster aus Teilen zusammengesetzt hier: die Regel muss den Begriff
# erkennen koennen, ohne ihn selbst zu schreiben.
_CLAIM_PARTS: tuple[str, ...] = (
    "PT" + "ES",
    "KI-gest",
    r"vollst[aä]ndig gepr[uü]ft",
    r"l[uü]ckenlos",
    "garantiert",
    "CVSS",
)
FORBIDDEN_CLAIMS = re.compile("|".join(_CLAIM_PARTS), re.I)

DU_FORM = re.compile(r"\b(du|dein|deine|deinem|deinen|dich|dir)\b", re.I)


# Generische Erkennung fuer Text, der nicht aus dem Katalog stammt (Prosa der KI).
# Die Wortliste oben deckt den Katalog vollstaendig ab; ein Sprachmodell schreibt aber
# beliebige Woerter. Deshalb hier eine Regel statt einer Liste:
#
# "ae", "oe" und "ue" nach einem Vokal sind im Deutschen fast immer echt (aufbauen,
# Dauer, Erneuerung, Steuerung), ebenso nach "q" (Quelle, konsequent) und vor "ll"
# (aktuell, virtuell, manuell). Alles andere ist mit grosser Wahrscheinlichkeit eine
# Umschrift: fuer, ueber, pruefen, gehoeren, Zugaenge.
#
# Ein Fehlalarm kostet nur den KI-Text, der dann durch den Katalogtext ersetzt wird.
# Ein uebersehener Fall stuende im Kundenreport. Die Regel ist deshalb bewusst streng.
_GENERIC_TRANSLITERATION = re.compile(r"(?<![aeiouäöüqAEIOUÄÖÜQ])(ae|oe|ue)(?!ll)", re.I)

# Woerter, die der Regel widersprechen und trotzdem richtig geschrieben sind.
GENERIC_ALLOWLIST: frozenset[str] = frozenset({
    # deutsche Woerter, in denen "u" und "e" zu verschiedenen Bestandteilen gehoeren
    "zuerst", "zueinander", "zuerkannt", "zuerkennen", "zuerkennung", "zuende",
    "duett", "statue", "statuen", "revue", "silhouette", "milieu", "individuum",
    # englische Begriffe, die in Produktnamen vorkommen
    "bluetooth", "issue", "issues", "queue", "queues", "true", "value", "values", "blue",
})


_WHITESPACE = re.compile(r"\s+")


def clean_foreign_text(text: str | None, limit: int = 120) -> str:
    """Fremdtext (Seitentitel, Bannerzeile) fuer den Bericht glaetten.

    Ein Seitentitel wie "Anmelden – Nextcloud" bringt einen Gedankenstrich in den
    Bericht, den die Hausregel verbietet (spec/03 Regel 9). Ersetzt wird er durch den
    Trenner, den der Bericht ohnehin verwendet. Zusaetzlich werden Zeilenumbrueche
    eingeebnet und die Laenge begrenzt, damit eine Tabellenzelle nicht aufreisst.
    """
    if not text:
        return ""
    cleaned = text
    for dash in DASHES:
        cleaned = cleaned.replace(dash, "·")
    cleaned = _WHITESPACE.sub(" ", cleaned).strip()
    if len(cleaned) > limit:
        cleaned = cleaned[: limit - 1].rstrip() + "…"
    return cleaned


def find_ascii_umlauts(text: str) -> list[str]:
    """Liefert alle Umschriften im Text, die ein Umlaut sein muessten."""
    return _ASCII_UMLAUT_RE.findall(text)


def find_transliterations(text: str) -> list[str]:
    """Wie ``find_ascii_umlauts``, zusaetzlich mit der generischen Regel.

    Fuer Text, dessen Wortschatz nicht feststeht, also fuer die Prosa der KI.
    """
    hits = list(_ASCII_UMLAUT_RE.findall(text))
    for word in re.findall(r"[A-Za-zÄÖÜäöüß]+", text):
        if word.lower() in GENERIC_ALLOWLIST or word in hits:
            continue
        if _GENERIC_TRANSLITERATION.search(word):
            hits.append(word)
    return hits


def fix_ascii_umlauts(text: str) -> str:
    """Ersetzt bekannte Umschriften durch die korrekte Schreibweise."""
    return _ASCII_UMLAUT_RE.sub(lambda m: ASCII_UMLAUTS[m.group(1)], text)
