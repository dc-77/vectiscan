# -*- coding: utf-8 -*-
"""Die wenigen Kundensaetze, die dem Renderer gehoeren.

Alles Fachliche steht in ``reporter/v3/narrative.py`` und im Pruefkatalog. Hier stehen
nur Saetze, die von einer *Darstellungs*entscheidung abhaengen und deshalb erst beim
Rendern entstehen koennen: der Prueflaufhinweis (Anzahl der Durchgaenge), die Aufteilung
von Kapitel 6 auf Hauptteil und Anhang, die Verteilungszeile der Zusammenfassung und die
Beschriftung fehlender Bildnachweise.

Sie laufen durch denselben Textlint wie der Katalog (tests/pdf_v3/test_template_text.py):
echte Umlaute, keine Gedankenstriche, Sie-Form, keine Zusagen.
"""
from __future__ import annotations

# Zahlwoerter bis zwoelf; darueber ist die Ziffer lesbarer als das Wort.
_ZAHLWORT: dict[int, str] = {
    1: "Ein", 2: "Zwei", 3: "Drei", 4: "Vier", 5: "Fünf", 6: "Sechs",
    7: "Sieben", 8: "Acht", 9: "Neun", 10: "Zehn", 11: "Elf", 12: "Zwölf",
}


def zahlwort(n: int) -> str:
    return _ZAHLWORT.get(n, str(n))


def runs_line(hosts_total: int, fqdns_total: int, runs: int) -> str:
    """Zeile unter den Domains auf dem Deckblatt.

    S6 (spec/08 Punkt 19): Auf dem Deckblatt eines Auftrags mit einem Host stand
    "1 IP-Adressen, 3 Hostnamen".
    """
    adressen = "IP-Adresse" if hosts_total == 1 else "IP-Adressen"
    namen = "Hostname" if fqdns_total == 1 else "Hostnamen"
    lauf = "Scandurchgang" if runs == 1 else "Scandurchgänge"
    return (f"{hosts_total} {adressen}, {fqdns_total} {namen}, "
            f"{zahlwort(runs).lower()} {lauf}")


def period_note(scan_window: str, runs: int) -> str:
    """Prueflaufhinweis in Kapitel 2.1.

    Ersetzt den fest verdrahteten Junkerwerk-Satz des Prototyps. Bei einem einzelnen
    Durchgang entfaellt der Konsolidierungshinweis, weil es nichts zu konsolidieren gibt.
    """
    if runs <= 1:
        return f"{scan_window}."
    return (f"{scan_window}. {zahlwort(runs)} Durchgänge wurden zu einem Ergebnis "
            "konsolidiert; abweichende Einzelmeldungen sind gegen die Rohdaten "
            "entschieden.")


def distribution_line(total: int, counts: list[tuple[str, int]]) -> str:
    """Gesamtzahl und Verteilung nach Dringlichkeit, Kapitel 1.

    Steht immer im Bericht, auch wenn Kapitel 6 nicht aufgeteilt wird: die Gesamtzahl
    darf nicht von einer Darstellungsregel abhaengen.
    """
    if not total:
        return ("Kein Befund. Kapitel 4 zeigt die geprüften Kategorien, Anhang A.2 die "
                "verwendeten Einstufungen.")
    # Nur den ersten Buchstaben kleinschreiben: aus "In Kürze" wird "in Kürze",
    # aus "Unverzüglich" wird "unverzüglich". label.lower() wuerde das Substantiv
    # mit kleinschreiben.
    teile = ", ".join(f"{n} {label[:1].lower()}{label[1:]}" for label, n in counts if n)
    wort = "Befund" if total == 1 else "Befunde"
    return (f"{total} {wort} insgesamt: {teile}. Kapitel 4 listet alle Befunde, "
            "Anhang A.2 zusätzlich mit Einstufung.")


def excluded_note(ids: list[str]) -> str:
    """Satz zu den Befunden, die der Admin auf Wunsch des Auftraggebers ausgeschlossen hat.

    Issue #28 Punkt 4: die uebrigen Befunde behalten ihre Nummer, die Folge hat an den
    ausgeschlossenen Stellen Luecken. Ohne diesen Satz waere die Luecke unerklaert.
    """
    if not ids:
        return ""
    liste = ", ".join(ids)
    if len(ids) == 1:
        return (f"Auf Wunsch des Auftraggebers ist ein Befund nicht aufgeführt ({liste}); "
                "die übrigen Befunde behalten ihre Nummer.")
    return (f"Auf Wunsch des Auftraggebers sind {len(ids)} Befunde nicht aufgeführt ({liste}); "
            "die übrigen Befunde behalten ihre Nummer.")


def split_note(main_n: int, more_n: int, total: int) -> str:
    """Hinweis im Kopf von Kapitel 6, wenn der Anhang gebraucht wird."""
    return (f"Dieses Kapitel zeigt die {main_n} dringendsten der {total} Befunde. Die "
            f"übrigen {more_n} stehen mit denselben Angaben im Anhang zu diesem "
            "Kapitel; weggelassen wird keiner.")


MORE_TITLE = "Weitere Sachverhalte"
MORE_KICKER = "Anhang zu Kapitel 6"
MORE_LEAD = ("Diese Befunde tragen dieselben Angaben wie die in Kapitel 6. Sie stehen "
             "hier, weil der Hauptteil nach Dringlichkeit begrenzt ist, nicht weil sie "
             "weniger belegt oder weniger wichtig wären.")

TOOL_FINDINGS_TITLE = "Werkzeugmeldungen ohne eigene Einstufung"
TOOL_FINDINGS_LEAD = ("Meldungen der eingesetzten Werkzeuge, für die der Prüfkatalog "
                      "keine eigene Einstufung vergibt. Sie stehen hier zur Einsicht "
                      "und sind nicht in die Bewertung eingeflossen.")

SCREENSHOT_MISSING = "Bildnachweis nicht verfügbar"
