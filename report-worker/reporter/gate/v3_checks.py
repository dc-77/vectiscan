# -*- coding: utf-8 -*-
"""Die vier Gate-Pruefungen aus S5, die ueber das Datenmodell hinausgehen.

``reporter/v3/selfcheck`` prueft Eigenschaften der Reportdaten allein. Die
Pruefungen hier brauchen zusaetzlich die Fakten oder das Katalogergebnis und
stehen deshalb hier, nicht dort. ``reporter/catalog``, ``reporter/facts`` und
``reporter/pdf`` werden dabei nur gelesen.
"""
from __future__ import annotations

import re
from typing import Any, Iterable, Optional

from reporter.gate.defects import ENGINE_V3, SEVERITY_ERROR, SEVERITY_WARNING, Defect

# Zielwert aus spec/06: unter fuenf Beobachtungen ohne Regel je Auftrag. Die
# Zaehlung selbst macht der Katalog (CatalogOutput.summary.unprocessed), hier
# steht nur die Schwelle. tests/catalog/test_snapshot_orders.py liest sie von
# hier, damit es die Zahl nicht ein zweites Mal gibt.
UNPROCESSED_WARN_THRESHOLD = 5

# Platzhalter aus reporter/v3/report_data.py, wenn kein Firmenname bekannt ist.
CUSTOMER_PLACEHOLDER = "Auftraggeber"

_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b")
_VERSION = r"v?(\d+(?:\.\d+)*)"
_NUMBER = re.compile(r"\d+")

# Woerter, die ein Produkt nicht unterscheidbar machen. Aus "Exchange Server"
# wird damit "Exchange", aus "nginx" bleibt "nginx".
_GENERIC = {"server", "service", "http", "https", "web", "linux", "windows",
            "core", "system", "edition", "open", "daemon", "gateway"}


# ---------------------------------------------------------------- Hilfen

def _components(value: str) -> tuple[int, ...]:
    """Fuehrende Zahlenbestandteile einer Version, etwa "8.4p1" -> (8, 4)."""
    parts: list[int] = []
    for chunk in value.split("."):
        match = _NUMBER.match(chunk)
        if not match:
            break
        parts.append(int(match.group(0)))
    return tuple(parts)


def _compatible(cited: str, known: Iterable[str]) -> bool:
    """Passt eine zitierte Version zu einer der bekannten Versionen?

    Verglichen wird komponentenweise und nur so weit, wie beide Seiten reichen.
    "8.4" passt zu "8.4p1", "15.2" passt zu "15.2.2562", "2016" passt zu keinem
    der beiden.
    """
    left = _components(cited)
    if not left:
        return True
    for candidate in known:
        right = _components(candidate)
        if not right:
            continue
        depth = min(len(left), len(right))
        if left[:depth] == right[:depth]:
            return True
    return False


def _needles(product: str) -> list[str]:
    """Namen, unter denen ein Produkt im Befundtext auftauchen kann."""
    product = (product or "").strip()
    if not product:
        return []
    names = [product]
    teile = re.split(r"[\s/_-]+", product)
    tokens = [t for t in teile if len(t) >= 4]
    distinctive = [t for t in tokens if t.lower() not in _GENERIC]
    # Der letzte unterscheidende Teil ist der Produktname, der erste meist der
    # Hersteller: aus "Microsoft Exchange" wird "Exchange". Faellt der Rueckgriff
    # auf das erste Wort zurueck ("Microsoft IIS" -> "Microsoft", "Apache HTTP
    # Server" -> "Apache"), bleibt es beim vollen Namen: ein zu allgemeiner Name
    # wuerde fremde Versionen einsammeln und den Bericht grundlos blockieren.
    if distinctive and distinctive[-1].lower() not in (product.lower(), teile[0].lower()):
        names.append(distinctive[-1])
    return names


def _software_by_host(facts: Any) -> dict[str, dict[str, tuple[str, set[str]]]]:
    """Je Host und Produkt die Versionen, die die Tech-Tabelle zeigt.

    Der Produktname ist der Schluessel, klein geschrieben: derselbe Bestandteil
    wird von mehreren Werkzeugen unterschiedlich geschrieben ("BeTheme" aus
    webtech, "betheme" aus wpscan) und steht dann mit beiden Versionen in der
    Tabelle. Beide sind belegt, also widerspricht keine von beiden.
    """
    index: dict[str, dict[str, tuple[str, set[str]]]] = {}
    for sw in list(getattr(facts, "software", []) or []):
        versions = {v for v in (sw.version_norm, sw.build) if v}
        if not versions:
            continue  # "unbekannt" behauptet nichts und widerspricht nichts
        produkte = index.setdefault(sw.host_ip, {})
        name, bekannt = produkte.get(sw.product.lower(), (sw.product, set()))
        produkte[sw.product.lower()] = (name, bekannt | versions)
    return index


def _host_vor(pos: int, hosts: list[tuple[int, str]]) -> Optional[str]:
    """Die IP, zu der eine Fundstelle gehoert: die letzte davor im Text.

    Eine Betroffenenliste nennt mehrere Hosts mit je eigener Version
    ("1.2.3.4:22 (OpenSSH 9.6p1), 5.6.7.8:22 (OpenSSH 10.0p2)"). Ohne diese
    Zuordnung wuerde jede Version gegen jeden Host geprueft.
    """
    treffer = None
    for start, ip in hosts:
        if start > pos:
            break
        treffer = ip
    if treffer is not None:
        return treffer
    # Produkt und Version stehen im Titel, der Host erst in der
    # Betroffenenliste. Eindeutig ist das nur bei genau einem Host; bei mehreren
    # bleibt die Zuordnung offen und es wird nichts gemeldet.
    eindeutig = {ip for _start, ip in hosts}
    return eindeutig.pop() if len(eindeutig) == 1 else None


# ---------------------------------------------------------------- Pruefungen

def unprocessed_ueber_schwelle(output: Any) -> list[Defect]:
    """Mehr als fuenf Beobachtungen ohne Regel: Warnung, kein Fehler."""
    total = int(getattr(getattr(output, "summary", None), "unprocessed", 0) or 0)
    if total <= UNPROCESSED_WARN_THRESHOLD:
        return []
    return [Defect(
        engine=ENGINE_V3,
        check="unprocessed_ueber_schwelle",
        severity=SEVERITY_WARNING,
        message=(f"{total} Beobachtungen ohne Regel, Zielwert ist "
                 f"{UNPROCESSED_WARN_THRESHOLD}. Bitte im Review pruefen, ob daraus "
                 "Pruefungen werden."),
        detail={"unprocessed": total, "schwelle": UNPROCESSED_WARN_THRESHOLD},
    )]


def tech_widerspricht_befund(data: Any, facts: Any) -> list[Defect]:
    """Nennt ein Befund eine andere Version als die Tech-Zeile desselben Hosts?

    Das ist der Exchange-Fall aus spec/05 B4: Tabelle "Exchange SE, Build
    15.2.2562", Befund "Exchange 2016 EOL". Geprueft werden Titel und
    Betroffenenliste; Empfehlungen bleiben aussen vor, weil dort absichtlich
    Zielversionen stehen.
    """
    index = _software_by_host(facts)
    if not index:
        return []
    needles: dict[str, str] = {}
    for produkte in index.values():
        for key, (name, _versions) in produkte.items():
            for needle in _needles(name):
                needles[needle.lower()] = key

    defects: list[Defect] = []
    for finding in list(getattr(data, "findings", []) or []):
        text = f"{finding.title} {finding.affected}"
        hosts = [(m.start(), m.group(0)) for m in _IP.finditer(text)]
        if not hosts:
            continue
        gemeldet: set[tuple[str, str]] = set()
        for needle, key in sorted(needles.items()):
            for match in re.finditer(re.escape(needle) + r"[\s,]+" + _VERSION, text,
                                     re.IGNORECASE):
                host_ip = _host_vor(match.start(), hosts)
                if host_ip is None or host_ip not in index:
                    continue
                eintrag = index[host_ip].get(key)
                if eintrag is None:
                    continue
                name, versions = eintrag
                cited = match.group(1)
                if _compatible(cited, versions) or (host_ip, key) in gemeldet:
                    continue
                gemeldet.add((host_ip, key))
                defects.append(Defect(
                    engine=ENGINE_V3,
                    check="tech_widerspricht_befund",
                    severity=SEVERITY_ERROR,
                    message=(f"{finding.id}: Befund nennt {name} {cited}, die "
                             f"Tech-Tabelle fuer {host_ip} nennt "
                             f"{', '.join(sorted(versions))}."),
                    finding_id=finding.id,
                    detail={"host_ip": host_ip, "produkt": name,
                            "befund": cited, "tabelle": sorted(versions)},
                ))
    return defects


def abdeckungskapitel_leer(data: Any) -> list[Defect]:
    """Kapitel 2 ohne eine einzige Abdeckungsangabe.

    Ohne ``scan_results``-Zeilen bleibt die Abdeckung fuer jeden Host leer. Der
    Bericht behauptet dann implizit eine vollstaendige Pruefung. Der Fall "gar
    keine Hosts" steht schon im Selbstcheck und wird hier nicht wiederholt.
    """
    hosts = list(getattr(getattr(data, "scope", None), "hosts", []) or [])
    if not hosts or any((h.coverage or "").strip() for h in hosts):
        return []
    return [Defect(
        engine=ENGINE_V3,
        check="abdeckungskapitel_leer",
        severity=SEVERITY_ERROR,
        message=("Kapitel 2 nennt fuer keinen Host eine Abdeckung. Ohne die "
                 "Werkzeuglaeufe aus scan_results ist der Umfang unbelegt."),
        detail={"hosts": len(hosts)},
    )]


def auftraggeber_fehlt(data: Any) -> list[Defect]:
    """Kein Firmenname im Kundenkontext: Warnung, der Bericht bleibt lesbar."""
    customer = str(getattr(getattr(data, "meta", None), "customer", "") or "")
    if customer and customer != CUSTOMER_PLACEHOLDER:
        return []
    return [Defect(
        engine=ENGINE_V3,
        check="auftraggeber_fehlt",
        severity=SEVERITY_WARNING,
        message=("Der Bericht nennt den Auftraggeber generisch. Firmenname im "
                 "Kundenkontext nachtragen (Reiter Kunde im Admin-Review)."),
    )]


def run_all(data: Any, facts: Any, output: Any) -> list[Defect]:
    """Alle vier Pruefungen in fester Reihenfolge."""
    defects: list[Defect] = []
    defects.extend(abdeckungskapitel_leer(data))
    defects.extend(tech_widerspricht_befund(data, facts))
    defects.extend(unprocessed_ueber_schwelle(output))
    defects.extend(auftraggeber_fehlt(data))
    return defects
