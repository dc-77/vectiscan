# -*- coding: utf-8 -*-
"""Die Gate-Pruefungen, die ueber das Datenmodell hinausgehen.

``reporter/v3/selfcheck`` prueft Eigenschaften der Reportdaten allein. Die
Pruefungen hier brauchen zusaetzlich die Fakten oder das Katalogergebnis und
stehen deshalb hier, nicht dort. ``reporter/catalog``, ``reporter/facts`` und
``reporter/pdf`` werden dabei nur gelesen.
"""
from __future__ import annotations

import re
from typing import Any, Iterable, Optional

from reporter.gate.defects import ENGINE_V3, SEVERITY_ERROR, SEVERITY_WARNING, Defect
from reporter.v3.report_data import DEFAULT_CUSTOMER as CUSTOMER_PLACEHOLDER

# Zielwert aus spec/06: unter fuenf Beobachtungen ohne Regel je Auftrag. Die
# Zaehlung selbst macht der Katalog (CatalogOutput.summary.unprocessed), hier
# steht nur die Schwelle. tests/catalog/test_snapshot_orders.py liest sie von
# hier, damit es die Zahl nicht ein zweites Mal gibt.
UNPROCESSED_WARN_THRESHOLD = 5

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


def auftraggeber_fehlt(data: Any, *, strict: bool = False) -> list[Defect]:
    """Kein Firmenname im Kundenkontext.

    Bis S6 eine Warnung, weil der Bericht auch ohne Namen lesbar ist. Der
    WebCheck-Bericht 75338c97 trug deshalb 39-mal "Auftraggeber" auf dem
    Deckblatt, in jeder Kopf- und jeder Fusszeile und ging mit 0 Fehlern durch
    das Gate (spec/08 Punkt 8). Im strict-Modus ist das jetzt ein Fehler: ein
    Bericht ohne Auftraggeber wird nicht ausgeliefert, der Rueckweg ist das
    Kundenkontext-Feld im Admin.
    """
    customer = str(getattr(getattr(data, "meta", None), "customer", "") or "")
    if customer and customer != CUSTOMER_PLACEHOLDER:
        return []
    return [Defect(
        engine=ENGINE_V3,
        check="auftraggeber_fehlt",
        severity=SEVERITY_ERROR if strict else SEVERITY_WARNING,
        message=("Der Bericht nennt den Auftraggeber generisch. Firmenname im "
                 "Kundenkontext nachtragen (Reiter Kunde im Admin-Review)."),
    )]


# Zustaende einer Abdeckungszeile, die kein Ergebnis bedeuten. ``skipped`` steht
# nicht darin: ein uebersprungenes Werkzeug hat einen Grund (kein TLS-Dienst,
# nicht im Paket) und ist keine Stoerung.
OHNE_ERGEBNIS = ("empty", "unknown", "failed", "blocked")


def abdeckung_ohne_ergebnis(facts: Any) -> list[Defect]:
    """Kein einziger Werkzeuglauf ueber alle Hosts hat etwas geliefert.

    Offener Punkt 1 nach S5b: faellt der Lader aus, stehen alle Zeilen auf
    ``empty`` oder ``unknown``, jede Pruefung wird nicht pruefbar, und der
    Bericht liest sich wie eine unauffaellige Pruefung. ``abdeckungskapitel_leer``
    greift dabei nicht, weil ein Abdeckungstext auch aus ``empty``-Zeilen
    entsteht. Ohne jede Abdeckungszeile meldet bereits die andere Pruefung.
    """
    rows = list(getattr(facts, "coverage", []) or [])
    if not rows:
        return []
    mit_ergebnis = [c for c in rows if getattr(c, "status", "") == "ok"]
    if mit_ergebnis:
        return []
    ohne = [c for c in rows if getattr(c, "status", "") in OHNE_ERGEBNIS]
    if not ohne:
        return []
    return [Defect(
        engine=ENGINE_V3,
        check="abdeckung_ohne_ergebnis",
        severity=SEVERITY_ERROR,
        message=(f"Keiner der {len(rows)} Werkzeuglaeufe hat ein Ergebnis geliefert. "
                 "Der Bericht haette keine belegte Aussage. Rohdaten und Lader pruefen."),
        detail={"zeilen": len(rows), "ohne_ergebnis": len(ohne)},
    )]


# ---------------------------------------------------------------- S6b-1

# Werkzeugnamen, die im Kundentext von Kapitel 2 und im Hinweis auf Seite 3 nichts zu
# suchen haben (spec/09 Q10). Im Nachweis, in der Quellenangabe und in der
# Werkzeugliste des Anhangs stehen sie zu Recht; die werden hier nicht geprueft.
TOOL_TOKENS = re.compile(
    r"\b(nmap|testssl|zap_(?:active|spider|ajax_spider)|ffuf(?:_sensitive|_param)?|feroxbuster|"
    r"header_check|httpx|webtech|wafw00f|wpscan|gobuster(?:_dns|_dir)?|subfinder|dnsx|crtsh|"
    r"certspotter|abuseipdb|securitytrails|web_probe|phase3_correlation)\b", re.I)


def einschraenkung_ohne_pruefung(data: Any) -> list[Defect]:
    """Jede Zeile der Einschraenkungstabelle nennt die betroffenen Pruefungen (spec/09 Q10)."""
    out: list[Defect] = []
    for row in getattr(data.scope, "limitations", []) or []:
        if not [c for c in (row.checks or []) if str(c).strip()]:
            out.append(Defect(
                engine=ENGINE_V3, check="einschraenkung_ohne_pruefung", severity=SEVERITY_ERROR,
                message=f"Einschraenkung ohne Pruefungsnamen: {row.what}",
                detail={"what": row.what}))
    return out


def werkzeugname_im_kundentext(data: Any) -> list[Defect]:
    """Kein Werkzeugname in Abdeckung, Einschraenkungen, Hinweiskasten und Posture."""
    texte: list[tuple[str, str]] = [("glance.coverage_warning", data.glance.coverage_warning or "")]
    for h in data.scope.hosts:
        texte.append((f"scope.hosts[{h.ip}].coverage", h.coverage or ""))
    for row in data.scope.limitations:
        texte.append((f"scope.limitations[{row.what}]", " ".join([row.what, row.detail, *row.checks])))
    for block in data.architecture.posture:
        for item in block.items:
            texte.append((f"posture[{block.short}]", f"{item.l} {item.v}"))
    out: list[Defect] = []
    for where, text in texte:
        treffer = sorted({m.group(0) for m in TOOL_TOKENS.finditer(text)})
        if treffer:
            out.append(Defect(
                engine=ENGINE_V3, check="werkzeugname_im_kundentext", severity=SEVERITY_ERROR,
                message=f"Werkzeugname im Kundentext ({where}): {', '.join(treffer)}",
                detail={"where": where, "werkzeuge": treffer}))
    return out


def rolle_ohne_fakt(data: Any) -> list[Defect]:
    """Ein Satz ueber eine Rolle ohne Fakt ist ein Gate-Fehler (spec/09 Q2).

    Geprueft wird der Endtext der Zusammenfassung, des Kontextabsatzes und der
    Systemsaetze, nachdem die Prosa-KI eingesetzt wurde. Zusammenfassung und
    Kontextabsatz duerfen nennen, was eine belegte Rolle oder ein Befund des Berichts
    traegt; ein Systemsatz nur die Rollen seines Systems.
    """
    from reporter.v3.roles import role_words_without_fact

    alle = {k for o in data.business.observed for k in o.role_keys}
    befundtexte = " ".join(f"{f.title} {f.found}" for f in data.findings)
    out: list[Defect] = []
    pruefen = [("glance.overall_text", data.glance.overall_text or "", alle, befundtexte),
               ("business.implication", data.business.implication or "", alle, befundtexte)]
    pruefen += [(f"business.observed[{o.system}]", o.meaning or "", set(o.role_keys), "")
                for o in data.business.observed]
    for where, text, rollen, bezug in pruefen:
        ohne = role_words_without_fact(text, rollen, bezug)
        if ohne:
            out.append(Defect(
                engine=ENGINE_V3, check="rolle_ohne_fakt", severity=SEVERITY_ERROR,
                message=f"Rolle ohne Fakt in {where}: {', '.join(ohne)}",
                detail={"where": where, "woerter": ohne}))
    return out


# ---------------------------------------------------------------- S6b-2

def _members_index(output: Any) -> dict[tuple[str, str], Any]:
    """(Pruefung, ``<group_key>|<member_key>``) -> Mitglied, ueber alle Ergebnisse."""
    out: dict[tuple[str, str], Any] = {}
    for r in getattr(output, "results", []) or []:
        for m in r.members:
            out[(r.check_id, f"{r.group_key}|{m.key}")] = m
    return out


def _results_index(output: Any) -> dict[tuple[str, str], Any]:
    return {(r.check_id, r.group_key): r for r in getattr(output, "results", []) or []}


def aussage_ohne_fakt(data: Any, output: Any) -> list[Defect]:
    """Jede Aussage im Kundentext hat eine erfuellte Fakten-Bedingung (S6b-2, spec/09 Q4).

    Befund: Titel, Befundtext, Auswirkung, Empfehlung und Verifikation bestehen genau aus
    den Aussagen in ``provenance``, jede Aussage stammt aus einer Pruefung, die fuer die
    genannten Mitglieder fehlgeschlagen ist, und ihre Bedingung gilt dort (``holds``).
    Positivbefund: jede genannte Pruefung hat fuer die genannten Gruppen bestanden.
    Ohne Katalogausgabe (Golden-Render ohne Output) entfaellt die Pruefung.
    """
    if output is None:
        return []
    mitglieder = _members_index(output)
    ergebnisse = _results_index(output)
    out: list[Defect] = []

    def fehler(fid: Optional[str], text: str, detail: dict) -> None:
        out.append(Defect(engine=ENGINE_V3, check="aussage_ohne_fakt", severity=SEVERITY_ERROR,
                          message=text, finding_id=fid, detail=detail))

    felder = {"observation": "found", "meaning": "impact", "verify": "verify"}
    for f in data.findings:
        prov = list(f.provenance or [])
        if not prov:
            fehler(f.id, f"Befund {f.id} ohne Herkunft seiner Aussagen", {})
            continue
        for feld, attr in felder.items():
            teile: list[str] = []
            for p in prov:
                if p.field == feld and p.text not in teile:
                    teile.append(p.text)
            if " ".join(teile) != (getattr(f, attr) or ""):
                fehler(f.id, f"{f.id}: Text in {attr} ohne Herkunft aus dem Katalog",
                       {"feld": attr})
        empfohlen = {p.text for p in prov if p.field == "recommendation"}
        for _stufe, text in f.recommendation:
            if text not in empfohlen:
                fehler(f.id, f"{f.id}: Empfehlung ohne Herkunft: {text[:60]}", {"feld": "recommendation"})
        for p in prov:
            if not p.members:
                fehler(f.id, f"{f.id}: Aussage {p.check}.{p.statement} ohne Mitglied", {"aussage": p.statement})
                continue
            for ref in p.members:
                m = mitglieder.get((p.check, ref))
                if m is None or m.status != "fail":
                    fehler(f.id, f"{f.id}: {p.check} ist fuer {ref} nicht fehlgeschlagen",
                           {"aussage": p.statement, "mitglied": ref})
                    continue
                # S6b-4: eine Titelvariante (spec/11 T4, T14) traegt wie jede Aussage eine
                # Bedingung; die Standardkurzform ist die Regel selbst.
                variante = p.statement.startswith("short_variants")
                if (p.field != "title" or variante) and p.statement not in m.holds:
                    fehler(f.id, f"{f.id}: Bedingung von {p.check}.{p.statement} gilt nicht fuer {ref}",
                           {"aussage": p.statement, "mitglied": ref})
    for pos in data.positives:
        prov = list(pos.provenance or [])
        if not prov:
            fehler(None, f"Positivbefund ohne Herkunft: {pos.title}", {})
            continue
        texte = [p.text for p in prov if p.statement == "positive.text"]
        if " ".join(dict.fromkeys(texte)) != pos.text:
            fehler(None, f"Positivtext ohne Herkunft: {pos.title}", {})
        for p in prov:
            if p.statement != "positive.text":
                continue
            for group_key in p.members:
                r = ergebnisse.get((p.check, group_key))
                if r is None or r.status != "pass" or not r.positive:
                    fehler(None, f"Positivbefund {pos.title}: {p.check} fuer {group_key} nicht bestanden",
                           {"pruefung": p.check, "gruppe": group_key})
    return out


def zaehlung_widerspruch(data: Any) -> list[Defect]:
    """Keine Zahl mit Zaehleinheit widerspricht der Zaehlung in 2.1 (S6b-2).

    Geprueft werden die Texte, die ueber den ganzen Auftrag sprechen: die Zusammenfassung
    auf Seite 2, der Kontextabsatz, die Einleitung von Kapitel 3 und die Systemsaetze.
    Teilmengen ("Fuer 1 System war die aktive Pruefung nur teilweise moeglich") stehen in
    Kapitel 2 und im Hinweis zur Abdeckung; sie kommen aus demselben Modell und bleiben
    hier aussen vor.
    """
    from reporter.v3.gate import count_mismatches
    from reporter.v3.prose import counts_of

    counts = counts_of(data)
    felder: list[tuple[str, str]] = [
        ("glance.overall_text", data.glance.overall_text or ""),
        ("glance.context", data.glance.context or ""),
        ("business.lead", data.business.lead or ""),
        ("business.implication", data.business.implication or ""),
        ("architecture.lead", data.architecture.lead or ""),
    ]
    felder += [(f"business.observed[{o.system}]", o.meaning or "") for o in data.business.observed]
    out: list[Defect] = []
    for where, text in felder:
        for grund in count_mismatches(text, counts):
            out.append(Defect(
                engine=ENGINE_V3, check="zaehlung_widerspruch", severity=SEVERITY_ERROR,
                message=f"{where}: {grund}", detail={"where": where}))
    return out


# ---------------------------------------------------------------- S6b-3 (spec/10)

def _ip_of(subject: str) -> str:
    """Adresse eines Subjekts: "name@ip" -> ip, "ip:port" -> ip, sonst das Subjekt selbst."""
    if "@" in subject:
        return subject.rsplit("@", 1)[1]
    if subject.count(":") == 1:
        return subject.split(":", 1)[0]
    return subject


def _family(check_id: str) -> Optional[str]:
    from reporter.catalog.families import family_of

    return family_of(check_id)


def _text_felder(f: Any) -> list[tuple[str, str]]:
    felder = [("found", f.found or ""), ("impact", f.impact or ""), ("verify", f.verify or "")]
    felder += [(f"recommendation[{i}]", r[1]) for i, r in enumerate(f.recommendation or []) if len(r) > 1]
    felder += [(f"plan[{p.check}]", p.action) for p in (getattr(f, "plan_items", None) or [])]
    return felder


def header_nicht_fehlend(data: Any) -> list[Defect]:
    """Ein Header steht im Befundtext, fehlt laut Messung aber nicht (spec/10 R2).

    castenow VS-007/009 und huendgen VS-009 nannten X-Frame-Options, obwohl die Endseite ihn
    setzte. Geprueft werden die vier Grundheader der Regel security_headers_incomplete; ein
    Header aus header_duplicate ("X-Frame-Options mehrfach gesetzt") ist kein Widerspruch.
    """
    from reporter.catalog.render import HEADER_NAMES

    grund = {HEADER_NAMES[k] for k in ("x-frame-options", "x-content-type-options", "referrer-policy",
                                       "permissions-policy") if k in HEADER_NAMES}
    out: list[Defect] = []
    for f in data.findings:
        checks = set(getattr(f, "checks", None) or [])
        if "security_headers_incomplete" not in checks:
            continue
        fehlend = set(getattr(f, "missing_headers", None) or [])
        erlaubt = fehlend | ({"X-Frame-Options"} if "header_duplicate" in checks else set())
        for where, text in _text_felder(f):
            genannt = sorted(h for h in grund if h in text and h not in erlaubt)
            if genannt:
                out.append(Defect(engine=ENGINE_V3, check="header_nicht_fehlend", severity=SEVERITY_ERROR,
                                  finding_id=f.id,
                                  message=f"{f.id} {where}: {', '.join(genannt)} steht im Text, fehlt laut Messung aber nicht",
                                  detail={"where": where, "header": genannt, "fehlend": sorted(fehlend)}))
    return out


# S6b-4 (spec/11 T4): Familien, die aus derselben Antwort gemessen werden. HSTS und die uebrigen
# Header stammen aus derselben HTTP-Antwort; heuel online trug "nur an einer Sicherheitsabfrage
# gemessen" (Header) neben dem HSTS-Befund an derselben 429. Das gilt fuer Fehlerseite und
# Sicherheitsabfrage; an einer Weiterleitung misst die HSTS-Regel nach E20 bewusst die erste
# Antwort, die uebrigen Header die Endseite.
MESSUNG: dict[str, str] = {"http_headers": "http_antwort", "hsts": "http_antwort"}
MESSUNG_CODES = frozenset({"headers_error_only", "headers_challenge_only"})


def _messung(check_id: str, code: str = "") -> Optional[str]:
    fam = _family(check_id)
    if not fam:
        return None
    return MESSUNG.get(fam, fam) if code in MESSUNG_CODES else fam


def _hsts_eigene_messung(facts: Any) -> set[str]:
    """Subjekte ("name@adresse"), deren HSTS aus einer eigenen gueltigen Messung stammt: testssl,
    die Endseite laut redirect_probe oder eine erste Antwort, die weder Fehlerseite noch
    Sicherheitsabfrage ist (krause filebrowser: 200 als text/plain, die uebrigen Header sind dort
    nicht bewertbar, HSTS schon)."""
    out: set[str] = set()
    for h in getattr(facts, "http", None) or []:
        hsts = getattr(h, "hsts", None)
        tool = getattr(hsts, "tool", None)
        basis = getattr(getattr(h, "header_eval", None), "basis", None)
        # S6b-4n (spec/11 N2, E24): ein gesetzter Header an einer Fehlerseite (400, nicht 429) ist
        # eine gueltige Messung.
        an_fehlerseite = (tool == "header_check" and basis == "client_error" and getattr(hsts, "present", None)
                          and getattr(hsts, "status_code", None) not in (None, 429))
        gueltig = tool in ("testssl", "redirect_probe") or an_fehlerseite or (
            tool == "header_check" and basis not in ("client_error", "server_error", "challenge"))
        if gueltig and h.fqdn:
            out.add(f"{h.fqdn}@{h.host_ip}")
    return out


def einschraenkung_widerspricht_befund(data: Any, facts: Any = None) -> list[Defect]:
    """Eine Einschraenkung "nicht pruefbar" neben einem Befund oder "unauffaellig" derselben
    Messung am selben Subjekt (spec/10 R4: DMARC, Zertifikat, Header; S6b-4, spec/11 T4: HSTS
    und Header aus derselben Antwort)."""
    eigene = _hsts_eigene_messung(facts) if facts is not None else set()
    befund: set[tuple[str, str]] = set()
    for f in data.findings:
        for eintrag in getattr(f, "subjects", None) or []:
            check, _, sub = eintrag.partition("|")
            familien = {_messung(check)}
            if not (_family(check) == "hsts" and sub in eigene):
                familien.add(_messung(check, "headers_error_only"))
            for fam in familien - {None}:
                befund.add((fam, sub))
    ruhig: set[tuple[str, str]] = set()
    for block in data.architecture.posture:
        for item in block.items:
            if item.v != "unauffällig":
                continue
            for check in getattr(item, "checks", None) or []:
                fam = _family(check)
                if fam:
                    for sub in getattr(item, "subjects", None) or []:
                        ruhig.add((fam, sub))
                        ruhig.add((fam, _ip_of(sub)))
    out: list[Defect] = []
    for lim in data.scope.limitations:
        for ref in getattr(lim, "refs", None) or []:
            check, _, gruppe = ref.partition("|")
            fam = _messung(check, getattr(lim, "code", "") or "")
            if not fam:
                continue
            if (fam, gruppe) in befund:
                grund = "Befund"
            elif (fam, gruppe) in ruhig or (fam, _ip_of(gruppe)) in ruhig:
                grund = "unauffällig in der Posture"
            else:
                continue
            out.append(Defect(engine=ENGINE_V3, check="einschraenkung_widerspricht_befund",
                              severity=SEVERITY_ERROR,
                              message=f"Einschränkung „{lim.what}“ ({check}, {gruppe}) neben {grund} derselben Familie {fam}",
                              detail={"ref": ref, "familie": fam}))
    return out


# Werkzeugsaetze, die eine Positivaussage offen lassen (legacy_protocols_present vor S6b-3:
# "Ob dort eine Anmeldung ohne Transportverschlüsselung abgelehnt wird, ließ sich von außen
# nicht feststellen" neben "POP3 und IMAP erzwingen TLS vor der Anmeldung").
UNGEWISS = re.compile(r"nicht feststellen|nicht festgestellt|nicht belegt|nicht prüfbar", re.I)


def positiv_widerspricht_befund(data: Any) -> list[Defect]:
    """Positivbefund und Befund am selben Host:Port widersprechen sich (spec/10 R7)."""
    out: list[Defect] = []
    for pos in data.positives:
        orte = {s for s in (getattr(pos, "subjects", None) or []) if s.count(":") == 1}
        if not orte:
            continue
        regeln = set(getattr(pos, "checks", None) or [])
        for f in data.findings:
            for pv in f.provenance or []:
                if pv.field == "title":
                    continue
                treffer = sorted({m.split("|", 1)[-1] for m in pv.members} & orte)
                if not treffer:
                    continue
                if pv.check in regeln or UNGEWISS.search(pv.text or ""):
                    out.append(Defect(engine=ENGINE_V3, check="positiv_widerspricht_befund",
                                      severity=SEVERITY_ERROR, finding_id=f.id,
                                      message=(f"Positivbefund „{pos.title}“ und {f.id} ({pv.check}) "
                                               f"widersprechen sich an {', '.join(treffer)}"),
                                      detail={"orte": treffer, "regel": pv.check}))
                    break
    return out


def posture_widerspricht_befund(data: Any) -> list[Defect]:
    """Posture "unauffällig" neben einem Befund derselben Regel oder "Handlungsbedarf" ohne
    Befund (spec/10 R8: DANE als Handlungsbedarf neben "MX beim Dienstleister").

    S6b-4 (spec/11 T16): alle vier Karten und jeder neutrale Zustand ("softfail", "teilweise
    geprüft", "nicht prüfbar", "entfällt") neben einem gelben oder roten Befund derselben Regel
    (castenow SPF softfail neben Gelb VS-005, Transport unauffällig neben dem Zertifikatsbefund)."""
    befunde: list[tuple[str, str]] = []
    ampel: list[tuple[str, str, str]] = []
    for f in data.findings:
        for eintrag in getattr(f, "subjects", None) or []:
            check, _, sub = eintrag.partition("|")
            befunde.append((check, sub))
            ampel.append((check, sub, f.status))
    out: list[Defect] = []
    for block in data.architecture.posture:
        for item in block.items:
            checks = set(getattr(item, "checks", None) or []) | set(getattr(item, "pulls", None) or [])
            if not checks:
                continue
            subs = set(getattr(item, "subjects", None) or [])
            subs |= {_ip_of(s) for s in subs}
            passend = [c for c, sub in befunde
                       if c in checks and (not subs or sub in subs or _ip_of(sub) in subs)]
            schwer = [c for c, sub, st in ampel
                      if st in ("rot", "gelb") and c in checks
                      and (not subs or sub in subs or _ip_of(sub) in subs)]
            if item.v == "unauffällig" and passend:
                grund = "unauffällig neben einem Befund"
            elif item.v == "Handlungsbedarf" and not passend:
                grund = "Handlungsbedarf ohne Befund"
            elif getattr(item, "ok", None) is None and schwer:
                grund = f"„{item.v}“ neben einem gelben oder roten Befund"
            else:
                continue
            out.append(Defect(engine=ENGINE_V3, check="posture_widerspricht_befund", severity=SEVERITY_ERROR,
                              message=f"Posture {block.name} / {item.l}: {grund}",
                              detail={"block": block.name, "eintrag": item.l, "status": item.v}))
    return out


def e5_fehlt(data: Any, facts: Any) -> list[Defect]:
    """Port 25 laut Passivquelle, vom Portscan nicht gesehen, ohne Einschraenkungszeile
    (spec/10 R10: lumbeck-wolter, junkerwerk 188.40.3.130, heuel 213.133.104.51)."""
    genannt: set[str] = set()
    for lim in data.scope.limitations:
        if getattr(lim, "code", "") in ("e5", "unreachable_from_scanner", "no_ipv6_route"):
            genannt.update(getattr(lim, "subjects", None) or [])
    eigene = {h.ip for h in facts.hosts if h.third_party is None}
    out: list[Defect] = []
    for p in facts.passive:
        if p.source == "shodan" and p.port == 25 and p.verified is False and p.host_ip in eigene \
                and p.host_ip not in genannt:
            out.append(Defect(engine=ENGINE_V3, check="e5_fehlt", severity=SEVERITY_ERROR,
                              message=f"{p.host_ip}:25 laut Passivquelle offen, Kapitel 2 nennt die Einschränkung nicht",
                              detail={"host": p.host_ip}))
    return out


# Zusagen im Kundentext (spec/10 R12): "wir prüfen sie und nehmen wiederkehrende Fälle in den
# Katalog auf", "werden auf Anfrage bereitgestellt".
ZUSAGE = re.compile(r"\bwir (?:prüfen|nehmen|stellen|liefern)\b|\bnehmen wir\b|\bauf Anfrage\b|"
                    r"\bwerden\b[^.]{0,40}\bbereitgestellt\b", re.I)
_OHNE_KUNDENTEXT = {"provenance", "tool_messages", "evidence", "meta", "refs", "subjects", "checks",
                    "sources", "key", "rule", "message"}


def _kundentexte(obj: Any, pfad: str = ""):
    if hasattr(obj, "model_dump"):
        obj = obj.model_dump()
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k not in _OHNE_KUNDENTEXT:
                yield from _kundentexte(v, f"{pfad}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _kundentexte(v, f"{pfad}[{i}]")
    elif isinstance(obj, str):
        yield pfad, obj


def zusage_im_kundentext(data: Any) -> list[Defect]:
    out: list[Defect] = []
    for pfad, text in _kundentexte(data):
        m = ZUSAGE.search(text)
        if m:
            out.append(Defect(engine=ENGINE_V3, check="zusage_im_kundentext", severity=SEVERITY_ERROR,
                              message=f"{pfad}: Zusage „{m.group(0)}“ im Kundentext",
                              detail={"where": pfad, "text": m.group(0)}))
    return out


_CVE_ID = re.compile(r"CVE-\d{4}-\d{4,}", re.I)


def cve_ohne_a3(data: Any) -> list[Defect]:
    """Eine CVE im Befundtext ohne Zeile in Anhang A.3 (spec/10 R14: 17 wpscan-CVEs bei DB)."""
    gelistet = {c.upper() for ref in data.appendix.cve_refs for c in _CVE_ID.findall(ref.cve)}
    out: list[Defect] = []
    for f in data.findings:
        text = " ".join([f.found or "", f.impact or "", f.evidence or ""]
                        + list(f.threat.cves if f.threat else []))
        fehlend = sorted({c.upper() for c in _CVE_ID.findall(text)} - gelistet)
        if fehlend:
            out.append(Defect(engine=ENGINE_V3, check="cve_ohne_a3", severity=SEVERITY_ERROR, finding_id=f.id,
                              message=f"{f.id} zitiert {', '.join(fehlend[:5])}" + (" und weitere" if len(fehlend) > 5 else "")
                                      + ", Anhang A.3 führt sie nicht",
                              detail={"cves": fehlend}))
    return out


def namen_nicht_geprueft(facts: Any) -> list[Defect]:
    """Die Hostsuche hat Namen gefunden, die nicht ins Inventar kamen (spec/10 R5, bis S6c)."""
    namen = sorted({d.fqdn for t in facts.targets for d in t.discovered})
    if not namen:
        return []
    return [Defect(engine=ENGINE_V3, check="namen_nicht_geprueft", severity=SEVERITY_WARNING,
                   message=(f"{len(namen)} gefundene Namen nicht geprüft (Kapitel 2 nennt sie): "
                            + ", ".join(namen[:6]) + (" und weitere" if len(namen) > 6 else "")),
                   detail={"namen": namen})]


_DATUM_DE = re.compile(r"(?:gültig bis|seit) (\d{2})\.(\d{2})\.(\d{4})")


def frist_vor_berichtsdatum(data: Any) -> list[Defect]:
    """Ein Ablaufdatum im Befund liegt vor dem Berichtsdatum (spec/10 R18, castenow mailstore
    24.09. bei Bericht vom 26.09.). Hinweis an den Admin im Review, kein Fehler."""
    from datetime import date

    def _tag(text: Any) -> Optional[date]:
        try:
            t, m, j = (int(x) for x in str(text).split("."))
            return date(j, m, t)
        except (ValueError, AttributeError):
            return None

    bericht, scan = _tag(data.meta.report_date), _tag(data.meta.scan_date)
    if bericht is None:
        return []
    out: list[Defect] = []
    for f in data.findings:
        for m_ in _DATUM_DE.finditer(" ".join([f.affected or "", f.found or ""])):
            frist = date(int(m_.group(3)), int(m_.group(2)), int(m_.group(1)))
            # Nur Fristen, die zwischen Scan- und Berichtstag ablaufen; was am Scantag schon
            # abgelaufen war, sagt der Befund selbst ("am Scantag seit ... abgelaufen").
            if (scan is None or frist >= scan) and frist < bericht and f.status in ("rot", "gelb"):
                out.append(Defect(engine=ENGINE_V3, check="frist_vor_berichtsdatum", severity=SEVERITY_WARNING,
                                  finding_id=f.id,
                                  message=(f"{f.id}: Frist {m_.group(0)} liegt vor dem Berichtsdatum "
                                           f"{data.meta.report_date}; Stand beim Kunden prüfen"),
                                  detail={"frist": frist.isoformat()}))
                break
    return out


# ---------------------------------------------------------------- S6b-4 (spec/11)

# S6b-4 (spec/11 T3): der Nachweis eines Befunds nennt den Fakt seiner Regel. DB VS-014 nannte
# "Antwort: 200" statt des wpscan-Funds; der VRFY-Befund stand ohne "VRFY in der EHLO-Liste".
REGELFAKT: dict[str, re.Pattern[str]] = {
    "hsts_missing": re.compile(r"Strict-Transport-Security"),
    "hsts_short": re.compile(r"Strict-Transport-Security"),
    "csp_missing": re.compile(r"Content-Security-Policy"),
    "security_headers_incomplete": re.compile(r"fehlende Header"),
    "http_header_disclosure": re.compile(r"Server:|X-Powered-By|X-AspNet-Version|X-FEServer"),
    "wordpress_xmlrpc_enabled": re.compile(r"XML-RPC"),
    "smtp_vrfy_enabled": re.compile(r"VRFY in der EHLO-Liste"),
    "smtp_vrfy_enabled_passive": re.compile(r"VRFY in der EHLO-Antwort"),
    "cert_expiring": re.compile(r"gültig bis"),
    "cert_expiring_later": re.compile(r"gültig bis"),
}


_ENDSEITE = re.compile(r"bewertet an der Endseite: (\S+)")


def nachweis_ohne_regelfakt(data: Any, facts: Any = None) -> list[Defect]:
    """Ein Befund, dessen Nachweis den Fakt seiner Regel nicht enthaelt (spec/11 T3).

    S6b-4n (spec/11 N3): ebenso ein Nachweis, der "bewertet an der Endseite" sagt, obwohl die
    bewerteten Header nicht aus der Endantwort stammen (heuel ose: redirect_probe speicherte die
    erste Antwort, gleicher ETag wie header_check)."""
    out: list[Defect] = []
    if facts is not None:
        auswertung = {h.header_eval.evaluated.url: h.header_eval for h in getattr(facts, "http", None) or []
                      if h.header_eval is not None and h.header_eval.evaluated is not None
                      and h.header_eval.evaluated.url}
        for f in data.findings:
            for url in _ENDSEITE.findall(f.evidence or ""):
                he = auswertung.get(url.rstrip("·").strip())
                if he is not None and (getattr(he, "final_response", None) is False or not he.complete):
                    out.append(Defect(engine=ENGINE_V3, check="nachweis_ohne_regelfakt", severity=SEVERITY_ERROR,
                                      finding_id=f.id,
                                      message=f"{f.id}: Nachweis nennt die Endseite {url} ohne Endantwort",
                                      detail={"endseite": url, "grund": "endseite_ohne_endantwort"}))
    for f in data.findings:
        text = f.evidence or ""
        for check in getattr(f, "checks", None) or []:
            muster = REGELFAKT.get(check)
            if muster is not None and not muster.search(text):
                out.append(Defect(engine=ENGINE_V3, check="nachweis_ohne_regelfakt", severity=SEVERITY_ERROR,
                                  finding_id=f.id,
                                  message=f"{f.id}: Nachweis ohne Regelfakt von {check}",
                                  detail={"regel": check, "muster": muster.pattern}))
    return out


def ipv6_ohne_inventar(facts: Any) -> list[Defect]:
    """AAAA-Adressen der Kundennamen, die der Scanner nicht ins Inventar uebernommen hat
    (spec/11 T7, bis S6c). Der Bericht nennt sie in Kapitel 2; der Hinweis geht an den Admin."""
    adressen = sorted({a.ip for h in facts.hosts for a in (getattr(h, "additional_ips", None) or [])
                       if getattr(a, "family", 6) == 6})
    if not adressen:
        return []
    # S6b-4n (spec/11 N13): Kapitel 2.1 fuehrt die Adresse; sie fehlt nur im Scan-Inventar.
    return [Defect(engine=ENGINE_V3, check="ipv6_ohne_inventar", severity=SEVERITY_WARNING,
                   message=(f"{len(adressen)} IPv6-Adresse(n) laut DNS nicht im Scan-Inventar, im Bericht als "
                            "ungeprüft ausgewiesen: " + ", ".join(adressen[:4])),
                   detail={"adressen": adressen})]


def messadresse_ausserhalb_inventar(facts: Any) -> list[Defect]:
    """Eine Messung lief an einer Adresse ausserhalb des Inventars (spec/11 T7: DNS-Rotation,
    huendgen testssl an 52.59.120.70 fuer den Inventar-Host 18.197.248.23)."""
    inventar = {h.ip for h in facts.hosts}
    orte: dict[str, set[str]] = {}
    for fact in list(facts.tls) + list(facts.http):
        ip = getattr(fact, "measured_ip", None)
        if ip and ip not in inventar:
            orte.setdefault(ip, set()).add(getattr(fact, "fqdn", None) or getattr(fact, "host_ip", ""))
    return [Defect(engine=ENGINE_V3, check="messadresse_ausserhalb_inventar", severity=SEVERITY_WARNING,
                   message=f"Messung an {ip} ausserhalb des Inventars ({', '.join(sorted(n for n in namen if n))})",
                   detail={"adresse": ip, "namen": sorted(n for n in namen if n)})
            for ip, namen in sorted(orte.items())]


# S6b-4n (spec/11 N6): Regeln, deren Positivbefund je Subjekt einen eigenen Rohfakt braucht, und das
# Werkzeug, dessen Nachweis am Fakt dieses Subjekts stehen muss.
ROHFAKT_POSITIV: dict[str, tuple[str, str]] = {
    "dns_zone_transfer": ("dns", "zone_transfer"),
}


def positiv_ohne_rohfakt(data: Any, facts: Any, output: Any) -> list[Defect]:
    """Ein Positivbefund nennt ein Subjekt, fuer das die Regel nicht bejaht ist oder dessen Fakt den
    Rohbeleg nicht traegt (spec/11 N6: Zonentransfer je Domain nur mit eigenem AXFR-Lauf)."""
    if output is None:
        return []
    bejaht = {(r.check_id, r.group_key) for r in output.results
              if r.status == "pass" and (r.positive or r.affirmed)}
    dns = {d.domain: d for d in getattr(facts, "dns", None) or []}
    out: list[Defect] = []
    for pos in data.positives:
        for p in pos.provenance or []:
            if p.statement != "positive.text":
                continue
            for check in p.check.split(","):
                for gruppe in p.members:
                    if (check, gruppe) not in bejaht:
                        out.append(Defect(engine=ENGINE_V3, check="positiv_ohne_rohfakt", severity=SEVERITY_ERROR,
                                          message=f"Positivbefund „{pos.title}“ nennt {gruppe} ohne bejahte Regel {check}",
                                          detail={"regel": check, "subjekt": gruppe}))
                        continue
                    art, werkzeug = ROHFAKT_POSITIV.get(check, ("", ""))
                    if art == "dns":
                        fakt = dns.get(gruppe)
                        if fakt is None or not any(e.tool == werkzeug for e in fakt.evidence):
                            out.append(Defect(engine=ENGINE_V3, check="positiv_ohne_rohfakt",
                                              severity=SEVERITY_ERROR,
                                              message=(f"Positivbefund „{pos.title}“ nennt {gruppe} ohne eigenen "
                                                       f"Rohbeleg ({werkzeug})"),
                                              detail={"regel": check, "subjekt": gruppe, "werkzeug": werkzeug}))
    return out


def anmeldename_im_kundentext(data: Any, facts: Any) -> list[Defect]:
    """Ein Anmeldename in Personenform steht im Kundentext (Entscheidung E25): der Bericht nennt Anzahl
    und Fundweg, die Namen bleiben in den Rohdaten."""
    namen = sorted({u for h in getattr(facts, "http", None) or [] if getattr(h, "wordpress", None)
                    for u in h.wordpress.users if u and len(u) >= 3})
    if not namen:
        return []
    muster = re.compile(r"\b(" + "|".join(re.escape(n) for n in namen) + r")\b")
    texte: list[tuple[str, str]] = []
    for f in data.findings:
        texte += [(f"{f.id}.{feld}", getattr(f, feld) or "")
                  for feld in ("title", "affected", "found", "evidence", "impact", "verify")]
        texte += [(f"{f.id}.recommendation", r[1]) for r in f.recommendation if len(r) > 1]
    texte += [(f"positiv:{p.title}", p.text) for p in data.positives]
    texte += [(f"anhang:{t.what}", f"{t.what} {t.where} {t.note}") for t in data.appendix.tool_findings]
    out: list[Defect] = []
    for wo, text in texte:
        treffer = sorted(set(muster.findall(text)))
        if treffer:
            out.append(Defect(engine=ENGINE_V3, check="anmeldename_im_kundentext", severity=SEVERITY_ERROR,
                              message=f"Anmeldename im Kundentext ({wo})", detail={"wo": wo, "anzahl": len(treffer)}))
    return out


def firmenname_nicht_bestaetigt(data: Any) -> list[Defect]:
    """Firmenname oder Kurzname stammen aus der Recherche-KI (Entscheidung E23): der Admin
    bestaetigt sie vor der Freigabe."""
    quellen = dict(getattr(data.meta, "context_sources", None) or {})
    felder = [f for f in ("firmenname", "kurzname") if quellen.get(f) == "recherche"]
    if not felder:
        return []
    return [Defect(engine=ENGINE_V3, check="firmenname_nicht_bestaetigt", severity=SEVERITY_WARNING,
                   message="Firmenname nicht bestätigt: " + " und ".join(felder) + " stammen aus der Recherche",
                   detail={"felder": felder})]


def run_all(data: Any, facts: Any, output: Any, *, strict: bool = False) -> list[Defect]:
    """Alle Pruefungen in fester Reihenfolge."""
    defects: list[Defect] = []
    defects.extend(abdeckungskapitel_leer(data))
    defects.extend(abdeckung_ohne_ergebnis(facts))
    defects.extend(tech_widerspricht_befund(data, facts))
    defects.extend(unprocessed_ueber_schwelle(output))
    defects.extend(auftraggeber_fehlt(data, strict=strict))
    defects.extend(einschraenkung_ohne_pruefung(data))
    defects.extend(werkzeugname_im_kundentext(data))
    defects.extend(rolle_ohne_fakt(data))
    defects.extend(aussage_ohne_fakt(data, output))
    defects.extend(zaehlung_widerspruch(data))
    # S6b-3 (spec/10): Widersprueche zwischen Teilen des Berichts, Zusagen, Fristen.
    defects.extend(header_nicht_fehlend(data))
    defects.extend(einschraenkung_widerspricht_befund(data, facts))
    defects.extend(positiv_widerspricht_befund(data))
    defects.extend(posture_widerspricht_befund(data))
    defects.extend(e5_fehlt(data, facts))
    defects.extend(zusage_im_kundentext(data))
    defects.extend(cve_ohne_a3(data))
    defects.extend(namen_nicht_geprueft(facts))
    defects.extend(frist_vor_berichtsdatum(data))
    # S6b-4 (spec/11 T3, T7, E23): Nachweis mit Regelfakt, Adressen ausserhalb des Inventars,
    # Firmenname aus der Recherche.
    defects.extend(nachweis_ohne_regelfakt(data, facts))
    defects.extend(ipv6_ohne_inventar(facts))
    defects.extend(messadresse_ausserhalb_inventar(facts))
    defects.extend(firmenname_nicht_bestaetigt(data))
    # S6b-4n (spec/11 N6, E25): Positivbefund gegen Rohfakt, Anmeldenamen im Kundentext.
    defects.extend(positiv_ohne_rohfakt(data, facts, output))
    defects.extend(anmeldename_im_kundentext(data, facts))
    return defects
