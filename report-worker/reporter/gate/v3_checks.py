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
                if p.field != "title" and p.statement not in m.holds:
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


def einschraenkung_widerspricht_befund(data: Any) -> list[Defect]:
    """Eine Einschraenkung "nicht pruefbar" neben einem Befund oder "unauffaellig" derselben
    Faktenfamilie am selben Subjekt (spec/10 R4: DMARC, Zertifikat, Header)."""
    befund: set[tuple[str, str]] = set()
    for f in data.findings:
        for eintrag in getattr(f, "subjects", None) or []:
            check, _, sub = eintrag.partition("|")
            fam = _family(check)
            if fam:
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
            fam = _family(check)
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
    Befund (spec/10 R8: DANE als Handlungsbedarf neben "MX beim Dienstleister")."""
    befunde: list[tuple[str, str]] = []
    for f in data.findings:
        for eintrag in getattr(f, "subjects", None) or []:
            check, _, sub = eintrag.partition("|")
            befunde.append((check, sub))
    out: list[Defect] = []
    for block in data.architecture.posture:
        for item in block.items:
            checks = set(getattr(item, "checks", None) or [])
            if not checks:
                continue
            subs = set(getattr(item, "subjects", None) or [])
            subs |= {_ip_of(s) for s in subs}
            passend = [c for c, sub in befunde
                       if c in checks and (not subs or sub in subs or _ip_of(sub) in subs)]
            if item.v == "unauffällig" and passend:
                grund = "unauffällig neben einem Befund"
            elif item.v == "Handlungsbedarf" and not passend:
                grund = "Handlungsbedarf ohne Befund"
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
    defects.extend(einschraenkung_widerspricht_befund(data))
    defects.extend(positiv_widerspricht_befund(data))
    defects.extend(posture_widerspricht_befund(data))
    defects.extend(e5_fehlt(data, facts))
    defects.extend(zusage_im_kundentext(data))
    defects.extend(cve_ohne_a3(data))
    defects.extend(namen_nicht_geprueft(facts))
    defects.extend(frist_vor_berichtsdatum(data))
    return defects
