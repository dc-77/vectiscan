#!/usr/bin/env python3
"""S0c Schritt 3: Negativ-Fixtures aus spec/06 Abschnitt 3.

Erzeugt report-worker/tests/golden/negative.json: die 35 belegbar falschen
Befunde aus ausgelieferten Reports, je mit Auftrag, Titel, Grund und dem Fakt,
der sie widerlegt. Kein Check des Pruefkatalogs (S2) darf einen dieser Befunde
erzeugen.

Quelle ist ausschliesslich report-worker/tests/golden/api-snapshot/, also
eingecheckte Daten. Das Skript ist damit ohne report-prototype wiederholbar.

Die neun Muster und ihre Sollzahlen stammen aus spec/06 Abschnitt 3. Die
Detektoren unten sind die maschinelle Fassung dieser Tabelle; Abweichungen
zwischen Soll und Fund werden gemeldet und landen als `abweichungen` in der
Ausgabe, statt stillschweigend korrigiert zu werden.

S6b-2 (spec/09, Scan-Runde 23.09.2026): dazu die in spec/09 belegten
Falschaussagen der sieben Auftraege der Scan-Runde (Muster NEG-S6B2-*). Sie
werden gegen die Golden-Fakten desselben Auftrags geprueft und tragen unter
`pruefung` die maschinelle Fassung des Verbots fuer den neu erzeugten Bericht
(tests/v3/test_negative_scanrunde.py). Die Sollzahlen der alten Muster folgen
dem Snapshot, der seit S0c um weitere Laeufe gewachsen ist.

Aufruf:
    python3 scripts/golden/build-negative-fixtures.py
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SNAPSHOT = REPO_ROOT / "report-worker" / "tests" / "golden" / "api-snapshot"
DEFAULT_DEST = REPO_ROOT / "report-worker" / "tests" / "golden" / "negative.json"

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

PLAIN_RE = re.compile(r"klartext|unverschl|plain|unencrypt", re.I)

# Muster-ID -> (Sollzahl Befunde, Sollzahl Kunden, Kurzbeschreibung aus spec/06)
# S6b-2: Sollzahlen nach dem Snapshot von heute. Seit S0c kamen 57b3ac85
# (lumbeck-wolter, S2b) und 860d0d5a (Junkerwerk-Rescan, S2c) mit Legacy-Berichten
# hinzu; sie tragen dieselben Muster (SPF 8, MariaDB 8, FTP 3, Titel 6). Die Zahlen
# aus spec/06 stehen in Klammern im Text.
EXPECTED = {
    "NEG-SPF-MISSING": (8, 8, "SPF-Record fehlt, SPF ist vorhanden (spec/06: 7/7)"),
    "NEG-MARIADB-55": (8, 7, "MySQL/MariaDB 5.5, real MariaDB 10.x, HIGH (spec/06: 5/5)"),
    "NEG-URLHAUS-POLICY": (6, 4, "Policy URLhaus-Kompromittierung auf FTP/RDP/Plesk/Kubernetes"),
    "NEG-MAIL-PLAINTEXT": (2, 2, "POP3/IMAP Klartext, Anmeldung erst nach STARTTLS (spec/06: 4/4)"),
    "NEG-FTP-PLAINTEXT": (3, 2, "FTP Klartext, TLS erzwungen, einmal CRITICAL (spec/06: 2/1)"),
    "NEG-WEBSERVER-EOL": (3, 3, "Nginx 1.24 EOL, Apache 2.4.41 EOL ohne Herstellerbasis"),
    "NEG-EXCHANGE-2016": (1, 1, "Exchange 2016, real Exchange SE"),
    "NEG-TITLE-PLACEHOLDER": (6, 3, "Platzhalter {host} oder [Hinweis: ...] im Titel (spec/06: 5/3)"),
    "NEG-WP-PLUGIN-VERSION": (2, 1, "WordPress-Plugin 27, 27 ist eine Theme-Version"),
}

# Abweichungen gegenueber spec/06, die geprueft und bewusst so belassen sind.
# Der Lauf faellt dafuer nicht rot; die Abweichung steht in der Ausgabedatei.
ACCEPTED_DEVIATIONS: dict[str, str] = {}

# Warum die Sollzahlen von spec/06 abweichen (steht in negative.json unter `hinweis_soll`).
SOLL_HINWEISE = {
    "NEG-MARIADB-55": (
        "spec/06 nennt 5 Befunde in 5 Kunden. Der Lauf a6df9d9d (junkerwerk.hu) traegt "
        "dasselbe Banner und denselben Datenbankbefund, sein Text nennt die Zahl 5.5 nur "
        "nicht; 57b3ac85 und 860d0d5a kamen nach S0c in den Snapshot."
    ),
    "NEG-MAIL-PLAINTEXT": (
        "S6b-2 (spec/08 Punkt 4): securess (ae8d1d70) und bergersysteme (b9759695) bieten "
        "die Anmeldung vor STARTTLS an (POP3 USER und SASL(PLAIN LOGIN ...), IMAP AUTH=PLAIN "
        "ohne LOGINDISABLED). Die Klartextaussage ist dort belegt und kein Falschbefund; "
        "gezaehlt wird nur, wo die Anmeldung vor TLS gesperrt ist."
    ),
}


def _mail_login_blocked(line: str) -> bool:
    """Sperrt der Dienst laut Capabilities die Anmeldung vor TLS?"""
    toks = line.replace("|", " ").split()
    up = [t.upper() for t in toks]
    if "imap-capabilities" in line:
        return any(t.startswith("LOGINDISABLED") for t in up)
    if "pop3-capabilities" in line:
        return "STLS" in up and "USER" not in up and not any(t.startswith("SASL(") for t in up)
    return False


# --------------------------------------------------------------- Faktenquelle

def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None


def nmap_port_blocks(raw: str, ports: set[int]) -> dict[int, str]:
    """Gibt je Port die nmap-Zeile samt Folgezeilen (Skript-Ausgaben) zurueck."""
    out: dict[int, str] = {}
    lines = raw.splitlines()
    for index, line in enumerate(lines):
        match = re.match(r"^\s*(\d+)/tcp\s+open\s+(.*)$", line)
        if not match:
            continue
        port = int(match.group(1))
        if port not in ports:
            continue
        block = [line.strip()]
        for follow in lines[index + 1:]:
            if re.match(r"^\s*\d+/tcp\s", follow):
                break
            if follow.strip():
                block.append(follow.strip())
        out[port] = "\n".join(block)
    return out


def collect_facts(order_dir: Path) -> dict:
    """Fakten aus dem API-Snapshot, angelehnt an catalog_sim.py extract_facts."""
    facts = {
        "spf": None,
        "nmap_raw": "",
        "mail_caps": {},     # port -> Capability-Zeile
        "ftp_lines": [],     # nmap-Zeilen zu Port 21
        "owa_builds": [],    # Exchange-Builds aus nmap
        "feserver": [],      # X-FEServer-Header
        "webtech": [],       # webtech/wpscan-Rohausgaben
    }
    order = (load_json(order_dir / "order.json") or {}).get("data") or {}
    discovered = (order.get("progress") or {}).get("discoveredHosts")
    if isinstance(discovered, dict):
        facts["spf"] = ((discovered.get("dns_findings") or {}).get("spf")) or None

    results = ((load_json(order_dir / "results.json") or {}).get("data") or {}).get("results") or []
    for row in results:
        tool = row.get("toolName")
        raw = row.get("rawOutput") or ""
        if tool == "nmap":
            facts["nmap_raw"] += raw + "\n"
            blocks = nmap_port_blocks(raw, {21, 110, 143})
            for port in (110, 143):
                if port in blocks:
                    caps = [
                        line for line in blocks[port].splitlines()
                        if re.search(r"(pop3|imap)-capabilities", line)
                    ]
                    facts["mail_caps"].setdefault(port, []).extend(caps or [blocks[port].splitlines()[0]])
            if 21 in blocks:
                facts["ftp_lines"].append(blocks[21].splitlines()[0])
            facts["owa_builds"] += re.findall(r"15\.\d+\.\d+", raw)
        elif tool == "header_check":
            try:
                parsed = json.loads(raw)
            except (ValueError, TypeError):
                continue
            headers = ((parsed or {}).get("result") or {}).get("headers") or {}
            for key, value in headers.items():
                if key.lower() == "x-feserver":
                    facts["feserver"].append(f"{parsed.get('vhost')}: {value}")
        elif tool in ("webtech", "wpscan"):
            facts["webtech"].append(raw)

    if not facts["spf"]:
        for row in results:
            if row.get("toolName") == "dns_records":
                try:
                    facts["spf"] = (json.loads(row.get("rawOutput") or "") or {}).get("spf")
                except (ValueError, TypeError):
                    pass
    return facts


def finding_text(finding: dict) -> str:
    keys = ("title", "description", "evidence", "impact", "recommendation")
    return " ".join(str(finding.get(key) or "") for key in keys)


# ----------------------------------------------------------------- Detektoren

def detect(finding: dict, facts: dict) -> list[tuple[str, str, str, dict]]:
    """Gibt je Treffer (muster, grund, verbotene_aussage, widerlegt_durch) zurueck."""
    hits: list[tuple[str, str, str, dict]] = []
    title = finding.get("title") or ""
    body = finding_text(finding)
    policy = finding.get("policy_id") or ""
    ftype = finding.get("finding_type") or ""

    # 1 SPF fehlt, SPF vorhanden
    if re.search(r"SPF[- ]Record fehlt", title, re.I) and facts["spf"]:
        hits.append((
            "NEG-SPF-MISSING",
            "Titel-Template SP-DNS-004 ueber DKIM-Inhalt; dns_findings.spf wird nicht geprueft",
            "SPF-Record fehlt",
            {"fakt": "dns.spf", "wert": facts["spf"],
             "quelle": "order.json data.progress.discoveredHosts.dns_findings.spf"},
        ))

    # 2 MariaDB-Kompatibilitaetspraefix als Produktversion
    # Der Defekt sitzt in der Versionsableitung (eol_detector, tech_table_builder,
    # spec/02 Ursache 1), nicht im Befundtext: das Banner 5.5.5-10.11.x-MariaDB
    # meldet Protokoll-Kompatibilitaet 5.5.5 und Produktversion 10.11.x. Das
    # Fixture haengt deshalb am Datenbankbefund des Auftrags und verbietet die
    # Ableitung, nicht den Befund selbst.
    if ftype == "database_port_exposed" or re.search(r"Datenbank[- ]Port\s*3306", title, re.I):
        banner = re.search(r"5\.5\.5-(\d+)\.(\d+)[.\d]*-MariaDB[^\s\"']*", facts["nmap_raw"])
        if banner and int(banner.group(1)) >= 10:
            hits.append((
                "NEG-MARIADB-55",
                "Banner 5.5.5-<version>-MariaDB ohne Praefix-Strip: 5.5.5 ist die "
                "Protokoll-Kompatibilitaetsangabe, die Produktversion steht dahinter. "
                "Der Befundtext dieses Laufs zitiert das Banner korrekt; falsch wird es "
                "in Tech-Tabelle und EOL-Ableitung",
                f"MySQL 5.5 als Produkt oder EOL-Befund fuer 3306 "
                f"(real MariaDB {banner.group(1)}.{banner.group(2)})",
                {"fakt": "service.version_raw", "wert": banner.group(0),
                 "quelle": "results.json toolName=nmap, Port 3306"},
            ))

    # 3 URLhaus-Policy auf einen exponierten Dienst
    if policy == "SP-URLHAUS-001" and not re.search(r"urlhaus|malware|kompromitt", title, re.I):
        hits.append((
            "NEG-URLHAUS-POLICY",
            "Type-Mapper-Fehltreffer: finding_type urlhaus_compromise_detected per Regex "
            "auf einen Expositionsbefund; Severity stammt aus der falschen Policy",
            "Kompromittierung laut Malware-Feed",
            {"fakt": "finding_type_source",
             "wert": f"{ftype} via {finding.get('_finding_type_source')}; "
                     "kein URLhaus-Treffer in results.json",
             "quelle": "findings.json finding_type / _finding_type_source"},
        ))

    # 4 POP3/IMAP Klartext trotz STARTTLS
    if re.search(r"(pop3|imap|mail|110|143)", title, re.I) and PLAIN_RE.search(title):
        caps = [line for lines in facts["mail_caps"].values() for line in lines]
        starttls = [line for line in caps if re.search(r"STLS|STARTTLS|LOGINDISABLED", line)]
        # S6b-2 (spec/08 Punkt 4): falsch ist die Klartextaussage nur, wenn jeder Dienst die
        # Anmeldung vor TLS sperrt; POP3 mit USER oder SASL-Verfahren und IMAP ohne
        # LOGINDISABLED nehmen sie an.
        if starttls and all(_mail_login_blocked(line) for line in starttls):
            hits.append((
                "NEG-MAIL-PLAINTEXT",
                "nmap-Capabilities nicht ausgewertet: STLS bzw. STARTTLS wird angeboten, "
                "die Anmeldung ohne TLS ist gesperrt",
                "POP3/IMAP uebertraegt im Klartext",
                {"fakt": "service.starttls", "wert": " | ".join(starttls)[:400],
                 "quelle": "results.json toolName=nmap, pop3-capabilities / imap-capabilities"},
            ))

    # 5 FTP Klartext trotz TLS-Zwang
    if re.search(r"ftp", title, re.I) and PLAIN_RE.search(title) and facts["ftp_lines"]:
        if all(re.search(r"requires SSL", line, re.I) for line in facts["ftp_lines"]):
            hits.append((
                "NEG-FTP-PLAINTEXT",
                "nmap meldet requires SSL: der Dienst erzwingt TLS vor der Anmeldung, "
                "es gibt keine Klartext-Anmeldung",
                "FTP uebertraegt Zugangsdaten im Klartext",
                {"fakt": "service.tls_required", "wert": " | ".join(facts["ftp_lines"])[:400],
                 "quelle": "results.json toolName=nmap, Port 21"},
            ))

    # 6 Webserver-EOL ohne Herstellerbasis
    if re.search(r"(nginx|apache)[^\n]{0,20}\d+\.\d+", title, re.I) and re.search(
        r"EOL|End.of.Life|End of Life|End of Support|Lebensende", body, re.I
    ):
        version = re.search(r"(?:nginx|apache)[^\d]{0,12}(\d+\.\d+(?:\.\d+)?)", title, re.I)
        found_version = version.group(1) if version else "unbekannt"
        hits.append((
            "NEG-WEBSERVER-EOL",
            "EOL-Behauptung ohne Herstellerbasis: fuer diese Version gibt es keinen "
            "Herstellertermin, die Aussage stammt aus dem Modell",
            f"Version {found_version} ist End-of-Life",
            {"fakt": "software.eol",
             "wert": f"Version {found_version} ohne Herstellertermin im EOL-Feed",
             "quelle": "findings.json title/description gegen endoflife.date"},
        ))

    # 7 Exchange 2016 obwohl Build 15.2 (2019 oder SE)
    if re.search(r"Exchange\s*(Server\s*)?2016", body, re.I):
        builds = sorted({b for b in re.findall(r"15\.\d+\.\d+", facts["nmap_raw"] + body)})
        modern = [b for b in builds if b.startswith("15.2.")]
        if modern:
            hits.append((
                "NEG-EXCHANGE-2016",
                "Build 15.2.x ist Exchange 2019 oder Subscription Edition; 2016 ist 15.1.x. "
                "Der Build wird nicht gegen die Produktfamilie geprueft",
                "Exchange 2016 ist End-of-Life",
                {"fakt": "software.build", "wert": ", ".join(modern)
                         + ("; X-FEServer " + "; ".join(facts["feserver"]) if facts["feserver"] else ""),
                 "quelle": "results.json toolName=nmap und header_check X-FEServer"},
            ))

    # 8 Platzhalter im Titel
    if re.search(r"\{[a-zA-Z_]+\}", title) or "[Hinweis" in title:
        hits.append((
            "NEG-TITLE-PLACEHOLDER",
            "Template-Variable nicht ersetzt oder interner Prompt-Hinweis durchgereicht; "
            "der Text geht so in den Kundenreport",
            "Titel mit Platzhalter oder internem Hinweis",
            {"fakt": "finding.title_vars",
             "wert": json.dumps(finding.get("title_vars"), ensure_ascii=False),
             "quelle": "findings.json title_vars gegen title"},
        ))

    # 9 WordPress-Plugin mit einer Versionszahl als Namen
    match = re.search(r"WordPress-Plugin\s+(\d+)\b", title)
    if match:
        theme = re.search(rf"([A-Za-z][A-Za-z0-9 _-]{{2,24}})\s{match.group(1)}\.\d+", body)
        hits.append((
            "NEG-WP-PLUGIN-VERSION",
            f"Smart-Var-Fallback greift die Zahl {match.group(1)} aus einer Versionsangabe "
            "und setzt sie als Plugin-Namen ein",
            f"WordPress-Plugin {match.group(1)} mit bekannter Schwachstelle",
            {"fakt": "tech.theme_version",
             "wert": (theme.group(0) if theme else match.group(1)) + " (Theme-Version, kein Plugin-Name)",
             "quelle": "findings.json evidence (webtech/wpscan)"},
        ))

    return hits


# ------------------------------------------------ Scan-Runde 23.09.2026 (S6b-2)
#
# spec/09 hat die sieben Auftraege der Scan-Runde gegengelesen (Engine catalog,
# Version 1). Die Detektoren unten erkennen die dort als falsch belegten Aussagen in
# findings.json dieser Auftraege; widerlegt werden sie durch die Golden-Fakten
# desselben Auftrags (tests/golden/facts/<order>.json, aus demselben Tar gebaut).
# Jeder Eintrag traegt unter `pruefung` eine maschinelle Fassung des Verbots, die
# tests/v3/test_negative_scanrunde.py gegen den neu erzeugten Bericht prueft:
#   art text:          `muster` (regulaerer Ausdruck, ohne Gross/Klein) darf in
#                      `bereich` (befunde, positive, alles) nicht vorkommen; ein Befund,
#                      der eine Regel aus `ausser_regeln` traegt, darf es; mit
#                      `nur_regeln` gilt das Verbot nur fuer Befunde mit diesen Regeln.
#   art dringlichkeit: jeder Befund, dessen Betroffen-Liste `betroffen` nennt, steht
#                      auf einer Dringlichkeit aus `erlaubt`, und es gibt ihn.
#   art skala:         dasselbe fuer die Skala (exposure, hygiene).
#   art regel:         kein Befund traegt die Regel `regel` fuer `betroffen`.

REPORT_WORKER = REPO_ROOT / "report-worker"
GOLDEN_FACTS = REPORT_WORKER / "tests" / "golden" / "facts"

# Auftrag -> Kuerzel aus spec/09
SCANRUNDE = {
    "1fbc92b9-34ab-414e-8843-a1f1e9f15431": "DB",
    "c3d5724c-bdbf-4da8-982f-4f1a52210e28": "LW",
    "31d67a02-b485-4d05-b228-dbdde092cc68": "JW",
    "3cf01f8d-4d21-4e6d-bac2-7342f1a4d6c7": "HE",
    "68d59573-7a93-4efa-89cc-e7b10cc4d140": "BS",
    "1f8bc977-39a7-47c7-b4ad-7b05dbac2d52": "CA",
    "2e56abe1-c1a6-442e-b36a-dc9f83c81da8": "HL",
}

# Muster-ID -> (Sollzahl Befunde, Sollzahl Kunden, Kurzbeschreibung mit spec/09-Stelle)
EXPECTED_SCANRUNDE = {
    "NEG-S6B2-DANE-FREMDZONE": (8, 7, "Q4: dane_missing bei MX in fremder, unsignierter Zone (alle sieben)"),
    "NEG-S6B2-DMARC-MELDEADRESSE": (4, 4, "Q4: Meldeadresse fehlt, obwohl rua gesetzt ist (DB, BS, CA, HL)"),
    "NEG-S6B2-DMARC-FEHLT-TITEL": (3, 2, "Q4: nicht durchsetzend bei fehlendem DMARC (LW, JW)"),
    "NEG-S6B2-TLS-VERALTET": (5, 4, "Q4: veraltete Protokolle bei TLS 1.2/1.3 (DB, BS, CA, HL)"),
    "NEG-S6B2-CAA-VORHANDEN": (1, 1, "Q4: CAA fehlt, obwohl vorhanden (CA)"),
    "NEG-S6B2-ZERTIFIKATSKETTE": (2, 2, "Q4: Kette unvollstaendig bei Chain of trust Ok (HE, derselbe Buendeltext bei CA)"),
    "NEG-S6B2-AUSLIEFERUNGSSEITE": (4, 3, "Q4: Auslieferungsseite ohne Titel-Fakt (HE, CA, HL)"),
    "NEG-S6B2-BREACH": (4, 3, "Q4: BREACH als Befund, bei CA mit CVE (DB, BS, CA)"),
    "NEG-S6B2-TRACE": (1, 1, "Q4: TRACE aktiv nur aus OPTIONS (JW)"),
    "NEG-S6B2-BANNER-PROTOKOLL": (5, 5, "Q4: SSH-Banner, MariaDB-Handshake, PostgreSQL unbekannt (DB, LW, JW, BS, HL)"),
    "NEG-S6B2-WAF-OHNE-PRODUKT": (3, 3, "Q12: WAF aus Generic-Heuristik oder Weiterleitungsziel (HE, CA, BS)"),
    "NEG-S6B2-REPUTATION-MELDUNGEN": (1, 1, "Q12: keine Eintraege bei 26 AbuseIPDB-Meldungen (HL)"),
    "NEG-S6B2-VERWAIST-ENTFAELLT": (2, 2, "Q12: keine verwaisten Eintraege, Pruefung entfaellt (DB, LW)"),
    "NEG-S6B2-VERWALTUNG-OHNE-KENNUNG": (2, 2, "Q13: Verwaltungsoberflaeche ohne Fingerabdruck (HL 4433, BS Cloudflare)"),
    "NEG-S6B2-WEBMIN-ERHOEHT": (1, 1, "Q13, E1: Webmin mit Anmeldung als erhoeht (DB)"),
    "NEG-S6B2-VERWALTUNG-HYGIENE": (2, 2, "Q13: Verwaltungsoberflaeche mit Kennung als Hygiene hoch (JW, CA)"),
    "NEG-S6B2-ZAP-UNTER-HIGH": (4, 3, "Q14: ZAP-Meldung unter Konfidenz High als Befund (DB, CA, HL)"),
    "NEG-S6B2-WORDPRESS-KERN": (2, 1, "Q18: WordPress 6.5.12 veraltet und ohne Pflege (DB)"),
    "NEG-S6B2-ZERTIFIKAT-FRIST": (2, 2, "Q18, E2: Dringlichkeit nach Restlaufzeit (CA 1 Tag, HE 17 Tage)"),
    "NEG-S6B2-EXCHANGE-SE-PFLEGE": (1, 1, "Teil 2 CA: laufende Herstellerpflege nur aus der Produktlinie"),
    "NEG-S6B2-POSTGRESQL-RATEANGRIFF": (2, 2, "Teil 2 LW, JW: Rateangriffe bei PostgreSQL mit Abweisung"),
}

# Innerhalb eines Satzes: Hostnamen und Versionen enthalten Punkte, ein Satzende ist
# ". " gefolgt von einem Grossbuchstaben.
SATZ = r"(?:(?!\. [A-ZÄÖÜ]).)"
DMARC_GAP_RE = re.compile(r"Rückmeldungen erreichen Sie nicht|Meldeadresse", re.I)
# Verboten ist die Aussage, eine Meldeadresse fehle; "Berichte gehen an die hinterlegte
# Meldeadresse" ist bei gesetztem rua richtig, TLS-RPT hat eine eigene Meldeadresse.
DMARC_GAP_VERBOT = (r"Rückmeldungen erreichen Sie nicht|mit (einer )?Meldeadresse|"
                    r"Meldeadresse (ergänzen|hinterlegen)|ohne Meldeadresse")
TLS_OLD_RE = re.compile(r"veraltete(n)? (Protokolle|Verfahren|Protokollversionen)|schwächere Verbindung", re.I)


def _rules(finding: dict) -> set[str]:
    return {r.strip() for r in str(finding.get("policy_id") or "").split(",") if r.strip()}


def _flat(value) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False)


def _text(finding: dict) -> str:
    keys = ("title", "description", "impact", "recommendation", "verification", "evidence", "affected")
    return " ".join(_flat(finding.get(k)) for k in keys)


def _facts_obj(order_id: str):
    sys.path.insert(0, str(REPORT_WORKER))
    from reporter.facts.schema import Facts  # noqa: E402
    return Facts.from_dict(json.loads((GOLDEN_FACTS / f"{order_id}.json").read_text(encoding="utf-8")))


def _entry(pattern, grund, verboten, fakt, wert, quelle, pruefung):
    return (pattern, grund, verboten, {"fakt": fakt, "wert": wert, "quelle": quelle}, pruefung)


def _text_rule(muster, bereich="befunde", ausser=None, nur=None):
    out = {"art": "text", "bereich": bereich, "muster": muster}
    if ausser:
        out["ausser_regeln"] = list(ausser)
    if nur:
        out["nur_regeln"] = list(nur)
    return out


def _nennt(text: str, name: str | None) -> bool:
    """Nennt der Text genau diesen Namen (nicht als Teil eines laengeren Namens)?"""
    if not name:
        return False
    return re.search(rf"(?<![\w.-]){re.escape(name)}(?![\w-])", text) is not None


def _ports(text: str) -> list[tuple[str, int]]:
    return [(m.group(1), int(m.group(2)))
            for m in re.finditer(r"\b(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})\b", text)]


def detect_scanrunde(finding: dict, facts, positive: bool) -> list[tuple]:
    """Treffer (muster, grund, verbotene_aussage, widerlegt_durch, pruefung) eines Befunds
    oder Positivbefunds der Scan-Runde."""
    sys.path.insert(0, str(REPORT_WORKER))
    from reporter.catalog.expr import f_admin_fp, f_mx_in_own_zone, f_redirects_elsewhere  # noqa: E402
    from reporter.catalog.tables import WAF_GENERIC  # noqa: E402

    hits: list[tuple] = []
    title = finding.get("title") or ""
    body = _text(finding)
    rules = _rules(finding)
    dns = {d.domain: d for d in facts.dns}
    domains = list(facts.scan.domains or [])

    if positive:
        text = f"{title} {finding.get('description') or ''}"
        if title.startswith("Web Application Firewall"):
            m = re.search(r"Vor (\S+) ", text)
            name = m.group(1) if m else ""
            for fq in facts.fqdns:
                if fq.name != name or not fq.waf or not fq.waf.detected:
                    continue
                generisch = not fq.waf.name or bool(WAF_GENERIC.search(fq.waf.name))
                if generisch or f_redirects_elsewhere(fq):
                    hits.append(_entry(
                        "NEG-S6B2-WAF-OHNE-PRODUKT",
                        "wafw00f meldet nur die Generic-Heuristik oder die Antwort des Weiterleitungsziels; "
                        "ein Schutz vor dem eigenen Webdienst ist nicht belegt",
                        "Web Application Firewall filtert Angriffe vor dem Webdienst",
                        "fqdn.waf", f"{name}: name={fq.waf.name}, final_url={fq.final_url}",
                        "tests/golden/facts, wafw00f und web_probe",
                        _text_rule(rf"Vor {re.escape(name)}{SATZ}*Web Application Firewall", "positive")))
                    break
        if title.startswith("Keine Einträge in Reputationsquellen"):
            for h in facts.hosts:
                rep = h.reputation
                if rep is not None and (rep.abuseipdb_total_reports or 0) > 0:
                    hits.append(_entry(
                        "NEG-S6B2-REPUTATION-MELDUNGEN",
                        "AbuseIPDB fuehrt Meldungen zu dieser Adresse; Score 0 kommt nur aus der Whitelist",
                        f"keine Eintraege in Reputationsquellen fuer {h.ip}",
                        "host.reputation", f"{h.ip}: totalReports {rep.abuseipdb_total_reports}, "
                        f"isWhitelisted {rep.abuseipdb_whitelisted}, lastReportedAt {rep.abuseipdb_last_reported_at}",
                        "phase0a/abuseipdb.json",
                        _text_rule(rf"{re.escape(h.ip)}{SATZ}{{0,300}}keine Meldungen|"
                                   rf"Zu den geprüften Adressen{SATZ}*kein Eintrag", "positive")))
        if "verwaist" in text.lower():
            cnames = [f.name for f in facts.fqdns if getattr(f, "cname", None)]
            dangling = [c for d in facts.dns for c in (d.dangling_cnames or [])]
            if not cnames and not dangling and SCANRUNDE.get(facts.scan.order_id) in ("DB", "LW"):
                hits.append(_entry(
                    "NEG-S6B2-VERWAIST-ENTFAELLT",
                    "Ohne CNAME-Eintrag entfaellt die Pruefung auf verwaiste Eintraege (Posture 'entfaellt'); "
                    "entfallen zaehlt nicht als bestanden",
                    "kein Eintrag zeigt auf ein aufgegebenes Ziel",
                    "dns.dangling_cnames", "keine CNAME-Eintraege in den Fakten",
                    "tests/golden/facts, dnsx",
                    _text_rule(r"verwaist", "positive")))
        if title.startswith("Serversoftware mit laufender Herstellerpflege"):
            for sw in facts.software:
                if sw.family == "exchange" and (sw.edition or "").upper() == "SE" and sw.host_ip in text:
                    hits.append(_entry(
                        "NEG-S6B2-EXCHANGE-SE-PFLEGE",
                        "Belegt ist nur die Produktlinie Exchange SE aus dem OWA-Pfad, nicht der Patchstand",
                        "laufende Herstellerpflege fuer Exchange SE",
                        "software.edition", f"{sw.host_ip}: {sw.product} {sw.version_norm} (Build {sw.build})",
                        "tests/golden/facts, nmap und header_check X-FEServer",
                        _text_rule(rf"{re.escape(sw.host_ip)}{SATZ}*gepflegten Version", "positive")))
                    break
        return hits

    if "dane_missing" in rules:
        for dom, d in dns.items():
            if d.mx and not (f_mx_in_own_zone(d, domains) and d.dnssec is not None and d.dnssec.signed):
                if dom in title or dom in body:
                    hits.append(_entry(
                        "NEG-S6B2-DANE-FREMDZONE",
                        "Der MX liegt in einer fremden Zone oder die Kundenzone ist nicht signiert; DANE kann "
                        "der Kunde nicht umsetzen",
                        "DANE fuer den Mailempfang fehlt",
                        "dns.mx, dns.dnssec.signed",
                        f"{dom}: MX {', '.join(d.mx)}; DNSSEC signiert {d.dnssec.signed if d.dnssec else None}",
                        "phase0/dns_records.json, dns_security",
                        # Verboten ist die Regel selbst: der Buendeltext von Version 1 nannte DANE
                        # nicht beim Namen, getroffen hatte dane_missing.
                        {"art": "regel", "regel": "dane_missing", "betroffen": dom}))
                    break
    if rules & {"dmarc_none", "dmarc_quarantine"} and DMARC_GAP_RE.search(body):
        for dom, d in dns.items():
            if d.dmarc and d.dmarc.rua and dom in title:
                hits.append(_entry(
                    "NEG-S6B2-DMARC-MELDEADRESSE",
                    "Der DMARC-Eintrag nennt eine Meldeadresse (rua); Rueckmeldungen gehen also ein",
                    "Rueckmeldungen erreichen Sie nicht, Meldeadresse ergaenzen",
                    "dns.dmarc.rua", f"{dom}: {d.dmarc.raw}", "phase0/dns_records.json",
                    _text_rule(DMARC_GAP_VERBOT, nur=["dmarc_none", "dmarc_quarantine", "dmarc_missing"])))
                break
    if "dmarc_missing" in rules and "nicht durchsetzend" in title:
        for dom, d in dns.items():
            if dom in title and (d.dmarc is None or not d.dmarc.present):
                hits.append(_entry(
                    "NEG-S6B2-DMARC-FEHLT-TITEL",
                    "Es gibt keinen DMARC-Eintrag; 'nicht durchsetzend' unterstellt eine Richtlinie",
                    "DMARC-Richtlinie nicht durchsetzend",
                    "dns.dmarc.present", f"{dom}: kein DMARC-Eintrag", "phase0/dns_records.json",
                    _text_rule(r"nicht durchsetzend")))
                break
    if (rules & {"tls_no_13", "tls_weakness"} and not rules & {"tls_legacy_protocols", "tls_weak_ciphers"}
            and TLS_OLD_RE.search(body)):
        wert = []
        for t in facts.tls:
            if _nennt(title, t.fqdn) or _nennt(title, t.host_ip):
                an = sorted(k for k, v in (t.protocols or {}).items() if v)
                wert.append(f"{t.fqdn or t.host_ip}:{t.port} {', '.join(an)}")
        hits.append(_entry(
            "NEG-S6B2-TLS-VERALTET",
            "testssl meldet nur TLS 1.2 und TLS 1.3 und keine schwachen Verfahren; getroffen hat "
            "tls_no_13, BREACH oder LUCKY13",
            "laesst veraltete Protokolle und Verfahren zu",
            "tls.protocols", "; ".join(wert) or "nur TLS 1.2/1.3 laut testssl", "testssl",
            _text_rule(TLS_OLD_RE.pattern, ausser=["tls_legacy_protocols", "tls_weak_ciphers"])))
    if "dnssec_missing" in rules and "caa_missing" not in rules and re.search(r"Ausstellung", body):
        for dom, d in dns.items():
            if d.caa and d.caa.present and dom in title:
                hits.append(_entry(
                    "NEG-S6B2-CAA-VORHANDEN",
                    "CAA ist veroeffentlicht; getroffen hat nur dnssec_missing",
                    "Eintraege, die die Ausstellung von Zertifikaten eingrenzen, fehlen",
                    "dns.caa.records", f"{dom}: {'; '.join(d.caa.records)}", "dns_security",
                    _text_rule(r"\bCAA\b|Ausstellung[^.]*eingrenz", ausser=["caa_missing"])))
                break
    if rules == {"cert_expiring"} and re.search(r"Vertrauenskette|Abgelaufene", body):
        for t in facts.tls:
            if _nennt(title, t.fqdn) and t.cert is not None and t.cert.chain_ok:
                hits.append(_entry(
                    "NEG-S6B2-ZERTIFIKATSKETTE",
                    "testssl meldet Chain of trust Ok; einziger Fakt ist die Restlaufzeit",
                    "abgelaufene Zertifikate erneuern und die Vertrauenskette hinterlegen",
                    "tls.cert.chain_complete", f"{t.fqdn}:{t.port}: Kette vollstaendig, {t.cert.days_left} Tage",
                    "testssl", _text_rule(r"Vertrauenskette|abgelaufene Zertifikate",
                                          ausser=["cert_chain_incomplete", "cert_expired"])))
                break
    if "http_alt_port" in rules and "default_page_exposed" not in rules and "Auslieferungsseite" in body:
        hits.append(_entry(
            "NEG-S6B2-AUSLIEFERUNGSSEITE",
            "Kein Titel- oder Inhaltsfakt belegt eine Auslieferungsseite; getroffen hat nur http_alt_port",
            "unveraenderte Auslieferungsseite des Herstellers",
            "service.port", _flat(finding.get("affected"))[:300], "nmap",
            _text_rule(r"Auslieferungsseite|Standard-Startseite", ausser=["default_page_exposed"])))
    if "tls_weakness" in rules and "BREACH" in body:
        hits.append(_entry(
            "NEG-S6B2-BREACH",
            "testssl: BREACH 'Can be ignored for static pages'; die Meldung traegt keinen Befund und keine CVE",
            "BREACH als Schwachstelle mit CVE am Befund",
            "tls.vulns", "BREACH potentially VULNERABLE (bedingt)", "testssl",
            _text_rule(r"BREACH|CVE-2013-3587")))
    if "http_trace_enabled" in rules:
        hits.append(_entry(
            "NEG-S6B2-TRACE",
            "nmap http-methods liest die Methodenliste aus der OPTIONS-Antwort; eine TRACE-Anfrage ist nicht belegt",
            "TRACE aktiv, der Server spiegelt Anfragen",
            "service.capabilities", "METHOD:TRACE aus http-methods (OPTIONS)", "nmap",
            _text_rule(r"TRACE aktiv|akzeptiert die HTTP-Methode TRACE|spiegelt", "alles")))
    if "service_banner_version" in rules and re.search(r"OpenSSH|MariaDB|MySQL|PostgreSQL unbekannt|Dropbear", body):
        hits.append(_entry(
            "NEG-S6B2-BANNER-PROTOKOLL",
            "SSH-Banner und MariaDB-Handshake gehoeren zum Protokoll; 'PostgreSQL unbekannt' ist keine Versionsangabe",
            "Dienst gibt abschaltbare Versionskennung preis (SSH, MariaDB, PostgreSQL)",
            "service.version_raw", _flat(finding.get("affected"))[:300], "nmap",
            _text_rule(r"PostgreSQL|OpenSSH|MariaDB|MySQL|Dropbear", nur=["service_banner_version"])))
    if "admin_service_exposed_passive" in rules:
        for ip, port in _ports(body):
            p = next((p for p in facts.passive if p.host_ip == ip and p.port == port), None)
            if p is None:
                continue
            if not f_admin_fp(p):
                hits.append(_entry(
                    "NEG-S6B2-VERWALTUNG-OHNE-KENNUNG",
                    "Die Passivquelle nennt keinen Fingerabdruck einer Verwaltungssoftware",
                    f"Verwaltungsoberflaeche auf {ip}:{port}",
                    "passive.banner_excerpt", f"{ip}:{port}: {p.banner_excerpt or p.product or 'ohne Kennung'}",
                    "phase0a/shodan.json", _text_rule(rf"{re.escape(ip)}:{port}\b")))
                break
            if (finding.get("scale") or "") == "hygiene":
                hits.append(_entry(
                    "NEG-S6B2-VERWALTUNG-HYGIENE",
                    "A.2 und E1: eine Verwaltungsoberflaeche mit Kennung ist eine Exposition, keine Hygiene",
                    f"Verwaltungsoberflaeche auf {ip}:{port} als Hygiene hoch",
                    "passive.product", f"{ip}:{port}: {p.product or p.banner_excerpt}", "phase0a/shodan.json",
                    {"art": "skala", "betroffen": f"{ip}:{port}", "erlaubt": ["exposure"]}))
                break
    if "admin_service_exposed" in rules and "erh" in str(finding.get("level") or ""):
        for ip, port in _ports(body):
            s = next((s for s in facts.services if s.host_ip == ip and s.port == port), None)
            if s is not None and s.fp_login and (s.fp_server or "").lower().startswith("miniserv"):
                hits.append(_entry(
                    "NEG-S6B2-WEBMIN-ERHOEHT",
                    "Webmin mit Anmeldung ohne vorgelagerten Schutz auf einem System des Kunden ist nach E1 "
                    "Exposition kritisch",
                    f"Verwaltungsoberflaeche auf {ip}:{port} nur erhoeht",
                    "service.fp_server, service.fp_login", f"{ip}:{port}: Server {s.fp_server}, Anmeldung belegt",
                    "nmap servicefp", {"art": "dringlichkeit", "betroffen": f"{ip}:{port}",
                                       "erlaubt": ["Unverzüglich"]}))
                break
    if rules & {"csrf_token_missing", "cors_misconfiguration"}:
        low = [(h.fqdn, a.plugin_id, a.confidence) for h in facts.http for a in h.alerts
               if a.plugin_id in ("10202", "40040", "10098") and a.confidence != "High"]
        if low:
            hits.append(_entry(
                "NEG-S6B2-ZAP-UNTER-HIGH",
                "Die ZAP-Meldung hat Konfidenz Low oder Medium; darunter traegt sie keinen Befund",
                "fehlender Formularschutz oder CORS-Fehlkonfiguration als Befund",
                "http.alerts.confidence", "; ".join(f"{f} {pid} {c}" for f, pid, c in low[:4]), "zap",
                _text_rule(r"Anti-CSRF|Formularschutz|Cross-Domain|\bCORS\b")))
    if rules & {"wordpress_core_outdated", "software_eol_runtime"} and "WordPress" in body:
        wp = [h.wordpress for h in facts.http if h.wordpress is not None and h.wordpress.version]
        if wp and all((w.core_vulnerabilities or 0) == 0 for w in wp):
            hits.append(_entry(
                "NEG-S6B2-WORDPRESS-KERN",
                "wpscan meldet WordPress 6.5.12 mit release_date 2026-09-22 und ohne Kern-Schwachstelle",
                "WordPress veraltet und unsicher, ohne Herstellerpflege",
                "http.wordpress", "; ".join(f"{w.version} ({w.release_date}), Kern-Schwachstellen "
                                            f"{w.core_vulnerabilities}" for w in wp[:2]), "wpscan",
                _text_rule(r"WordPress-Kernversion veraltet|WordPress[^,;]{0,80}(ohne Herstellerpflege|Support beendet)")))
    if "cert_expiring" in rules:
        for t in facts.tls:
            if t.cert is None or t.cert.days_left is None or t.cert.days_left > 30:
                continue
            if not _nennt(_flat(finding.get("affected")), f"{t.fqdn}:{t.port}"):
                continue
            tage = t.cert.days_left
            erlaubt = ["Unverzüglich"] if tage <= 7 else (["Mittelfristig"] if tage > 14 else None)
            if erlaubt and finding.get("urgency") not in erlaubt:
                hits.append(_entry(
                    "NEG-S6B2-ZERTIFIKAT-FRIST",
                    "E2: bis sieben Tage Unverzueglich, acht bis 14 Tage In Kuerze, darueber mittelfristig",
                    f"Zertifikat mit {tage} Tagen Restlaufzeit {finding.get('urgency')}",
                    "tls.cert.days_left", f"{t.fqdn}:{t.port}: {tage} Tage bis {t.cert.not_after}", "testssl",
                    {"art": "dringlichkeit", "betroffen": f"{t.fqdn}:{t.port}", "erlaubt": erlaubt}))
                break
    if "db_exposed" in rules and "Rateangriff" in body:
        for s in facts.services:
            if s.port == 5432 and s.rejects_before_auth:
                hits.append(_entry(
                    "NEG-S6B2-POSTGRESQL-RATEANGRIFF",
                    "PostgreSQL weist fremde Quellen vor der Anmeldung ab (no pg_hba.conf entry)",
                    "Passwort-Rateangriffe rund um die Uhr auf PostgreSQL",
                    "service.rejects_before_auth", f"{s.host_ip}:5432 weist vor der Anmeldung ab",
                    "phase0a/shodan.json",
                    # Version 1 sagte "Rateangriffe" ohne Einschraenkung; verboten ist der Satz
                    # an 5432 oder ohne den Satz zur Abweisung vor der Anmeldung.
                    _text_rule(r"(?s)Rateangriffe[^.]*5432|^(?=.*Rateangriff)(?!.*vor der Anmeldung ab)",
                               nur=["db_exposed"])))
                break
    return hits


# ---------------------------------------------------------------------- Lauf

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--snapshot", type=Path, default=DEFAULT_SNAPSHOT)
    ap.add_argument("--dest", type=Path, default=DEFAULT_DEST)
    args = ap.parse_args()

    snapshot: Path = args.snapshot.resolve()
    orders_doc = load_json(snapshot / "orders.json")
    if not orders_doc:
        print(f"orders.json fehlt in {snapshot}", file=sys.stderr)
        return 2
    meta = {o["id"]: o for o in orders_doc["data"]["orders"]}

    entries: list[dict] = []
    for order_dir in sorted(d for d in snapshot.iterdir() if d.is_dir() and UUID_RE.match(d.name)):
        findings_doc = load_json(order_dir / "findings.json")
        if not findings_doc:
            continue
        findings = (findings_doc.get("data") or {}).get("findings") or []
        if not findings:
            continue
        facts = collect_facts(order_dir)
        domain = meta.get(order_dir.name, {}).get("domain") or "unbekannt"
        if order_dir.name in SCANRUNDE:
            fobj = _facts_obj(order_dir.name)
            data = findings_doc.get("data") or {}
            kandidaten = [(f, False) for f in findings] + [(p, True) for p in data.get("positive_findings") or []]
            for finding, positive in kandidaten:
                for pattern, reason, forbidden, refuted_by, pruefung in detect_scanrunde(finding, fobj, positive):
                    entries.append({
                        "pattern": pattern, "order": order_dir.name, "domain": domain,
                        "kuerzel": SCANRUNDE[order_dir.name],
                        "finding_id": finding.get("id"), "titel": finding.get("title"),
                        "severity": finding.get("severity"), "policy_id": finding.get("policy_id"),
                        "positiv": positive,
                        "verbotene_aussage": forbidden, "grund": reason,
                        "widerlegt_durch": refuted_by, "pruefung": pruefung,
                    })
            continue
        for finding in findings:
            for pattern, reason, forbidden, refuted_by in detect(finding, facts):
                entries.append(
                    {
                        "pattern": pattern,
                        "order": order_dir.name,
                        "domain": domain,
                        "finding_id": finding.get("id"),
                        "titel": finding.get("title"),
                        "severity": finding.get("severity"),
                        "policy_id": finding.get("policy_id"),
                        "verbotene_aussage": forbidden,
                        "grund": reason,
                        "widerlegt_durch": refuted_by,
                    }
                )

    entries.sort(key=lambda e: (e["pattern"], e["order"], e["finding_id"] or ""))

    deviations = []
    patterns = []
    for pattern, (want_findings, want_customers, label) in {**EXPECTED, **EXPECTED_SCANRUNDE}.items():
        found = [e for e in entries if e["pattern"] == pattern]
        customers = {e["domain"] for e in found}
        patterns.append(
            {
                "id": pattern,
                "muster": label,
                "soll_befunde": want_findings,
                "soll_kunden": want_customers,
                "ist_befunde": len(found),
                "ist_kunden": len(customers),
            }
        )
        if len(found) != want_findings or len(customers) != want_customers:
            note = ACCEPTED_DEVIATIONS.get(pattern)
            deviations.append(
                {
                    "pattern": pattern,
                    "soll": f"{want_findings} Befunde / {want_customers} Kunden",
                    "ist": f"{len(found)} Befunde / {len(customers)} Kunden",
                    "geprueft": bool(note),
                    "begruendung": note,
                }
            )

    distinct = {(e["order"], e["finding_id"]) for e in entries}
    out = {
        "source": ("report-prototype/spec/06-katalog-simulation.md Abschnitt 3; "
                   "Scan-Runde 23.09.2026 aus report-prototype/spec/09-gegenlesen-scanrunde.md (S6b-2)"),
        "hinweis_scanrunde": (
            "Die Muster NEG-S6B2-* stammen aus den Version-1-Berichten der sieben Auftraege der "
            "Scan-Runde (Engine catalog) und sind gegen die Golden-Fakten desselben Auftrags "
            "belegt. `pruefung` ist die maschinelle Fassung des Verbots fuer den neu erzeugten "
            "Bericht; tests/v3/test_negative_scanrunde.py wendet sie an."
        ),
        "hinweis_soll": SOLL_HINWEISE,
        "hinweis": (
            "Jeder Eintrag verbietet eine Aussage: kein Check des Pruefkatalogs darf fuer "
            "diesen Auftrag die unter verbotene_aussage genannte Behauptung erzeugen. "
            "`titel` ist der Titel des ausgelieferten Befundes, an dem der Defekt haengt. "
            "Ein Befund kann auf mehrere Muster passen, deshalb ist die Zahl der Eintraege "
            "groesser als die Zahl der betroffenen Befunde."
        ),
        "hinweis_mariadb": (
            "Bei NEG-MARIADB-55 sitzt der Defekt in der Versionsableitung (eol_detector, "
            "tech_table_builder, spec/02 Ursache 1), nicht im Befundtext: die Texte dieser "
            "Laeufe zitieren das Banner korrekt. Nicht gelistet ist trunk-immobilien.de "
            "(45bb234c), dessen Banner MySQL 5.5.68-MariaDB kein Kompatibilitaetspraefix "
            "traegt, also tatsaechlich MariaDB 5.5.68 meldet."
        ),
        "count": len(entries),
        "count_distinct_findings": len(distinct),
        "patterns": patterns,
        "abweichungen": deviations,
        "entries": entries,
    }

    args.dest.parent.mkdir(parents=True, exist_ok=True)
    args.dest.write_text(
        json.dumps(out, ensure_ascii=False, indent=1) + "\n", encoding="utf-8", newline="\n"
    )

    for row in patterns:
        flag = "ok " if (row["ist_befunde"], row["ist_kunden"]) == (row["soll_befunde"], row["soll_kunden"]) else "ABW"
        print(f"{flag} {row['id']:24} soll {row['soll_befunde']}/{row['soll_kunden']}  "
              f"ist {row['ist_befunde']}/{row['ist_kunden']}")
    print(f"{len(entries)} Eintraege, {len(distinct)} verschiedene Befunde -> {args.dest}")
    unreviewed = [d for d in deviations if not d["geprueft"]]
    for deviation in deviations:
        mark = "geprueft" if deviation["geprueft"] else "UNGEPRUEFT"
        print(f"Abweichung {deviation['pattern']} ({mark}): soll {deviation['soll']}, "
              f"ist {deviation['ist']}")
    return 1 if unreviewed else 0


if __name__ == "__main__":
    raise SystemExit(main())
