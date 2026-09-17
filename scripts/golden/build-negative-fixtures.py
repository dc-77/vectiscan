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
EXPECTED = {
    "NEG-SPF-MISSING": (7, 7, "SPF-Record fehlt, SPF ist vorhanden"),
    "NEG-MARIADB-55": (5, 5, "MySQL/MariaDB 5.5, real MariaDB 10.x, HIGH"),
    "NEG-URLHAUS-POLICY": (6, 4, "Policy URLhaus-Kompromittierung auf FTP/RDP/Plesk/Kubernetes"),
    "NEG-MAIL-PLAINTEXT": (4, 4, "POP3/IMAP Klartext, STARTTLS vorhanden"),
    "NEG-FTP-PLAINTEXT": (2, 1, "FTP Klartext, TLS erzwungen, einmal CRITICAL"),
    "NEG-WEBSERVER-EOL": (3, 3, "Nginx 1.24 EOL, Apache 2.4.41 EOL ohne Herstellerbasis"),
    "NEG-EXCHANGE-2016": (1, 1, "Exchange 2016, real Exchange SE"),
    "NEG-TITLE-PLACEHOLDER": (5, 3, "Platzhalter {host} oder [Hinweis: ...] im Titel"),
    "NEG-WP-PLUGIN-VERSION": (2, 1, "WordPress-Plugin 27, 27 ist eine Theme-Version"),
}

# Abweichungen gegenueber spec/06, die geprueft und bewusst so belassen sind.
# Der Lauf faellt dafuer nicht rot; die Abweichung steht in der Ausgabedatei.
ACCEPTED_DEVIATIONS = {
    "NEG-MARIADB-55": (
        "spec/06 nennt 5 Befunde in 5 Kunden. Die faktenbasierte Erkennung findet 6: der "
        "Lauf a6df9d9d (junkerwerk.hu) traegt dasselbe Banner und denselben Datenbank"
        "befund, sein Befundtext nennt die Zahl 5.5 nur nicht. Der zusaetzliche Eintrag "
        "ist belegt und bleibt drin."
    ),
}


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
        if starttls:
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
    for pattern, (want_findings, want_customers, label) in EXPECTED.items():
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
        "source": "report-prototype/spec/06-katalog-simulation.md Abschnitt 3",
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
