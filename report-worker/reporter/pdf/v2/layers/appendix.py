"""Anhaenge A-F + Filter-Anhang (Doc 02 Seite 14+).

  Anhang A.1 - CVSS-Tabelle (alle Befunde mit scale="cvss")
  Anhang A.2 - VECTISCAN-Hygiene-Skala (scale="hygiene")
  Anhang B   - Service-Inventar (pro Host)
  Anhang C   - Eingesetzte Tools + Konfidenz
  Anhang D   - Compliance-Mapping (NIS2 / BSI / ISO / DSGVO)
  Anhang E   - Methodische Filterungen (additional_findings + FP-Statistik)
  Anhang F   - Haftungsausschluss + Wiederholungsempfehlung mit Trigger
"""
from __future__ import annotations

from typing import Any

from reportlab.platypus import (
    Paragraph, Spacer, PageBreak, Table, TableStyle, KeepTogether,
)
from reportlab.lib.units import mm
from reportlab.lib.colors import HexColor

from reporter.pdf.branding import COLORS


# ====================================================================
# RENDER-HELPER
# ====================================================================
def _section(story, styles, title: str) -> None:
    section_style = styles.get("SectionTitle") or styles["BodyText"]
    story.append(Paragraph(f"<b>{title}</b>", section_style))


def _subsection(story, styles, title: str) -> None:
    subsec_style = styles.get("SubsectionTitle") or styles["BodyText"]
    story.append(Paragraph(f"<b>{title}</b>", subsec_style))


def _body(story, styles, text: str) -> None:
    body_style = styles.get("BodyText2") or styles["BodyText"]
    story.append(Paragraph(text, body_style))


def _table(
    story, styles,
    header: list[str], rows: list[list[Any]],
    col_widths: list[float],
) -> None:
    header_style = styles.get("TableHeader") or styles["BodyText"]
    cell_style = styles.get("TableCell") or styles["BodyText"]

    table_rows: list[list[Paragraph]] = [
        [Paragraph(f"<b>{h}</b>", header_style) for h in header],
    ]
    for r in rows:
        rendered_row: list[Paragraph] = []
        for c in r:
            if isinstance(c, Paragraph):
                rendered_row.append(c)
            else:
                rendered_row.append(Paragraph(str(c) if c is not None else "—", cell_style))
        table_rows.append(rendered_row)

    t = Table(table_rows, colWidths=col_widths, hAlign="LEFT", repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), COLORS["primary"]),
        ("TEXTCOLOR", (0, 0), (-1, 0), COLORS["white"]),
        ("GRID", (0, 0), (-1, -1), 0.4, COLORS["light_accent"]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 3),
        ("RIGHTPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(t)


# ====================================================================
# ANHANG A.1 - CVSS-TABELLE
# ====================================================================
def _hygiene_level_label(level: str | None) -> str:
    return {
        "low":    "niedrig",
        "medium": "mittel",
        "high":   "hoch",
    }.get((level or "").lower(), level or "—")


def _hygiene_reason(finding: dict[str, Any]) -> str:
    """Kurze Begruendung pro Hygiene-Eintrag (Doc 02 Anhang A.2)."""
    pid = (finding.get("policy_id") or "").upper()
    ft = (finding.get("finding_type") or "").lower()
    impact = (finding.get("impact") or "").strip()
    if impact and impact != "—":
        # Erste Satzhaelfte des Impact-Felds reicht meist
        first_sentence = impact.split(".")[0].strip()
        if first_sentence:
            return first_sentence
    if pid.startswith("SP-HDR"):
        return "Fehlender Schutz-Header"
    if pid.startswith("SP-CSP"):
        return "CSP-Konfiguration schwaecht XSS-Schutz"
    if pid.startswith("SP-COOK"):
        return "Cookie-Flag fehlt, erleichtert Session-Hijack"
    if "csrf" in ft:
        return "Fehlende CSRF-Absicherung"
    return "Best-Practice-Abweichung"


def _build_appendix_a(story, styles, data: dict[str, Any]) -> None:
    """A.1 CVSS-Tabelle + A.2 Hygiene-Tabelle (Doc 02 Anhang A)."""
    layer1 = data.get("layer1") or {}
    split = layer1.get("hygiene_split") or {
        "cvss": [], "hygiene": [],
    }
    # Falls Layer1 nicht greifbar: fallback ueber findings + scale
    if not split.get("cvss") and not split.get("hygiene"):
        for f in data.get("findings") or []:
            (split["hygiene"] if (f.get("scale") or "cvss") == "hygiene"
             else split["cvss"]).append(f)

    _section(story, styles, "ANHANG A - CVSS-REFERENZ &amp; HYGIENE-SKALA")
    story.append(Spacer(1, 3 * mm))
    _body(
        story, styles,
        "Befunde werden in zwei klar getrennten Skalen ausgewiesen: "
        "<b>CVSS v3.1</b> fuer ausnutzbare Schwachstellen, "
        "<b>VECTISCAN-Hygiene-Skala</b> fuer Best-Practice-Abweichungen ohne "
        "ausnutzbaren Vektor. Diese Trennung vermeidet rechnerisch unklare "
        "Werte (z.B. CVSS 0.0 trotz Auswirkung).",
    )
    story.append(Spacer(1, 3 * mm))

    # ---- A.1 CVSS -------------------------------------------------
    _subsection(story, styles, "A.1 - Befunde mit CVSS v3.1")
    story.append(Spacer(1, 2 * mm))
    cvss_findings = split.get("cvss") or []
    if cvss_findings:
        rows = []
        for f in cvss_findings:
            rows.append([
                f.get("external_id") or f.get("id") or "—",
                f.get("title") or "—",
                (f.get("severity") or "").upper(),
                f.get("cvss_score") if f.get("cvss_score") not in (None, "") else "—",
                f.get("cvss_vector") or "—",
                f.get("cwe") or "—",
            ])
        _table(
            story, styles,
            ["ID", "Titel", "Severity", "Score", "Vektor", "CWE"],
            rows,
            [18 * mm, 56 * mm, 18 * mm, 14 * mm, 50 * mm, 14 * mm],
        )
    else:
        _body(story, styles, "<i>(keine Befunde mit CVSS-Skala in diesem Report)</i>")
    story.append(Spacer(1, 4 * mm))

    # ---- A.2 Hygiene ---------------------------------------------
    _subsection(story, styles, "A.2 - Befunde mit VECTISCAN-Hygiene-Skala")
    story.append(Spacer(1, 2 * mm))
    hygiene_findings = split.get("hygiene") or []
    if hygiene_findings:
        rows = []
        for f in hygiene_findings:
            level = f.get("hygiene_level")
            rows.append([
                f.get("external_id") or f.get("id") or "—",
                f.get("title") or "—",
                _hygiene_level_label(level),
                _hygiene_reason(f),
            ])
        _table(
            story, styles,
            ["ID", "Titel", "Hygiene-Stufe", "Begruendung"],
            rows,
            [18 * mm, 65 * mm, 22 * mm, 65 * mm],
        )
    else:
        _body(story, styles, "<i>(keine Befunde mit Hygiene-Skala in diesem Report)</i>")
    story.append(PageBreak())


# ====================================================================
# ANHANG B - SERVICE-INVENTAR
# ====================================================================
_SERVICE_RECOMMENDATION_HINT: dict[int, str] = {
    21:    "Klartext-FTP - SFTP einsetzen, Port schliessen",
    23:    "Telnet - nicht mehr produktiv einsetzen",
    25:    "SMTP - nur ausgehender Mailverkehr; eingehend STARTTLS pflicht",
    53:    "DNS - Open-Resolver-Check; rekursive Anfragen begrenzen",
    80:    "HTTP - auf HTTPS umstellen, 301-Redirect",
    110:   "POP3 - durch IMAPS/POP3S ersetzen",
    143:   "IMAP - durch IMAPS ersetzen",
    389:   "LDAP - LDAPS bzw. STARTTLS verlangen",
    443:   "HTTPS - TR-03116-Konformitaet pruefen",
    465:   "SMTPS - aktiv",
    587:   "SUBMISSION - aktiv mit STARTTLS",
    993:   "IMAPS - aktiv",
    995:   "POP3S - aktiv",
    1433:  "MSSQL - intern halten oder Firewall-Regel",
    1521:  "Oracle - intern halten oder Firewall-Regel",
    3306:  "MariaDB/MySQL - intern halten oder Firewall-Regel",
    3389:  "RDP - nur ueber VPN/MFA erreichbar machen",
    5432:  "PostgreSQL - intern halten oder Firewall-Regel",
    5900:  "VNC - nur ueber VPN; Klartext-Protokoll",
    6379:  "Redis - intern halten, Auth aktivieren",
    8080:  "HTTP-Alt - meist Reverse-Proxy / Tomcat",
    8443:  "HTTPS-Alt - TLS pruefen",
    9200:  "Elasticsearch - intern halten, Auth",
    11211: "Memcached - intern halten",
    27017: "MongoDB - intern halten, Auth",
}


def _service_recommendation_text(port: int, finding_refs: list[str]) -> str:
    """Liefert pro Port den ersten Empfehlungs-Hinweis + ggf. Finding-IDs."""
    hint = _SERVICE_RECOMMENDATION_HINT.get(port, "—")
    if finding_refs:
        return f"siehe {', '.join(finding_refs[:3])}"
    return hint


def _findings_by_port_host(
    findings: list[dict[str, Any]],
) -> dict[tuple[str, int], list[str]]:
    """Map (host_ish, port) -> [finding_ids] fuer Anhang-B-Cross-References."""
    out: dict[tuple[str, int], list[str]] = {}
    import re
    for f in findings:
        fid = f.get("external_id") or f.get("id")
        if not fid:
            continue
        # Host-Kandidaten: vhost, host, host_ip, affected
        host_candidates: list[str] = []
        for k in ("vhost", "fqdn", "host", "host_ip", "ip"):
            v = f.get(k)
            if v:
                host_candidates.append(str(v))
        aff = f.get("affected")
        if isinstance(aff, str):
            host_candidates.append(aff.split(":")[0].strip())
        elif isinstance(aff, list):
            for a in aff:
                if isinstance(a, str):
                    host_candidates.append(a.split(":")[0].strip())

        # Port-Kandidaten
        ports: list[int] = []
        if f.get("port"):
            try:
                ports.append(int(f["port"]))
            except (ValueError, TypeError):
                pass
        if isinstance(aff, str):
            for m in re.finditer(r":(\d{1,5})\b", aff):
                try:
                    ports.append(int(m.group(1)))
                except ValueError:
                    pass

        for host in host_candidates:
            for port in ports:
                out.setdefault((host, port), [])
                if fid not in out[(host, port)]:
                    out[(host, port)].append(fid)
    return out


def _build_appendix_b(story, styles, data: dict[str, Any]) -> None:
    """Anhang B Service-Inventar (Doc 02 Seite 14)."""
    cards = data.get("service_cards") or []
    if not cards:
        return

    findings = data.get("findings") or []
    f_by_port = _findings_by_port_host(findings)

    _section(story, styles, "ANHANG B - SERVICE-INVENTAR")
    story.append(Spacer(1, 3 * mm))
    _body(
        story, styles,
        "Pro Host eine kompakte Liste aller von aussen erreichbaren Ports + "
        "Services. Diese Tabelle ist die Grundlage fuer jeden Befund, der "
        "einen Port nennt - der Massnahmenplan referenziert ausschliesslich "
        "Eintraege, die hier auftauchen.",
    )
    story.append(Spacer(1, 3 * mm))

    # Hosts mit Ports zuerst, danach eine kompakte Sammel-Zeile mit allen
    # Hosts ohne erreichbare Ports (verhindert Whitespace-Seitenfortsaetze).
    empty_hosts: list[str] = []
    for card in cards:
        host_label = card.get("host_label", "?")
        host_ip = card.get("ip") or ""

        ports = card.get("ports") or []
        if not ports:
            empty_hosts.append(host_label)
            continue

        _subsection(story, styles, host_label)
        story.append(Spacer(1, 1 * mm))

        rows = []
        for entry in ports:
            # ports: list[(port, service_label, color)]
            port = entry[0] if isinstance(entry, (list, tuple)) else entry.get("port")
            svc = (entry[1] if isinstance(entry, (list, tuple)) and len(entry) > 1
                   else entry.get("service")) or ""
            try:
                port_int = int(port)
            except (ValueError, TypeError):
                continue

            refs: list[str] = []
            # Match per (host_ip, port) ODER (host_label, port)
            for k in ((host_ip, port_int), (host_label, port_int)):
                refs = f_by_port.get(k) or refs
                if refs:
                    break
            rec = _service_recommendation_text(port_int, refs)
            rows.append([
                str(port_int), svc, "—",  # Version-Spalte (nicht zuverlaessig vorhanden)
                rec,
            ])

        _table(
            story, styles,
            ["Port", "Service", "Version", "Empfehlung / Querverweis"],
            rows,
            [16 * mm, 30 * mm, 22 * mm, 102 * mm],
        )
        story.append(Spacer(1, 3 * mm))

    # Sammel-Zeile fuer alle Hosts ohne erreichbare Ports
    if empty_hosts:
        story.append(Spacer(1, 2 * mm))
        _body(
            story, styles,
            "<i>Folgende Hosts haben in der externen Pruefung keine "
            f"erreichbaren Ports gezeigt: {', '.join(empty_hosts)}.</i>",
        )

    story.append(PageBreak())


# ====================================================================
# ANHANG C - EINGESETZTE TOOLS + KONFIDENZ
# ====================================================================
# Konfidenz-Spalte: deterministische Bewertung pro Tool. Stand 2026-05-13.
# Wertet die typische Aussagekraft des Tools im VectiScan-Kontext.
_TOOL_CONFIDENCE: dict[str, str] = {
    "nmap":                "hoch (Service-Detection mit -sV)",
    "webtech":             "mittel-hoch (Signatur-basiert)",
    "wafw00f":             "mittel",
    "subfinder":           "hoch (passive)",
    "crt.sh / certspotter": "hoch (CT-Logs autoritativ)",
    "dnsx":                "hoch",
    "httpx":               "hoch",
    "gobuster":            "mittel",
    "testssl.sh":          "sehr hoch (autoritative TLS-Analyse)",
    "ZAP Spider":          "mittel",
    "ZAP Ajax Spider":     "mittel",
    "ZAP Active Scan":     "mittel-hoch",
    "ffuf":                "mittel",
    "feroxbuster":         "mittel",
    "wpscan":              "hoch (CVE-Datenbank-Match)",
    "NVD/EPSS/KEV":        "hoch (autoritative Threat-Intel)",
}


def _tool_confidence(name: str) -> str:
    return _TOOL_CONFIDENCE.get(name, "mittel")


def _build_appendix_c(story, styles, data: dict[str, Any]) -> None:
    """Anhang C Eingesetzte Tools (Doc 02 Seite 14)."""
    # Quelle: hartcodiert in report_mapper.SCAN_TOOLS; falls scan_meta
    # tool_versions liefert, merge eingelesen wir die.
    try:
        from reporter.report_mapper import SCAN_TOOLS
    except ImportError:
        SCAN_TOOLS = []

    _section(story, styles, "ANHANG C - EINGESETZTE TOOLS")
    story.append(Spacer(1, 3 * mm))
    _body(
        story, styles,
        "Die folgende Liste zeigt die im Scan aktiven Tools mit Phase und "
        "der typischen Konfidenz ihrer Aussage im VectiScan-Kontext.",
    )
    story.append(Spacer(1, 3 * mm))

    rows = []
    for tool in SCAN_TOOLS:
        rows.append([
            tool.get("tool", "—"),
            tool.get("phase", "—"),
            tool.get("description", "—"),
            _tool_confidence(tool.get("tool", "")),
        ])
    _table(
        story, styles,
        ["Tool", "Phase", "Funktion", "Konfidenz"],
        rows,
        [32 * mm, 22 * mm, 70 * mm, 46 * mm],
    )
    story.append(PageBreak())


# ====================================================================
# ANHANG D - COMPLIANCE-MAPPING
# ====================================================================
def _build_appendix_d(story, styles, data: dict[str, Any]) -> None:
    """Anhang D systematisches Compliance-Mapping pro Befund.

    Quelle ist `report_data["compliance_mappings"]` (von _augment_for_v2
    befuellt). Pro Befund eine Zeile mit den vier Frameworks.
    """
    findings = data.get("findings") or []
    mappings = data.get("compliance_mappings") or {}
    if not findings:
        return

    _section(story, styles, "ANHANG D - COMPLIANCE-MAPPING")
    story.append(Spacer(1, 3 * mm))
    _body(
        story, styles,
        "Pro Befund eine Zuordnung auf die vier relevanten Frameworks. "
        "Diese Tabelle macht aus dem Pentest-Bericht ein nutzbares Dokument "
        "fuer Audits und Versicherungsfragen.",
    )
    story.append(Spacer(1, 3 * mm))

    rows = []
    for f in findings:
        fid = f.get("external_id") or f.get("id") or "—"
        m = mappings.get(fid) if isinstance(mappings, dict) else None
        if not isinstance(m, dict):
            # Keine Mapping-Daten -> "nicht definiert"
            rows.append([
                fid,
                (f.get("title") or "—")[:60],
                "nicht definiert", "nicht definiert",
                "nicht definiert", "nicht definiert",
            ])
            continue
        rows.append([
            fid,
            (f.get("title") or "—")[:60],
            m.get("nis2") or "—",
            m.get("bsi") or "—",
            m.get("iso27001") or "—",
            m.get("dsgvo") or "—",
        ])
    _table(
        story, styles,
        ["ID", "Befund", "NIS2 / §30 BSIG", "BSI-Grundschutz",
         "ISO 27001", "DSGVO"],
        rows,
        [18 * mm, 40 * mm, 28 * mm, 25 * mm, 18 * mm, 35 * mm],
    )
    story.append(PageBreak())


# ====================================================================
# ANHANG E - METHODISCHE FILTERUNGEN
# ====================================================================
def _aggregate_filter_reasons(additional: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Aggregiert (reason, tool) und zaehlt die Vorkommen."""
    from collections import defaultdict
    bucket: dict[tuple[str, str], int] = defaultdict(int)
    for entry in additional:
        if not isinstance(entry, dict):
            continue
        reason = (entry.get("reason") or entry.get("filter_reason")
                  or "ohne Begruendung")
        tool = entry.get("tool") or entry.get("source") or "—"
        bucket[(str(reason), str(tool))] += 1
    items = []
    for (reason, tool), n in bucket.items():
        items.append({"reason": reason, "tool": tool, "count": n})
    items.sort(key=lambda x: (-x["count"], x["reason"], x["tool"]))
    return items


def _build_appendix_e(story, styles, data: dict[str, Any]) -> None:
    """Anhang E methodische Filterungen + Filter-Statistik (Doc 02)."""
    stats = data.get("methodology_stats") or {}
    filtered_count = int(stats.get("filtered_count") or 0)
    selected_count = int(stats.get("selected_count") or 0)
    filter_rate = stats.get("filter_rate_pct") or 0.0

    additional = data.get("additional_findings") or []

    _section(story, styles, "ANHANG E - METHODISCHE FILTERUNGEN")
    story.append(Spacer(1, 3 * mm))
    total_raw = filtered_count + selected_count
    if total_raw > 0:
        _body(
            story, styles,
            f"Waehrend dieses Scans wurden <b>{total_raw} Roh-Befunde</b> von "
            f"den eingesetzten Tools erzeugt. Nach Korrelation, "
            f"False-Positive-Filterung und Severity-Bewertung verbleiben "
            f"<b>{selected_count} validierte Befunde</b> "
            f"(Filterrate {filter_rate}%).",
        )
    else:
        _body(
            story, styles,
            "Fuer diesen Scan liegen keine Filter-Statistiken vor.",
        )
    story.append(Spacer(1, 3 * mm))

    # Aufschluesselung pro Filter-Grund
    if additional:
        _subsection(story, styles, "E.1 - Aufschluesselung pro Filter-Grund")
        story.append(Spacer(1, 2 * mm))
        reasons = _aggregate_filter_reasons(additional)
        rows = [[r["reason"], r["tool"], str(r["count"])] for r in reasons]
        _table(
            story, styles,
            ["Filter-Grund", "Tool", "Anzahl"],
            rows,
            [85 * mm, 40 * mm, 18 * mm],
        )
        story.append(Spacer(1, 3 * mm))

    # Erklaerung warum gefiltert wurde
    _subsection(story, styles, "E.2 - Was wurde typischerweise gefiltert?")
    story.append(Spacer(1, 2 * mm))
    _body(
        story, styles,
        "Gefilterte Findings betreffen typischerweise:"
        "<br/>&nbsp;&nbsp;&#8226; <b>Doppelmeldungen</b> ueber mehrere Tools "
        "(z.B. nmap + nuclei erkennen denselben Port);"
        "<br/>&nbsp;&nbsp;&#8226; <b>generische Hinweise ohne praktische "
        "Auswirkung</b> (z.B. 'Server reagiert mit HTTP 200');"
        "<br/>&nbsp;&nbsp;&#8226; <b>Findings unterhalb der Bagatell-Grenze</b>"
        "<br/>&nbsp;&nbsp;&#8226; <b>False-Positives</b> der KI-Korrelation "
        "(Phase 3 Cross-Tool-Confidence-Boost mit Sonnet 4.6).",
    )
    story.append(Spacer(1, 2 * mm))
    _body(
        story, styles,
        "Der vollstaendige Roh-Output ist auf Anforderung beim Auftraggeber "
        "verfuegbar (Aufbewahrungsfrist 90 Tage).",
    )
    story.append(PageBreak())


# ====================================================================
# ANHANG F - WIEDERHOLUNGSEMPFEHLUNG + HAFTUNGSAUSSCHLUSS
# ====================================================================
_TRIGGER_LIST = (
    "jeder groesseren Architekturaenderung (neue Hosts, neue Domains, "
    "Migration zwischen Hostern);",
    "jedem CMS-Major-Upgrade oder Framework-Wechsel;",
    "jeder Freischaltung eines neuen extern erreichbaren Dienstes;",
    "jedem Verdacht auf einen Sicherheitsvorfall (Phishing-Welle, "
    "Account-Kompromittierung, ungewoehnliche Logs);",
    "Vorhandensein eines neu bekannt gewordenen CVEs in einer der "
    "eingesetzten Komponenten (relevant: NVD-Watch oder Hersteller-Feed);",
    "Vorbereitung auf einen NIS2/BSI/ISO-Audit.",
)


def _build_appendix_f(story, styles, data: dict[str, Any]) -> None:
    """Anhang F Haftungsausschluss + Wiederholungsempfehlung."""
    scope = data.get("scope_meta") or {}
    scan_date = scope.get("scan_date") or "?"

    _section(story, styles, "ANHANG F - WIEDERHOLUNGSEMPFEHLUNG &amp; HAFTUNGSAUSSCHLUSS")
    story.append(Spacer(1, 3 * mm))

    _subsection(story, styles, "F.1 - Wiederholungsempfehlung")
    story.append(Spacer(1, 2 * mm))
    _body(
        story, styles,
        "<b>12 Monate</b> als Default-Intervall fuer einen erneuten "
        "Vollscan im selben Paket. Zusaetzlich ist eine Wiederholung "
        "empfohlen nach:",
    )
    triggers_html = "<br/>".join(
        f"&nbsp;&nbsp;&#8226; {t}" for t in _TRIGGER_LIST
    )
    _body(story, styles, triggers_html)
    story.append(Spacer(1, 4 * mm))

    _subsection(story, styles, "F.2 - Geltungsdauer")
    story.append(Spacer(1, 2 * mm))
    _body(
        story, styles,
        f"Dieser Bericht bildet den Zustand vom <b>{scan_date}</b> ab. "
        f"Bereits am Folgetag koennen neue Schwachstellen bekannt geworden "
        f"sein, die zum Scan-Zeitpunkt noch nicht oeffentlich waren. Die "
        f"Pruefergebnisse sind eine Momentaufnahme - sie ersetzen keine "
        f"kontinuierliche Ueberwachung.",
    )
    story.append(Spacer(1, 4 * mm))

    _subsection(story, styles, "F.3 - Haftungsausschluss")
    story.append(Spacer(1, 2 * mm))
    _body(
        story, styles,
        "Die Pruefung erfolgte mit der gebotenen Sorgfalt nach dem aktuellen "
        "Stand der Technik. Eine vollstaendige Erkennung aller theoretisch "
        "moeglichen Schwachstellen ist mit einem externen automatischen Scan "
        "nicht zu gewaehrleisten. Insbesondere Insider-Bedrohungen, "
        "Konfigurationsfehler hinter Authentifizierungs-Stufen und Zero-Day-"
        "Schwachstellen koennen ueber diesen Scan-Typ nicht abschliessend "
        "ausgeschlossen werden.",
    )


# ====================================================================
# ENTRY-POINT
# ====================================================================
def build_appendix(story, styles, data: dict[str, Any]) -> None:
    """Rendert alle Anhaenge A-F."""
    data = data or {}

    _build_appendix_a(story, styles, data)
    _build_appendix_b(story, styles, data)
    _build_appendix_c(story, styles, data)
    _build_appendix_d(story, styles, data)
    _build_appendix_e(story, styles, data)
    _build_appendix_f(story, styles, data)
