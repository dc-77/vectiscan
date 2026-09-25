# -*- coding: utf-8 -*-
"""Befundspezifischer Nachweis: was die Regel getroffen hat, nicht was das Werkzeug sagte.

Bis S6 war der Nachweis eines Befunds die Evidenz des tragenden Fakts plus die
Evidenz aller in ``evidence: [...]`` genannten Bereiche. Bei ``evidence: [http]``
war das die Zusammenfassungszeile des ``header_check``
(``erreichbar=ja score=1/7 server=Apache``), und dieselbe Zeile stand deshalb in
sieben verschiedenen Befunden. Header-Namen, REST-Adresse oder Zertifikatsdaten
fehlten dagegen ganz, und ein Administrator konnte keinen Befund nachvollziehen
(spec/08 Punkt 3).

S6b-2 (spec/09 Q7): Der Nachweis ist die Evidenz der Fakten, auf die die getroffene Regel
sieht, je Fakt eine Zeile. Welche Fakten das sind, sagen die Attributpfade ihrer Ausdruecke
(``when``, ``applicable_when``, ``item_when``; ``Expr.paths``). Damit steht bei DNSSEC die
Zeile aus ``dns_security`` und nicht mehr die SPF/DMARC-Zeile aus ``dns_records``. Der
tragende Wert wird nie gekuerzt (vorher "max-age...", "Ket..."); Listen enden mit
"und N weitere". Bezeichnungen und Werte stehen auf Deutsch mit Umlauten statt als
Rohbezeichner ("gueltig_bis", "Pflegestatus=unknown", "pre_128cipher").

Der Bereich ergibt sich aus dem ``scope`` der Pruefung; eine Pruefung kann ihn
mit ``evidence_detail`` ueberschreiben.
"""
from __future__ import annotations

from typing import Any, Callable, Iterable, Optional

from reporter.catalog import tables as _T
from reporter.catalog.schema import EvidenceRef
from reporter.facts.serialize import kv

# Obergrenze einer Nachweiszeile. Sie greift nur als Sicherheitsnetz gegen Rohtext; die
# Listen darin sind vorher auf wenige Eintraege mit "und N weitere" gekuerzt.
DETAIL_MAX = 2000
LIST_MAX = 6

# Bereiche, deren Fakt-Evidenz ein woertlicher Werkzeugauszug ist (nmap-Zeile,
# testssl-Ausgabe) und deshalb zusaetzlich zur Detailzeile stehenbleibt. Fuer ``http``,
# ``dns``, ``fqdn`` und ``passive`` ist die Detailzeile der vollstaendige Nachweis.
KEEP_FACT_EVIDENCE: frozenset[str] = frozenset({
    "service", "threat",
})

# Trenner der Angaben in einer Nachweiszeile. Werte enthalten Semikolons (CSP) und
# Leerzeichen; der Punkt in der Mitte kommt in Werkzeugwerten praktisch nicht vor. Ueber ihn
# fuehrt ``merge_parts`` die Zeilen mehrerer Regeln zu einer Zeile je Fakt zusammen.
PART_SEP = " · "

# Werte, die als Rohbezeichner aus den Werkzeugen kommen, in Kundensprache.
# S6b-2 (spec/09 Q7): Risiko und Konfidenz der ZAP-Meldung in Kundensprache.
ZAP_LEVEL_TEXT: dict[str, str] = {"High": "hoch", "Medium": "mittel", "Low": "niedrig",
                                  "Informational": "Information", "Confirmed": "bestätigt"}
ZAP_ACTIVE_IDS: frozenset[str] = frozenset(pid for pid, _ in _T.ZAP_ACTIVE)

VALUE_TEXT: dict[str, str] = {
    # Lebenszyklus
    "eol": "ohne Herstellerpflege", "supported": "gepflegt", "unknown": "unbekannt",
    # WordPress-Kernstand (wpscan)
    "outdated": "nicht die neueste Version", "insecure": "unsicher", "latest": "aktuell",
    # testssl-Urteil
    "vulnerable": "verwundbar", "potential": "möglicherweise verwundbar",
    "not_tested": "nicht geprüft",
    # Uebernahmerisiko verwaister Eintraege
    "high": "hoch", "medium": "mittel", "low": "gering",
}

# testssl-Kennungen schwacher Verfahren, die sonst roh im Nachweis standen.
CIPHER_TEXT: dict[str, str] = {
    "pre_128cipher": "Verfahren unter 128 Bit", "null": "Verfahren ohne Verschlüsselung",
    "anon": "anonyme Verfahren", "export": "Exportverfahren", "low": "schwache Verfahren",
    "3des": "3DES", "rc4": "RC4", "des": "DES", "idea": "IDEA",
    "cbc": "CBC-Verfahren", "low_grade": "Verfahren niedriger Stärke",
}
CIPHER_TEXT["low"] = "Verfahren niedriger Stärke"


def value_text(value: Any) -> Any:
    if isinstance(value, str):
        return VALUE_TEXT.get(value, value)
    return value


def liste(values: Iterable[Any], limit: int = LIST_MAX) -> Optional[str]:
    """Aufzaehlung mit hoechstens ``limit`` Eintraegen und "und N weitere"."""
    items = [str(v) for v in values if v not in (None, "")]
    if not items:
        return None
    if len(items) <= limit:
        return ", ".join(items)
    return ", ".join(items[:limit]) + f" und {len(items) - limit} weitere"


def _zeile(pairs: list[tuple[str, Any]]) -> str:
    """Eine Nachweiszeile: erste Angabe die Fundstelle, dann "Bezeichnung: Wert"."""
    parts: list[str] = []
    for name, value in pairs:
        if value is None or value == "" or value == [] or value == {}:
            continue
        if isinstance(value, bool):
            text = "ja" if value else "nein"
        elif isinstance(value, (list, tuple, set)):
            text = liste(value, LIST_MAX) or ""
            if not text:
                continue
        else:
            text = " ".join(str(value).split())
        parts.append(f"{name}: {text}" if name else text)
    return kv([("", PART_SEP.join(parts))], DETAIL_MAX)


def merge_parts(lines: Iterable[str]) -> str:
    """Nachweiszeilen desselben Fakts zu einer Zeile, jede Angabe einmal (spec/09 Q7)."""
    out: list[str] = []
    for line in lines:
        for part in line.split(PART_SEP):
            if part and part not in out:
                out.append(part)
    return PART_SEP.join(out)


def _ref(fact: Any, tool: str | None = None) -> tuple[str, str, str]:
    """(fact_id, Werkzeug, Fundstelle) des tragenden Fakts, bei ``tool`` dessen Evidenz."""
    fid = getattr(fact, "id", "") or ""
    evs = getattr(fact, "evidence", None) or []
    first = next((e for e in evs if tool and getattr(e, "tool", "") == tool), None)
    if first is None and not tool:
        first = evs[0] if evs else None
    werkzeug = tool or (getattr(first, "tool", "") if first else "") or getattr(fact, "source", "") or ""
    ref = getattr(first, "ref", "") if first else ""
    # Rueckfall-Fundstellen aus der Datenbank ("scan_results:testssl:...") sind kein Ort,
    # an dem ein Administrator nachsehen kann; sie stehen nicht im Bericht.
    if ref.startswith("scan_results:"):
        ref = ""
    return fid, werkzeug, ref


def _line(fact: Any, text: str, tool: str | None = None,
          fact_id: str | None = None) -> list[EvidenceRef]:
    if not text:
        return []
    fid, werkzeug, ref = _ref(fact, tool)
    return [EvidenceRef(fact_id=fact_id or fid, tool=werkzeug, ref=ref, excerpt=text)]


def auszug(text: str) -> str:
    """Woertlicher Werkzeugauszug, dessen Ende die Faktenschicht abgeschnitten hat.

    Statt der drei Punkte sagt der Text, dass es ein Auszug ist (spec/09 Q7).
    """
    if text.endswith("..."):
        return text[:-3].rstrip() + " (Auszug)"
    return text


def _touches(paths: frozenset[str], *prefixes: str) -> bool:
    return any(p == pre or p.startswith(pre + ".") or p.startswith(pre + "[")
               for p in paths for pre in prefixes)


# ---------------------------------------------------------------- je Bereich

def _http(item: Any, ictx: dict[str, Any], paths: frozenset[str]) -> list[EvidenceRef]:
    """Die Header, auf die die Regel sieht, mit Adresse (spec/08 Punkt 3, spec/09 Q7)."""
    http = item.fact
    alle = not paths
    paare: list[tuple[str, Any]] = [("", f"{http.fqdn or http.host_ip}")]
    if http.url:
        paare.append(("Adresse", http.url))
    if alle or _touches(paths, "http.security_headers"):
        fehlend = sorted(name for name, h in (http.security_headers or {}).items()
                         if not getattr(h, "present", False))
        if fehlend:
            paare.append(("fehlende Header", liste(fehlend, 10)))
    if alle or _touches(paths, "http.csp"):
        if http.csp is not None and http.csp.present and http.csp.value:
            paare.append(("Content-Security-Policy", http.csp.value))
        elif http.csp is not None and not http.csp.present:
            paare.append(("Content-Security-Policy", "nicht gesetzt"))
    if alle or _touches(paths, "http.hsts"):
        if http.hsts is not None and http.hsts.present:
            paare.append(("Strict-Transport-Security", http.hsts.raw or f"max-age={http.hsts.max_age}"))
        elif http.hsts is not None:
            paare.append(("Strict-Transport-Security", "nicht gesetzt"))
    if alle or _touches(paths, "http.server_header", "http.powered_by", "http.x_feserver"):
        if http.server_header:
            paare.append(("Server", http.server_header))
        if http.powered_by:
            paare.append(("X-Powered-By", http.powered_by))
        if http.x_feserver:
            paare.append(("X-FEServer", http.x_feserver))
    if alle or _touches(paths, "http.duplicate_headers"):
        if http.duplicate_headers:
            paare.append(("doppelt gesetzt", liste(http.duplicate_headers)))
    if len(paare) <= 2 and not paths:
        return []
    return _line(http, _zeile(paare), tool="header_check")


def _http_alert(item: Any, ictx: dict[str, Any], paths: frozenset[str]) -> list[EvidenceRef]:
    """Die ZAP-Meldung selbst: Name, Kennung, Adresse, Beleg, Konfidenz (Issue #15).

    S6b-2 (spec/09 Q14): das Werkzeug nennt den Lauf, aus dem die Meldung stammt; eine
    Meldung des Passivscanners heisst nicht mehr "zap_active".
    """
    alert = item.obj
    http = item.fact
    paare: list[tuple[str, Any]] = [
        ("", alert.name),
        ("ZAP-Kennung", alert.plugin_id),
        ("Risiko", ZAP_LEVEL_TEXT.get(alert.risk or "", alert.risk)),
        ("Konfidenz", ZAP_LEVEL_TEXT.get(alert.confidence or "", alert.confidence)),
        ("Adresse", alert.url or (alert.urls_sample[0] if alert.urls_sample else None)),
        ("Beleg", alert.evidence),
        ("CWE", alert.cwe),
        ("betroffene Adressen", alert.count if alert.count and alert.count > 1 else None),
    ]
    run = getattr(alert, "run", None)
    if run is None:
        # Fakten ohne Laufangabe (vor 1.0.7): Regeln des aktiven Scanners sind aktiv.
        run = "active" if str(alert.plugin_id) in ZAP_ACTIVE_IDS else "passive"
    tool = "zap_active" if run == "active" else "zap"
    return [EvidenceRef(fact_id=getattr(http, "id", "") or "", tool=tool,
                        ref="", excerpt=_zeile(paare))]


def _http_wordpress(item: Any, ictx: dict[str, Any], paths: frozenset[str]) -> list[EvidenceRef]:
    """Benutzernamen und Kernstand einer WordPress-Installation laut wpscan.

    S6b-2 (spec/09 Teil 2 DB, CA): die Fundstelle der Benutzernamen ist die Adresse, ueber
    die wpscan sie fand, nicht fest ``/wp-json/wp/v2/users``.
    """
    http = item.fact
    wp = http.wordpress
    if wp is None:
        return []
    paare: list[tuple[str, Any]] = [("", f"{http.fqdn or http.host_ip}")]
    if wp.users and (not paths or _touches(paths, "http.wordpress.users")):
        paare.append(("Benutzernamen", liste(sorted(wp.users))))
        if wp.users_found_by:
            paare.append(("gefunden über", liste(wp.users_found_by, 3)))
    if not paths or _touches(paths, "http.wordpress.version_status", "http.wordpress.core_vulnerabilities"):
        paare.append(("WordPress", wp.version))
        paare.append(("Veröffentlichung", wp.release_date))
        paare.append(("Kernstand", value_text(wp.version_status)))
        if wp.core_vulnerabilities is not None:
            paare.append(("bekannte Kern-Schwachstellen", wp.core_vulnerabilities))
    return _line(http, _zeile(paare), tool="wpscan")


def _http_cookie(item: Any, ictx: dict[str, Any], paths: frozenset[str]) -> list[EvidenceRef]:
    cookie = item.obj
    http = item.fact
    fehlt = [n for n, on in (("Secure", cookie.secure), ("HttpOnly", cookie.httponly)) if not on]
    if not cookie.samesite:
        fehlt.append("SameSite")
    return _line(http, _zeile([("", f"{http.fqdn or http.host_ip}"),
                               ("Cookie", cookie.name), ("ohne", liste(fehlt)),
                               ("SameSite", cookie.samesite)]), tool="header_check")


def _http_path(item: Any, ictx: dict[str, Any], paths: frozenset[str]) -> list[EvidenceRef]:
    path = item.obj
    return _line(item.fact, _zeile([("Adresse", path.url), ("Status", path.status),
                                    ("Länge", path.length)]))


_CERT_FIELDS: tuple[tuple[str, str, str], ...] = (
    # (Pfad, Bezeichnung, Attribut)
    ("tls.cert.expired", "abgelaufen", "expired"),
    ("tls.cert.days_left", "Restlaufzeit in Tagen", "days_left"),
    ("tls.cert.chain_ok", "Vertrauenskette vollständig", "chain_ok"),
    ("tls.cert.mismatch", "Name passt nicht", "mismatch"),
    ("tls.cert.self_signed", "selbstsigniert", "self_signed"),
)


def _tls(item: Any, ictx: dict[str, Any], paths: frozenset[str]) -> list[EvidenceRef]:
    """Zertifikat, Protokolle und Verfahren des Dienstes, soweit die Regel darauf sieht."""
    tls = item.fact
    alle = not paths
    paare: list[tuple[str, Any]] = [("", f"{tls.fqdn or tls.host_ip}:{tls.port}")]
    cert = tls.cert
    if cert is not None and (alle or _touches(paths, "tls.cert")):
        paare += [("Zertifikat für", cert.cn), ("weitere Namen", liste(cert.san, 4)),
                  ("Aussteller", cert.issuer), ("gültig bis", (cert.not_after or "")[:10] or None)]
        for pfad, label, attr in _CERT_FIELDS:
            if alle or _touches(paths, pfad):
                paare.append((label, getattr(cert, attr, None)))
    if alle or _touches(paths, "tls.protocols"):
        aktiv = sorted(name.replace("TLS1.", "TLS 1.") for name, on in (tls.protocols or {}).items() if on is True)
        if aktiv:
            paare.append(("Protokolle", liste(aktiv)))
    if alle or _touches(paths, "tls.ciphers_weak"):
        if tls.ciphers_weak:
            paare.append(("schwache Verfahren", liste(CIPHER_TEXT.get(c, c) for c in tls.ciphers_weak)))
    if alle or _touches(paths, "tls.fallback_scsv"):
        if tls.fallback_scsv is not None:
            paare.append(("Schutz vor Rückstufung", tls.fallback_scsv))
    if alle or _touches(paths, "tls.hsts"):
        if tls.hsts is not None and tls.hsts.max_age is not None:
            paare.append(("HSTS max-age", tls.hsts.max_age))
    if tls.assigned_from:
        paare.append(("geprüft über", tls.assigned_from))
    return _line(tls, _zeile(paare), tool="testssl" if tls.source == "testssl" else None)


def _tls_vuln(item: Any, ictx: dict[str, Any], paths: frozenset[str]) -> list[EvidenceRef]:
    """Das Urteil von testssl zu genau dieser Pruefung, mit seiner Ausgabezeile."""
    from reporter.v3.tables import testssl_name

    vuln = item.obj
    tls = item.fact
    # Die CVE-Kennung steht nicht am Urteil, sondern an der Ausgabezeile
    # desselben Tests (``entries``); ohne sie waere der Nachweis dünner als die
    # Aussage des Befunds.
    eintrag = next((e for e in (tls.entries or []) if e.id == vuln.name), None)
    return _line(tls, _zeile([("", f"{tls.fqdn or tls.host_ip}:{tls.port}"),
                              ("Prüfung", testssl_name(vuln.name)), ("Urteil", value_text(vuln.status)),
                              ("CVE", liste(eintrag.cves or [eintrag.cve]) if eintrag else None),
                              ("Ausgabe", auszug(eintrag.finding) if eintrag and eintrag.finding else None)]),
                 tool="testssl", fact_id=f"{getattr(tls, 'id', '')}#{vuln.name}")


def _service(item: Any, ictx: dict[str, Any], paths: frozenset[str]) -> list[EvidenceRef]:
    svc = item.obj
    return _line(svc, _zeile([("", f"{svc.host_ip}:{svc.port}/{svc.proto}"),
                              ("Dienst", svc.service), ("Produkt", svc.product),
                              ("Version", svc.version_raw or svc.version_norm),
                              ("Server-Kennung", svc.fp_server),
                              ("Seitentitel", svc.fp_title),
                              ("Anmeldung verlangt", svc.fp_login),
                              ("TLS erzwungen", svc.tls_required),
                              ("STARTTLS", svc.starttls),
                              ("Anmeldung vor TLS gesperrt", svc.login_disabled),
                              ("Anmeldeverfahren", liste(svc.auth_mechanisms or [], 4)),
                              ("Abweisung vor der Anmeldung laut Passivquelle", svc.rejects_before_auth)]),
                 tool="nmap")


# DNS: je Teilfakt eine Zeile mit dem liefernden Werkzeug.
_DNS_PARTS: tuple[tuple[str, str], ...] = (
    ("mx", "dns_records"), ("spf", "dns_records"), ("dmarc", "dns_records"), ("dkim", "dns_records"),
    ("zone_transfer", "dns_records"), ("dnssec", "dns_security"), ("caa", "dns_security"),
    ("mta_sts", "dns_security"), ("tls_rpt", "dns_security"), ("dane", "dns_security"),
)


def _dns_part(dns: Any, part: str) -> Optional[str]:
    if part == "mx":
        return f"MX-Einträge: {liste(dns.mx, 3)}" if dns.mx else "kein MX-Eintrag"
    if part == "spf":
        return f"SPF: {dns.spf.raw}" if dns.spf is not None else "kein SPF-Eintrag"
    if part == "dmarc":
        if dns.dmarc is None or not dns.dmarc.present:
            return "kein DMARC-Eintrag"
        return f"DMARC: {dns.dmarc.raw}" if dns.dmarc.raw else f"DMARC: p={dns.dmarc.p}"
    if part == "dkim":
        if dns.dkim is None:
            return None
        if dns.dkim.selectors:
            return f"DKIM-Selektoren gefunden: {liste(dns.dkim.selectors)}"
        geprueft = len(dns.dkim.probed) if dns.dkim.probed else None
        # S6a Nachtrag (spec/07): "keiner bekannt" las sich wie "fehlt".
        return (f"DKIM: keine Selektoren gefunden, {geprueft} geprüft" if geprueft
                else "DKIM: keine Selektoren gefunden")
    if part == "zone_transfer":
        zt = dns.zone_transfer
        if zt is None or zt.allowed is None:
            return None
        return "Abruf der gesamten Zone: " + ("möglich" if zt.allowed else "abgewiesen") + \
            (f" (geprüft bei {liste(zt.ns_tested, 3)})" if zt.ns_tested else "")
    if part == "dnssec":
        if dns.dnssec is None or dns.dnssec.signed is None:
            return None
        return "DNSSEC: Zone " + ("signiert" if dns.dnssec.signed else "nicht signiert")
    if part == "caa":
        if dns.caa is None or dns.caa.present is None:
            return None
        return f"CAA-Einträge: {liste(dns.caa.records, 4)}" if dns.caa.present and dns.caa.records else \
            ("CAA-Einträge vorhanden" if dns.caa.present else "keine CAA-Einträge")
    if part == "mta_sts":
        m = dns.mta_sts
        if m is None:
            return None
        teile = ["DNS-Eintrag " + ("vorhanden" if m.dns_record else "nicht vorhanden"),
                 "Richtlinie " + ("vorhanden" if m.policy else "nicht vorhanden")]
        if m.mode:
            teile.append(f"Modus {m.mode}")
        return "MTA-STS: " + ", ".join(teile)
    if part == "tls_rpt":
        if dns.tls_rpt is None or dns.tls_rpt.present is None:
            return None
        return "TLS-RPT: " + ("Eintrag vorhanden" if dns.tls_rpt.present else "kein Eintrag")
    if part == "dane":
        if dns.dane is None or dns.dane.smtp is None:
            return None
        return "DANE für SMTP: " + ("TLSA-Einträge vorhanden" if dns.dane.smtp else "keine TLSA-Einträge")
    return None


def _dns(item: Any, ictx: dict[str, Any], paths: frozenset[str]) -> list[EvidenceRef]:
    """Die DNS-Eintraege, auf die die Regel gesehen hat, je Eintrag eine Zeile (spec/09 Q7)."""
    dns = item.fact
    out: list[EvidenceRef] = []
    for part, tool in _DNS_PARTS:
        if paths and not _touches(paths, f"dns.{part}"):
            continue
        text = _dns_part(dns, part)
        if not text:
            continue
        out.extend(_line(dns, f"{dns.domain}{PART_SEP}{text}", tool=tool))
    return out


def _dns_dangling(item: Any, ictx: dict[str, Any], paths: frozenset[str]) -> list[EvidenceRef]:
    entry = item.obj
    return _line(item.fact, _zeile([("Name", entry.fqdn), ("verweist auf", entry.cname_target),
                                    ("Übernahmerisiko", value_text(entry.takeover_risk)),
                                    ("Grund", entry.reason)]))


def _software(item: Any, ictx: dict[str, Any], paths: frozenset[str]) -> list[EvidenceRef]:
    sw = item.obj
    paare: list[tuple[str, Any]] = [
        ("", f"{sw.host_ip}"), ("Produkt", sw.product),
        ("Version", sw.version_norm or sw.version_raw), ("Build", sw.build),
    ]
    if sw.eol is not None and sw.eol.status != "unknown":
        paare += [("Pflegestatus", value_text(sw.eol.status)), ("Pflegeende", sw.eol.date),
                  ("Quelle der Lebenszyklusdaten", sw.eol.source)]
    if sw.release_date:
        paare.append(("Veröffentlichung", sw.release_date))
    # Die woertliche Zeile des Dienstes, aus der die Version stammt (nmap-Banner,
    # Server-Header); Zusammenfassungen von wpscan und Profildatei stehen schon oben.
    beleg = next((e for e in sw.evidence if e.tool in ("nmap", "header_check", "httpx")), None)
    if beleg is not None:
        paare.append(("Beleg", beleg.excerpt))
    if sw.vulnerabilities:
        paare.append(("bekannte Schwachstellen laut wpscan", len(sw.vulnerabilities)))
    out = _line(sw, _zeile(paare))
    # spec/08 Punkt 20 (#16): die Kennungen stehen im Nachweis, je Schwachstelle eine Zeile.
    for v in sw.vulnerabilities[:LIST_MAX]:
        text = v.title + (f" ({', '.join(v.cves)})" if v.cves else "") + \
            (f", behoben in {v.fixed_in}" if v.fixed_in else "")
        out.extend(_line(sw, text, tool="wpscan"))
    rest = len(sw.vulnerabilities) - LIST_MAX
    if rest > 0:
        out.extend(_line(sw, f"und {rest} weitere Schwachstellen laut wpscan", tool="wpscan"))
    return out


def _passive(item: Any, ictx: dict[str, Any], paths: frozenset[str]) -> list[EvidenceRef]:
    """Passivquelle mit dem Zeitstempel des Dienstes (spec/09 Q13).

    Fehlt der Zeitstempel des Dienstes, steht kein Datum da; die Aktualisierung des ganzen
    Hosts bei der Quelle ist nicht der Zeitpunkt, an dem dieser Dienst gesehen wurde.
    """
    pv = item.obj
    return _line(pv, _zeile([("Quelle", pv.source),
                             ("", f"{pv.host_ip}:{pv.port}" if pv.port else pv.domain),
                             ("Produkt", pv.product), ("Version", pv.version),
                             ("Dienst gesehen am", (pv.service_seen_at or "")[:10] or None),
                             ("Banner (Auszug)", _auszug(pv.banner_excerpt))]))


def _auszug(text: Optional[str]) -> Optional[str]:
    """Bannerauszug ohne Kuerzungszeichen; die Bezeichnung sagt, dass es ein Auszug ist."""
    if not text:
        return None
    return text[:-3].rstrip() if text.endswith("...") else text


def _threat(item: Any, ictx: dict[str, Any], paths: frozenset[str]) -> list[EvidenceRef]:
    t = item.obj
    paare: list[tuple[str, Any]] = [("", t.cve_id), ("Quelle", t.source)]
    if t.cvss_nvd is not None and t.cvss_nvd.score is not None:
        paare.append(("NVD-Basiswert", t.cvss_nvd.score))
    if t.kev is not None and t.kev.listed:
        paare.append(("CISA KEV", "gelistet"))
    return _line(t, _zeile(paare))


def _fqdn(item: Any, ictx: dict[str, Any], paths: frozenset[str]) -> list[EvidenceRef]:
    f = item.fact
    waf = f.waf.name if (f.waf is not None and f.waf.detected) else None
    return _line(f, _zeile([("", f.name), ("Status", f.http_status), ("Titel", f.title),
                            ("Zieladresse", f.final_url), ("Schutzsystem", waf),
                            ("erreichbar", f.web_probe_reachable)]))


def _host(item: Any, ictx: dict[str, Any], paths: frozenset[str]) -> list[EvidenceRef]:
    h = item.fact
    rep = h.reputation
    if rep is None:
        return []
    return _line(h, _zeile([("", h.ip), ("AbuseIPDB-Bewertung", rep.abuseipdb_score),
                            ("Meldungen", rep.abuseipdb_total_reports),
                            ("zuletzt gemeldet", (rep.abuseipdb_last_reported_at or "")[:10] or None),
                            ("auf der Freigabeliste von AbuseIPDB", rep.abuseipdb_whitelisted),
                            ("Tor-Knoten", rep.is_tor), ("OTX-Pulse", rep.otx_pulse_count)]),
                 tool="abuseipdb")


Builder = Callable[[Any, dict[str, Any], frozenset[str]], list[EvidenceRef]]

BUILDERS: dict[str, Builder] = {
    "http": _http,
    "http.alerts": _http_alert,
    "http.paths": _http_path,
    "http.cookies": _http_cookie,
    "http.wordpress": _http_wordpress,
    "tls": _tls,
    "tls.vulns": _tls_vuln,
    "service": _service,
    "dns": _dns,
    "dns.dangling_cnames": _dns_dangling,
    "software": _software,
    "passive": _passive,
    "threat": _threat,
    "fqdn": _fqdn,
    "host": _host,
}


def detail_evidence(scope: str, item: Any, ictx: dict[str, Any],
                    override: Optional[str] = None,
                    paths: frozenset[str] = frozenset()) -> list[EvidenceRef]:
    """Nachweiszeilen zum getroffenen Teilobjekt, leer wenn der Bereich keine kennt."""
    builder = BUILDERS.get(override or scope)
    if builder is None:
        return []
    try:
        return builder(item, ictx, paths)
    except AttributeError:
        # Ein Bereich ohne die erwarteten Felder liefert keinen Nachweis; die
        # bereichsweite Evidenz greift dann wie bisher.
        return []


def ist_redundant(roh: str, detail: str) -> bool:
    """Sagt die Werkzeugzeile schon alles, was in der Detailzeile steht?

    Die nmap-Zeile ``21/tcp open ftp ProFTPD`` steht vollstaendig in
    ``92.205.163.53:21/tcp Dienst=ftp Produkt=ProFTPD Zustand=open``; zweimal
    dasselbe macht den Nachweis nur laenger. Die Zeile
    ``pop3-capabilities: CAPA AUTH-RESP-CODE STLS ...`` dagegen traegt etwas
    Eigenes und bleibt. Geprueft wird ueber die Bestandteile: steht jeder von
    mindestens drei Zeichen Laenge irgendwo in der Detailzeile, ist die
    Werkzeugzeile entbehrlich.
    """
    teile = [t for t in (roh or "").replace(",", " ").split()
             if len(t) >= 3 and t not in _REDUNDANT_TOKENS]
    if not teile:
        return True
    return all(t in detail for t in teile)


# Woerter der nmap-Zeile, die in der Detailzeile anders heissen oder nichts sagen.
_REDUNDANT_TOKENS = frozenset({"open", "tunnel=ssl", "(protocol", "2.0)"})


__all__ = ["detail_evidence", "ist_redundant", "BUILDERS", "DETAIL_MAX",
           "KEEP_FACT_EVIDENCE", "VALUE_TEXT", "value_text", "liste"]
