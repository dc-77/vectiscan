# -*- coding: utf-8 -*-
"""Befundspezifischer Nachweis: was die Regel getroffen hat, nicht was das Werkzeug sagte.

Bis S6 war der Nachweis eines Befunds die Evidenz des tragenden Fakts plus die
Evidenz aller in ``evidence: [...]`` genannten Bereiche. Bei ``evidence: [http]``
war das die Zusammenfassungszeile des ``header_check``
(``erreichbar=ja score=1/7 server=Apache``), und dieselbe Zeile stand deshalb in
sieben verschiedenen Befunden. Header-Namen, REST-Adresse oder Zertifikatsdaten
fehlten dagegen ganz, und ein Administrator konnte keinen Befund nachvollziehen
(spec/08 Punkt 3).

Hier steht die Gegenrichtung: je Bereich eine kleine Funktion, die aus dem
getroffenen Teilobjekt die entscheidenden Werte als eine Zeile schreibt, mit dem
Werkzeug und der Fundstelle des tragenden Fakts. Diese Zeile steht im Bericht
vorn; die bereichsweite Evidenz kommt nur noch dran, wenn keine Detailzeile
entstanden ist.

Der Bereich ergibt sich aus dem ``scope`` der Pruefung; eine Pruefung kann ihn
mit ``evidence_detail`` ueberschreiben.
"""
from __future__ import annotations

from typing import Any, Callable, Optional

from reporter.catalog.schema import EvidenceRef
from reporter.facts.serialize import excerpt, kv

DETAIL_MAX = 240

# Bereiche, deren Fakt-Evidenz ein woertlicher Werkzeugauszug ist (nmap-Zeile,
# testssl-Ausgabe, Shodan-Banner) und deshalb zusaetzlich zur Detailzeile
# stehenbleibt. Fuer ``http``, ``dns`` und ``fqdn`` ist sie dagegen genau die
# Zusammenfassung, die in sieben Befunden gleich lautete (spec/08 Punkt 3).
KEEP_FACT_EVIDENCE: frozenset[str] = frozenset({
    "service", "software", "tls", "tls.vulns", "passive", "threat",
})


def _ref(fact: Any, tool: str | None = None) -> tuple[str, str, str]:
    """(fact_id, Werkzeug, Fundstelle) des tragenden Fakts."""
    fid = getattr(fact, "id", "") or ""
    evs = getattr(fact, "evidence", None) or []
    first = evs[0] if evs else None
    return (fid,
            tool or (getattr(first, "tool", "") if first else "") or getattr(fact, "source", "") or "",
            getattr(first, "ref", "") if first else "")


def _line(fact: Any, text: str, tool: str | None = None) -> list[EvidenceRef]:
    if not text:
        return []
    fid, werkzeug, ref = _ref(fact, tool)
    # Nennt die Zeile ein anderes Werkzeug als der Fakt, passt dessen Fundstelle
    # nicht dazu; eine falsche Fundstelle ist schlechter als keine.
    if tool and tool != _ref(fact)[1]:
        ref = ""
    return [EvidenceRef(fact_id=fid, tool=werkzeug, ref=ref, excerpt=excerpt(text, DETAIL_MAX))]


# ---------------------------------------------------------------- je Bereich

def _http(item: Any, ictx: dict[str, Any]) -> list[EvidenceRef]:
    """Sicherheits-Header, Cookies, CSP und die Kopfdaten der Antwort.

    Welche Header fehlen, ist die Aussage des Befunds; genau sie standen bisher
    nirgends (spec/08 Punkt 3, VS-2026-012).
    """
    http = item.fact
    fehlend = sorted(name for name, h in (http.security_headers or {}).items()
                     if not getattr(h, "present", False))
    gesetzt = sorted(f"{name}: {h.value}" for name, h in (http.security_headers or {}).items()
                     if getattr(h, "present", False) and getattr(h, "value", None))
    paare: list[tuple[str, Any]] = [("", f"{http.fqdn or http.host_ip}:")]
    if http.url:
        paare.append(("URL", http.url))
    if fehlend:
        paare.append(("fehlende Header", fehlend))
    if gesetzt:
        paare.append(("gesetzte Header", gesetzt[:4]))
    if http.csp is not None and http.csp.present and http.csp.value:
        paare.append(("CSP", http.csp.value))
    if http.server_header:
        paare.append(("Server", http.server_header))
    if http.powered_by:
        paare.append(("X-Powered-By", http.powered_by))
    if http.duplicate_headers:
        paare.append(("doppelt gesetzt", http.duplicate_headers))
    cookies = [f"{c.name} ohne " + ", ".join(
        [n for n, on in (("Secure", c.secure), ("HttpOnly", c.httponly)) if not on]
        + ([] if c.samesite else ["SameSite"]))
        for c in (http.cookies or [])
        if not (c.secure and c.httponly and c.samesite)]
    if cookies:
        paare.append(("Cookies", cookies[:3]))
    return _line(http, kv(paare, DETAIL_MAX))


def _http_alert(item: Any, ictx: dict[str, Any]) -> list[EvidenceRef]:
    """Die ZAP-Meldung selbst: Name, Kennung, Adresse, Beleg, Konfidenz (Issue #15)."""
    alert = item.obj
    http = item.fact
    paare: list[tuple[str, Any]] = [
        ("", alert.name),
        ("ZAP-Kennung", alert.plugin_id),
        ("Risiko", alert.risk),
        ("Konfidenz", alert.confidence),
        ("Adresse", alert.url or (alert.urls_sample[0] if alert.urls_sample else None)),
        ("Beleg", alert.evidence),
        ("CWE", alert.cwe),
        ("betroffene Adressen", alert.count if alert.count and alert.count > 1 else None),
    ]
    # Die Fundstelle des http-Fakts zeigt auf den header_check; fuer eine
    # ZAP-Meldung waere das irrefuehrend (spec/08 Punkt 2).
    return [EvidenceRef(fact_id=getattr(http, "id", "") or "", tool="zap_active",
                        ref="", excerpt=excerpt(kv(paare, DETAIL_MAX), DETAIL_MAX))]


def _http_wordpress(item: Any, ictx: dict[str, Any]) -> list[EvidenceRef]:
    """Benutzernamen und Kernstand einer WordPress-Installation.

    Der Befund "Benutzernamen von aussen ermittelbar" nannte die REST-Adresse
    nicht, unter der sie stehen (spec/08 Punkt 3, VS-2026-015).
    """
    http = item.fact
    wp = http.wordpress
    if wp is None:
        return []
    basis = (http.url or f"https://{http.fqdn or http.host_ip}").rstrip("/")
    paare: list[tuple[str, Any]] = [("", f"{http.fqdn or http.host_ip}:")]
    if wp.users:
        paare.append(("Benutzernamen unter", f"{basis}/wp-json/wp/v2/users"))
        paare.append(("gefunden", sorted(wp.users)[:8]))
    if wp.version_status:
        paare.append(("Kernstand", wp.version_status))
    return _line(http, kv(paare, DETAIL_MAX), tool="wpscan")


def _http_cookie(item: Any, ictx: dict[str, Any]) -> list[EvidenceRef]:
    cookie = item.obj
    http = item.fact
    fehlt = [n for n, on in (("Secure", cookie.secure), ("HttpOnly", cookie.httponly)) if not on]
    if not cookie.samesite:
        fehlt.append("SameSite")
    return _line(http, kv([("", f"{http.fqdn or http.host_ip}:"),
                           ("Cookie", cookie.name), ("ohne", fehlt),
                           ("SameSite", cookie.samesite)], DETAIL_MAX))


def _http_path(item: Any, ictx: dict[str, Any]) -> list[EvidenceRef]:
    path = item.obj
    return _line(item.fact, kv([("Adresse", path.url), ("Status", path.status),
                                ("Laenge", path.length)], DETAIL_MAX))


def _tls(item: Any, ictx: dict[str, Any]) -> list[EvidenceRef]:
    """Zertifikat, Protokolle und Verfahren des betroffenen Dienstes.

    Der WebCheck-Zertifikatsbefund zeigte bisher nur die Protokollliste; die
    Zertifikatsdaten fehlten (spec/08 Punkt 3).
    """
    tls = item.fact
    paare: list[tuple[str, Any]] = [("", f"{tls.fqdn or tls.host_ip}:{tls.port}")]
    cert = tls.cert
    if cert is not None:
        paare += [
            ("CN", cert.cn),
            ("SAN", (cert.san or [])[:4]),
            ("Aussteller", cert.issuer),
            ("gueltig_bis", cert.not_after),
            ("abgelaufen", cert.expired),
            ("Resttage", cert.days_left),
            ("selbstsigniert", cert.self_signed),
            ("Namensabweichung", cert.mismatch),
            ("Kette vollstaendig", cert.chain_ok),
        ]
    aktiv = sorted(name for name, on in (tls.protocols or {}).items() if on is True)
    if aktiv:
        paare.append(("Protokolle", aktiv))
    if tls.ciphers_weak:
        paare.append(("schwache Verfahren", tls.ciphers_weak[:4]))
    vulns = [v.name for v in (tls.vulns or []) if v.status == "vulnerable"]
    if vulns:
        paare.append(("verwundbar", vulns))
    if tls.hsts is not None and tls.hsts.max_age is not None:
        paare.append(("HSTS max-age", tls.hsts.max_age))
    return _line(tls, kv(paare, DETAIL_MAX))


def _tls_vuln(item: Any, ictx: dict[str, Any]) -> list[EvidenceRef]:
    """Das Urteil von testssl zu genau dieser Pruefung, mit seiner Ausgabezeile."""
    vuln = item.obj
    tls = item.fact
    # Die CVE-Kennung steht nicht am Urteil, sondern an der Ausgabezeile
    # desselben Tests (``entries``); ohne sie waere der Nachweis dünner als die
    # Aussage des Befunds.
    eintrag = next((e for e in (tls.entries or []) if e.id == vuln.name), None)
    return _line(tls, kv([("", f"{tls.fqdn or tls.host_ip}:{tls.port}"),
                          ("Pruefung", vuln.name), ("Urteil", vuln.status),
                          ("CVE", eintrag.cve if eintrag else None),
                          ("Ausgabe", eintrag.finding if eintrag else None)], DETAIL_MAX),
                 tool="testssl")


def _service(item: Any, ictx: dict[str, Any]) -> list[EvidenceRef]:
    svc = item.obj
    return _line(svc, kv([("", f"{svc.host_ip}:{svc.port}/{svc.proto}"),
                          ("Dienst", svc.service), ("Produkt", svc.product),
                          ("Version", svc.version_raw or svc.version_norm),
                          ("Zustand", svc.state),
                          ("TLS erzwungen", svc.tls_required),
                          ("STARTTLS", svc.starttls),
                          ("Anmeldung gesperrt", svc.login_disabled),
                          ("Verfahren", (svc.auth_mechanisms or [])[:4]),
                          ("Capabilities", (svc.capabilities or [])[:4])],
                         DETAIL_MAX), tool="nmap")


def _dns(item: Any, ictx: dict[str, Any]) -> list[EvidenceRef]:
    """Die DNS-Eintraege, auf die die Regel gesehen hat, im Klartext."""
    dns = item.fact
    paare: list[tuple[str, Any]] = [("", f"{dns.domain}:")]
    if dns.spf is not None:
        paare.append(("SPF", dns.spf.raw or "nicht vorhanden"))
    if dns.dmarc is not None:
        paare.append(("DMARC", dns.dmarc.raw or "nicht vorhanden"))
    if dns.dkim is not None:
        paare.append(("DKIM-Selektoren", dns.dkim.selectors or "keiner bekannt"))
    if dns.mx:
        paare.append(("MX", dns.mx[:3]))
    if dns.dnssec is not None:
        paare.append(("DNSSEC", "signiert" if dns.dnssec.signed else "nicht signiert"))
    if dns.caa is not None:
        paare.append(("CAA", dns.caa.records or "nicht vorhanden"))
    if dns.mta_sts is not None:
        paare.append(("MTA-STS", "vorhanden" if dns.mta_sts.policy else "nicht vorhanden"))
    if dns.tls_rpt is not None:
        paare.append(("TLS-RPT", "vorhanden" if dns.tls_rpt.present else "nicht vorhanden"))
    return _line(dns, kv(paare, DETAIL_MAX))


def _dns_dangling(item: Any, ictx: dict[str, Any]) -> list[EvidenceRef]:
    entry = item.obj
    return _line(item.fact, kv([("Name", entry.fqdn), ("verweist auf", entry.cname_target),
                                ("Uebernahmerisiko", entry.takeover_risk),
                                ("Grund", entry.reason)], DETAIL_MAX))


def _software(item: Any, ictx: dict[str, Any]) -> list[EvidenceRef]:
    sw = item.obj
    paare: list[tuple[str, Any]] = [
        ("", f"{sw.host_ip}:"), ("Produkt", sw.product), ("Familie", sw.family),
        ("Version", sw.version_norm or sw.version_raw), ("Build", sw.build),
    ]
    if sw.eol is not None:
        paare += [("Pflegestatus", sw.eol.status), ("Pflegeende", sw.eol.date),
                  ("Quelle", sw.eol.source)]
    return _line(sw, kv(paare, DETAIL_MAX))


def _passive(item: Any, ictx: dict[str, Any]) -> list[EvidenceRef]:
    pv = item.obj
    return _line(pv, kv([("Quelle", pv.source),
                         ("", f"{pv.host_ip}:{pv.port}" if pv.port else pv.domain),
                         ("Produkt", pv.product), ("Version", pv.version),
                         ("gesehen am", pv.seen_at), ("Banner", pv.banner_excerpt)],
                        DETAIL_MAX))


def _threat(item: Any, ictx: dict[str, Any]) -> list[EvidenceRef]:
    t = item.obj
    paare: list[tuple[str, Any]] = [("", t.cve_id), ("Quelle", t.source)]
    if t.cvss_nvd is not None and t.cvss_nvd.score is not None:
        paare.append(("NVD-Basiswert", t.cvss_nvd.score))
    if t.kev is not None and t.kev.listed:
        paare.append(("CISA KEV", "gelistet"))
    return _line(t, kv(paare, DETAIL_MAX))


def _fqdn(item: Any, ictx: dict[str, Any]) -> list[EvidenceRef]:
    f = item.fact
    waf = f.waf.name if (f.waf is not None and f.waf.detected) else None
    return _line(f, kv([("", f.name), ("Status", f.http_status), ("Titel", f.title),
                        ("Zieladresse", f.final_url), ("Schutzsystem", waf),
                        ("erreichbar", f.web_probe_reachable)], DETAIL_MAX))


BUILDERS: dict[str, Callable[[Any, dict[str, Any]], list[EvidenceRef]]] = {
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
}


def detail_evidence(scope: str, item: Any, ictx: dict[str, Any],
                    override: Optional[str] = None) -> list[EvidenceRef]:
    """Nachweiszeile zum getroffenen Teilobjekt, leer wenn der Bereich keine kennt."""
    builder = BUILDERS.get(override or scope)
    if builder is None:
        return []
    try:
        return builder(item, ictx)
    except AttributeError:
        # Ein Bereich ohne die erwarteten Felder liefert keinen Nachweis; die
        # bereichsweite Evidenz greift dann wie bisher.
        return []


__all__ = ["detail_evidence", "BUILDERS", "DETAIL_MAX"]
