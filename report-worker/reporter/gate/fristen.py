# -*- coding: utf-8 -*-
"""Fristregeln am Scantag und an einem spaeteren Stichtag (E27, spec/11 Teil 6; S7a Punkt 8).

Entscheidung DC (E27): Stufe und Regelausloesung bleiben am Scantag, weil der Bericht den Zustand
des Scantags beschreibt. Faellt eine Fristregel am Berichtsdatum anders aus (heuel online.heuel.com:
31 Tage am Scantag, 28 am Berichtsdatum, Schwelle 30), bekommt der Admin im Review einen Hinweis.
Im Bericht steht dafuer der bestehende R18-Hinweis.

Die Einordnung folgt den Schwellen des Katalogs (``reporter/catalog/tables.py``):

- ``cert_expired`` (Zertifikat aus testssl) und ``service_cert_expired`` (Zertifikat aus dem
  Portscan an einem Dienst ohne eigenen testssl-Lauf): abgelaufen
- ``cert_expiring``: bis ``CERT_SOON_DAYS`` Tage, bis ``CERT_URGENT_DAYS`` Unverzueglich
- ``cert_expiring_later``: bis ``CERT_EXPIRING_DAYS`` Tage
- ``domain_expiring``: bis ``DOMAIN_EXPIRING_DAYS`` Tage

Die Tage am Stichtag sind die Tage am Scantag minus die Tage zwischen Scan- und Stichtag; dieselbe
Rechnung macht die API fuer den Freigabetag (``api/src/lib/fristen.ts``), deshalb stehen Schwellen
und Scantag mit in der Nutzlast.
"""
from __future__ import annotations

from datetime import date
from typing import Any, Optional

from reporter.catalog import tables as CT
from reporter.facts.serialize import iso_date

# Fristen bis so viele Tage nach dem Scantag gehen in die Liste fuer den Review; eine spaete
# Freigabe kann eine Schwelle noch kreuzen, solange der Bericht nicht erneut erzeugt wird.
VORLAUF_TAGE = 60

SCHWELLEN: dict[str, int] = {
    "sofort": CT.CERT_URGENT_DAYS,
    "bald": CT.CERT_SOON_DAYS,
    "spaeter": CT.CERT_EXPIRING_DAYS,
    "domain": CT.DOMAIN_EXPIRING_DAYS,
}

REGEL_TEXT = {
    "cert_expired": "abgelaufen",
    "service_cert_expired": "abgelaufen",
    "cert_expiring_sofort": f"höchstens {CT.CERT_URGENT_DAYS} Tage, Unverzüglich",
    "cert_expiring": f"höchstens {CT.CERT_SOON_DAYS} Tage",
    "cert_expiring_later": f"höchstens {CT.CERT_EXPIRING_DAYS} Tage",
    "domain_expiring": f"höchstens {CT.DOMAIN_EXPIRING_DAYS} Tage",
}


def klasse(art: str, tage: Optional[int]) -> Optional[str]:
    """Welche Fristregel bei ``tage`` Restlaufzeit ausloest (None: keine)."""
    if tage is None:
        return None
    if art == "domain":
        return "domain_expiring" if tage <= SCHWELLEN["domain"] else None
    if tage < 0:
        return "service_cert_expired" if art == "service_cert" else "cert_expired"
    if art == "service_cert":
        # Am Dienst ohne eigenen testssl-Lauf gibt es nur die Ablaufregel.
        return None
    if tage <= SCHWELLEN["sofort"]:
        return "cert_expiring_sofort"
    if tage <= SCHWELLEN["bald"]:
        return "cert_expiring"
    if tage <= SCHWELLEN["spaeter"]:
        return "cert_expiring_later"
    return None


def _scan_tag(facts: Any) -> Optional[date]:
    wert = iso_date(getattr(facts.scan, "finished_at", None) or getattr(facts.scan, "started_at", None))
    return date.fromisoformat(wert) if wert else None


def fristen(facts: Any) -> list[dict[str, Any]]:
    """Fristen mit Restlaufzeit am Scantag zwischen 0 und ``VORLAUF_TAGE`` Tagen, je Subjekt einmal."""
    if facts is None:
        return []
    eigene = {h.ip for h in facts.hosts if h.third_party is None}
    out: dict[tuple[str, str], dict[str, Any]] = {}

    def add(art: str, subjekt: str, not_after: Optional[str], tage: Optional[int]) -> None:
        if not not_after or tage is None or tage < 0 or tage > VORLAUF_TAGE:
            return
        key = (subjekt, iso_date(not_after) or not_after)
        out.setdefault(key, {"art": art, "subjekt": subjekt, "gueltig_bis": iso_date(not_after),
                             "tage_scantag": tage})

    mit_tls = set()
    for t in facts.tls:
        if t.host_ip not in eigene or t.cert is None:
            continue
        mit_tls.add((t.host_ip, t.port))
        add("tls", f"{t.fqdn or t.host_ip}:{t.port}", t.cert.not_after, t.cert.days_left)
    for s in facts.services:
        if s.host_ip not in eigene or s.cert is None or s.foreign or (s.host_ip, s.port) in mit_tls:
            continue
        add("service_cert", f"{s.host_ip}:{s.port}", s.cert.not_after, s.cert.days_left)
    scan = _scan_tag(facts)
    for target in facts.targets:
        whois = getattr(target, "whois", None)
        ablauf = iso_date(getattr(whois, "expires_at", None)) if whois else None
        if ablauf and scan:
            add("domain", target.domain, ablauf, (date.fromisoformat(ablauf) - scan).days)
    return sorted(out.values(), key=lambda f: (f["tage_scantag"], f["subjekt"]))


def abweichungen(facts: Any, stichtag: date) -> list[dict[str, Any]]:
    """Fristen, deren Regel am Stichtag anders ausfiele als am Scantag."""
    scan = _scan_tag(facts)
    if scan is None or stichtag <= scan:
        return []
    verschiebung = (stichtag - scan).days
    out: list[dict[str, Any]] = []
    for f in fristen(facts):
        tage = f["tage_scantag"] - verschiebung
        vorher, nachher = klasse(f["art"], f["tage_scantag"]), klasse(f["art"], tage)
        if vorher != nachher:
            out.append({**f, "tage_stichtag": tage, "regel_scantag": vorher, "regel_stichtag": nachher})
    return out


def nutzlast(facts: Any) -> dict[str, Any]:
    """Teil von ``orders.report_defects`` fuer die Nachrechnung am Freigabetag in der API."""
    scan = _scan_tag(facts) if facts is not None else None
    return {"fristen": fristen(facts), "fristen_schwellen": dict(SCHWELLEN),
            "fristen_scantag": scan.isoformat() if scan else None}


def regel_text(regel: Optional[str]) -> str:
    return f"{regel.replace('_sofort', '')} ({REGEL_TEXT[regel]})" if regel else "keine Fristregel"
