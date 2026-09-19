"""Ignorierliste und die drei Auffangregeln (spec/06 Abschnitt 4).

Ein Fakt gilt als verarbeitet (``claimed``), wenn das ``when`` einer Pruefung auf ihn
getroffen hat (auch bei ``kind: note``). Alles, was danach uebrig bleibt, ist entweder
in ``ignore.yaml`` begruendet ausgeschlossen oder landet unter ``unprocessed``:

1. ``service_unknown_port``: offener Dienst ohne Treffer, Port nicht in KNOWN_PORTS.
2. ``zap_alert_unmapped``: ZAP-Alert ohne Treffer und ohne Eintrag in der Ignorierliste.
3. ``passive_port_unverified``: Shodan-Port ohne Treffer, den nmap nicht bestaetigt hat
   (``verified False``) oder dessen Host nicht aktiv gescannt wurde (``verified None``).
"""
from __future__ import annotations

import re
from collections import OrderedDict
from typing import Any

from reporter.catalog import tables as T
from reporter.catalog.schema import IgnoredItem, IgnoreEntry, IgnoreList, Unprocessed
from reporter.catalog.scope import FactsIndex
from reporter.facts.serialize import ip_token, sort_key

_RX: dict[str, re.Pattern[str]] = {}


def _rx(pattern: str) -> re.Pattern[str]:
    if pattern not in _RX:
        _RX[pattern] = re.compile(pattern, re.I)
    return _RX[pattern]


def alert_ignored(alert: Any, entries: list[IgnoreEntry]) -> IgnoreEntry | None:
    """Eintrag der Ignorierliste, der auf einen ZAP-Alert passt (plugin_id und/oder Name)."""
    pid = alert.plugin_id
    name = alert.name or ""
    for e in entries:
        if e.kind != "zap_alert":
            continue
        if e.plugin_id and e.name:
            if pid == e.plugin_id and _rx(e.name).search(name):
                return e
            if pid is None and _rx(e.name).search(name):
                return e
        elif e.plugin_id:
            if pid == e.plugin_id:
                return e
        elif e.name and _rx(e.name).search(name):
            return e
    return None


def passive_ignored(port: int | None, is_cdn: bool, entries: list[IgnoreEntry]) -> IgnoreEntry | None:
    for e in entries:
        if e.kind != "passive_port" or port is None or port not in e.ports:
            continue
        if e.only_cdn and not is_cdn:
            continue
        return e
    return None


def run_catchalls(index: FactsIndex, claimed: set[str], ignore: IgnoreList) -> tuple[list[Unprocessed], list[IgnoredItem]]:
    f = index.facts
    entries = ignore.entries
    unprocessed: "OrderedDict[tuple, Unprocessed]" = OrderedDict()
    ignored: "OrderedDict[tuple, IgnoredItem]" = OrderedDict()

    def add_unprocessed(kind: str, what: str, *, host_ip=None, fqdn=None, port=None, count=1, fact_id=None, note=None) -> None:
        key = (kind, what, host_ip)
        if key in unprocessed:
            u = unprocessed[key]
            u.count += count
            if fact_id and fact_id not in u.fact_ids:
                u.fact_ids.append(fact_id)
            if fqdn and fqdn not in u.fqdns:
                u.fqdns.append(fqdn)
        else:
            unprocessed[key] = Unprocessed(kind=kind, what=what, host_ip=host_ip, fqdns=[fqdn] if fqdn else [], port=port,
                                           count=count, fact_ids=[fact_id] if fact_id else [], note=note)

    def add_ignored(kind: str, what: str, reason: str, *, host_ip=None, fqdn=None, count=1) -> None:
        key = (kind, what, host_ip)
        if key in ignored:
            ignored[key].count += count
            if fqdn and fqdn not in ignored[key].fqdns:
                ignored[key].fqdns.append(fqdn)
        else:
            ignored[key] = IgnoredItem(kind=kind, what=what, host_ip=host_ip, fqdns=[fqdn] if fqdn else [], count=count,
                                       reason=reason)

    # 1 Dienste
    for ip, svcs in sorted(index.services_by_ip.items(), key=lambda kv: sort_key(kv[0])):
        for s in svcs:
            if s.id in claimed or s.port in T.KNOWN_PORTS:
                continue
            what = f"{s.port}/{s.proto} {s.service or 'unbekannt'}" + (f" ({s.product})" if s.product else "")
            add_unprocessed("service_unknown_port", what, host_ip=ip, port=s.port, fact_id=s.id,
                            note="Zweck des Dienstes klaeren; nicht bewertet.")

    # 2 ZAP-Alerts
    for h in sorted(f.http, key=lambda x: sort_key(x.id)):
        for a in h.alerts:
            claim_id = f"{h.id}#alert:{a.plugin_id or '-'}|{a.name}"
            if claim_id in claimed:
                continue
            entry = alert_ignored(a, entries)
            what = f"{a.name} ({a.plugin_id})" if a.plugin_id else a.name
            if entry is not None:
                add_ignored("zap_alert", what, entry.reason, host_ip=h.host_ip, fqdn=h.fqdn, count=a.count)
            else:
                add_unprocessed("zap_alert_unmapped", what, host_ip=h.host_ip, fqdn=h.fqdn, count=a.count, fact_id=h.id,
                                note="Werkzeugbefund ohne Zuordnung; Anhang ohne Bewertung.")

    # 3 Passivports
    for p in sorted(f.passive, key=lambda x: sort_key(x.id)):
        if p.source != "shodan" or p.port is None or p.id in claimed or p.verified is True:
            continue
        is_cdn = index.is_cdn_host(p.host_ip)
        entry = passive_ignored(p.port, is_cdn, entries)
        what = f"{ip_token(p.host_ip) if p.host_ip else '-'}:{p.port}" + (f" ({p.product})" if p.product else "")
        if entry is not None:
            add_ignored("passive_port", what, entry.reason, host_ip=p.host_ip)
            continue
        note = ("Laut Passivquelle gemeldet, vom Portscan nicht bestaetigt." if p.verified is False
                else "Laut Passivquelle gemeldet; Host wurde nicht aktiv gescannt.")
        add_unprocessed("passive_port_unverified", what, host_ip=p.host_ip, port=p.port, fact_id=p.id, note=note)

    return list(unprocessed.values()), list(ignored.values())


__all__ = ["run_catchalls", "alert_ignored", "passive_ignored"]
