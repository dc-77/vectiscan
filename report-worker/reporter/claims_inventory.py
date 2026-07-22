"""Deterministisches Evidenz-Inventar fuer den Claims-Guard (VEC — Phase 1 / C1).

Konsolidiert die belastbaren, tool-belegten Fakten eines Scans zu einem
kompakten Inventar, gegen das der Claims-Guard (``claims_guard.py``) KI-
Freitext-Behauptungen pruefen kann:

  * welche Hostnamen/IPs tatsaechlich zum Auftrag gehoeren,
  * welche Ports pro Host (und ueber alle Hosts) offen sind,
  * welche Produkt-Versionen detektiert wurden und
  * welchen Patch-/EOL-Status diese Produkte laut Tech-Tabelle bzw. wpscan haben.

Bewusst KEINE KI, rein deterministisch — analog zu ``cve_guard.build_allowlist``.
Jede Quelle wird defensiv eingelesen: ein Fehler in einer Teilquelle darf das
Inventar NIE kippen (try/except + ``log.warning``, Fail-open).  Ein leeres
Inventar bedeutet fuer den Guard einen No-op — das ist die Fail-open-Garantie
(Muster wie ``cve_guard._collect_curated_cves`` cve_guard.py:88-104).

Quellen (Belege in der Spec, current_state Punkt 4):
  * ``host_inventory`` — phase0/host_inventory.json (ip/fqdns/rdns/domain)
  * ``tech_profiles[]`` — fqdns/primary_vhost/vhost_results/web_fqdn/open_ports/
    exposed_services/technologies/cms/cms_version/server
  * ``build_tech_table_for_host`` — klassifizierter patch_status pro Produkt
  * ``host_tool_data`` (parser-Fundament) — nmap-Ports mit Produkt/Version +
    WordPress-Versionsstatus (wp_version_status).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import structlog

log = structlog.get_logger()


# ---------------------------------------------------------------------------
# Status-Semantik
# ---------------------------------------------------------------------------

# Status-Werte, die "die genannte Version ist aktuell" bedeuten.  Quelle:
# tech_table_builder._patch_status_from ("aktuell") bzw. _classify_status
# ("current") und wpscan version.status ("latest").
CURRENT_STATUSES: frozenset[str] = frozenset({"aktuell", "current", "latest"})

# Rang je Status — je hoeher, desto "schlimmer".  Wird genutzt, um bei mehreren
# Hosts den KONSERVATIVEN (schlechtesten) Status zu behalten: ein Produkt gilt
# nur dann als "aktuell", wenn KEIN Host es als veraltet/eol meldet.  Damit
# entschaerft der Guard eine Versionsaussage nur, wenn sie durchgaengig belegt
# widerlegt ist ("bei Unsicherheit NICHTS tun").
_STATUS_RANK: dict[str, int] = {
    "aktuell": 0,
    "current": 0,
    "latest": 0,
    "unbekannt": 1,
    "unknown": 1,
    "minor_eol": 2,
    "outdated": 3,
    "eol": 4,
    "insecure": 4,
}

# Mapping wpscan version.status -> Inventar-Status.
_WPSCAN_STATUS_MAP: dict[str, str] = {
    "latest": "aktuell",
    "outdated": "outdated",
    "insecure": "eol",
}


def _status_rank(status: str) -> int:
    return _STATUS_RANK.get((status or "").strip().lower(), 1)


# ---------------------------------------------------------------------------
# Produktnamen-Normalisierung
# ---------------------------------------------------------------------------

def _norm_product(name: Any) -> str:
    """Normalisiert einen Produktnamen auf lowercase + kollabierte Whitespaces."""
    return re.sub(r"\s+", " ", str(name or "").strip().lower())


def _match_terms(name: Any) -> set[str]:
    """Liefert Such-Terme fuer einen Produktnamen (voller Name + ggf. 1. Token).

    Der erste Token wird nur als Alias uebernommen, wenn er hinreichend
    spezifisch ist (>= 4 Zeichen) — verhindert generische Fehltreffer bei
    kurzen Tokens.  Beispiel: "Apache HTTP Server" -> {"apache http server",
    "apache"}, "WordPress" -> {"wordpress"}.
    """
    n = _norm_product(name)
    if not n:
        return set()
    terms = {n}
    first = n.split()[0]
    if len(first) >= 4 and first != n:
        terms.add(first)
    return terms


# ---------------------------------------------------------------------------
# Inventar-Datenstruktur
# ---------------------------------------------------------------------------

@dataclass
class EvidenceInventory:
    """Konsolidiertes, tool-belegtes Evidenz-Inventar eines Scans.

    Attribute:
        hosts:          alle belegten Hostnamen/IPs (lowercase)
        ports_by_host:  offene Ports je Host-Schluessel
        all_ports:      Vereinigung aller offenen Ports ueber alle Hosts
        versions:       normalisierter Produktname -> Menge belegter Versionen
        version_status: normalisierter Produktname -> konservativer Status
                        (aktuell|outdated|eol|minor_eol|unbekannt)
        eol_dates:      normalisierter Produktname -> ISO-EOL-Datum
        product_terms:  normalisierter Produktname -> Such-Terme fuer Freitext
    """

    hosts: set[str] = field(default_factory=set)
    ports_by_host: dict[str, set[int]] = field(default_factory=dict)
    all_ports: set[int] = field(default_factory=set)
    versions: dict[str, set[str]] = field(default_factory=dict)
    version_status: dict[str, str] = field(default_factory=dict)
    eol_dates: dict[str, str] = field(default_factory=dict)
    product_terms: dict[str, set[str]] = field(default_factory=dict)

    def is_empty(self) -> bool:
        """True, wenn keine verwertbare Evidenz vorliegt (Guard-No-op)."""
        return not (self.hosts or self.all_ports or self.versions)

    def is_current(self, product_key: str) -> bool:
        """True, wenn das Produkt laut Inventar durchgaengig als aktuell gilt."""
        status = self.version_status.get(product_key)
        return bool(status) and status in CURRENT_STATUSES

    def current_products(self) -> list[tuple[str, set[str]]]:
        """Produkte mit belegtem 'aktuell'-Status inkl. ihrer Such-Terme."""
        out: list[tuple[str, set[str]]] = []
        for key in self.version_status:
            if self.is_current(key):
                out.append((key, self.product_terms.get(key, {key})))
        return out

    def _record_status(self, product: Any, status: str,
                       eol_date: str = "") -> None:
        """Traegt einen Produkt-Status konservativ (schlechtester gewinnt) ein."""
        key = _norm_product(product)
        if not key:
            return
        prev = self.version_status.get(key)
        if prev is None or _status_rank(status) > _status_rank(prev):
            self.version_status[key] = (status or "").strip().lower()
        self.product_terms.setdefault(key, set()).update(_match_terms(product))
        if eol_date and not self.eol_dates.get(key):
            self.eol_dates[key] = eol_date

    def _record_version(self, product: Any, version: Any) -> None:
        """Traegt eine belegte Produkt-Version ein (leere Versionen werden ignoriert)."""
        key = _norm_product(product)
        ver = str(version or "").strip()
        if not key or not ver or ver.lower() in ("unknown", "unbekannt"):
            return
        self.versions.setdefault(key, set()).add(ver)
        self.product_terms.setdefault(key, set()).update(_match_terms(product))


# ---------------------------------------------------------------------------
# Teil-Extraktoren (jeweils defensiv gekapselt)
# ---------------------------------------------------------------------------

def _add_hosts(inv: EvidenceInventory, host_inventory: Any,
               tech_profiles: Any) -> None:
    """Sammelt alle belegten Hostnamen/IPs aus host_inventory + tech_profiles."""
    try:
        if isinstance(host_inventory, dict):
            dom = host_inventory.get("domain")
            if isinstance(dom, str) and dom:
                inv.hosts.add(dom.strip().lower())
            for h in host_inventory.get("hosts") or []:
                if not isinstance(h, dict):
                    continue
                ip = h.get("ip")
                if isinstance(ip, str) and ip:
                    inv.hosts.add(ip.strip().lower())
                for fq in h.get("fqdns") or []:
                    if isinstance(fq, str) and fq:
                        inv.hosts.add(fq.strip().lower())
                rdns = h.get("rdns")
                if isinstance(rdns, str) and rdns:
                    inv.hosts.add(rdns.strip().lower())
    except Exception as exc:  # pragma: no cover - reine Absicherung
        log.warning("claims_inventory_hosts_failed", error=str(exc))

    try:
        for p in tech_profiles or []:
            if not isinstance(p, dict):
                continue
            for fq in p.get("fqdns") or []:
                if isinstance(fq, str) and fq:
                    inv.hosts.add(fq.strip().lower())
            for key in ("primary_vhost", "web_fqdn"):
                v = p.get(key)
                if isinstance(v, str) and v:
                    inv.hosts.add(v.strip().lower())
            vr = p.get("vhost_results")
            if isinstance(vr, dict):
                for vh in vr.keys():
                    if isinstance(vh, str) and vh:
                        inv.hosts.add(vh.strip().lower())
    except Exception as exc:  # pragma: no cover - reine Absicherung
        log.warning("claims_inventory_profile_hosts_failed", error=str(exc))


def _add_ports(inv: EvidenceInventory, tech_profiles: Any,
               host_tool_data: Any) -> None:
    """Sammelt offene Ports aus open_ports + exposed_services + nmap-Projektion."""
    def _host_key(p: dict) -> str:
        ip = p.get("ip")
        if isinstance(ip, str) and ip:
            return ip.strip().lower()
        fqdns = p.get("fqdns") or []
        if fqdns and isinstance(fqdns[0], str):
            return fqdns[0].strip().lower()
        return "?"

    try:
        for p in tech_profiles or []:
            if not isinstance(p, dict):
                continue
            hk = _host_key(p)
            bucket = inv.ports_by_host.setdefault(hk, set())
            for port in p.get("open_ports") or []:
                try:
                    pi = int(port)
                except (ValueError, TypeError):
                    continue
                bucket.add(pi)
                inv.all_ports.add(pi)
            for svc in p.get("exposed_services") or []:
                if not isinstance(svc, dict):
                    continue
                try:
                    pi = int(svc.get("port"))
                except (ValueError, TypeError):
                    continue
                bucket.add(pi)
                inv.all_ports.add(pi)
    except Exception as exc:  # pragma: no cover - reine Absicherung
        log.warning("claims_inventory_ports_failed", error=str(exc))

    try:
        if isinstance(host_tool_data, dict):
            for ip, data in host_tool_data.items():
                if not isinstance(data, dict):
                    continue
                nmap = data.get("nmap")
                if not isinstance(nmap, dict):
                    continue
                hk = str(ip).strip().lower()
                bucket = inv.ports_by_host.setdefault(hk, set())
                for entry in nmap.get("open_ports") or []:
                    if not isinstance(entry, dict):
                        continue
                    try:
                        pi = int(entry.get("port"))
                    except (ValueError, TypeError):
                        continue
                    bucket.add(pi)
                    inv.all_ports.add(pi)
    except Exception as exc:  # pragma: no cover - reine Absicherung
        log.warning("claims_inventory_nmap_ports_failed", error=str(exc))


def _add_versions_raw(inv: EvidenceInventory, tech_profiles: Any) -> None:
    """Sammelt Roh-Versionen aus technologies[] + cms/cms_version + server."""
    try:
        for p in tech_profiles or []:
            if not isinstance(p, dict):
                continue
            for tech in p.get("technologies") or []:
                if isinstance(tech, dict):
                    inv._record_version(tech.get("name"), tech.get("version"))
            if p.get("cms"):
                inv._record_version(p.get("cms"), p.get("cms_version"))
            # server (z.B. "Apache/2.4.62") -> Produkt + Version aufspalten
            server = p.get("server")
            if isinstance(server, str) and server:
                m = re.match(r"([A-Za-z][\w .+-]*?)[/ ]v?(\d+(?:\.\d+){0,3})",
                             server.strip())
                if m:
                    inv._record_version(m.group(1), m.group(2))
    except Exception as exc:  # pragma: no cover - reine Absicherung
        log.warning("claims_inventory_versions_failed", error=str(exc))


def _add_version_status(inv: EvidenceInventory, tech_profiles: Any,
                        host_tool_data: Any) -> None:
    """Sammelt klassifizierten Patch-Status pro Produkt (Tech-Tabelle + wpscan)."""
    try:
        from reporter.tech_table_builder import build_tech_table_for_host
        for p in tech_profiles or []:
            if not isinstance(p, dict):
                continue
            try:
                rows = build_tech_table_for_host(p)
            except Exception as exc:
                log.warning("claims_inventory_tech_table_failed",
                            ip=p.get("ip"), error=str(exc))
                continue
            for r in rows or []:
                if not isinstance(r, dict):
                    continue
                name = r.get("name")
                status = r.get("patch_status") or r.get("status") or ""
                if name and status:
                    inv._record_status(name, status, r.get("eol_date", ""))
                if r.get("version"):
                    inv._record_version(name, r.get("version"))
    except ImportError:  # pragma: no cover - defensiv
        log.warning("claims_inventory_tech_table_unavailable")
    except Exception as exc:  # pragma: no cover - reine Absicherung
        log.warning("claims_inventory_version_status_failed", error=str(exc))

    # wpscan-Versionsstatus als zweite Quelle (Defekt 2 — "latest" belegt).
    try:
        if isinstance(host_tool_data, dict):
            for _ip, data in host_tool_data.items():
                if not isinstance(data, dict):
                    continue
                wpscan = data.get("wpscan")
                if not isinstance(wpscan, dict):
                    continue
                raw = str(wpscan.get("wp_version_status", "") or "").strip().lower()
                mapped = _WPSCAN_STATUS_MAP.get(raw)
                if mapped:
                    inv._record_status("WordPress", mapped)
                ver = wpscan.get("wp_version")
                if ver:
                    inv._record_version("WordPress", ver)
    except Exception as exc:  # pragma: no cover - reine Absicherung
        log.warning("claims_inventory_wpscan_status_failed", error=str(exc))


# ---------------------------------------------------------------------------
# Hauptfunktion
# ---------------------------------------------------------------------------

def build_evidence_inventory(scan_context: Any,
                             host_tool_data: Any = None) -> EvidenceInventory:
    """Baut das Evidenz-Inventar aus dem scan_context (Fail-open).

    Args:
        scan_context: das im Worker gebaute Kontext-Dict (dns_records,
            tech_profiles, enrichment, host_inventory).  Robust gegen None
            und unerwartete Typen.
        host_tool_data: optionale schlanke Per-Host-Tool-Projektion aus dem
            Parser (nmap-Ports + wp_version_status).  Wird durchgereicht, wenn
            der Worker sie kuenftig in den Kontext legt.

    Returns:
        EvidenceInventory — leer, wenn keine Quelle verwertbar war.
    """
    inv = EvidenceInventory()
    try:
        sc = scan_context if isinstance(scan_context, dict) else {}
        host_inventory = sc.get("host_inventory")
        tech_profiles = sc.get("tech_profiles") or sc.get("techProfiles") or []
        if host_tool_data is None:
            host_tool_data = sc.get("host_tool_data")

        _add_hosts(inv, host_inventory, tech_profiles)
        _add_ports(inv, tech_profiles, host_tool_data)
        _add_versions_raw(inv, tech_profiles)
        _add_version_status(inv, tech_profiles, host_tool_data)
    except Exception as exc:  # pragma: no cover - reine Absicherung
        log.warning("claims_inventory_build_failed", error=str(exc))
        return EvidenceInventory()

    log.info("claims_inventory_built",
             hosts=len(inv.hosts),
             ports=len(inv.all_ports),
             products=len(inv.versions),
             classified=len(inv.version_status))
    return inv


__all__ = [
    "EvidenceInventory",
    "build_evidence_inventory",
    "CURRENT_STATUSES",
]
