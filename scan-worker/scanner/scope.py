"""Multi-Target Scope-Enforcement.

Laedt approved scan_targets aus der DB, baut pro Target ein (Teil-)Inventar
mit Policy-passenden Discovery-Methoden und filtert das finale Host-Inventar
gegen die Scope-Grenzen.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import json
import os
import re
from dataclasses import dataclass
from typing import Any, Optional

import psycopg2
import psycopg2.extras
import structlog

from scanner.common import cidr_utils, dns_utils, http_utils

log = structlog.get_logger()


@dataclass
class ScanTarget:
    id: str
    raw_input: str
    canonical: str
    target_type: str          # fqdn_root | fqdn_specific | ipv4 | cidr
    discovery_policy: str     # enumerate | scoped | ip_only
    exclusions: list[str]


def _conn():
    return psycopg2.connect(
        os.environ.get("DATABASE_URL", "postgresql://localhost:5432/vectiscan"),
        connect_timeout=10,
        options="-c statement_timeout=30000",
    )


def load_approved_targets(order_id: str) -> list[ScanTarget]:
    """Liefert alle fuer diesen Scan-Lauf in-scope Targets.

    Bevorzugt `scan_run_targets` (Snapshot pro Scan-Lauf, funktioniert fuer
    Single-Scan-Orders UND Abo-Rescans). Faellt auf direktes
    `scan_targets.order_id` zurueck, falls kein Snapshot existiert (z.B.
    aelterer Daten-Stand).
    """
    with _conn() as conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            """SELECT t.id, t.raw_input, t.canonical, t.target_type,
                      COALESCE(r.snapshot_discovery_policy, t.discovery_policy) AS discovery_policy,
                      COALESCE(r.snapshot_exclusions, t.exclusions) AS exclusions
               FROM scan_run_targets r
               JOIN scan_targets t ON t.id = r.scan_target_id
               WHERE r.order_id = %s AND r.in_scope = true
               ORDER BY t.created_at""",
            (order_id,),
        )
        rows = cur.fetchall()
        if not rows:
            cur.execute(
                """SELECT id, raw_input, canonical, target_type,
                          discovery_policy, exclusions
                   FROM scan_targets
                   WHERE order_id = %s AND status = 'approved'
                   ORDER BY created_at""",
                (order_id,),
            )
            rows = cur.fetchall()
        return [
            ScanTarget(
                id=str(row["id"]),
                raw_input=row["raw_input"],
                canonical=row["canonical"],
                target_type=row["target_type"],
                discovery_policy=row["discovery_policy"],
                exclusions=list(row["exclusions"] or []),
            )
            for row in rows
        ]


def derive_primary_domain(targets: list[ScanTarget]) -> str:
    """Bestimme die 'Haupt'-Domain fuer Phase 0a/0b Alt-Logik.

    Praeferenz: erstes enumerate-FQDN-Target > erstes FQDN > erstes CIDR/IP.
    """
    for t in targets:
        if t.target_type in ("fqdn_root", "fqdn_specific") and t.discovery_policy == "enumerate":
            return t.canonical
    for t in targets:
        if t.target_type in ("fqdn_root", "fqdn_specific"):
            return t.canonical
    for t in targets:
        return t.canonical
    return "unknown"


def build_partial_inventory_for_non_enumerate(
    targets: list[ScanTarget],
) -> list[dict[str, Any]]:
    """Fuer scoped + ip_only Targets: erzeuge Hosts direkt ohne Enumeration.

    - scoped (FQDN): DNS-Resolve + httpx-Probe
    - ip_only (IPv4): httpx + reverse DNS
    - ip_only (CIDR): expandiere zu Einzel-IPs, pro IP httpx + reverse DNS

    Diese Hosts werden spaeter mit dem enumerate-Inventar gemerged.
    """
    hosts: list[dict[str, Any]] = []
    for t in targets:
        if t.discovery_policy == "enumerate":
            continue
        try:
            if t.target_type in ("fqdn_root", "fqdn_specific"):
                hosts.extend(_hosts_for_scoped_fqdn(t.canonical))
            elif t.target_type == "ipv4":
                hosts.append(_host_for_ip(t.canonical))
            elif t.target_type == "cidr":
                for ip in cidr_utils.expand_raw(t.canonical, max_hosts=256):
                    hosts.append(_host_for_ip(ip))
        except Exception as exc:
            log.warning("partial_inventory_failed", target=t.canonical, error=str(exc))
    return hosts


def _hosts_for_scoped_fqdn(fqdn: str) -> list[dict[str, Any]]:
    dns = dns_utils.resolve_all(fqdn)
    ips = sorted(set(dns.get("a", []) + dns.get("aaaa", [])))
    if not ips:
        return []
    http = http_utils.probe_both_schemes(fqdn)
    return [{
        "ip": ip,
        "fqdns": [fqdn],
        "web_probe": {
            "has_web": bool(http.get("reachable")),
            "web_fqdn": fqdn,
            "final_url": http.get("final_url"),
            "status": http.get("status"),
        },
        "ports": [],
        "status": "pending",
    } for ip in ips]


def _host_for_ip(ip: str) -> dict[str, Any]:
    reverse = dns_utils.reverse_dns(ip)
    http = http_utils.probe_both_schemes(ip)
    return {
        "ip": ip,
        "fqdns": [reverse] if reverse else [],
        "web_probe": {
            "has_web": bool(http.get("reachable")),
            "web_fqdn": reverse,
            "final_url": http.get("final_url"),
            "status": http.get("status"),
        },
        "ports": [],
        "status": "pending",
    }


def merge_inventories(primary: dict[str, Any], extra_hosts: list[dict[str, Any]]) -> dict[str, Any]:
    """Merge zusätzlicher Hosts in das Haupt-Inventar, dedupliziert nach IP."""
    existing_ips = {h["ip"] for h in primary.get("hosts", [])}
    merged = list(primary.get("hosts", []))
    for h in extra_hosts:
        if h["ip"] in existing_ips:
            # FQDN aus scoped/ip_only-Target dem existierenden Host anheften
            for existing in merged:
                if existing["ip"] == h["ip"]:
                    for f in h.get("fqdns", []):
                        if f and f not in existing.get("fqdns", []):
                            existing.setdefault("fqdns", []).append(f)
                    break
        else:
            merged.append(h)
            existing_ips.add(h["ip"])
    return {**primary, "hosts": merged}


def _fqdn_matches_target(fqdn: str, target: ScanTarget) -> bool:
    """Ist dieser FQDN durch dieses Target abgedeckt?"""
    fqdn_l = fqdn.lower()
    if target.target_type in ("fqdn_root", "fqdn_specific"):
        if target.discovery_policy == "enumerate":
            # alle Subdomains erlaubt
            return fqdn_l == target.canonical or fqdn_l.endswith("." + target.canonical)
        # scoped: nur exakte FQDN
        return fqdn_l == target.canonical
    return False


def _ip_matches_target(ip: str, target: ScanTarget) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if target.target_type == "ipv4":
        return str(addr) == target.canonical
    if target.target_type == "cidr":
        try:
            net = ipaddress.ip_network(target.canonical, strict=False)
            return addr in net
        except ValueError:
            return False
    return False


def _matches_exclusion(ip: str, fqdns: list[str], exclusion: str) -> bool:
    """Prueft Exclusion gegen IP oder FQDN (Glob-Muster)."""
    # CIDR-Exclusion
    if "/" in exclusion and re.match(r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$", exclusion):
        try:
            net = ipaddress.ip_network(exclusion, strict=False)
            return ipaddress.ip_address(ip) in net
        except ValueError:
            return False
    # Einzel-IP
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", exclusion):
        return ip == exclusion
    # FQDN / Glob
    excl_l = exclusion.lower()
    for f in fqdns:
        if fnmatch.fnmatchcase(f.lower(), excl_l):
            return True
    return False


def enforce_scope(
    inventory: dict[str, Any],
    targets: list[ScanTarget],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Verwirft Hosts ausserhalb der Target-Scope und wendet Exclusions an.

    Returns:
        (gefiltertes Inventar, Liste entfernter Hosts mit _out_of_scope_reason)
    """
    in_scope: list[dict[str, Any]] = []
    out_of_scope: list[dict[str, Any]] = []

    for host in inventory.get("hosts", []):
        ip = host.get("ip", "")
        fqdns = host.get("fqdns", [])

        # Match gegen alle Targets
        matched = False
        for t in targets:
            if _ip_matches_target(ip, t):
                matched = True
                break
            for f in fqdns:
                if _fqdn_matches_target(f, t):
                    matched = True
                    break
            if matched:
                break

        if not matched:
            reason = "out_of_scope"
            out_of_scope.append({**host, "_out_of_scope_reason": reason})
            continue

        # Exclusion-Check
        excluded = False
        for t in targets:
            for excl in t.exclusions:
                if _matches_exclusion(ip, fqdns, excl):
                    excluded = True
                    break
            if excluded:
                break

        if excluded:
            out_of_scope.append({**host, "_out_of_scope_reason": "excluded_by_pattern"})
            continue

        in_scope.append(host)

    log.info("scope_enforced", total=len(inventory.get("hosts", [])),
             in_scope=len(in_scope), out_of_scope=len(out_of_scope))

    return {**inventory, "hosts": in_scope}, out_of_scope


def snapshot_run_targets(order_id: str, targets: list[ScanTarget]) -> None:
    """Persistiere welche Targets in diesem Scan-Lauf im Scope waren.

    Muss nur einmal pro Scan aufgerufen werden. Bestehende Eintraege (aus
    dem Admin-Release oder Scheduler) werden ueberschrieben.
    """
    with _conn() as conn, conn.cursor() as cur:
        for t in targets:
            cur.execute(
                """INSERT INTO scan_run_targets
                     (order_id, scan_target_id, in_scope,
                      snapshot_discovery_policy, snapshot_exclusions)
                   VALUES (%s, %s, true, %s, %s)
                   ON CONFLICT (order_id, scan_target_id) DO UPDATE SET
                     snapshot_discovery_policy = EXCLUDED.snapshot_discovery_policy,
                     snapshot_exclusions = EXCLUDED.snapshot_exclusions""",
                (order_id, t.id, t.discovery_policy, t.exclusions),
            )
        conn.commit()


def update_live_hosts_count(order_id: str, count: int) -> None:
    with _conn() as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE orders SET live_hosts_count = %s, updated_at = NOW() WHERE id = %s",
            (count, order_id),
        )
        conn.commit()
