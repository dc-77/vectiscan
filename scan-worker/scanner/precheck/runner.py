"""Pre-Check-Orchestrator pro Target.

Liest `scan_targets`-Zeile, fuehrt typspezifische Prozeduren aus
(FQDN: DNS+httpx, IPv4: reverse+httpx+nmap-light, CIDR: expand+nmap+httpx),
schreibt `scan_target_hosts`-Eintraege und publisht Events.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import structlog

from scanner.progress import publish_event
from scanner.precheck import (
    cidr_expander,
    dns_resolver,
    httpx_probe,
    nmap_light,
    saas_heuristic,
    writer,
)

log = structlog.get_logger()

PRECHECK_TIMEOUT_PER_TARGET = 180  # 3 Min
CIDR_MAX_PARALLEL = 20


def _publish(owner_id: str, target_id: str, phase: str, message: str) -> None:
    publish_event(owner_id, {
        "type": "precheck_progress",
        "orderId": owner_id,
        "targetId": target_id,
        "phase": phase,
        "message": message,
    })


def run_target(target: dict[str, Any]) -> dict[str, Any]:
    """Fuehre Pre-Check fuer ein Target aus. Returns Summary-Dict."""
    target_id = str(target["id"])
    owner_id = str(target.get("order_id") or target.get("subscription_id") or "")
    raw = target["raw_input"]
    canonical = target.get("canonical") or raw
    target_type = target["target_type"]

    writer.set_target_status(target_id, "precheck_running")
    _publish(owner_id, target_id, "start", f"Pre-Check: {raw}")

    started = time.time()
    try:
        if target_type in ("fqdn_root", "fqdn_specific"):
            summary = _run_fqdn(target_id, owner_id, canonical)
        elif target_type == "ipv4":
            summary = _run_ipv4(target_id, owner_id, canonical)
        elif target_type == "cidr":
            summary = _run_cidr(target_id, owner_id, canonical)
        else:
            log.warning("unknown_target_type", target_id=target_id, type=target_type)
            summary = {"live_hosts": 0, "total_hosts": 0, "error": "unknown_type"}

        writer.set_target_status(target_id, "precheck_complete")
        publish_event(owner_id, {
            "type": "precheck_target_complete",
            "orderId": owner_id,
            "targetId": target_id,
            "result": summary,
        })
    except Exception as exc:
        log.error("precheck_target_failed", target_id=target_id, error=str(exc))
        writer.set_target_status(target_id, "precheck_failed")
        summary = {"error": str(exc), "live_hosts": 0, "total_hosts": 0}
        publish_event(owner_id, {
            "type": "precheck_target_complete",
            "orderId": owner_id,
            "targetId": target_id,
            "result": summary,
        })

    summary["duration_s"] = round(time.time() - started, 1)
    return summary


def _run_fqdn(target_id: str, owner_id: str, fqdn: str) -> dict[str, Any]:
    _publish(owner_id, target_id, "dns", f"DNS-Aufloesung {fqdn}")
    dns = dns_resolver.resolve(fqdn)
    ips = sorted(set(dns.get("a", []) + dns.get("aaaa", [])))

    _publish(owner_id, target_id, "http", f"HTTP-Probe {fqdn}")
    http = httpx_probe.probe(fqdn)

    # Cloud-Provider ueber erste A-IP
    cloud = None
    for ip in ips:
        cloud = saas_heuristic.detect_cloud_provider(ip)
        if cloud:
            break

    if not ips:
        # Schreib trotzdem einen Eintrag, damit Admin sieht, dass nichts aufgeloest wurde
        writer.insert_host(
            target_id=target_id, ip=None, fqdns=[fqdn], is_live=False,
            ports=[], http_status=http.get("status"), http_title=http.get("title"),
            http_final_url=http.get("final_url"), reverse=None,
            cloud_provider=None, parking=http.get("parking", False),
            source="precheck_dns",
        )
        return {"live_hosts": 0, "total_hosts": 0, "fqdn": fqdn, "dns": dns, "http": http}

    live_count = 0
    for ip in ips:
        reachable = bool(http.get("reachable"))
        if reachable:
            live_count += 1
        writer.insert_host(
            target_id=target_id, ip=ip, fqdns=[fqdn],
            is_live=reachable, ports=[],
            http_status=http.get("status"), http_title=http.get("title"),
            http_final_url=http.get("final_url"),
            reverse=None, cloud_provider=cloud,
            parking=http.get("parking", False),
            source="precheck_httpx",
        )

    return {
        "live_hosts": live_count,
        "total_hosts": len(ips),
        "fqdn": fqdn,
        "ips": ips,
        "cloud_provider": cloud,
        "http": http,
    }


def _run_ipv4(target_id: str, owner_id: str, ip: str) -> dict[str, Any]:
    _publish(owner_id, target_id, "dns", f"Reverse-DNS {ip}")
    reverse = dns_resolver.reverse(ip)

    _publish(owner_id, target_id, "nmap", f"Top-10-Ports {ip}")
    nmap_result = nmap_light.scan([ip])
    ports = nmap_result.get(ip, [])

    _publish(owner_id, target_id, "http", f"HTTP-Probe {ip}")
    http = httpx_probe.probe(ip)

    cloud = saas_heuristic.detect_cloud_provider(ip)
    is_live = bool(ports) or bool(http.get("reachable"))

    writer.insert_host(
        target_id=target_id, ip=ip,
        fqdns=[reverse] if reverse else [],
        is_live=is_live, ports=ports,
        http_status=http.get("status"), http_title=http.get("title"),
        http_final_url=http.get("final_url"),
        reverse=reverse, cloud_provider=cloud,
        parking=http.get("parking", False),
        source="precheck_nmap",
    )

    return {
        "live_hosts": 1 if is_live else 0,
        "total_hosts": 1,
        "ip": ip,
        "ports": ports,
        "reverse_dns": reverse,
        "cloud_provider": cloud,
    }


def _run_cidr(target_id: str, owner_id: str, cidr: str) -> dict[str, Any]:
    ips = cidr_expander.expand(cidr, max_hosts=256)
    _publish(owner_id, target_id, "expand", f"{cidr}: {len(ips)} IPs expandiert")

    if not ips:
        return {"live_hosts": 0, "total_hosts": 0, "error": "cidr_expansion_failed"}

    # Dead hosts trotzdem als expansion-Eintrag persistieren
    for ip in ips:
        writer.insert_host(
            target_id=target_id, ip=ip, fqdns=[], is_live=False,
            ports=[], http_status=None, http_title=None,
            http_final_url=None, reverse=None,
            cloud_provider=saas_heuristic.detect_cloud_provider(ip),
            parking=False, source="expansion",
        )

    _publish(owner_id, target_id, "nmap", f"Top-10-Ports fuer {len(ips)} IPs")
    nmap_result = nmap_light.scan(ips)
    live_ips = [ip for ip, ports in nmap_result.items() if ports]

    _publish(owner_id, target_id, "http", f"HTTP-Probe auf {len(live_ips)} live Hosts")
    live_count = 0
    with ThreadPoolExecutor(max_workers=CIDR_MAX_PARALLEL) as pool:
        futures = {pool.submit(_probe_live_cidr_host, target_id, ip, nmap_result.get(ip, [])): ip
                   for ip in live_ips}
        for fut in futures:
            try:
                if fut.result():
                    live_count += 1
            except Exception as exc:
                log.warning("cidr_host_probe_failed", ip=futures[fut], error=str(exc))

    return {
        "live_hosts": live_count,
        "total_hosts": len(ips),
        "cidr": cidr,
    }


def _probe_live_cidr_host(target_id: str, ip: str, ports: list[int]) -> bool:
    """Probe live host from CIDR expansion — write detailed entry."""
    reverse = dns_resolver.reverse(ip)
    http = httpx_probe.probe(ip)
    cloud = saas_heuristic.detect_cloud_provider(ip)

    # Write a precheck_httpx entry alongside the expansion stub.
    writer.insert_host(
        target_id=target_id, ip=ip,
        fqdns=[reverse] if reverse else [],
        is_live=True, ports=ports,
        http_status=http.get("status"), http_title=http.get("title"),
        http_final_url=http.get("final_url"),
        reverse=reverse, cloud_provider=cloud,
        parking=http.get("parking", False),
        source="precheck_httpx",
    )
    return True
