"""Tech-Profile-Enricher (Mai 2026, securess.de-Drift-Fix).

Liest Phase-2-Outputs (header_check, httpx, zap_spider) und reichert
das Phase-1-Tech-Profile um Signale an, die webtech/cms_fingerprinter
nicht erkennt — primaerer Treiber: Microsoft Exchange / OWA Build-Version.

Konkret:
- header_check.headers["x-feserver"] (z.B. "EXCHANGE-2016") +
  ["x-owa-version"] (z.B. "15.1.2507.x") -> Microsoft Exchange-Eintrag
  in technologies[] und cms/cms_version (falls leer).
- zap_spider URLs nach `/owa/auth/<build>/` parsen -> Build-Version.
- httpx tech[]-Array (httpx hat eigene Wappalyzer-Lite) ergaenzt
  technologies[].

Wirkt IN-PLACE auf das uebergebene tech_profile-Dict und persistiert
das angereicherte Profil zurueck nach
``<scan_dir>/hosts/<ip>/phase1/tech_profile.json``.

Idempotent: doppelte Aufrufe fuegen keine Duplikate ein
(Dedup ueber lowercase-Namen).
"""

from __future__ import annotations

import json
import os
import re
from typing import Any

import structlog

from scanner.phase1 import _split_tech_name_version

log = structlog.get_logger()


_OWA_BUILD_RE = re.compile(r"/owa/auth/(\d+\.\d+\.\d+(?:\.\d+)?)/", re.IGNORECASE)
_FESERVER_YEAR_RE = re.compile(r"EXCHANGE[-\s_]?(\d{4})", re.IGNORECASE)


def _add_to_technologies(
    technologies: list[dict[str, str]],
    seen: dict[str, int],
    name: str,
    version: str = "",
) -> None:
    """Fuegt einen Tech-Eintrag hinzu oder mergt Versions-Info in den
    bestehenden Eintrag (Dedup ueber lowercase-Namen).
    """
    n, v = _split_tech_name_version((name or "").strip(), (version or "").strip())
    if not n:
        return
    key = n.lower()
    if key in seen:
        existing = technologies[seen[key]]
        if not existing.get("version") and v:
            existing["version"] = v
            existing["name"] = n
        return
    seen[key] = len(technologies)
    technologies.append({"name": n, "version": v})


def _read_json(path: str) -> Any:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None


def _exchange_from_headers(headers: dict[str, str]) -> tuple[str, str] | None:
    """Liefert (name, version) wenn Headers Exchange-/OWA-Marker haben."""
    if not isinstance(headers, dict):
        return None
    # Case-insensitive lookup
    lower = {k.lower(): str(v) for k, v in headers.items()}
    feserver = lower.get("x-feserver") or ""
    owa_version = lower.get("x-owa-version") or ""
    if owa_version:
        # Konkreter Build (z.B. "15.1.2507.32")
        return ("Microsoft Exchange", owa_version.strip())
    if feserver:
        m = _FESERVER_YEAR_RE.search(feserver)
        if m:
            return ("Microsoft Exchange", m.group(1))
        # Fallback: ganzer Wert als Version
        return ("Microsoft Exchange", feserver.strip())
    return None


def _exchange_build_from_zap(zap_data: Any) -> str | None:
    """Sucht in zap_spider-URLs nach /owa/auth/<build>/-Pfaden."""
    if not zap_data:
        return None
    urls: list[str] = []
    if isinstance(zap_data, dict):
        urls = list(zap_data.get("urls") or [])
    elif isinstance(zap_data, list):
        urls = [u for u in zap_data if isinstance(u, str)]
    for url in urls:
        m = _OWA_BUILD_RE.search(url)
        if m:
            return m.group(1)
    return None


def _httpx_tech(httpx_data: Any) -> list[tuple[str, str]]:
    """Extrahiert tech[]-Array aus httpx-Output (NDJSON oder Dict)."""
    out: list[tuple[str, str]] = []
    candidates: list[Any] = []
    if isinstance(httpx_data, list):
        candidates = httpx_data
    elif isinstance(httpx_data, dict):
        candidates = [httpx_data]
    for entry in candidates:
        if not isinstance(entry, dict):
            continue
        for t in (entry.get("tech") or []):
            if isinstance(t, str):
                # httpx liefert oft "Name:Version"
                if ":" in t:
                    name, _, version = t.partition(":")
                    out.append((name.strip(), version.strip()))
                else:
                    out.append((t.strip(), ""))
            elif isinstance(t, dict):
                out.append((t.get("name", ""), t.get("version", "")))
    return out


def _enrich_one_host(
    tech_profile: dict[str, Any],
    host_dir: str,
) -> dict[str, Any]:
    """Reichert ein einzelnes tech_profile-Dict in-place an.

    Returns: das Dict mit Stats (added_techs, exchange_detected etc.).
    """
    technologies: list[dict[str, str]] = list(tech_profile.get("technologies") or [])
    seen: dict[str, int] = {
        (t.get("name") or "").strip().lower(): i
        for i, t in enumerate(technologies)
        if t.get("name")
    }
    initial_count = len(technologies)

    phase2_dir = os.path.join(host_dir, "phase2")
    headers_data = _read_json(os.path.join(phase2_dir, "headers.json"))
    httpx_data = _read_json(os.path.join(phase2_dir, "httpx.json"))
    zap_spider_data = _read_json(os.path.join(phase2_dir, "zap_spider.json"))

    exchange_version: str | None = None
    exchange_source: str | None = None

    # 1. headers.json — kann eine einzelne Analysis sein, oder pro VHost
    headers_records: list[dict[str, Any]] = []
    if isinstance(headers_data, dict):
        if "headers" in headers_data:
            headers_records = [headers_data]
        else:
            # Pro-VHost-Map (fqdn -> analysis)
            headers_records = [v for v in headers_data.values() if isinstance(v, dict)]
    elif isinstance(headers_data, list):
        headers_records = [r for r in headers_data if isinstance(r, dict)]

    for rec in headers_records:
        headers = rec.get("headers") or {}
        ex = _exchange_from_headers(headers)
        if ex:
            name, ver = ex
            _add_to_technologies(technologies, seen, name, ver)
            if not exchange_version or len(ver) > len(exchange_version):
                exchange_version = ver
                exchange_source = "header_check"
        # x-aspnet-version / x-powered-by als Tech-Signale
        lower = {k.lower(): str(v) for k, v in headers.items() if isinstance(headers, dict)}
        aspnet = lower.get("x-aspnet-version") or ""
        if aspnet:
            _add_to_technologies(technologies, seen, "ASP.NET", aspnet)
        powered = lower.get("x-powered-by") or ""
        if powered:
            _add_to_technologies(technologies, seen, powered)

    # 2. zap_spider — Build aus URL-Pfad
    zap_build = _exchange_build_from_zap(zap_spider_data)
    if zap_build:
        _add_to_technologies(technologies, seen, "Microsoft Exchange", zap_build)
        # zap_build ist konkreter (4-Tupel-Build), bevorzuge ihn
        exchange_version = zap_build
        exchange_source = exchange_source or "zap_spider"

    # 3. httpx tech[]
    for name, ver in _httpx_tech(httpx_data):
        if name:
            _add_to_technologies(technologies, seen, name, ver)

    tech_profile["technologies"] = technologies

    # cms / cms_version setzen falls Exchange erkannt und kein anderes CMS
    # bereits gesetzt war (CMSFingerprinter kennt Exchange nicht).
    if exchange_version and not tech_profile.get("cms"):
        tech_profile["cms"] = "Microsoft Exchange"
        tech_profile["cms_version"] = exchange_version
        tech_profile["cms_confidence"] = 0.95
        tech_profile.setdefault("cms_details", {})
        tech_profile["cms_details"]["enriched_from"] = exchange_source
        # Auch in vhost_results fuer den primary VHost ergaenzen
        primary = tech_profile.get("primary_vhost") or (
            (tech_profile.get("fqdns") or [None])[0]
        )
        if primary:
            vh_results = tech_profile.setdefault("vhost_results", {})
            entry = vh_results.setdefault(primary, {})
            if not entry.get("cms"):
                entry["cms"] = "Microsoft Exchange"
                entry["cms_version"] = exchange_version
                entry["cms_confidence"] = 0.95

    return {
        "added_techs": len(technologies) - initial_count,
        "total_techs": len(technologies),
        "exchange_detected": exchange_version is not None,
        "exchange_version": exchange_version,
        "exchange_source": exchange_source,
    }


def enrich_after_phase2(
    tech_profiles: list[dict[str, Any]],
    scan_dir: str,
) -> dict[str, Any]:
    """Reichert alle tech_profiles um Phase-2-Signale an.

    Persistiert jedes Profil zurueck nach
    ``<scan_dir>/hosts/<ip>/phase1/tech_profile.json``.

    Returns: Aggregations-Stats fuer Logging/Audit.
    """
    if not tech_profiles:
        return {"profiles": 0, "exchange_hosts": 0, "added_techs_total": 0}

    exchange_hosts = 0
    added_total = 0
    for tp in tech_profiles:
        if not isinstance(tp, dict) or tp.get("skipped"):
            continue
        ip = tp.get("ip")
        if not ip:
            continue
        host_dir = os.path.join(scan_dir, "hosts", ip)
        try:
            stats = _enrich_one_host(tp, host_dir)
        except Exception as e:
            log.warning("tech_enricher_host_failed", ip=ip, error=str(e))
            continue
        added_total += stats.get("added_techs", 0)
        if stats.get("exchange_detected"):
            exchange_hosts += 1
        # Persistieren
        try:
            phase1_dir = os.path.join(host_dir, "phase1")
            os.makedirs(phase1_dir, exist_ok=True)
            with open(os.path.join(phase1_dir, "tech_profile.json"), "w",
                      encoding="utf-8") as f:
                json.dump(tp, f, indent=2, ensure_ascii=False)
        except Exception as e:
            log.warning("tech_enricher_persist_failed", ip=ip, error=str(e))

    log.info(
        "tech_enricher_complete",
        profiles=len(tech_profiles),
        exchange_hosts=exchange_hosts,
        added_techs_total=added_total,
    )
    return {
        "profiles": len(tech_profiles),
        "exchange_hosts": exchange_hosts,
        "added_techs_total": added_total,
    }


__all__ = ["enrich_after_phase2"]
