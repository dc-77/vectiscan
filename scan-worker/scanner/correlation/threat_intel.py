"""Threat Intelligence clients — NVD, EPSS, CISA KEV, ExploitDB.

All clients are designed for graceful degradation: missing API keys or
network errors never crash the pipeline — they just return empty results.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from typing import Any, Optional

import redis
import requests
import structlog

log = structlog.get_logger()

# ---------------------------------------------------------------------------
# Redis cache helper
# ---------------------------------------------------------------------------

def _get_redis() -> redis.Redis:
    return redis.from_url(os.environ.get("REDIS_URL", "redis://localhost:6379"))


def _cache_get(key: str) -> Optional[dict[str, Any]]:
    """Get cached value from Redis."""
    try:
        r = _get_redis()
        raw = r.get(key)
        if raw:
            return json.loads(raw)
    except Exception:
        pass
    return None


def _cache_set(key: str, value: Any, ttl: int = 86400) -> None:
    """Set cached value in Redis with TTL (default 24h)."""
    try:
        r = _get_redis()
        r.set(key, json.dumps(value, default=str), ex=ttl)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# NVD API Client
# ---------------------------------------------------------------------------

class NVDClient:
    """NVD (National Vulnerability Database) API client.

    Fetches authoritative CVSS scores, CWE-IDs, and patch references for CVEs.
    Rate limit: 5 req/30s without key, 50 req/30s with key.
    """

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self):
        self.api_key = os.environ.get("NVD_API_KEY", "")
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "VectiScan/2.0"})
        if self.api_key:
            self.session.headers.update({"apiKey": self.api_key})
        # Rate limiting: track last request time
        self._last_request = 0.0
        self._min_interval = 0.6 if self.api_key else 6.0  # 50/30s vs 5/30s

    @property
    def available(self) -> bool:
        return True  # NVD works without key (just slower)

    def _rate_limit(self) -> None:
        elapsed = time.monotonic() - self._last_request
        if elapsed < self._min_interval:
            time.sleep(self._min_interval - elapsed)
        self._last_request = time.monotonic()

    def lookup_cve(self, cve_id: str) -> Optional[dict[str, Any]]:
        """Fetch CVE details from NVD. Returns enriched data or None."""
        cache_key = f"nvd:{cve_id}"
        cached = _cache_get(cache_key)
        if cached:
            return cached

        self._rate_limit()
        try:
            resp = self.session.get(
                self.BASE_URL,
                params={"cveId": cve_id},
                timeout=15,
            )
            if resp.status_code == 429:
                log.warning("nvd_rate_limited", cve=cve_id)
                time.sleep(10)
                return None
            if resp.status_code != 200:
                log.warning("nvd_http_error", cve=cve_id, status=resp.status_code)
                return None

            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return None

            cve_data = vulns[0].get("cve", {})
            result = self._parse_cve(cve_id, cve_data)
            _cache_set(cache_key, result, ttl=86400)  # 24h cache
            return result

        except Exception as e:
            log.warning("nvd_lookup_error", cve=cve_id, error=str(e))
            return None

    def lookup_batch(self, cve_ids: list[str], max_lookups: int = 50) -> dict[str, dict[str, Any]]:
        """Fetch multiple CVEs. Returns dict of cve_id → enrichment data."""
        results: dict[str, dict[str, Any]] = {}
        for cve_id in cve_ids[:max_lookups]:
            data = self.lookup_cve(cve_id)
            if data:
                results[cve_id] = data
        log.info("nvd_batch_complete", requested=len(cve_ids),
                 fetched=len(results), max=max_lookups)
        return results

    def _parse_cve(self, cve_id: str, cve_data: dict) -> dict[str, Any]:
        """Parse NVD CVE response into structured enrichment data."""
        # Extract CVSS v3.1 score
        cvss_v31 = None
        cvss_score = None
        cvss_vector = None
        metrics = cve_data.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30"):
            metric_list = metrics.get(key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_vector = cvss_data.get("vectorString")
                cvss_v31 = {
                    "score": cvss_score,
                    "vector": cvss_vector,
                    "severity": cvss_data.get("baseSeverity"),
                }
                break

        # Extract CWE
        cwes: list[str] = []
        for weakness in cve_data.get("weaknesses", []):
            for desc in weakness.get("description", []):
                cwe_val = desc.get("value", "")
                if cwe_val.startswith("CWE-"):
                    cwes.append(cwe_val)

        # Extract description
        description = ""
        for desc in cve_data.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        # Extract references (patches, advisories)
        references: list[dict[str, str]] = []
        for ref in cve_data.get("references", [])[:5]:  # Max 5
            references.append({
                "url": ref.get("url", ""),
                "source": ref.get("source", ""),
                "tags": ref.get("tags", []),
            })

        return {
            "cve_id": cve_id,
            "cvss_v31": cvss_v31,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "cwes": cwes,
            "description": description[:500],
            "references": references,
            "source": "nvd",
        }


# ---------------------------------------------------------------------------
# EPSS Client
# ---------------------------------------------------------------------------

class EPSSClient:
    """EPSS (Exploit Prediction Scoring System) client.

    Free API from FIRST.org. Returns probability that a CVE will be
    exploited in the next 30 days.
    """

    BASE_URL = "https://api.first.org/data/v1/epss"

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "VectiScan/2.0"})

    @property
    def available(self) -> bool:
        return True  # Public API, no key needed

    def lookup_batch(self, cve_ids: list[str]) -> dict[str, dict[str, float]]:
        """Fetch EPSS scores for multiple CVEs in one request.

        Returns dict of cve_id → {"epss": float, "percentile": float}.
        """
        if not cve_ids:
            return {}

        results: dict[str, dict[str, float]] = {}

        # EPSS API accepts comma-separated CVEs (batch)
        # Process in chunks of 100
        for i in range(0, len(cve_ids), 100):
            chunk = cve_ids[i:i + 100]

            # Check cache first
            uncached: list[str] = []
            for cve_id in chunk:
                cached = _cache_get(f"epss:{cve_id}")
                if cached:
                    results[cve_id] = cached
                else:
                    uncached.append(cve_id)

            if not uncached:
                continue

            try:
                resp = self.session.get(
                    self.BASE_URL,
                    params={"cve": ",".join(uncached)},
                    timeout=15,
                )
                if resp.status_code != 200:
                    log.warning("epss_http_error", status=resp.status_code)
                    continue

                data = resp.json()
                for entry in data.get("data", []):
                    cve_id = entry.get("cve", "")
                    epss_data = {
                        "epss": float(entry.get("epss", 0)),
                        "percentile": float(entry.get("percentile", 0)),
                    }
                    results[cve_id] = epss_data
                    _cache_set(f"epss:{cve_id}", epss_data, ttl=43200)  # 12h

            except Exception as e:
                log.warning("epss_batch_error", error=str(e), chunk_size=len(uncached))

        log.info("epss_batch_complete", requested=len(cve_ids), fetched=len(results))
        return results


# ---------------------------------------------------------------------------
# CISA KEV (Known Exploited Vulnerabilities)
# ---------------------------------------------------------------------------

class CISAKEVLoader:
    """CISA Known Exploited Vulnerabilities Catalog.

    Downloads the full catalog (JSON, ~1.5 MB) and caches locally.
    Refresh every 6 hours.
    """

    CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    CACHE_KEY = "cisa_kev:catalog"
    CACHE_TTL = 21600  # 6 hours

    def __init__(self):
        self._catalog: dict[str, dict[str, Any]] = {}
        self._loaded = False

    @property
    def available(self) -> bool:
        return True  # Public, no key needed

    def _load(self) -> None:
        """Load the KEV catalog from cache or remote."""
        if self._loaded:
            return

        # Try Redis cache first
        cached = _cache_get(self.CACHE_KEY)
        if cached and isinstance(cached, dict):
            self._catalog = cached
            self._loaded = True
            log.info("cisa_kev_loaded_from_cache", count=len(self._catalog))
            return

        # Fetch from CISA
        try:
            resp = requests.get(self.CATALOG_URL, timeout=30,
                                headers={"User-Agent": "VectiScan/2.0"})
            if resp.status_code != 200:
                log.warning("cisa_kev_fetch_failed", status=resp.status_code)
                self._loaded = True
                return

            data = resp.json()
            vulns = data.get("vulnerabilities", [])

            # Index by CVE ID for fast lookup
            for vuln in vulns:
                cve_id = vuln.get("cveID", "")
                if cve_id:
                    self._catalog[cve_id] = {
                        "vendor": vuln.get("vendorProject", ""),
                        "product": vuln.get("product", ""),
                        "name": vuln.get("vulnerabilityName", ""),
                        "date_added": vuln.get("dateAdded", ""),
                        "due_date": vuln.get("requiredAction", ""),
                        "known_ransomware": vuln.get("knownRansomwareCampaignUse", "Unknown"),
                    }

            _cache_set(self.CACHE_KEY, self._catalog, ttl=self.CACHE_TTL)
            self._loaded = True
            log.info("cisa_kev_loaded_from_remote", count=len(self._catalog))

        except Exception as e:
            log.warning("cisa_kev_load_error", error=str(e))
            self._loaded = True

    def check_cve(self, cve_id: str) -> Optional[dict[str, Any]]:
        """Check if a CVE is in the CISA KEV catalog."""
        self._load()
        return self._catalog.get(cve_id)

    def check_batch(self, cve_ids: list[str]) -> dict[str, dict[str, Any]]:
        """Check multiple CVEs against the KEV catalog."""
        self._load()
        results: dict[str, dict[str, Any]] = {}
        for cve_id in cve_ids:
            kev = self._catalog.get(cve_id)
            if kev:
                results[cve_id] = kev
        log.info("cisa_kev_batch_complete", checked=len(cve_ids), matches=len(results))
        return results


# ---------------------------------------------------------------------------
# ExploitDB Client (local searchsploit)
# ---------------------------------------------------------------------------

class ExploitDBClient:
    """ExploitDB client using local searchsploit binary.

    searchsploit is part of the exploit-database package and searches
    the local offline database for public exploits.
    """

    def __init__(self):
        self._available: Optional[bool] = None

    @property
    def available(self) -> bool:
        if self._available is None:
            try:
                result = subprocess.run(
                    ["searchsploit", "--help"],
                    capture_output=True, timeout=5,
                )
                self._available = result.returncode == 0
            except Exception:
                self._available = False
        return self._available

    def search_cve(self, cve_id: str) -> Optional[dict[str, Any]]:
        """Search ExploitDB for exploits matching a CVE ID.

        Returns enrichment dict or None if no exploits found.
        """
        if not self.available:
            return None

        cache_key = f"exploitdb:{cve_id}"
        cached = _cache_get(cache_key)
        if cached:
            return cached

        try:
            result = subprocess.run(
                ["searchsploit", "--cve", cve_id, "-j"],
                capture_output=True, text=True, timeout=10,
                start_new_session=True,
            )
            if result.returncode != 0:
                return None

            data = json.loads(result.stdout)
            exploits = data.get("RESULTS_EXPLOIT", [])

            if not exploits:
                return None

            # Determine exploit types
            exploit_types: set[str] = set()
            has_metasploit = False
            for exp in exploits:
                path = exp.get("Path", "").lower()
                if "remote" in path:
                    exploit_types.add("remote")
                elif "local" in path:
                    exploit_types.add("local")
                elif "webapps" in path:
                    exploit_types.add("webapps")
                elif "dos" in path:
                    exploit_types.add("dos")

                # Check for Metasploit modules
                if "metasploit" in path or exp.get("Type", "").lower() == "metasploit":
                    has_metasploit = True

            enrichment = {
                "cve": cve_id,
                "exploits_available": True,
                "exploit_count": len(exploits),
                "exploit_types": sorted(exploit_types),
                "metasploit_module": has_metasploit,
                "exploits": [
                    {
                        "title": exp.get("Title", ""),
                        "path": exp.get("Path", ""),
                        "type": exp.get("Type", ""),
                    }
                    for exp in exploits[:5]  # Max 5 for brevity
                ],
            }

            _cache_set(cache_key, enrichment, ttl=86400)  # 24h
            return enrichment

        except Exception as e:
            log.warning("exploitdb_search_error", cve=cve_id, error=str(e))
            return None

    def search_batch(self, cve_ids: list[str]) -> dict[str, dict[str, Any]]:
        """Search ExploitDB for multiple CVEs."""
        results: dict[str, dict[str, Any]] = {}
        for cve_id in cve_ids:
            data = self.search_cve(cve_id)
            if data:
                results[cve_id] = data
        log.info("exploitdb_batch_complete", searched=len(cve_ids), found=len(results))
        return results
