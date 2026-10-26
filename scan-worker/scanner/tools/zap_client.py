"""ZAP daemon REST API client with context-based session isolation.

Communicates with OWASP ZAP running as a daemon container on port 8090.
Each scan gets its own ZAP context (named ctx-{order_id[:8]}-{ip}) so that
multiple scan-worker replicas can share one ZAP instance without interference.
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
from typing import Any, Callable, Optional

import requests
import structlog

log = structlog.get_logger()

ZAP_BASE_URL = os.environ.get("ZAP_BASE_URL", "http://zap:8090")
CONNECT_TIMEOUT = 5
READ_TIMEOUT = 30

# Abholung der Alerts: ZAP serialisiert alle angeforderten Alerts in eine
# einzige Antwort. Bei grossen Zielen (rankingcoach: 2252 gespiderte URLs)
# brauchte ein Aufruf mit count=5000 laenger als READ_TIMEOUT, die Anfrage lief
# in den Timeout und der komplette Host verlor seine Befunde ("alles oder
# nichts", 10 von 15 Hosts in Auftrag 11aa6a3c). Deshalb seitenweise holen und
# fuer diese Seiten einen eigenen, groesseren Lesetimeout verwenden.
ALERT_PAGE_SIZE = 500
ALERT_READ_TIMEOUT = 120
ALERT_MAX_TOTAL = 5000

# Warten auf die Passiv-Queue: der Passiv-Scanner arbeitet jeden Treffer von
# Spider und Active Scan nach. 30 Sekunden reichten dafuer nur auf kleinen
# Zielen; danach wurden die Alerts trotzdem geholt und die unvollstaendige
# Menge als vollstaendig verbucht. Grosszuegiger warten und das Ergebnis des
# Wartens auswerten, statt still eine Teilmenge auszugeben.
PASSIVE_WAIT_TIMEOUT = 300

# Thread-local pool assignment: worker.py leases a zap_id for the duration
# of a host scan and stores it here. ZapClient() (no args) reads it as
# fallback so every existing call site picks up the right daemon without
# signature changes.
_thread_local = threading.local()


def set_thread_zap_id(zap_id: str | None) -> None:
    """Set the ZAP daemon for the current thread. ``None`` clears it."""
    _thread_local.zap_id = zap_id


def get_thread_zap_id() -> str | None:
    return getattr(_thread_local, "zap_id", None)


_UNSAFE_NAME_CHARS = re.compile(r"[^A-Za-z0-9_-]")


def safe_name_part(value: str) -> str:
    """Make ``value`` usable inside a ZAP context or scan-policy name.

    S0b: ZAP prueft Policy-Namen mit ``isLegalPolicyName`` und verbietet
    ``/``, ``\\``, ``:``, ``;``, ``"`` und ``'``. ``ip.replace(".", "_")``
    liess bei IPv6 die Doppelpunkte stehen, ZAP antwortete
    ``illegal_parameter`` und der Active Scan fiel aus. Hier wird alles
    ausserhalb ``[A-Za-z0-9_-]`` zu ``_``.

    Context- und Policy-Namen benutzen denselben Helfer, damit
    ``zap_pool.get_all_active_context_names`` denselben Namen bildet wie
    ``phase2`` -- sonst raeumt der Pool laufende Kontexte weg.
    """
    return _UNSAFE_NAME_CHARS.sub("_", value or "")


def _parse_zap_error_body(text: str) -> tuple[str | None, str]:
    """Split a ZAP API error body into ``(code, readable_text)``.

    ZAP antwortet auf Fehler mit ``{"code": ..., "message": ..., "detail": ...}``.
    ``detail`` liefert es nur, wenn ``api.incerrordetails=true`` gesetzt ist.
    Bis S0b stand in den Scan-Ergebnissen nur der auf 200 Zeichen gekuerzte
    Rohtext, deshalb war ``does_not_exist`` aus ``enableScanners`` nicht von
    ``does_not_exist`` aus ``ascan/action/scan`` zu unterscheiden.
    """
    raw = (text or "").strip()
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return None, raw[:200]
    if not isinstance(data, dict):
        return None, raw[:200]
    code = data.get("code") or None
    parts = [str(data.get("code", "")).strip()]
    for key in ("message", "detail"):
        value = str(data.get(key, "")).strip()
        if value:
            parts.append(value)
    readable = " / ".join(p for p in parts if p) or raw[:200]
    return (str(code) if code else None), readable[:300]


class ZapError(Exception):
    """Raised when a ZAP API call fails or times out.

    S0a: traegt zusaetzlich den Endpunkt und die Parameter der
    fehlgeschlagenen Anfrage. Ohne diese Angaben war in 42 Produktionsscans
    nicht zu erkennen, welcher der ZAP-Aufrufe (Kontext, Policy, Spider,
    Active Scan) "does_not_exist" geliefert hat -- Vorarbeit fuer S0b
    (spec/07 Abschnitt 4).
    """

    def __init__(
        self,
        message: str,
        *,
        endpoint: str | None = None,
        params: dict[str, Any] | None = None,
        zap_id: str | None = None,
        zap_code: str | None = None,
        http_status: int | None = None,
        base_url: str | None = None,
    ):
        self.endpoint = endpoint
        self.params = dict(params) if params else {}
        self.zap_id = zap_id
        # S0b: der ZAP-Fehlercode ("does_not_exist", "already_exists", ...)
        # als eigenes Feld. Aufrufer koennen damit unterscheiden, statt im
        # Fehlertext nach Teilstrings zu suchen.
        self.zap_code = zap_code
        self.http_status = http_status
        self.base_url = base_url
        detail = []
        if endpoint:
            detail.append(f"endpoint={endpoint}")
        if self.params:
            detail.append(f"params={self.params}")
        if zap_id:
            detail.append(f"zap={zap_id}")
        elif base_url:
            detail.append(f"zap={base_url}")
        if detail:
            message = f"{message} [{', '.join(detail)}]"
        super().__init__(message)


class ZapClient:
    """ZAP daemon REST API client with context-based session isolation."""

    def __init__(
        self,
        base_url: str | None = None,
        zap_id: str | None = None,
    ):
        """Connect to a ZAP daemon.

        Precedence: explicit ``base_url`` > explicit ``zap_id`` > thread-local
        ``zap_id`` (set by the pool-leased worker task) > env ``ZAP_BASE_URL``
        (legacy single-daemon fallback).
        """
        effective_zap_id = zap_id or get_thread_zap_id()
        if base_url:
            resolved = base_url
        elif effective_zap_id:
            resolved = f"http://{effective_zap_id}:8090"
        else:
            resolved = ZAP_BASE_URL
        self.base_url = resolved.rstrip("/")
        self.zap_id = effective_zap_id
        self.session = requests.Session()
        self.session.headers["Accept"] = "application/json"
        # S0b: welche angeforderten Scanner-IDs der Daemon nicht kennt.
        # Wird von phase2 in die Abdeckung geschrieben.
        self.last_dropped_scanner_ids: list[int] = []

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get(self, path: str, params: dict[str, Any] | None = None,
             read_timeout: int | None = None) -> dict[str, Any]:
        """GET request to ZAP API. Returns parsed JSON response.

        ``read_timeout`` ueberschreibt den Lesetimeout fuer diesen einen
        Aufruf; ohne Angabe gilt READ_TIMEOUT.
        """
        url = f"{self.base_url}{path}"
        # S0a: Kontext fuer jede ZapError -- welcher Endpunkt, welche Parameter,
        # welche Pool-Instanz. Ohne das ist "does_not_exist" nicht zuordenbar.
        ctx = {"endpoint": path, "params": params, "zap_id": self.zap_id,
               "base_url": self.base_url}
        try:
            resp = self.session.get(
                url, params=params or {},
                timeout=(CONNECT_TIMEOUT, read_timeout or READ_TIMEOUT),
            )
            resp.raise_for_status()
            return resp.json()
        except requests.ConnectionError as e:
            raise ZapError(f"ZAP unreachable at {self.base_url}: {e}", **ctx) from e
        except requests.Timeout as e:
            raise ZapError("ZAP request timed out", **ctx) from e
        except requests.HTTPError as e:
            code, body = _parse_zap_error_body(resp.text)
            raise ZapError(f"ZAP API error {resp.status_code}: {body}",
                           zap_code=code, http_status=resp.status_code, **ctx) from e
        except ValueError as e:
            raise ZapError("ZAP returned invalid JSON", **ctx) from e

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    def health_check(self) -> bool:
        """Check if ZAP daemon is responsive. Returns True/False, never raises."""
        try:
            data = self._get("/JSON/core/view/version/")
            version = data.get("version", "unknown")
            log.info("zap_health_ok", version=version)
            return True
        except ZapError:
            log.warning("zap_health_failed", base_url=self.base_url)
            return False

    def get_version(self) -> str:
        """Return ZAP version string."""
        data = self._get("/JSON/core/view/version/")
        return data.get("version", "unknown")

    # ------------------------------------------------------------------
    # Context Management
    # ------------------------------------------------------------------

    def create_context(self, context_name: str) -> int:
        """Create a new ZAP context. Returns the context ID."""
        data = self._get("/JSON/context/action/newContext/", {"contextName": context_name})
        context_id = int(data.get("contextId", 0))
        # S0b: base_url mitloggen. Kontext, Policy und Active Scan muessen auf
        # derselben Instanz liegen, und nur die Logs koennen das belegen.
        log.info("zap_context_created", name=context_name, id=context_id,
                 zap_id=self.zap_id, base_url=self.base_url)
        return context_id

    def context_exists(self, context_name: str) -> bool:
        """True, wenn dieser Daemon den Kontext gerade fuehrt."""
        try:
            return context_name in self.get_context_list()
        except ZapError as e:
            log.warning("zap_context_check_failed", name=context_name,
                        endpoint=e.endpoint, error=str(e))
            return False

    def access_url(self, url: str) -> None:
        """Einen URL ueber ZAP abrufen, damit er im Site-Tree steht.

        S0b: ``ascan/action/scan`` antwortet ``url_not_found``, wenn der
        Site-Tree keinen Knoten fuer die Ziel-URL hat. Das passierte, wenn der
        Spider gegen einen anderen VHost lief als der Active Scan.
        """
        self._get("/JSON/core/action/accessUrl/", {"url": url, "followRedirects": "true"})
        log.info("zap_url_accessed", url=url[:120], zap_id=self.zap_id)

    def include_in_context(self, context_name: str, regex: str) -> None:
        """Add a URL regex pattern to the context scope."""
        self._get("/JSON/context/action/includeInContext/", {
            "contextName": context_name,
            "regex": regex,
        })

    def remove_context(self, context_name: str) -> None:
        """Remove a context and all its data."""
        try:
            self._get("/JSON/context/action/removeContext/", {"contextName": context_name})
            log.info("zap_context_removed", name=context_name)
        except ZapError as e:
            log.warning("zap_context_remove_failed", name=context_name,
                        endpoint=e.endpoint, error=str(e))

    def get_context_list(self) -> list[str]:
        """List all context names that currently exist on the ZAP daemon."""
        data = self._get("/JSON/context/view/contextList/")
        raw = data.get("contextList", [])
        # ZAP historically returns the list as a JSON-encoded string with brackets;
        # modern builds return a proper list. Normalize both shapes.
        if isinstance(raw, str):
            stripped = raw.strip().lstrip("[").rstrip("]")
            if not stripped:
                return []
            return [p.strip().strip('"').strip("'") for p in stripped.split(",") if p.strip()]
        return [str(entry) for entry in raw]

    def delete_context(self, context_name: str) -> None:
        """Alias for ``remove_context`` used by the pool-cleanup path."""
        self.remove_context(context_name)

    def cleanup_stale_contexts(self, active_context_names: set[str]) -> int:
        """Remove all ``ctx-*`` contexts that are not in ``active_context_names``.

        Called at the start of every pool lease so a worker never inherits
        contexts from a previous (crashed) lease on the same ZAP daemon.
        Non-``ctx-`` contexts (default, manually created) are left alone.
        """
        deleted = 0
        try:
            contexts = self.get_context_list()
        except ZapError as e:
            log.warning("zap_context_list_failed", endpoint=e.endpoint, error=str(e))
            return 0
        for ctx_name in contexts:
            if not ctx_name.startswith("ctx-"):
                continue
            if ctx_name in active_context_names:
                continue
            self.delete_context(ctx_name)
            deleted += 1
        if deleted:
            log.info("zap_cleanup_performed", zap_id=self.zap_id, stale_contexts_deleted=deleted)
        return deleted

    # ------------------------------------------------------------------
    # Traditional Spider
    # ------------------------------------------------------------------

    def start_spider(
        self,
        url: str,
        context_name: str | None = None,
        max_depth: int = 5,
    ) -> int:
        """Start the traditional spider. Returns scan ID."""
        params: dict[str, Any] = {"url": url, "maxChildren": 0, "recurse": "true"}
        if context_name:
            params["contextName"] = context_name
        data = self._get("/JSON/spider/action/scan/", params)
        scan_id = int(data.get("scan", 0))
        log.info("zap_spider_started", url=url, scan_id=scan_id, max_depth=max_depth)

        # Set max depth
        self._get("/JSON/spider/action/setOptionMaxDepth/", {"Integer": str(max_depth)})
        return scan_id

    def spider_status(self, scan_id: int) -> int:
        """Get spider progress (0-100)."""
        data = self._get("/JSON/spider/view/status/", {"scanId": str(scan_id)})
        return int(data.get("status", 0))

    def spider_results(self, scan_id: int) -> list[str]:
        """Get list of URLs discovered by the spider."""
        data = self._get("/JSON/spider/view/results/", {"scanId": str(scan_id)})
        return data.get("results", [])

    # ------------------------------------------------------------------
    # AJAX Spider
    # ------------------------------------------------------------------

    def start_ajax_spider(self, url: str, context_name: str | None = None) -> None:
        """Start the AJAX spider (headless browser crawl)."""
        params: dict[str, Any] = {"url": url}
        if context_name:
            params["contextName"] = context_name
        self._get("/JSON/ajaxSpider/action/scan/", params)
        log.info("zap_ajax_spider_started", url=url)

    def ajax_spider_status(self) -> str:
        """Get AJAX spider status: 'running' or 'stopped'."""
        data = self._get("/JSON/ajaxSpider/view/status/")
        return data.get("status", "stopped")

    def stop_ajax_spider(self) -> None:
        """Stop the AJAX spider."""
        self._get("/JSON/ajaxSpider/action/stop/")
        log.info("zap_ajax_spider_stopped")

    # ------------------------------------------------------------------
    # Passive Scanner
    # ------------------------------------------------------------------

    def wait_for_passive_scan(self, timeout: int = PASSIVE_WAIT_TIMEOUT) -> bool:
        """Wait for ZAP passive scanner queue to drain.

        The passive scanner runs automatically on all traffic (spider, active scan).
        After spider/active scan completes, there may still be items queued.
        Call this before collecting alerts to ensure passive findings are included.

        Gibt True zurueck, wenn die Queue leer ist, und False, wenn das
        Zeitlimit zuerst greift. Der Aufrufer muss False auswerten: die danach
        geholten Alerts sind dann unvollstaendig.
        """
        return self.poll_until_complete(
            lambda: int(self._get("/JSON/pscan/view/recordsToScan/").get("recordsToScan", "0")),
            timeout=timeout, interval=3, stop_value=0,
            tool_name="zap_passive_wait",
        )

    # ------------------------------------------------------------------
    # Active Scan
    # ------------------------------------------------------------------

    def start_active_scan(
        self,
        url: str,
        context_id: int | None = None,
        scan_policy: str | None = None,
    ) -> int:
        """Start active scan. Returns scan ID."""
        params: dict[str, Any] = {"url": url, "recurse": "true"}
        if context_id is not None:
            params["contextId"] = str(context_id)
        if scan_policy:
            params["scanPolicyName"] = scan_policy
        data = self._get("/JSON/ascan/action/scan/", params)
        scan_id = int(data.get("scan", 0))
        log.info("zap_active_scan_started", url=url, scan_id=scan_id, policy=scan_policy,
                 context_id=context_id, zap_id=self.zap_id, base_url=self.base_url)
        return scan_id

    def active_scan_status(self, scan_id: int) -> int:
        """Get active scan progress (0-100)."""
        data = self._get("/JSON/ascan/view/status/", {"scanId": str(scan_id)})
        return int(data.get("status", 0))

    def stop_active_scan(self, scan_id: int) -> None:
        """Stop an active scan."""
        self._get("/JSON/ascan/action/stop/", {"scanId": str(scan_id)})
        log.info("zap_active_scan_stopped", scan_id=scan_id)

    # ------------------------------------------------------------------
    # Scan Policy & Rate Config
    # ------------------------------------------------------------------

    # Active scan category → ZAP scanner IDs (groups)
    # See: https://www.zaproxy.org/docs/alerts/
    CATEGORY_SCANNER_IDS: dict[str, list[int]] = {
        # 40024 (SQLi SQLite) fehlt in zaproxy/zap-stable:2.17.0. Die
        # Kategorie bleibt nutzbar, sie deckt dann fuenf statt sechs Regeln ab.
        "sqli": [40018, 40019, 40020, 40021, 40022, 40024],
        "xss": [40012, 40014, 40016, 40017],
        "lfi": [6, 40009],        # Path Traversal + SSRF overlap
        "rfi": [7],               # Remote File Inclusion
        "ssrf": [40046],          # Server Side Request Forgery, siehe CATEGORIES_UNAVAILABLE
        "cmdi": [90020],          # Remote OS Command Injection
        "xxe": [90023],           # XML External Entity
        "crlf": [40003],          # CRLF Injection
        "pathtraversal": [6],     # Path Traversal
        # S0b: 10054 (Cookie without SameSite) und 10010 (Cookie No HttpOnly)
        # sind passive Regeln. In einer Active-Scan-Policy existieren sie nicht,
        # ZAP antwortet auf enableScanners mit "does_not_exist" und der ganze
        # Active Scan faellt aus. "headerinjection" behaelt die aktive
        # CRLF-Regel, "defaultlogin" hat keine passende aktive Regel mehr und
        # ist damit eine leere Kategorie.
        "headerinjection": [40003],
        "defaultlogin": [],
    }

    # S0b: Kategorien, die der gepinnte ZAP nicht bedienen kann, mit Grund.
    # Die IDs bleiben oben stehen, damit ein spaeteres Image sie wieder
    # aktiviert, aber nach aussen (KI-Prompt, Regelkonfiguration, Doku,
    # Methodikseite) darf keine dieser Kategorien als Zusage auftauchen.
    # Wiedervorlage bei der Paketdefinition in S7.
    #
    # Entscheidung DC (17.09.2026): kein Add-on nachziehen. SSRF-Tests und
    # SQLite-SQL-Injection gegen fremde Produktionssysteme sind ohnehin an
    # der Grenze dessen, was ein automatisierter Aussenscan tun sollte.
    CATEGORIES_UNAVAILABLE: dict[str, str] = {
        "ssrf": "Regel 40046 nicht in zaproxy/zap-stable:2.17.0",
    }

    @classmethod
    def offered_categories(cls) -> list[str]:
        """Kategorien, die angeboten werden duerfen, alphabetisch.

        Leere Kategorien und die als nicht verfuegbar markierten fallen raus.
        Das ist die Liste, gegen die sich Regelkonfiguration, KI-Prompt und
        Doku messen lassen muessen.
        """
        return sorted(
            name for name, ids in cls.CATEGORY_SCANNER_IDS.items()
            if ids and name not in cls.CATEGORIES_UNAVAILABLE
        )

    # Forbidden categories — NEVER enable these
    FORBIDDEN_SCANNERS: set[int] = {
        # DoS scanners
        40032,  # .htaccess as source
        # Buffer overflow
        30001, 30002,
        # Fuzzer categories — too noisy, too slow
        40033, 40034,
    }

    def get_installed_scanner_ids(self) -> set[int]:
        """IDs aller aktiven Scan-Regeln, die dieser Daemon installiert hat.

        S0b: welche Regeln vorhanden sind, entscheidet der Add-on-Satz des
        Images, nicht unser Code. Wird eine unbekannte ID an
        ``enableScanners`` geschickt, antwortet ZAP mit ``does_not_exist``
        und die gesamte Policy-Erzeugung scheitert. Deshalb wird die
        Wunschliste vorher gegen diese Menge geschnitten.
        """
        data = self._get("/JSON/ascan/view/scanners/")
        ids: set[int] = set()
        for entry in data.get("scanners", []) or []:
            if not isinstance(entry, dict):
                continue
            try:
                ids.add(int(entry.get("id")))
            except (TypeError, ValueError):
                continue
        return ids

    def get_scan_policy_names(self) -> list[str]:
        """Namen aller Scan-Policies dieses Daemons."""
        data = self._get("/JSON/ascan/view/scanPolicyNames/")
        raw = data.get("scanPolicyNames", [])
        if isinstance(raw, str):
            stripped = raw.strip().lstrip("[").rstrip("]")
            if not stripped:
                return []
            return [p.strip().strip('"').strip("'") for p in stripped.split(",") if p.strip()]
        return [str(entry) for entry in raw or []]

    def resolve_scanner_ids(self, categories: list[str]) -> tuple[set[int], set[int]]:
        """Kategorien zu Scanner-IDs aufloesen.

        Rueckgabe ``(enabled, dropped)``: ``enabled`` sind die IDs, die dieser
        Daemon kennt und die nicht verboten sind, ``dropped`` sind die
        angeforderten IDs, die er nicht kennt. ``dropped`` gehoert in die
        Abdeckung, damit der Bericht spaeter sagen kann, was nicht geprueft
        wurde.
        """
        requested: set[int] = set()
        unknown_names: list[str] = []
        for cat in categories or []:
            if cat not in self.CATEGORY_SCANNER_IDS:
                # S0b: Kategorienamen sind zwischen Regelkonfiguration,
                # KI-Prompt und diesem Katalog auseinandergelaufen
                # ("path_traversal" statt "pathtraversal", "auth_bypass" ohne
                # jede Entsprechung). Solche Namen liefen bisher still ins
                # Leere. Der Drift-Test test_zap_categories_drift haelt das
                # fest, hier wird der Einzelfall wenigstens sichtbar.
                unknown_names.append(cat)
                continue
            requested.update(self.CATEGORY_SCANNER_IDS[cat])
        if unknown_names:
            log.warning("zap_unknown_categories", categories=unknown_names,
                        zap_id=self.zap_id)
        requested -= self.FORBIDDEN_SCANNERS
        if not requested:
            return set(), set()
        try:
            installed = self.get_installed_scanner_ids()
        except ZapError as e:
            # fail-open: die Sicht ist nur eine Vorpruefung. Faellt sie aus,
            # geht es mit der Wunschliste weiter wie bisher.
            log.warning("zap_scanner_view_failed", endpoint=e.endpoint, error=str(e))
            return requested, set()
        if not installed:
            return requested, set()
        enabled = requested & installed
        dropped = requested - installed
        if dropped:
            log.warning("zap_scanner_ids_dropped", zap_id=self.zap_id,
                        dropped=sorted(dropped), enabled=len(enabled))
        return enabled, dropped

    def create_scan_policy(
        self,
        name: str,
        categories: list[str],
        policy_type: str = "standard",
    ) -> set[int]:
        """Create a custom active scan policy. Returns the enabled scanner IDs.

        policy_type: "waf-safe"|"standard"|"aggressive"
        categories: list of category names from CATEGORY_SCANNER_IDS

        S0b: idempotent. Existiert die Policy schon (Rest einer abgebrochenen
        Lease), wird sie weiterverwendet statt den Aufruf scheitern zu lassen.
        Unbekannte Scanner-IDs werden vorher ausgesiebt, und am Ende wird
        geprueft, dass der Daemon die Policy wirklich kennt: genau diese
        Pruefung fehlte, als ``ascan/action/scan`` 26-mal ``does_not_exist``
        lieferte.
        """
        # Create base policy. already_exists ist kein Fehler.
        try:
            self._get("/JSON/ascan/action/addScanPolicy/", {"scanPolicyName": name})
        except ZapError as e:
            if e.zap_code != "already_exists":
                raise
            log.info("zap_scan_policy_reused", name=name, zap_id=self.zap_id)

        # Disable all scanners first
        self._get("/JSON/ascan/action/disableAllScanners/", {"scanPolicyName": name})

        enabled_ids, dropped_ids = self.resolve_scanner_ids(categories)
        self.last_dropped_scanner_ids = sorted(dropped_ids)

        if enabled_ids:
            ids_str = ",".join(str(i) for i in sorted(enabled_ids))
            self._get("/JSON/ascan/action/enableScanners/", {
                "ids": ids_str,
                "scanPolicyName": name,
            })

        # Set strength based on policy type
        strength_map = {"waf-safe": "LOW", "standard": "MEDIUM", "aggressive": "HIGH"}
        strength = strength_map.get(policy_type, "MEDIUM")
        threshold_map = {"waf-safe": "HIGH", "standard": "MEDIUM", "aggressive": "LOW"}
        threshold = threshold_map.get(policy_type, "MEDIUM")

        # Set attack strength and alert threshold for all enabled scanners
        for scanner_id in enabled_ids:
            try:
                self._get("/JSON/ascan/action/setScannerAttackStrength/", {
                    "id": str(scanner_id),
                    "attackStrength": strength,
                    "scanPolicyName": name,
                })
                self._get("/JSON/ascan/action/setScannerAlertThreshold/", {
                    "id": str(scanner_id),
                    "alertThreshold": threshold,
                    "scanPolicyName": name,
                })
            except ZapError:
                pass  # Some scanners don't support strength/threshold

        # S0b: Bestaetigen, dass derselbe Daemon die Policy jetzt fuehrt.
        # Schlaegt das fehl, ist der Active Scan zum Scheitern verurteilt und
        # der Fehler soll hier stehen, nicht spaeter als nacktes
        # "does_not_exist" aus ascan/action/scan.
        try:
            known = self.get_scan_policy_names()
        except ZapError as e:
            log.warning("zap_scan_policy_names_failed", endpoint=e.endpoint, error=str(e))
            known = []
        if known and name not in known:
            raise ZapError(
                f"scan policy '{name}' not present after creation",
                endpoint="/JSON/ascan/view/scanPolicyNames/",
                params={"scanPolicyName": name},
                zap_id=self.zap_id,
                base_url=self.base_url,
                zap_code="policy_missing_after_create",
            )

        log.info("zap_scan_policy_created", name=name, policy_type=policy_type,
                 categories=categories, enabled_scanners=len(enabled_ids),
                 dropped_scanners=self.last_dropped_scanner_ids or None,
                 zap_id=self.zap_id, base_url=self.base_url)
        return enabled_ids

    def remove_scan_policy(self, name: str) -> None:
        """Remove a scan policy."""
        try:
            self._get("/JSON/ascan/action/removeScanPolicy/", {"scanPolicyName": name})
        except ZapError:
            pass

    def configure_rate_limit(
        self,
        req_per_sec: int = 80,
        threads: int = 5,
        delay_ms: int = 0,
    ) -> None:
        """Configure ZAP rate limiting for WAF-safe scanning."""
        try:
            # Spider thread count
            self._get("/JSON/spider/action/setOptionThreadCount/", {
                "Integer": str(threads),
            })
            # Spider delay
            if delay_ms > 0:
                self._get("/JSON/spider/action/setOptionPostForm/", {
                    "Boolean": "false",  # Disable form posting when throttled
                })
            # Active scan threads per host
            self._get("/JSON/ascan/action/setOptionThreadPerHost/", {
                "Integer": str(threads),
            })
            # Active scan delay in ms
            self._get("/JSON/ascan/action/setOptionDelayInMs/", {
                "Integer": str(delay_ms),
            })
            log.info("zap_rate_configured", req_per_sec=req_per_sec,
                     threads=threads, delay_ms=delay_ms)
        except ZapError as e:
            log.warning("zap_rate_config_failed", endpoint=e.endpoint, error=str(e))

    # ------------------------------------------------------------------
    # Alerts
    # ------------------------------------------------------------------

    def get_alerts(
        self,
        base_url: str = "",
        context_name: str = "",
        start: int = 0,
        count: int = ALERT_MAX_TOTAL,
    ) -> list[dict[str, Any]]:
        """Get all alerts, optionally filtered by base URL.

        Holt die Alerts seitenweise (ALERT_PAGE_SIZE je Anfrage) statt in einem
        Zug. Ein einzelner Aufruf ueber alle Alerts lief auf grossen Zielen in
        den Lesetimeout und kostete den ganzen Host seine Befunde; eine Seite
        von 500 Alerts beantwortet ZAP verlaesslich. ``start`` ist der
        Startversatz, ``count`` die Obergrenze ueber alle Seiten.

        Returns list of alert dicts from ZAP.
        """
        alerts: list[dict[str, Any]] = []
        offset = start
        while len(alerts) < count:
            page_size = min(ALERT_PAGE_SIZE, count - len(alerts))
            params: dict[str, Any] = {"start": str(offset), "count": str(page_size)}
            if base_url:
                params["baseurl"] = base_url
            try:
                data = self._get("/JSON/alert/view/alerts/", params,
                                 read_timeout=ALERT_READ_TIMEOUT)
            except ZapError:
                # Ehrlicher Ausfall: der Aufrufer schreibt die Zeile als
                # gescheitert. Die Zahl der bis dahin geholten Alerts steht im
                # Log, damit erkennbar ist, ab welcher Seite es klemmt.
                log.warning("zap_alert_page_failed", retrieved=len(alerts),
                            offset=offset, page_size=page_size)
                raise
            page = data.get("alerts", [])
            alerts.extend(page)
            if len(alerts) >= count:
                del alerts[count:]  # Obergrenze gilt auch, wenn ZAP mehr liefert
                break
            if len(page) < page_size:
                break  # letzte Seite
            offset += len(page)
        log.info("zap_alerts_retrieved", count=len(alerts),
                 base_url=base_url[:60] if base_url else "all")
        return alerts

    def message_status(self, message_id: str) -> Optional[int]:
        """Statuscode der Antwort einer ZAP-Nachricht (S6c/N2, spec/11 Teil 6).

        ZAP-Alerts tragen die ``messageId``; der Statuscode steckt in der
        Antwortkopfzeile der Nachricht. Damit lassen sich Meldungen an
        Abwehrseiten (HL online 429) und Nebenpfaden (robots.txt) zuordnen.
        Best-effort: gibt None zurueck, wenn die Nachricht fehlt oder nicht
        parsebar ist."""
        try:
            data = self._get("/JSON/core/view/message/", {"id": str(message_id)})
        except ZapError:
            return None
        msg = data.get("message") if isinstance(data, dict) else None
        header = (msg or {}).get("responseHeader", "") if isinstance(msg, dict) else ""
        first = header.split("\n", 1)[0].strip() if header else ""
        parts = first.split()
        if len(parts) >= 2 and parts[1].isdigit():
            return int(parts[1])
        return None

    # ------------------------------------------------------------------
    # Generic Polling
    # ------------------------------------------------------------------

    def poll_until_complete(
        self,
        status_fn: Callable[[], int | str],
        timeout: int = 300,
        interval: int = 5,
        stop_value: int | str = 100,
        order_id: str = "",
        tool_name: str = "",
    ) -> bool:
        """Poll a status function until it returns stop_value or timeout.

        Returns True if completed, False if timed out.
        On timeout, does NOT raise — caller handles partial results.
        """
        start = time.monotonic()
        last_status: int | str = 0

        while True:
            elapsed = time.monotonic() - start
            if elapsed >= timeout:
                log.warning("zap_poll_timeout", tool=tool_name, timeout=timeout,
                            last_status=last_status)
                return False

            try:
                status = status_fn()
                last_status = status
            except ZapError as e:
                log.warning("zap_poll_error", tool=tool_name, endpoint=e.endpoint,
                            error=str(e))
                return False

            if status == stop_value:
                log.info("zap_poll_complete", tool=tool_name,
                         elapsed_s=round(elapsed, 1))
                return True

            time.sleep(interval)
