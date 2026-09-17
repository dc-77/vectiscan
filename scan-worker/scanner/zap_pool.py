"""ZAP-Daemon-Pool mit Redis-Lease-Koordination.

Loest die feste Bindung Worker <-> ZAP-Daemon auf. Mehrere Worker teilen
sich einen Pool aus ZAP-Daemons. Jeder Host-Scan leaset kurzzeitig einen
ZAP, fuehrt die Phase-2-Tools durch und gibt ihn wieder frei.

Redis-Key-Konventionen (alle Prefix ``zap:``):

    zap:pool:available       SET  — IDs aller konfigurierten ZAPs
    zap:lease:<zap_id>       STRING  (TTL 900s) — exklusiver Lease-Value
    zap:heartbeat:<zap_id>   STRING  (TTL 60s) — Lebenszeichen des Leasers
    zap:stats:leases_total   INTEGER
    zap:stats:lease_wait_ms  LIST (getrimmt auf 100 Eintraege)
    zap:stats:expired_leases INTEGER

Dieser Modul haengt von ``redis-py`` ab und von ``zap_client.safe_name_part``
(gemeinsame Namensbildung fuer Kontexte, siehe S0b). Tests setzen fakeredis ein.

Stand 17.09.2026: **in Produktion ist der Pool aus.** ``ZAP_POOL_ENABLED``
steht in ``/opt/apps/vectiscan/.env`` nicht drin, damit greift der
Compose-Default ``false``. Jeder Worker spricht fest mit einem Daemon ueber
``ZAP_BASE_URL`` (scan-worker-1 mit zap-1, -2 mit zap-2, -3 mit zap-3),
``zap-4`` laeuft ungenutzt mit. Der Code hier ist also vorbereitet, nicht
aktiv. Wer ihn einschaltet, braucht die Affinitaets-Korrektur aus S0b in
``phase2.run_phase2``: bis dahin setzte ``worker.py`` die geleaste Instanz nur
als Thread-Local, und die verschachtelten Stage-Executors haben davon nichts
mitbekommen -- Lease und tatsaechliche Verbindung waeren auseinandergelaufen.
"""

from __future__ import annotations

import os
import time
from typing import Any, Iterable, Optional

import structlog

from scanner.tools.zap_client import safe_name_part

log = structlog.get_logger()


LEASE_TTL_SEC = 900
HEARTBEAT_TTL_SEC = 60
HEARTBEAT_INTERVAL_SEC = 30
ACQUIRE_POLL_INTERVAL_SEC = 0.5

STATS_WAIT_MS_KEY = "zap:stats:lease_wait_ms"
STATS_LEASES_TOTAL_KEY = "zap:stats:leases_total"
STATS_EXPIRED_KEY = "zap:stats:expired_leases"
POOL_AVAILABLE_KEY = "zap:pool:available"

# Lua: nur Owner (exact match lease_value) loescht den Key.
_RELEASE_LUA = """
local val = redis.call('get', KEYS[1])
if val == ARGV[1] then
  redis.call('del', KEYS[2])
  return redis.call('del', KEYS[1])
else
  return 0
end
"""

# Lua: Heartbeat nur vom aktuellen Owner. Erneuert Lease-TTL und Heartbeat-TTL.
_HEARTBEAT_LUA = """
local val = redis.call('get', KEYS[1])
if val == ARGV[1] then
  redis.call('expire', KEYS[1], tonumber(ARGV[2]))
  redis.call('set', KEYS[2], '1', 'EX', tonumber(ARGV[3]))
  return 1
else
  return 0
end
"""


def build_context_name(order_id: str, host_ip: str) -> str:
    """Context-Name eines Host-Scans: ``ctx-<order8>-<ip>``.

    S0b: eine Quelle fuer ``phase2`` und die Pool-Bereinigung. Solange beide
    den Namen getrennt bildeten, konnte die Bereinigung bei IPv6-Hosts einen
    laufenden Kontext fuer fremd halten und loeschen.
    """
    return f"ctx-{order_id[:8]}-{safe_name_part(host_ip)}"


def build_policy_name(order_id: str, host_ip: str) -> str:
    """Policy-Name eines Host-Scans: ``policy-<order8>-<ip>``."""
    return f"policy-{order_id[:8]}-{safe_name_part(host_ip)}"


def get_pool_members() -> list[str]:
    """ZAP-Pool-Mitglieder aus Env ``ZAP_POOL`` (komma-separiert)."""
    raw = os.getenv("ZAP_POOL", "zap-1,zap-2,zap-3,zap-4")
    return [m.strip() for m in raw.split(",") if m.strip()]


def get_max_parallel_per_order() -> int:
    """Maximale Anzahl paralleler Leases pro Auftrag.

    Default: ``len(pool) - 1`` (Fairness-Reserve fuer andere Auftraege).
    Ueberschreibbar via Env ``ZAP_MAX_PARALLEL_PER_ORDER``.
    """
    override = os.getenv("ZAP_MAX_PARALLEL_PER_ORDER")
    if override:
        try:
            return max(1, int(override))
        except ValueError:
            log.warning("zap_max_parallel_invalid", value=override)
    pool_size = len(get_pool_members())
    return max(1, pool_size - 1)


def init_zap_pool(redis_client: Any, members: Optional[Iterable[str]] = None) -> int:
    """Registriert alle konfigurierten ZAPs im Pool. Idempotent.

    Wird bei jedem Worker-Start aufgerufen. SADD ist atomar, doppeltes
    Einfuegen ist ein No-op. Rueckgabe: Groesse des Pools nach dem Add.
    """
    member_list = list(members) if members is not None else get_pool_members()
    if not member_list:
        log.warning("zap_pool_empty")
        return 0
    redis_client.sadd(POOL_AVAILABLE_KEY, *member_list)
    size = redis_client.scard(POOL_AVAILABLE_KEY)
    log.info("zap_pool_initialized", members=member_list, pool_size=size)
    return int(size)


LEASE_FIELD_SEP = "|"


def _build_lease_value(order_id: str, host_ip: str, worker_id: str) -> str:
    """Ein eindeutiger Lease-Value pro Acquire-Versuch.

    S0b: Die Felder waren frueher durch ``:`` getrennt und wurden in
    ``get_all_active_context_names`` per ``split(":", 3)`` wieder zerlegt.
    Eine IPv6-Adresse enthaelt selbst Doppelpunkte, dadurch kam dort nur das
    erste Hextet an und der rekonstruierte Kontextname passte nicht zu dem,
    den ``phase2`` angelegt hat. ``cleanup_stale_contexts`` hielt den
    laufenden Kontext dann fuer verwaist und loeschte ihn mitten im Scan.
    Das Trennzeichen ist deshalb ``|``, das in keinem der Felder vorkommt.
    """
    return LEASE_FIELD_SEP.join(
        [order_id, host_ip, worker_id, str(int(time.time() * 1000))]
    )


def _split_lease_value(value: str) -> list[str]:
    """Lease-Value zerlegen, altes ``:``-Format eingeschlossen.

    Waehrend eines rollenden Deploys liegen beide Formate gleichzeitig in
    Redis. Das alte wird weiter gelesen, damit die Bereinigung keine
    laufenden Kontexte anderer Worker loescht.
    """
    if LEASE_FIELD_SEP in value:
        return value.split(LEASE_FIELD_SEP, 3)
    return value.split(":", 3)


def acquire_zap(
    redis_client: Any,
    order_id: str,
    host_ip: str,
    worker_id: str,
    timeout_s: int = 600,
) -> Optional[tuple[str, str]]:
    """Leaset einen freien ZAP aus dem Pool.

    Polling-Schleife: versucht atomar ``SET NX EX`` auf jeden Kandidaten.
    Rueckgabe: ``(zap_id, lease_value)`` bei Erfolg, ``None`` bei Timeout.
    Der ``lease_value`` wird fuer Release und Heartbeat benoetigt.
    """
    deadline = time.monotonic() + timeout_s
    start = time.monotonic()
    lease_value = _build_lease_value(order_id, host_ip, worker_id)

    while True:
        members_raw = redis_client.smembers(POOL_AVAILABLE_KEY)
        members = [m.decode() if isinstance(m, bytes) else m for m in members_raw]

        for zap_id in members:
            key = f"zap:lease:{zap_id}"
            acquired = redis_client.set(key, lease_value, nx=True, ex=LEASE_TTL_SEC)
            if acquired:
                redis_client.set(f"zap:heartbeat:{zap_id}", "1", ex=HEARTBEAT_TTL_SEC)
                redis_client.incr(STATS_LEASES_TOTAL_KEY)
                wait_ms = int((time.monotonic() - start) * 1000)
                redis_client.lpush(STATS_WAIT_MS_KEY, wait_ms)
                redis_client.ltrim(STATS_WAIT_MS_KEY, 0, 99)
                return zap_id, lease_value

        if time.monotonic() >= deadline:
            return None
        time.sleep(ACQUIRE_POLL_INTERVAL_SEC)


def release_zap(redis_client: Any, zap_id: str, lease_value: str) -> bool:
    """Gibt den Lease frei. Loescht Lease- und Heartbeat-Key atomar.

    Nur erfolgreich, wenn der gespeicherte Lease-Value exakt ``lease_value``
    ist (Owner-Check). Fremde Leases werden nicht angetastet.
    """
    lease_key = f"zap:lease:{zap_id}"
    hb_key = f"zap:heartbeat:{zap_id}"
    result = redis_client.eval(_RELEASE_LUA, 2, lease_key, hb_key, lease_value)
    return bool(result)


def heartbeat_zap(redis_client: Any, zap_id: str, lease_value: str) -> bool:
    """Erneuert Lease- und Heartbeat-TTL. Nur wenn wir noch Owner sind.

    Rueckgabe ``False`` signalisiert Lease-Verlust (TTL-Expiry durch
    Ueberlast oder Clock-Drift). Der Aufrufer sollte dann die Phase
    abbrechen und die Arbeit als gescheitert markieren.
    """
    lease_key = f"zap:lease:{zap_id}"
    hb_key = f"zap:heartbeat:{zap_id}"
    result = redis_client.eval(
        _HEARTBEAT_LUA,
        2,
        lease_key,
        hb_key,
        lease_value,
        LEASE_TTL_SEC,
        HEARTBEAT_TTL_SEC,
    )
    return bool(result)


def get_all_active_context_names(redis_client: Any) -> set[str]:
    """Liefert alle Context-Namen, die gerade aktiven Leases entsprechen.

    Wird beim Lease-Start vor ``cleanup_stale_contexts`` aufgerufen.
    Die Context-Namen folgen dem Schema ``ctx-{order_id[:8]}-{ip_}``,
    dieselbe Logik wie in ``phase2.py`` / ``zap_client``.
    """
    active: set[str] = set()
    for key in redis_client.scan_iter(match="zap:lease:*"):
        val = redis_client.get(key)
        if val is None:
            continue
        if isinstance(val, bytes):
            val = val.decode(errors="replace")
        parts = _split_lease_value(val)
        if len(parts) < 2:
            continue
        order_id, host_ip = parts[0], parts[1]
        active.add(build_context_name(order_id, host_ip))
    return active


def get_lease_wait_ms_samples(redis_client: Any) -> list[int]:
    """Letzte bis zu 100 Wartezeiten in Millisekunden."""
    raw = redis_client.lrange(STATS_WAIT_MS_KEY, 0, -1) or []
    out: list[int] = []
    for entry in raw:
        try:
            out.append(int(entry))
        except (TypeError, ValueError):
            continue
    return out


def get_leases_total(redis_client: Any) -> int:
    val = redis_client.get(STATS_LEASES_TOTAL_KEY)
    if val is None:
        return 0
    try:
        return int(val)
    except (TypeError, ValueError):
        return 0
