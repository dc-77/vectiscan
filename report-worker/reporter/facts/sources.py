"""Quellenschicht des Facts-Pakets: ein ScanBundle aus Tar, Verzeichnis oder API-Snapshot.

Drei Eingaenge, eine Struktur:
- ``load_from_tar``: ``<order>.tar.gz`` direkt ueber ``tarfile`` im Speicher (kein
  Entpacken; IPv6-Hostverzeichnisse mit Doppelpunkt sind unter Windows nicht anlegbar).
- ``load_from_dir``: entpacktes Scan-Verzeichnis wie in ``reporter/worker.py``.
- ``load_from_snapshot``: ``api-snapshot/<order>/`` mit ``results.json`` (Zeilen aus
  ``scan_results``) und ``order.json``; das ist die Referenzform aus
  ``report-prototype/build/catalog_sim.py``.

``merge_tool_runs`` ergaenzt ein Tar-Bundle um die ``scan_results``-Zeilen. Deren
``rawOutput`` fuellt die bekannten Luecken des Tars (spec/07 S1, Scanner-Befunde 2 und 3):
header_check je VHost, testssl-Rohtext mit Protokollzeilen, KI#3-Konfiguration.
"""
from __future__ import annotations

import io
import re
import tarfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Optional
from urllib.parse import urlsplit

from reporter.facts.serialize import (
    iso_utc, jsonl, load_json, sha256_bytes, sha256_file, sort_key, try_json,
)

DOMAIN_LABEL_KEY = "_domain"


def _without_domain_label(data: dict[str, Any]) -> dict[str, Any]:
    """Das Etikett ist Transportmittel, kein Fakt (Issue #12)."""
    if DOMAIN_LABEL_KEY in data:
        return {k: v for k, v in data.items() if k != DOMAIN_LABEL_KEY}
    return data


def _host_from_url(url: Any) -> Optional[str]:
    """Hostname aus einer URL, wie build._headers_by_vhost es tut."""
    text = str(url or "")
    if not text:
        return None
    return urlsplit(text).hostname or None


NON_TOOL_ROWS = frozenset({"report_cost"})
AI_ROW_PREFIX = "ai_"
DEBUG_ROW_SUFFIX = "_debug"


def normalize_tool_name(name: str | None) -> str:
    """``crtsh_retry2`` -> ``crtsh``; ``ffuf_param``/``ffuf_sensitive`` bleiben, weil sie
    verschiedene Pruefungen sind; ``zap_active`` bleibt ebenfalls."""
    if not name:
        return ""
    n = re.sub(r"_retry\d+$", "", name.strip())
    return n


@dataclass
class ToolRun:
    tool: str
    host_ip: Optional[str] = None
    phase: Optional[int] = None
    status: Optional[str] = None
    reason: Optional[str] = None
    exit_code: Optional[int] = None
    duration_ms: Optional[int] = None
    created_at: Optional[str] = None
    raw_output: Optional[str] = None
    index: int = 0
    raw_omitted: bool = False

    @property
    def tool_norm(self) -> str:
        return normalize_tool_name(self.tool)

    @property
    def raw_known(self) -> bool:
        """Ist der Rohtext dieser Zeile ueberhaupt geladen worden?

        "Nicht geladen" ist ein ausdrueckliches Signal des Laders
        (``raw_output_omitted``, siehe ``worker._load_tool_runs``), kein
        stillschweigendes ``None``: eine Zeile, deren Spalte in der Datenbank
        wirklich leer ist, hat kein Ergebnis geliefert, und das ist eine
        Aussage. Nur die wegen der Groessengrenze ausgelassene Zeile darf die
        Abdeckung nicht als leeres Ergebnis werten.
        """
        return not self.raw_omitted

    @property
    def is_ai(self) -> bool:
        return self.tool.startswith(AI_ROW_PREFIX)

    @property
    def is_debug(self) -> bool:
        return self.tool.endswith(DEBUG_ROW_SUFFIX)

    @property
    def ref(self) -> str:
        return f"scan_results:{self.tool}" + (f":{self.host_ip}" if self.host_ip else "")

    def json(self) -> Any:
        return try_json(self.raw_output)

    def vhost(self) -> Optional[str]:
        data = self.json()
        if isinstance(data, dict):
            v = data.get("vhost")
            if isinstance(v, str) and v:
                return v
        return None

    def domain(self) -> Optional[str]:
        """Domain-Etikett einer domainweiten Zeile (Issue #12).

        scan_results hat keine Domainspalte; der Scanner schreibt die Domain
        seit S2b als ``_domain`` in das JSON des ``raw_output`` (analog zum
        ``vhost``-Schluessel bei header_check). Aeltere Zeilen haben den
        Schluessel nicht, dann bleibt es beim bisherigen Verhalten.
        """
        data = self.json()
        if isinstance(data, dict):
            v = data.get(DOMAIN_LABEL_KEY)
            if isinstance(v, str) and v:
                return v
        return None


def tool_run_from_row(row: dict[str, Any], index: int) -> ToolRun:
    """API-Zeile (camelCase) oder DB-Zeile (snake_case) -> ToolRun."""
    def pick(*keys: str) -> Any:
        for k in keys:
            if k in row and row[k] is not None:
                return row[k]
        return None
    exit_code = pick("exitCode", "exit_code")
    duration = pick("durationMs", "duration_ms")
    phase = pick("phase")
    return ToolRun(
        tool=str(pick("toolName", "tool_name") or ""),
        host_ip=pick("hostIp", "host_ip"),
        phase=int(phase) if phase is not None else None,
        status=pick("status"),
        reason=pick("skipReason", "skip_reason", "reason"),
        exit_code=int(exit_code) if exit_code is not None else None,
        duration_ms=int(duration) if duration is not None else None,
        created_at=iso_utc(pick("createdAt", "created_at")),
        raw_output=pick("rawOutput", "raw_output"),
        index=index,
        raw_omitted=bool(row.get("raw_output_omitted") or row.get("rawOutputOmitted")),
    )


@dataclass
class HostData:
    ip: str
    nmap_xml: Optional[str] = None
    nmap_txt: Optional[str] = None
    tech_profile: Optional[dict[str, Any]] = None
    webtech: Optional[dict[str, Any]] = None
    wafw00f: Optional[list[dict[str, Any]]] = None
    wafw00f_text: dict[str, str] = field(default_factory=dict)
    testssl_json: Optional[list[dict[str, Any]]] = None
    testssl_txt: Optional[str] = None
    headers_json: Optional[dict[str, Any]] = None
    headers_by_vhost: dict[str, dict[str, Any]] = field(default_factory=dict)
    httpx_lines: list[dict[str, Any]] = field(default_factory=list)
    httpx_rows: dict[str, dict[str, Any]] = field(default_factory=dict)
    # Issue #10: seit S2b legt der Scanner je VHost eine eigene Datei ab
    # (headers_<slug>.json, httpx_<slug>.json). Bewusst getrennt von den
    # zeilengespeisten Feldern darueber, damit der bisherige Weg unberuehrt
    # bleibt. Aeltere Tars haben diese Dateien nicht, dann bleiben die Maps leer.
    headers_by_vhost_tar: dict[str, dict[str, Any]] = field(default_factory=dict)
    headers_ref_by_vhost: dict[str, str] = field(default_factory=dict)
    httpx_by_vhost_tar: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    httpx_ref_by_vhost: dict[str, str] = field(default_factory=dict)
    zap_alerts: Optional[list[dict[str, Any]]] = None
    zap_summary: Optional[dict[str, Any]] = None
    zap_spider_urls: Optional[list[str]] = None
    zap_spider_summary: Optional[dict[str, Any]] = None
    feroxbuster: Optional[list[dict[str, Any]]] = None
    ffuf: Optional[dict[str, Any]] = None
    wpscan: Optional[dict[str, Any]] = None
    ai_rows: list[ToolRun] = field(default_factory=list)
    refs: dict[str, str] = field(default_factory=dict)
    unparsed: list[str] = field(default_factory=list)


@dataclass
class ScanBundle:
    order_id: str
    source_kind: str
    source_name: str
    source_sha256: Optional[str] = None
    meta: dict[str, Any] = field(default_factory=dict)
    host_inventory: dict[str, Any] = field(default_factory=dict)
    tech_profiles: list[dict[str, Any]] = field(default_factory=list)
    dns_records: Optional[dict[str, Any]] = None
    dns_security: Optional[dict[str, Any]] = None
    zone_transfer_txt: Optional[str] = None
    passive: dict[str, Any] = field(default_factory=dict)
    # Issue #12: je Domain der Order. Die Skalare darueber bleiben die Sicht
    # des Primaerziels, damit jeder bisherige Leser unveraendert weiterlaeuft.
    dns_records_by_domain: dict[str, dict[str, Any]] = field(default_factory=dict)
    dns_security_by_domain: dict[str, dict[str, Any]] = field(default_factory=dict)
    zone_transfer_by_domain: dict[str, str] = field(default_factory=dict)
    passive_by_domain: dict[str, dict[str, Any]] = field(default_factory=dict)
    host_strategy: Optional[dict[str, Any]] = None
    ai_prioritization: Optional[dict[str, Any]] = None
    # Bilanz der Phase-3-Korrelation (Zeile ``phase3_correlation``): wie viele
    # Werkzeugmeldungen eingingen, wie viele als Doppel- oder Falschmeldung
    # verworfen wurden und mit welcher Begruendung. Protokoll, nie ein Befund.
    phase3_summary: Optional[dict[str, Any]] = None
    correlated_findings: list[dict[str, Any]] = field(default_factory=list)
    enrichment: dict[str, Any] = field(default_factory=dict)
    tool_runs: list[ToolRun] = field(default_factory=list)
    tool_runs_name: Optional[str] = None
    tool_runs_sha256: Optional[str] = None
    hosts: dict[str, HostData] = field(default_factory=dict)
    targets: list[str] = field(default_factory=list)
    targets_source: str = "meta"
    order_meta: Optional[dict[str, Any]] = None
    refs: dict[str, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    unparsed: list[tuple[str, str, Optional[str]]] = field(default_factory=list)

    def host(self, ip: str) -> HostData:
        if ip not in self.hosts:
            self.hosts[ip] = HostData(ip=ip)
        return self.hosts[ip]

    def warn(self, text: str) -> None:
        if text not in self.warnings:
            self.warnings.append(text)


# ------------------------------------------------------------------ Leser

class _Reader:
    """Einheitlicher Zugriff auf Tar-Mitglieder oder Dateien, Namen immer POSIX."""

    def __init__(self, files: dict[str, Any], getter):
        self.files = files
        self._get = getter

    def names(self) -> list[str]:
        return sorted(self.files)

    def exists(self, name: str) -> bool:
        return name in self.files

    def bytes(self, name: str) -> Optional[bytes]:
        if name not in self.files:
            return None
        return self._get(self.files[name])

    def text(self, name: str) -> Optional[str]:
        data = self.bytes(name)
        if data is None:
            return None
        return data.decode("utf-8", "replace")

    def json(self, name: str) -> Any:
        text = self.text(name)
        if text is None:
            return None
        return try_json(text)


def _strip_root(names: list[str]) -> tuple[str, dict[str, str]]:
    """Gemeinsames Wurzelverzeichnis (``<orderId>/``) abtrennen."""
    roots = {n.split("/", 1)[0] for n in names if "/" in n}
    plain = {n for n in names if "/" not in n}
    if len(roots) == 1 and not plain:
        root = next(iter(roots))
        return root, {n[len(root) + 1:]: n for n in names if n.startswith(root + "/") and len(n) > len(root) + 1}
    return "", {n: n for n in names}


def _tar_reader(path: Path) -> tuple[_Reader, str]:
    tar = tarfile.open(path, "r:gz")
    members = {m.name: m for m in tar.getmembers() if m.isfile()}
    root, mapping = _strip_root(list(members))
    files = {rel: members[full] for rel, full in mapping.items()}

    def getter(member: tarfile.TarInfo) -> bytes:
        fh = tar.extractfile(member)
        return fh.read() if fh else b""

    return _Reader(files, getter), root


def _dir_reader(path: Path) -> tuple[_Reader, str]:
    base = path
    if not (base / "hosts").is_dir():
        subdirs = [d for d in base.iterdir() if d.is_dir()]
        if len(subdirs) == 1 and (subdirs[0] / "hosts").is_dir():
            base = subdirs[0]
    files: dict[str, Path] = {}
    for p in base.rglob("*"):
        if p.is_file():
            files[PurePosixPath(p.relative_to(base).as_posix()).as_posix()] = p
    return _Reader(files, lambda p: p.read_bytes()), base.name


_HOST_RE = re.compile(r"^hosts/([^/]+)/phase(\d)/([^/]+)$")


# Issue #12: je Domain abgelegte Dateien. Der Dateiname traegt einen Slug der
# Domain, die Wahrheit steht als "_domain" im Inhalt (bei zone_transfer, das
# reiner Text ist, gilt der Slug). Aeltere Tars haben diese Dateien nicht.
_DOMAIN_FILE_RE = re.compile(
    r"^phase0a?/(dns_records|dns_security|whois)_(.+)\.json$")
_DOMAIN_ZONE_RE = re.compile(r"^phase0/zone_transfer_(.+)\.txt$")


def _load_domain_scoped(reader: "_Reader", b: "ScanBundle") -> None:
    """Domainbezogene Zusatzdateien einlesen (Issue #12)."""
    for name in reader.names():
        m = _DOMAIN_FILE_RE.match(name)
        if m:
            kind, slug = m.group(1), m.group(2)
            data = reader.json(name)
            if not isinstance(data, dict):
                if (reader.text(name) or "").strip():
                    b.unparsed.append(("file_unparsable", name, None))
                continue
            dom = str(data.get(DOMAIN_LABEL_KEY) or slug)
            data = _without_domain_label(data)
            if kind == "dns_records":
                b.dns_records_by_domain.setdefault(dom, data)
            elif kind == "dns_security":
                b.dns_security_by_domain.setdefault(dom, data)
            else:
                b.passive_by_domain.setdefault(dom, {}).setdefault("whois", data)
            b.refs.setdefault(f"{kind}:{dom}", name)
            continue
        m = _DOMAIN_ZONE_RE.match(name)
        if m:
            text = reader.text(name)
            if text:
                b.zone_transfer_by_domain.setdefault(m.group(1), text)
                b.refs.setdefault(f"zone_transfer:{m.group(1)}", name)


def _load_bundle_from_reader(reader: _Reader, order_id_hint: str, source_kind: str,
                             source_name: str, source_sha: Optional[str]) -> ScanBundle:
    meta = reader.json("meta.json") or {}
    order_id = str(meta.get("orderId") or order_id_hint)
    b = ScanBundle(order_id=order_id, source_kind=source_kind, source_name=source_name,
                   source_sha256=source_sha, meta=meta)
    if not meta:
        b.warn("meta.json fehlt, Scanfenster unbekannt")
    inv = reader.json("phase0/host_inventory.json")
    if isinstance(inv, dict):
        b.host_inventory = inv
        b.refs["host_inventory"] = "phase0/host_inventory.json"
    else:
        b.warn("phase0/host_inventory.json fehlt oder unlesbar")
    # Die Dateien des Primaerziels tragen seit S2b ebenfalls das
    # Domain-Etikett. Es ist Transportmittel, kein Fakt, und faellt hier weg.
    dr = reader.json("phase0/dns_records.json")
    if isinstance(dr, dict):
        b.dns_records = _without_domain_label(dr)
        b.refs["dns_records"] = "phase0/dns_records.json"
    ds = reader.json("phase0a/dns_security.json")
    if isinstance(ds, dict):
        b.dns_security = _without_domain_label(ds)
        b.refs["dns_security"] = "phase0a/dns_security.json"
    b.zone_transfer_txt = reader.text("phase0/zone_transfer.txt")
    hs = reader.json("phase0/host_strategy.json")
    if isinstance(hs, dict):
        b.host_strategy = hs
        b.refs["host_strategy"] = "phase0/host_strategy.json"
    for key in ("shodan_hosts", "shodan_domain", "abuseipdb", "otx", "securitytrails", "urlhaus",
                "greynoise", "whois", "summary", "virustotal"):
        name = f"phase0a/{key}.json"
        if reader.exists(name):
            data = reader.json(name)
            if data is None:
                b.unparsed.append(("file_unparsable", name, None))
            else:
                b.passive[key] = (_without_domain_label(data)
                                  if isinstance(data, dict) else data)
                b.refs[key] = name
    cs = reader.json("phase0/certspotter.json")
    if isinstance(cs, dict):
        b.passive["certspotter"] = cs
        b.refs["certspotter"] = "phase0/certspotter.json"
    _load_domain_scoped(reader, b)
    cf = reader.json("phase3/correlated_findings.json")
    if isinstance(cf, list):
        b.correlated_findings = cf
        b.refs["correlated_findings"] = "phase3/correlated_findings.json"
    en = reader.json("phase3/enrichment.json")
    if isinstance(en, dict):
        b.enrichment = en
        b.refs["enrichment"] = "phase3/enrichment.json"
    ap = reader.json("phase3/ai_prioritization.json")
    if isinstance(ap, dict):
        b.ai_prioritization = ap
        b.refs["ai_prioritization"] = "phase3/ai_prioritization.json"

    for name in reader.names():
        m = _HOST_RE.match(name)
        if not m:
            continue
        ip, phase, fname = m.group(1), m.group(2), m.group(3)
        h = b.host(ip)
        h.refs[fname] = name
        if fname == "nmap.xml":
            h.nmap_xml = reader.text(name)
        elif fname == "nmap.txt":
            h.nmap_txt = reader.text(name)
        elif fname == "tech_profile.json":
            data = reader.json(name)
            if isinstance(data, dict):
                h.tech_profile = data
                b.tech_profiles.append(data)
            else:
                h.unparsed.append(name)
        elif fname == "webtech.json":
            data = reader.json(name)
            if isinstance(data, dict):
                h.webtech = data
        elif fname == "wafw00f.json":
            data = reader.json(name)
            if isinstance(data, list):
                h.wafw00f = data
            elif (reader.text(name) or "").strip():
                h.unparsed.append(name)
        elif fname == "testssl.json":
            data = reader.json(name)
            if isinstance(data, list):
                h.testssl_json = data
            elif (reader.text(name) or "").strip():
                h.unparsed.append(name)
        elif fname == "headers.json":
            data = reader.json(name)
            if isinstance(data, dict):
                h.headers_json = data
            elif (reader.text(name) or "").strip():
                h.unparsed.append(name)
        elif fname == "httpx.json":
            h.httpx_lines = [x for x in jsonl(reader.text(name)) if isinstance(x, dict)]
        elif fname == "zap_alerts.json":
            data = reader.json(name)
            if isinstance(data, list):
                h.zap_alerts = data
            elif isinstance(data, dict):
                h.zap_summary = data
            elif (reader.text(name) or "").strip():
                h.unparsed.append(name)
        elif fname == "zap_spider_urls.json":
            data = reader.json(name)
            if isinstance(data, list):
                h.zap_spider_urls = [str(x) for x in data]
        elif fname.startswith("headers_") and fname.endswith(".json"):
            # Issue #10: je VHost eine Datei. Der FQDN kommt aus dem Inhalt,
            # nicht aus dem Dateinamen (der Name ist nur eindeutig, nicht
            # verlaesslich: Wildcards und lange Namen werden gekuerzt).
            data = reader.json(name)
            if isinstance(data, dict) and data.get("headers") is not None:
                vh = _host_from_url(data.get("url"))
                if vh:
                    h.headers_by_vhost_tar.setdefault(vh, data)
                    h.headers_ref_by_vhost.setdefault(vh, name)
            elif (reader.text(name) or "").strip():
                h.unparsed.append(name)
        elif fname.startswith("httpx_") and fname.endswith(".json"):
            lines = [x for x in jsonl(reader.text(name)) if isinstance(x, dict)]
            vh = ""
            if lines:
                vh = str(lines[0].get("input") or lines[0].get("host") or "").split("/")[0]
            if vh:
                h.httpx_by_vhost_tar.setdefault(vh, lines)
                h.httpx_ref_by_vhost.setdefault(vh, name)
        elif fname == "feroxbuster.json":
            h.feroxbuster = [x for x in jsonl(reader.text(name)) if isinstance(x, dict)]
        elif fname.startswith("ffuf") and fname.endswith(".json"):
            data = reader.json(name)
            if isinstance(data, dict):
                h.ffuf = data
        elif fname == "wpscan.json":
            data = reader.json(name)
            if isinstance(data, dict):
                h.wpscan = data
            elif (reader.text(name) or "").strip():
                h.unparsed.append(name)
        elif fname.endswith((".png", ".jpg", ".jpeg", ".txt")):
            continue
        else:
            h.unparsed.append(name)
    # Issue #12: meta.json fuehrt seit S2b alle Domains der Order, Primaerziel
    # zuerst. Ohne die Liste sieht ein reiner Tar-Bau (ohne orders.json) nur
    # die erste Domain; aeltere Tars haben nur "domain".
    meta_domains = meta.get("domains")
    if isinstance(meta_domains, list) and meta_domains:
        b.targets = [str(d) for d in meta_domains if d]
    else:
        b.targets = [str(meta.get("domain") or b.host_inventory.get("domain") or "")]
    b.targets = [t for t in b.targets if t]
    b.targets_source = "meta"
    return b


def load_from_tar(path: Path) -> ScanBundle:
    reader, root = _tar_reader(path)
    return _load_bundle_from_reader(reader, root or path.name.split(".")[0], "tar", path.name, sha256_file(path))


def load_from_dir(path: Path) -> ScanBundle:
    reader, root = _dir_reader(path)
    return _load_bundle_from_reader(reader, root, "dir", path.name, None)


def load_scan_source(path: str | Path) -> ScanBundle:
    p = Path(path)
    if p.is_dir():
        return load_from_dir(p)
    return load_from_tar(p)


# ------------------------------------------------------------------ tool_runs

def load_tool_runs(rows_or_path: Any) -> tuple[list[ToolRun], Optional[str], Optional[str]]:
    """Zeilen aus ``results.json`` (API-Form ``{"data": {"results": [...]}}``), einer
    reinen Liste oder DB-Dicts. Liefert (runs, name, sha256).

    Kommen die Zeilen nicht aus einer Datei, sondern aus der Datenbank (so im
    Produktionspfad, ``worker._load_tool_runs``), gibt es keinen Dateinamen. Die
    Herkunft bleibt trotzdem vermerkt: Name ``scan_results``, Pruefsumme ueber
    die gelesenen Zeilen. Sonst stuende in den Fakten, sie seien ohne Zeilen
    entstanden.
    """
    name = None
    sha = None
    rows = rows_or_path
    if isinstance(rows_or_path, (str, Path)):
        p = Path(rows_or_path)
        name = p.name
        data = p.read_bytes()
        sha = sha256_bytes(data)
        rows = try_json(data.decode("utf-8", "replace"))
    if isinstance(rows, dict):
        rows = (rows.get("data") or {}).get("results") if "data" in rows else rows.get("results")
    if not isinstance(rows, list):
        return [], name, sha
    runs = [tool_run_from_row(r, i) for i, r in enumerate(rows) if isinstance(r, dict)]
    runs.sort(key=lambda r: sort_key(r.phase, r.tool, r.host_ip, r.created_at, r.index))
    if name is None and runs:
        name = "scan_results"
        sha = sha256_bytes(_runs_digest(runs).encode("utf-8"))
    return runs, name, sha


def _runs_digest(runs: list[ToolRun]) -> str:
    """Stabile Textform der Zeilen fuer die Pruefsumme der Herkunft."""
    return "\n".join(
        "\t".join(str(v) for v in (r.phase, r.tool, r.host_ip, r.status, r.reason,
                                   r.exit_code, r.duration_ms, r.created_at,
                                   len(r.raw_output or ""), r.raw_omitted))
        for r in runs
    )


def _useful(raw: str) -> bool:
    """Rohtext traegt Inhalt (kein Statusmarker wie ``SKIPPED: no_ssl``)."""
    s = (raw or "").strip()
    return bool(s) and not s.startswith(("SKIPPED", "FAILED", "TIMEOUT", "OK:"))


def merge_tool_runs(bundle: ScanBundle, runs: list[ToolRun], *, name: str | None = None,
                    sha256: str | None = None) -> None:
    """Zeilen an ein Bundle haengen und die Tar-Luecken aus ``raw_output`` fuellen."""
    bundle.tool_runs = list(runs)
    bundle.tool_runs_name = name
    bundle.tool_runs_sha256 = sha256
    for run in runs:
        if run.tool in NON_TOOL_ROWS:
            continue
        raw = run.raw_output or ""
        if not _useful(raw) and not run.is_ai:
            if run.tool == "urlhaus" and not run.host_ip and "urlhaus" not in bundle.passive:
                bundle.passive["urlhaus"] = {"raw": raw.strip()[:200], "no_data": "no_data" in raw}
                bundle.refs["urlhaus"] = run.ref
            continue
        if run.host_ip:
            h = bundle.host(run.host_ip)
            if run.is_ai:
                h.ai_rows.append(run)
                continue
            if run.tool == "header_check":
                data = run.json()
                if isinstance(data, dict) and isinstance(data.get("result"), dict):
                    vh = data.get("vhost") or data["result"].get("url", "")
                    vh = re.sub(r"^https?://", "", str(vh)).split("/")[0]
                    if vh:
                        h.headers_by_vhost.setdefault(vh, data["result"])
            elif run.tool == "httpx":
                for line in jsonl(raw):
                    if isinstance(line, dict):
                        vh = str(line.get("input") or line.get("host") or "")
                        if vh:
                            h.httpx_rows.setdefault(vh, line)
            elif run.tool == "testssl":
                if raw.strip() and h.testssl_txt is None:
                    h.testssl_txt = raw
            elif run.tool == "nmap":
                if raw.strip() and h.nmap_txt is None:
                    h.nmap_txt = raw
            elif run.tool == "wafw00f":
                m = re.search(r"Checking (https?://[^\s]+)", raw)
                if m:
                    vh = re.sub(r"^https?://", "", m.group(1)).split("/")[0]
                    h.wafw00f_text.setdefault(vh, raw)
            elif run.tool == "webtech":
                data = run.json()
                if isinstance(data, dict) and h.webtech is None:
                    h.webtech = data
            elif run.tool == "zap":
                data = run.json()
                if isinstance(data, dict) and h.zap_summary is None:
                    h.zap_summary = data
            elif run.tool == "zap_spider":
                data = run.json()
                if isinstance(data, dict) and h.zap_spider_summary is None:
                    h.zap_spider_summary = data
            elif run.tool == "feroxbuster":
                if h.feroxbuster is None and raw.strip():
                    h.feroxbuster = [x for x in jsonl(raw) if isinstance(x, dict)]
            elif run.tool.startswith("ffuf"):
                data = run.json()
                if isinstance(data, dict) and h.ffuf is None and data.get("results") is not None:
                    h.ffuf = data
            elif run.tool == "wpscan":
                data = run.json()
                if isinstance(data, dict) and h.wpscan is None:
                    h.wpscan = data
        else:
            if run.tool == "phase3_correlation":
                # Die einzige Zeile der Phase 3. Sie hat keinen Host und ist
                # deshalb bis S5b durch jedes Raster gefallen.
                data = run.json()
                if isinstance(data, dict) and bundle.phase3_summary is None:
                    bundle.phase3_summary = data
                    bundle.refs["phase3_summary"] = run.ref
                continue
            if run.is_ai:
                continue
            data = run.json()
            # Issue #12: traegt die Zeile ein Domain-Etikett, gehoert sie in
            # die Domain-Maps. Das Primaerziel fuellt zusaetzlich die Skalare,
            # damit jeder bisherige Leser unveraendert weiterlaeuft. Zeilen
            # ohne Etikett (alle Altdaten) verhalten sich wie vorher.
            row_domain = run.domain()
            if row_domain and isinstance(data, dict):
                data = _without_domain_label(data)
                if run.tool == "dns_records":
                    bundle.dns_records_by_domain.setdefault(row_domain, data)
                elif run.tool == "dns_security":
                    bundle.dns_security_by_domain.setdefault(row_domain, data)
                elif run.tool in ("whois", "otx", "urlhaus", "securitytrails",
                                  "virustotal", "shodan_domain"):
                    bundle.passive_by_domain.setdefault(row_domain, {}).setdefault(
                        run.tool, data)
                bundle.refs.setdefault(f"{run.tool}:{row_domain}", run.ref)
                is_primary = bool(bundle.targets) and row_domain == bundle.targets[0]
                if not is_primary:
                    continue
            if run.tool == "dns_records" and isinstance(data, dict) and bundle.dns_records is None:
                bundle.dns_records = data
                bundle.refs["dns_records"] = run.ref
            elif run.tool == "dns_security" and isinstance(data, dict) and bundle.dns_security is None:
                bundle.dns_security = data
                bundle.refs["dns_security"] = run.ref
            elif run.tool == "shodan" and isinstance(data, dict):
                for key in ("shodan_hosts", "shodan_domain"):
                    if key in data and key not in bundle.passive:
                        bundle.passive[key] = data[key]
                        bundle.refs[key] = run.ref
            elif run.tool in ("abuseipdb", "otx", "securitytrails", "urlhaus", "greynoise", "whois",
                              "certspotter") and isinstance(data, dict) and run.tool not in bundle.passive:
                bundle.passive[run.tool] = data
                bundle.refs[run.tool] = run.ref
            elif run.tool == "urlhaus" and run.tool not in bundle.passive:
                bundle.passive["urlhaus"] = {"raw": raw.strip()[:200], "no_data": "no_data" in raw}
                bundle.refs["urlhaus"] = run.ref


# ------------------------------------------------------------------ Snapshot

def load_from_snapshot(order_dir: str | Path) -> ScanBundle:
    """``api-snapshot/<order>/`` (results.json + order.json, optional ../orders.json)."""
    d = Path(order_dir)
    order_json = load_json(d / "order.json")
    od = order_json.get("data", order_json) if isinstance(order_json, dict) else {}
    order_id = str(od.get("id") or d.name)
    runs, name, sha = load_tool_runs(d / "results.json")
    progress = od.get("progress") or {}
    inv = progress.get("discoveredHosts") or {}
    if not isinstance(inv, dict):
        # Demo-Auftraege fuehren discoveredHosts als Liste ohne Inventarstruktur.
        inv = {"domain": od.get("domain"), "hosts": [h for h in inv if isinstance(h, dict) and h.get("ip")]} \
            if isinstance(inv, list) else {}
    created = [r.created_at for r in runs if r.created_at]
    meta = {
        "orderId": order_id,
        "domain": inv.get("domain") or od.get("domain"),
        "package": od.get("package"),
        "startedAt": od.get("startedAt"),
        "finishedAt": max(created) if created else od.get("finishedAt"),
        "toolVersions": [],
        "hostsScanned": len(inv.get("hosts") or []),
    }
    b = ScanBundle(order_id=order_id, source_kind="snapshot", source_name=d.name,
                   source_sha256=sha, meta=meta)
    b.warn("Quelle ist der API-Snapshot: kein Tar, kein tech_profile.json, ZAP nur top_alerts, "
           "Scanende aus der letzten scan_results-Zeile")
    if isinstance(inv, dict) and inv:
        b.host_inventory = inv
        b.refs["host_inventory"] = "order.json:progress.discoveredHosts"
    pis = od.get("passiveIntelSummary") or {}
    if isinstance(pis.get("dns_security"), dict):
        b.dns_security = pis["dns_security"]
        b.refs["dns_security"] = "order.json:passiveIntelSummary.dns_security"
    for key in ("otx", "securitytrails", "shodan_domain"):
        if isinstance(pis.get(key), dict):
            b.passive.setdefault(key, pis[key])
            b.refs.setdefault(key, f"order.json:passiveIntelSummary.{key}")
    b.order_meta = dict(od)
    orders_path = d.parent / "orders.json"
    if orders_path.exists():
        ol = load_json(orders_path)
        entries = (ol.get("data") or {}).get("orders") if isinstance(ol, dict) else None
        for e in entries or []:
            if str(e.get("id")) == order_id:
                targets = [t.get("canonical") for t in (e.get("targets") or []) if t.get("canonical")]
                if targets:
                    b.targets = targets
                    b.targets_source = "orders.json"
                b.order_meta.setdefault("createdAt", e.get("createdAt"))
                break
    if not b.targets:
        dom = meta.get("domain")
        b.targets = [dom] if dom and not str(dom).startswith("multi-target") else []
        b.targets_source = "meta"
    merge_tool_runs(b, runs, name=name, sha256=sha)
    if b.dns_records is None:
        dnsf = inv.get("dns_findings") if isinstance(inv, dict) else None
        if isinstance(dnsf, dict):
            b.dns_records = dnsf
            b.refs["dns_records"] = "order.json:progress.discoveredHosts.dns_findings"
    # webtech-Zeilen liefern im Snapshot den einzigen Tech-Hinweis je Host.
    for ip, h in b.hosts.items():
        if h.webtech and h.tech_profile is None:
            h.tech_profile = None
    return b


def attach_orders_json(bundle: ScanBundle, orders_path: str | Path) -> None:
    """Zielliste (targets[]) und createdAt aus api-snapshot/orders.json uebernehmen."""
    ol = load_json(Path(orders_path))
    entries = (ol.get("data") or {}).get("orders") if isinstance(ol, dict) else None
    for e in entries or []:
        if str(e.get("id")) == bundle.order_id:
            targets = [t.get("canonical") for t in (e.get("targets") or []) if t.get("canonical")]
            if targets:
                bundle.targets = targets
                bundle.targets_source = "orders.json"
            bundle.order_meta = dict(bundle.order_meta or {})
            bundle.order_meta.setdefault("createdAt", e.get("createdAt"))
            return


def apply_overrides(bundle: ScanBundle, *, host_inventory: dict | None = None,
                    tech_profiles: list | None = None, correlated_findings: list | None = None,
                    job_payload: dict | None = None, order: dict | None = None) -> None:
    """Explizite Argumente von ``build_facts`` haben Vorrang vor Tar-Inhalten."""
    if isinstance(host_inventory, dict) and host_inventory.get("hosts"):
        bundle.host_inventory = host_inventory
        bundle.refs["host_inventory"] = "argument:host_inventory"
    if tech_profiles:
        bundle.tech_profiles = list(tech_profiles)
        for tp in tech_profiles:
            if isinstance(tp, dict) and tp.get("ip"):
                bundle.host(str(tp["ip"])).tech_profile = tp
    if correlated_findings:
        bundle.correlated_findings = list(correlated_findings)
        bundle.refs["correlated_findings"] = "argument:correlated_findings"
    if isinstance(job_payload, dict):
        if isinstance(job_payload.get("enrichment"), dict) and job_payload["enrichment"]:
            bundle.enrichment = job_payload["enrichment"]
            bundle.refs["enrichment"] = "job_payload:enrichment"
        if not correlated_findings and isinstance(job_payload.get("correlatedFindings"), list) \
                and job_payload["correlatedFindings"]:
            bundle.correlated_findings = job_payload["correlatedFindings"]
            bundle.refs["correlated_findings"] = "job_payload:correlatedFindings"
        if job_payload.get("package") and not bundle.meta.get("package"):
            bundle.meta["package"] = job_payload["package"]
        if job_payload.get("policyVersion") or job_payload.get("policy_version"):
            bundle.meta["policyVersion"] = job_payload.get("policyVersion") or job_payload.get("policy_version")
    if isinstance(order, dict):
        bundle.order_meta = dict(order)
        targets = order.get("targets")
        if isinstance(targets, list):
            canon = [t.get("canonical") if isinstance(t, dict) else str(t) for t in targets]
            canon = [c for c in canon if c]
            if canon:
                bundle.targets = canon
                bundle.targets_source = "order"
