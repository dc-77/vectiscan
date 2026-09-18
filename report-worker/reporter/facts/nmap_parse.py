"""nmap-Leser fuer das Facts-Paket.

Primaer wird ``hosts/<ip>/phase1/nmap.xml`` gelesen, weil nur das XML die
Service-Attribute (``extrainfo``, ``tunnel``, ``conf``, ``servicefp``) und
die NSE-Skriptausgaben (``pop3-capabilities``, ``imap-capabilities``,
``smtp-commands``, ``ssl-cert``, ``mysql-info``) vollstaendig traegt.
Fallback ist der ``-oN``-Text (Snapshot-Zeilen ``scan_results.raw_output``),
nach dem Muster aus ``report-prototype/build/catalog_sim.py::parse_nmap``.

Der Leser erzeugt keine Befunde; er liefert Ports mit Rohattributen und die
abgeleiteten Flags (TLS-Zwang, STARTTLS, LOGINDISABLED, AUTH-Mechanismen).
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional

from reporter.facts.serialize import iso_utc

IMPLICIT_TLS_SERVICES = frozenset({
    "https", "imaps", "pop3s", "smtps", "ftps", "ldapssl", "ldaps", "ssl", "ms-wbt-server-ssl",
})
MAIL_AUTH_SERVICES = frozenset({"smtp", "submission", "imap", "pop3", "imaps", "pop3s", "smtps"})

_EGRESS_RE = re.compile(r"Hello\s+\S+\s+\[([0-9a-fA-F.:]+)\]")


@dataclass
class NmapScript:
    id: str
    output: str


@dataclass
class NmapPort:
    port: int
    proto: str
    state: str
    reason: Optional[str] = None
    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    extrainfo: Optional[str] = None
    tunnel: Optional[str] = None
    conf: Optional[int] = None
    method: Optional[str] = None
    hostname: Optional[str] = None
    servicefp: Optional[str] = None
    scripts: list[NmapScript] = field(default_factory=list)

    def script(self, script_id: str) -> Optional[str]:
        for s in self.scripts:
            if s.id == script_id:
                return s.output
        return None


@dataclass
class NmapHost:
    address: str
    state: Optional[str] = None
    reason: Optional[str] = None
    hostnames: list[str] = field(default_factory=list)
    ports: list[NmapPort] = field(default_factory=list)
    extraports: dict[str, int] = field(default_factory=dict)
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    os_match: Optional[str] = None


@dataclass
class NmapRun:
    version: Optional[str] = None
    args: Optional[str] = None
    hosts: list[NmapHost] = field(default_factory=list)
    hosts_up: Optional[int] = None
    hosts_total: Optional[int] = None
    targets_skipped: list[tuple[str, str]] = field(default_factory=list)
    finished_at: Optional[str] = None
    summary: Optional[str] = None
    source_format: str = "xml"

    @property
    def scanned(self) -> bool:
        return bool(self.hosts) or bool(self.hosts_total)

    def host_for(self, ip: str) -> Optional[NmapHost]:
        """Host-Eintrag fuer ``ip``; mit ``--open`` fehlt das ``<host>``-Element,
        wenn kein Port offen ist. Dann wird aus ``runstats`` ein leerer Host
        synthetisiert (state aus ``hosts up``)."""
        for h in self.hosts:
            if h.address == ip:
                return h
        if self.hosts:
            return self.hosts[0]
        if self.hosts_total:
            return NmapHost(address=ip, state="up" if self.hosts_up else "down", reason="runstats")
        return None


# ------------------------------------------------------------------ XML

def parse_nmap_xml(text: str | bytes | None) -> Optional[NmapRun]:
    if not text:
        return None
    try:
        root = ET.fromstring(text if isinstance(text, (bytes, bytearray)) else text.encode("utf-8"))
    except ET.ParseError:
        return None
    if root.tag != "nmaprun":
        return None
    run = NmapRun(version=root.get("version"), args=root.get("args"))
    for target in root.findall("target"):
        if target.get("status") == "skipped":
            run.targets_skipped.append((target.get("specification", ""), target.get("reason", "")))
    for h in root.findall("host"):
        host = NmapHost(address="")
        addr = h.find("address")
        if addr is not None:
            host.address = addr.get("addr", "")
        st = h.find("status")
        if st is not None:
            host.state = st.get("state")
            host.reason = st.get("reason")
        host.hostnames = [hn.get("name", "") for hn in h.findall("hostnames/hostname") if hn.get("name")]
        host.start_time = iso_utc(h.get("starttime"))
        host.end_time = iso_utc(h.get("endtime"))
        ports = h.find("ports")
        if ports is not None:
            for ep in ports.findall("extraports"):
                try:
                    host.extraports[ep.get("state", "unknown")] = int(ep.get("count", "0"))
                except ValueError:
                    continue
            for p in ports.findall("port"):
                try:
                    portid = int(p.get("portid", "0"))
                except ValueError:
                    continue
                state_el = p.find("state")
                np = NmapPort(
                    port=portid,
                    proto=p.get("protocol", "tcp"),
                    state=state_el.get("state", "unknown") if state_el is not None else "unknown",
                    reason=state_el.get("reason") if state_el is not None else None,
                )
                svc = p.find("service")
                if svc is not None:
                    np.service = svc.get("name")
                    np.product = svc.get("product")
                    np.version = svc.get("version")
                    np.extrainfo = svc.get("extrainfo")
                    np.tunnel = svc.get("tunnel")
                    np.method = svc.get("method")
                    np.hostname = svc.get("hostname")
                    np.servicefp = svc.get("servicefp")
                    conf = svc.get("conf")
                    if conf is not None:
                        try:
                            np.conf = int(conf)
                        except ValueError:
                            np.conf = None
                for s in p.findall("script"):
                    np.scripts.append(NmapScript(id=s.get("id", ""), output=s.get("output", "") or ""))
                host.ports.append(np)
        osm = h.find("os/osmatch")
        if osm is not None:
            host.os_match = osm.get("name")
        host.ports.sort(key=lambda x: (x.proto, x.port))
        run.hosts.append(host)
    fin = root.find("runstats/finished")
    if fin is not None:
        run.finished_at = iso_utc(fin.get("time"))
        run.summary = fin.get("summary")
    hosts_el = root.find("runstats/hosts")
    if hosts_el is not None:
        try:
            run.hosts_up = int(hosts_el.get("up", "0"))
            run.hosts_total = int(hosts_el.get("total", "0"))
        except ValueError:
            pass
    return run


# ------------------------------------------------------------------ Text-Fallback

_PORT_LINE = re.compile(r"^(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)\s+(\S+)\s*(.*)$")
_SCRIPT_LINE = re.compile(r"^\|[_ ]?\s*([a-z0-9-]+):\s*(.*)$")
_REPORT_LINE = re.compile(r"^Nmap scan report for (\S+)", re.M)
_NOT_SHOWN = re.compile(r"Not shown: (\d+) (\w+) (?:tcp|udp) ports")
_ALL_PORTS = re.compile(r"All (\d+) scanned ports on .* are (?:in ignored states|(\w+))")


def parse_nmap_text(text: str | None, host_ip: str) -> Optional[NmapRun]:
    """``-oN``-Text lesen (Snapshot). Skriptausgaben werden je Port gesammelt."""
    if not text:
        return None
    run = NmapRun(source_format="text")
    m = re.search(r"Nmap (\d+\.\d+\S*)", text)
    if m:
        run.version = m.group(1)
    if not _REPORT_LINE.search(text):
        # Nur die Banner-Zeile: nmap hat kein Ziel gescannt (IPv6 ohne -6 o. ae.).
        run.hosts_total = 0
        run.hosts_up = 0
        if ":" in host_ip:
            run.targets_skipped.append((host_ip, "invalid"))
        return run
    host = NmapHost(address=host_ip)
    if re.search(r"^Host is up", text, re.M):
        host.state = "up"
    m = _NOT_SHOWN.search(text)
    if m:
        host.extraports[m.group(2)] = int(m.group(1))
    m = _ALL_PORTS.search(text)
    if m and m.group(2):
        host.extraports[m.group(2)] = int(m.group(1))
    cur: Optional[NmapPort] = None
    cur_script: Optional[NmapScript] = None
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        pm = _PORT_LINE.match(line)
        if pm:
            port, proto, state, svc, reason, rest = pm.groups()
            cur = NmapPort(port=int(port), proto=proto, state=state, reason=reason, service=svc)
            cur_script = None
            rest = rest.strip()
            if rest:
                _apply_text_version(cur, rest)
            if svc.endswith("?"):
                # nmap markiert unsichere Dienstnamen mit "?" (Tabellen-Treffer).
                cur.service = svc[:-1]
                cur.conf = 3
                cur.method = "table"
            if cur.service and cur.service.startswith("ssl/"):
                cur.tunnel = "ssl"
                cur.service = cur.service[4:]
            host.ports.append(cur)
            continue
        if cur is not None and line.startswith("|"):
            sm = _SCRIPT_LINE.match(line)
            if sm and not line.startswith("|  ") and not line.startswith("|_  "):
                cur_script = NmapScript(id=sm.group(1), output=sm.group(2))
                cur.scripts.append(cur_script)
            elif cur_script is not None:
                cur_script.output += "\n" + line.lstrip("|_ ").rstrip()
            continue
        if line and not line.startswith("|"):
            cur_script = None
    host.ports.sort(key=lambda x: (x.proto, x.port))
    run.hosts.append(host)
    run.hosts_total = 1
    run.hosts_up = 1 if host.state == "up" else 0
    m = re.search(r"Nmap done at (.+?); ", text)
    if m:
        run.summary = m.group(0)
    return run


def _apply_text_version(port: NmapPort, rest: str) -> None:
    """``ProFTPD (requires SSL)`` / ``MySQL 5.5.5-10.11.18-MariaDB-0+deb12u1`` / ``OpenSSH 9.2p1 (protocol 2.0)``."""
    m = re.match(r"^(.*?)\s*\(([^)]*)\)\s*$", rest)
    if m:
        rest, port.extrainfo = m.group(1).strip(), m.group(2).strip()
    # Version beginnt beim ersten Token, das mit einer Ziffer anfaengt; der Rest
    # der Zeile bleibt Teil der Version ("9.6.0 or later", "5.5.5-10.11.18-MariaDB").
    vm = re.match(r"^(.*?)(?:^|\s)(\d[\w.+~-]*(?:\s.*)?)$", rest)
    if vm and vm.group(1).strip():
        port.product = vm.group(1).strip()
        port.version = vm.group(2).strip()
    elif vm and not vm.group(1).strip():
        port.product = None
        port.version = vm.group(2).strip()
    else:
        port.product = rest or None
    if port.method is None:
        port.method = "text"


# ------------------------------------------------------------------ Ableitungen

@dataclass
class ServiceFlags:
    tunnel_ssl: bool = False
    tls_required: Optional[bool] = None
    starttls: Optional[bool] = None
    login_disabled: Optional[bool] = None
    auth_required: Optional[bool] = None
    auth_mechanisms: list[str] = field(default_factory=list)
    capabilities: list[str] = field(default_factory=list)
    cert_cn: Optional[str] = None
    cert_san: list[str] = field(default_factory=list)
    cert_not_after: Optional[str] = None
    egress_ip: Optional[str] = None


def _tokens(text: str) -> list[str]:
    return [t for t in re.split(r"[\s,]+", text.strip()) if t]


def derive_service_flags(port: NmapPort) -> ServiceFlags:
    f = ServiceFlags()
    svc = (port.service or "").lower()
    extrainfo = port.extrainfo or ""
    f.tunnel_ssl = port.tunnel == "ssl" or "%T=SSL" in (port.servicefp or "")
    implicit = f.tunnel_ssl or svc in IMPLICIT_TLS_SERVICES or "requires SSL" in extrainfo \
        or "requires TLS" in extrainfo
    if implicit:
        f.tls_required = True

    caps_text = None
    for sid in ("pop3-capabilities", "imap-capabilities"):
        out = port.script(sid)
        if out is not None:
            caps_text = out
            toks = _tokens(out.replace("\n", " "))
            f.capabilities = toks
            if any(t.upper() in ("STLS", "STARTTLS") for t in toks):
                f.starttls = True
            elif f.starttls is None:
                f.starttls = False
            if any(t.upper().startswith("LOGINDISABLED") for t in toks):
                f.login_disabled = True
            elif sid == "imap-capabilities":
                f.login_disabled = False
            for t in toks:
                up = t.upper()
                if up.startswith("AUTH="):
                    f.auth_mechanisms.append(re.sub(r"A\d{4}$", "", up[5:]))
                elif up.startswith("SASL(") and up.endswith(")"):
                    f.auth_mechanisms.extend(x for x in up[5:-1].split(",") if x)
    smtp = port.script("smtp-commands")
    if smtp is not None:
        caps_text = smtp
        ehlo = smtp.split("Commands supported", 1)[0]
        parts = [p.strip() for p in ehlo.split(",") if p.strip()]
        f.capabilities = parts
        m = _EGRESS_RE.search(ehlo)
        if m:
            f.egress_ip = m.group(1)
        has_starttls = any(p.upper() == "STARTTLS" for p in parts)
        f.starttls = has_starttls
        for p in parts:
            if p.upper().startswith("AUTH "):
                f.auth_mechanisms.extend(x.upper() for x in p.split()[1:])
        if has_starttls and not f.auth_mechanisms:
            # AUTH wird vor STARTTLS nicht angeboten: Anmeldung nur nach TLS.
            f.login_disabled = True
    mysql = port.script("mysql-info")
    if mysql is not None:
        m = re.search(r"Auth Plugin Name:\s*(\S+)", mysql)
        if m:
            f.auth_mechanisms.append(m.group(1))
    ftp_anon = port.script("ftp-anon")
    if ftp_anon is not None and "Anonymous FTP login allowed" in ftp_anon:
        f.auth_required = False
        f.capabilities.append("ANONYMOUS-LOGIN")
    methods = port.script("http-methods")
    if methods is not None:
        m = re.search(r"Potentially risky methods:\s*([A-Z ,]+)", methods)
        if m:
            f.capabilities.extend(f"METHOD:{x.strip()}" for x in re.split(r"[\s,]+", m.group(1)) if x.strip())

    if f.auth_mechanisms:
        f.auth_mechanisms = sorted(set(f.auth_mechanisms))
        if f.auth_required is None:
            f.auth_required = True
    if f.tls_required is None and f.starttls and f.login_disabled:
        f.tls_required = True
    elif f.tls_required is None and f.starttls is not None and svc in MAIL_AUTH_SERVICES:
        f.tls_required = False if (f.starttls and f.login_disabled is False) else None

    cert = port.script("ssl-cert")
    if cert:
        m = re.search(r"commonName=([^/\n,]+)", cert)
        if m:
            f.cert_cn = m.group(1).strip()
        m = re.search(r"Subject Alternative Name:\s*([^\n]+)", cert)
        if m:
            f.cert_san = sorted({x.strip()[4:] for x in m.group(1).split(",") if x.strip().startswith("DNS:")})
        m = re.search(r"Not valid after:\s*(\S+)", cert)
        if m:
            f.cert_not_after = iso_utc(m.group(1))
    _ = caps_text
    return f
