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
from reporter.facts.tool_errors import clean as _clean_tool_error
from reporter.facts.tool_errors import is_tool_error

IMPLICIT_TLS_SERVICES = frozenset({
    "https", "imaps", "pop3s", "smtps", "ftps", "ldapssl", "ldaps", "ssl", "ms-wbt-server-ssl",
})
MAIL_AUTH_SERVICES = frozenset({"smtp", "submission", "imap", "pop3", "imaps", "pop3s", "smtps"})

_EGRESS_RE = re.compile(r"Hello\s+\S+\s+\[([0-9a-fA-F.:]+)\]")


@dataclass
class NmapScript:
    id: str
    output: str
    # S6b-3 (spec/10 R3): strukturierte Felder aus dem XML (``<table key>``/``<elem key>``),
    # Schluessel als Pfad ("issuer.commonName", "validity.notAfter", "sha1").
    elems: dict[str, str] = field(default_factory=dict)


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
    # S6b-4 (spec/11 T15): Betriebssystem laut Dienstkennung ("Service Info: OS: Windows").
    ostype: Optional[str] = None
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
    # S6b-4 (spec/11 T1): gepruefter Portbereich laut ``<scaninfo services=...>`` (Top 1000).
    scan_services: Optional[str] = None
    scan_numservices: Optional[int] = None

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
    si = root.find("scaninfo")
    if si is not None and si.get("services"):
        run.scan_services = si.get("services")
        try:
            run.scan_numservices = int(si.get("numservices") or 0) or None
        except ValueError:
            run.scan_numservices = None
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
                    np.ostype = svc.get("ostype")
                    conf = svc.get("conf")
                    if conf is not None:
                        try:
                            np.conf = int(conf)
                        except ValueError:
                            np.conf = None
                for s in p.findall("script"):
                    np.scripts.append(NmapScript(id=s.get("id", ""), output=s.get("output", "") or "",
                                                 elems=_script_elems(s)))
                _drop_tool_errors(np)
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


def _drop_tool_errors(port: NmapPort) -> None:
    """S7a Punkt 0: Fehlermeldungen des Werkzeugs sind keine Beobachtung am Dienst.

    Eine Skriptausgabe wie "ERROR: Script execution failed (use -d to debug)" faellt ganz
    weg; damit zaehlt sie weder als Server-Kennung (``_fingerprint``) noch als Skript mit
    Ausgabe (``service_kennung``) noch als Nachweis. Dasselbe gilt fuer Produkt, Version
    und Zusatzangabe der Dienstkennung. Echte Fehlerseiten eines Servers (CloudFront
    "ERROR: The request could not be satisfied") treffen die Muster nicht.
    """
    port.scripts = [sc for sc in port.scripts if not is_tool_error(sc.output)]
    port.product = _clean_tool_error(port.product)
    port.version = _clean_tool_error(port.version)
    port.extrainfo = _clean_tool_error(port.extrainfo)


def _script_elems(script: ET.Element) -> dict[str, str]:
    """``<table key="issuer"><elem key="commonName">YR2</elem></table>`` -> ``issuer.commonName``.

    Nur die erste Ebene unter benannten Tabellen und benannte Elemente direkt am Skript;
    Listen ohne Schluessel (Erweiterungen, SAN-Liste) bleiben im Ausgabetext."""
    out: dict[str, str] = {}
    for el in script.findall("elem"):
        if el.get("key") and el.text:
            out[el.get("key", "")] = el.text.strip()
    for table in script.findall("table"):
        key = table.get("key")
        if not key:
            continue
        for el in table.findall("elem"):
            if el.get("key") and el.text:
                out.setdefault(f"{key}.{el.get('key')}", el.text.strip())
    return out


def in_port_range(spec: Optional[str], port: int) -> Optional[bool]:
    """Liegt ``port`` im Portbereich ``"1,3-4,6-7,..."``? None ohne Angabe."""
    if not spec:
        return None
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, _, hi = part.partition("-")
            try:
                if int(lo) <= port <= int(hi):
                    return True
            except ValueError:
                continue
        else:
            try:
                if int(part) == port:
                    return True
            except ValueError:
                continue
    return False


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
    for port in host.ports:
        _drop_tool_errors(port)
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
    # S6b-3 (spec/10 R3): Aussteller, Beginn, Fingerabdruck und Selbstsignatur aus ssl-cert.
    cert_issuer: Optional[str] = None
    cert_not_before: Optional[str] = None
    cert_self_signed: Optional[bool] = None
    cert_sha1: Optional[str] = None
    egress_ip: Optional[str] = None
    # S6b-2 (spec/09 Q13): Fingerabdruck aus der Antwort des Dienstes.
    fp_server: Optional[str] = None
    fp_title: Optional[str] = None
    fp_login: Optional[bool] = None
    # S6b-3 (spec/10 R9): Name eines Audiostreams (Shoutcast/Icecast ``icy-name``).
    fp_stream: Optional[str] = None
    # S6b-3 (spec/10 R19): SMTP vor STARTTLS.
    smtp_vrfy: Optional[bool] = None
    auth_before_starttls: Optional[bool] = None


# Woerter aus der Satzform von nmap ("Pre-login capabilities listed; have more ...
# post-login"), keine Faehigkeiten des Dienstes (spec/10 R14).
_NMAP_CAP_WORDS = frozenset({"more", "have", "ok", "listed", "capabilities", "post-login", "pre-login"})


def _tokens(text: str) -> list[str]:
    return [t for t in re.split(r"[\s,]+", text.strip()) if t]


def capability_tokens(text: str) -> list[str]:
    """Faehigkeiten aus pop3-/imap-capabilities ohne nmap-Satzteile und ohne das
    Befehlskennzeichen ``A0001`` am Wortende ("LOGINDISABLEDA0001", "AUTH=PLAINA0001").
    Ein SASL-Block mit Leerzeichen ("SASL(PLAIN LOGIN)") bleibt ein Token."""
    text = re.sub(r"SASL\(([^)]*)\)", lambda m: "SASL(" + ",".join(m.group(1).split()) + ")", text)
    out: list[str] = []
    for t in text.split():
        t = t.rstrip(";")
        if t.lower() in _NMAP_CAP_WORDS:
            continue
        if len(t) > 5:
            t = re.sub(r"A\d{4}$", "", t)
        if t and t not in out:
            out.append(t)
    return out


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
            toks = capability_tokens(out)
            f.capabilities = toks
            if any(t.upper() in ("STLS", "STARTTLS") for t in toks):
                f.starttls = True
            elif f.starttls is None:
                f.starttls = False
            if any(t.upper() == "LOGINDISABLED" for t in toks):
                f.login_disabled = True
            elif sid == "imap-capabilities":
                f.login_disabled = False
            for t in toks:
                up = t.upper()
                if up.startswith("AUTH="):
                    f.auth_mechanisms.append(up[5:])
                elif up.startswith("SASL(") and up.endswith(")"):
                    f.auth_mechanisms.extend(x for x in up[5:-1].split(",") if x)
            # S6b-2 (spec/08 Punkt 4): POP3 kennt kein LOGINDISABLED. Bietet der Dienst vor
            # STLS die Anmeldung per USER oder ein SASL-Verfahren an, nimmt er sie ohne
            # Transportverschluesselung entgegen ("SASL(PLAIN LOGIN) USER ... STLS").
            # S6b-3 (spec/10 R7): umgekehrt sperrt ein Dienst, der vor STLS weder USER noch
            # ein SASL-Verfahren nennt ("STLS ... SASL" mit leerer Liste), die Anmeldung vor
            # TLS; das ist das POP3-Gegenstueck zu IMAP LOGINDISABLED.
            if sid == "pop3-capabilities" and f.starttls:
                sasl_mech = any(t.upper().startswith("SASL(") and t.upper() != "SASL()" for t in toks)
                if sasl_mech or any(t.upper() == "USER" for t in toks):
                    f.login_disabled = False
                else:
                    f.login_disabled = True
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
        # S6b-3 (spec/10 R19): VRFY in den EHLO-Faehigkeiten oder der Befehlsliste; AUTH vor
        # STARTTLS nur ohne impliziten TLS-Tunnel (auf 465 laeuft EHLO schon verschluesselt).
        commands = smtp.split("Commands supported", 1)[1] if "Commands supported" in smtp else ""
        f.smtp_vrfy = bool(re.search(r"\bVRFY\b", ehlo.upper() + " " + commands.upper()))
        if has_starttls and not f.tunnel_ssl:
            f.auth_before_starttls = bool(f.auth_mechanisms)
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
        m = re.search(r"Not valid before:\s*(\S+)", cert)
        if m:
            f.cert_not_before = iso_utc(m.group(1))
        _cert_details(f, port)
    fp = _fingerprint(port)
    f.fp_server, f.fp_title, f.fp_login = fp
    # S7a Punkt 0: zweite Sperre, falls ein Fehlertext ueber den Fingerprint kommt.
    f.fp_server = _clean_tool_error(f.fp_server)
    f.fp_title = _clean_tool_error(f.fp_title)
    f.fp_stream = _stream_name(port)
    if not f.fp_server:
        f.fp_server = _stream_server(port)
    _ = caps_text
    return f


def _cert_details(f: ServiceFlags, port: NmapPort) -> None:
    """Aussteller, Fingerabdruck und Selbstsignatur aus ssl-cert (XML-Tabellen, sonst Text)."""
    script = next((s for s in port.scripts if s.id == "ssl-cert"), None)
    if script is None:
        return
    el = script.elems
    text = script.output or ""
    issuer = el.get("issuer.commonName") or el.get("issuer.organizationName")
    if not issuer:
        m = re.search(r"Issuer:\s*commonName=([^/\n,]+)", text)
        issuer = m.group(1).strip() if m else None
    f.cert_issuer = issuer
    subject = (el.get("subject.commonName"), el.get("subject.organizationName"))
    issuer_pair = (el.get("issuer.commonName"), el.get("issuer.organizationName"))
    if any(subject) and any(issuer_pair):
        f.cert_self_signed = subject == issuer_pair
    sha1 = el.get("sha1")
    if not sha1:
        m = re.search(r"SHA-1:\s*([0-9a-fA-F ]{40,})", text)
        sha1 = m.group(1).replace(" ", "") if m else None
    f.cert_sha1 = sha1.replace(" ", "").lower() if sha1 else None
    if not f.cert_not_before and el.get("validity.notBefore"):
        f.cert_not_before = iso_utc(el["validity.notBefore"])
    if not f.cert_not_after and el.get("validity.notAfter"):
        f.cert_not_after = iso_utc(el["validity.notAfter"])


_ICY_NAME_RE = re.compile(r"^icy-name:\s*([^\n]{1,80})", re.M | re.I)
_ICY_SERVER_RE = re.compile(r"^icy-notice2:\s*(Shoutcast[^<\n/]*?)(?:/[^\n<]*?)?\s+v?(\d+(?:\.\d+)+)", re.M | re.I)


def _stream_name(port: NmapPort) -> Optional[str]:
    """Name eines Audiostreams aus dem Antwortkopf (``icy-name``), spec/10 R9 (castenow 8000)."""
    m = _ICY_NAME_RE.search(_fp_text(port.servicefp))
    return m.group(1).strip() if m else None


def _stream_server(port: NmapPort) -> Optional[str]:
    """Shoutcast nennt sich nicht im Kopf ``Server``, sondern in ``icy-notice2``."""
    m = _ICY_SERVER_RE.search(_fp_text(port.servicefp))
    if not m:
        return None
    return f"{m.group(1).strip()} {m.group(2)}"


def _fp_text(servicefp: Optional[str]) -> str:
    """nmap-Fingerprint lesbar machen (``\\x20`` zu Leerzeichen, ``\\r\\n`` zu Zeilen)."""
    if not servicefp:
        return ""
    text = servicefp.replace("\\r\\n", "\n").replace("\\n", "\n")
    text = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), text)
    # nmap maskiert Sonderzeichen im Fingerprint ("tonausstrom\.de", "posix\(linux").
    return re.sub(r"\\([^\w\s])", r"\1", text.replace('\\"', '"'))


_FP_SERVER_RE = re.compile(r"^Server:\s*([^\n]{1,120})", re.M | re.I)
_FP_TITLE_RE = re.compile(r"<title>\s*([^<]{1,160}?)\s*</title>", re.I)
_FP_LOGIN_RE = re.compile(
    r"auth-required=1|session_login|type=\W?password|WWW-Authenticate|name=\W?(?:pass|password|passwd)\b|"
    r"\blog ?in\b|anmeld", re.I)


def _fingerprint(port: NmapPort) -> tuple[Optional[str], Optional[str], Optional[bool]]:
    """(Server-Kennung, Seitentitel, Anmeldung belegt) aus Skripten und Fingerprint.

    Webmin auf 10000 erkennt nmap nicht als Produkt ("snet-sensor-mgmt?"), der Fingerprint
    zeigt aber ``Server: MiniServ`` und ``session_login`` (spec/09 Q13, dortmund-beach).
    ``fp_login`` ist True nur mit Beleg, sonst None; ein fehlender Beleg ist kein Nein.
    """
    fp = _fp_text(port.servicefp)
    server = (port.script("http-server-header") or "").splitlines()[0].strip() if port.script("http-server-header") else ""
    if not server:
        m = _FP_SERVER_RE.search(fp)
        server = m.group(1).strip() if m else ""
    title = (port.script("http-title") or "").splitlines()[0].strip() if port.script("http-title") else ""
    # S6b-3 (spec/10 R14): die Textausgabe kuerzt lange Titel mitten im Wort ("Web Applications
    # Po..."), das XML-Element traegt den vollen Titel.
    voll = next((sc.elems.get("title") for sc in port.scripts if sc.id == "http-title" and sc.elems.get("title")), None)
    if voll and title.endswith("...") and voll.strip().startswith(title[:-3].strip()):
        title = voll.strip()
    if title.lower().startswith(("did not follow redirect", "site doesn't have a title")):
        # nmap meldet eine Weiterleitung als Titel; das ist keine Seite des Dienstes.
        title = ""
    if not title:
        m = _FP_TITLE_RE.search(fp)
        title = m.group(1).strip() if m else ""
    if title:
        # nmap gibt HTML-Entitaeten roh aus und kuerzt lange Titel mit drei Punkten.
        import html as _html
        title = _html.unescape(title)
        if title.endswith("..."):
            title = title[:-3].rstrip() + " (Auszug)"
    login = bool(_FP_LOGIN_RE.search(fp) or (title and _FP_LOGIN_RE.search(title)))
    return (server or None), (title or None), (True if login else None)
