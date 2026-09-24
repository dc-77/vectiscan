"""Versionsnormalisierung mit Plausibilitaet (spec/05 B4, M1).

Regeln (jede mit Testfall in tests/test_facts_versions.py):
1. MariaDB-Kompatibilitaetspraefix: ``5.5.5-10.11.18-MariaDB-0+deb12u1`` ist
   MariaDB 10.11.18, nicht MySQL 5.5.
2. ``or later``, ``or newer``, ``>=``, ``x`` und Bereiche ergeben ``version None``.
3. Exchange-Familie aus dem OWA-Build: 15.0 = 2013, 15.1 = 2016,
   15.2 < 2562 = 2019, 15.2 >= 2562 = SE. ``X-FEServer`` ist nur ein Hinweis.
4. Banner (nginx, Apache, PHP, OpenSSH, IIS, Exim ...) werden in Produkt,
   Version und Distribution zerlegt.
5. ``kind`` kommt aus einer kuratierten Tabelle; unbekannt ist ``component``.
   Eine Familie gilt nur, wenn der Name ausserhalb des Treffers nur neutrale Zusaetze
   traegt (``httpd``, ``pop3d``, ``HTTP Server``, Hersteller); ``jQuery Migrate`` ist
   nicht ``jQuery`` und ``Apache Tomcat`` nicht ``Apache httpd`` (spec/09 Q11).
6. EOL nur bei sicherer Familie und Version; Distro-Pakete ergeben ``unknown``
   mit dem Upstream-Termin als Hinweis (Entscheidung DC 18.09.2026).
"unbekannt" ist ueberall ein zulaessiges Ergebnis.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional

from reporter.facts.schema import CONFIDENCE_DERIVED, CONFIDENCE_TOOL, Eol

# family -> (kind, canonical product, (vendor, product) fuer EOL_DATA)
_FAMILIES: list[tuple[re.Pattern[str], str, str, str, tuple[str, str] | None]] = [
    (re.compile(r"mariadb", re.I), "mariadb", "database", "MariaDB", ("mariadb", "")),
    (re.compile(r"^mysql\b", re.I), "mysql", "database", "MySQL", ("mysql", "")),
    (re.compile(r"postgres", re.I), "postgresql", "database", "PostgreSQL", ("postgresql", "")),
    (re.compile(r"microsoft sql|ms-sql|mssql", re.I), "mssql", "database", "Microsoft SQL Server", ("microsoft", "sql-server")),
    (re.compile(r"mongodb", re.I), "mongodb", "database", "MongoDB", ("mongodb", "")),
    (re.compile(r"^redis", re.I), "redis", "database", "Redis", ("redis", "")),
    (re.compile(r"elasticsearch", re.I), "elasticsearch", "database", "Elasticsearch", ("elastic", "elasticsearch")),
    (re.compile(r"outlook web app|owa|microsoft exchange|^exchange", re.I), "exchange", "mail", "Microsoft Exchange", ("microsoft", "exchange")),
    (re.compile(r"^nginx", re.I), "nginx", "webserver", "nginx", ("nginx", "")),
    (re.compile(r"apache httpd|^apache/|^apache$|^apache\b", re.I), "apache", "webserver", "Apache httpd", ("apache", "httpd")),
    (re.compile(r"microsoft-iis|^iis\b|microsoft iis", re.I), "iis", "webserver", "Microsoft IIS", ("microsoft", "iis")),
    (re.compile(r"litespeed", re.I), "litespeed", "webserver", "LiteSpeed", None),
    (re.compile(r"lighttpd", re.I), "lighttpd", "webserver", "lighttpd", ("lighttpd", "")),
    (re.compile(r"openresty", re.I), "openresty", "webserver", "OpenResty", None),
    (re.compile(r"caddy", re.I), "caddy", "webserver", "Caddy", None),
    (re.compile(r"sw-cp-server|plesk", re.I), "plesk", "control_panel", "Plesk", None),
    (re.compile(r"^php\b", re.I), "php", "language", "PHP", ("php", "")),
    (re.compile(r"asp\.net", re.I), "aspnet", "language", "ASP.NET", None),
    (re.compile(r"^python", re.I), "python", "language", "Python", ("python", "")),
    (re.compile(r"node\.?js", re.I), "nodejs", "language", "Node.js", ("nodejs", "")),
    (re.compile(r"openssl", re.I), "openssl", "library", "OpenSSL", ("openssl", "")),
    (re.compile(r"^jquery", re.I), "jquery", "library", "jQuery", None),
    (re.compile(r"bootstrap", re.I), "bootstrap", "library", "Bootstrap", None),
    (re.compile(r"wordpress", re.I), "wordpress", "cms_core", "WordPress", ("wordpress", "")),
    (re.compile(r"typo3", re.I), "typo3", "cms_core", "TYPO3", ("typo3", "")),
    (re.compile(r"joomla", re.I), "joomla", "cms_core", "Joomla", ("joomla", "")),
    (re.compile(r"drupal", re.I), "drupal", "cms_core", "Drupal", ("drupal", "")),
    (re.compile(r"nextcloud", re.I), "nextcloud", "application", "Nextcloud", ("nextcloud", "")),
    (re.compile(r"owncloud", re.I), "owncloud", "application", "ownCloud", None),
    (re.compile(r"roundcube", re.I), "roundcube", "application", "Roundcube", ("roundcube", "")),
    (re.compile(r"bitwarden|vaultwarden", re.I), "bitwarden", "application", "Bitwarden", None),
    (re.compile(r"gitlab", re.I), "gitlab", "application", "GitLab", ("gitlab", "")),
    (re.compile(r"grafana", re.I), "grafana", "application", "Grafana", ("grafana", "")),
    (re.compile(r"webmin", re.I), "webmin", "control_panel", "Webmin", None),
    (re.compile(r"portainer", re.I), "portainer", "control_panel", "Portainer", None),
    (re.compile(r"^exim", re.I), "exim", "mail", "Exim", ("exim", "")),
    (re.compile(r"postfix", re.I), "postfix", "mail", "Postfix", ("postfix", "")),
    (re.compile(r"dovecot", re.I), "dovecot", "mail", "Dovecot", ("dovecot", "")),
    (re.compile(r"courier", re.I), "courier", "mail", "Courier", None),
    (re.compile(r"sendmail", re.I), "sendmail", "mail", "Sendmail", None),
    (re.compile(r"(?:proftpd\s+)?mod_sftp", re.I), "proftpd_sftp", "ssh", "ProFTPD mod_sftp", None),
    (re.compile(r"openssh", re.I), "openssh", "ssh", "OpenSSH", ("openssh", "")),
    (re.compile(r"dropbear", re.I), "dropbear", "ssh", "Dropbear", None),
    (re.compile(r"proftpd", re.I), "proftpd", "ftp", "ProFTPD", None),
    (re.compile(r"vsftpd", re.I), "vsftpd", "ftp", "vsftpd", None),
    (re.compile(r"pure-?ftpd", re.I), "pureftpd", "ftp", "Pure-FTPd", None),
    (re.compile(r"filezilla", re.I), "filezilla", "ftp", "FileZilla Server", None),
    (re.compile(r"windows server", re.I), "windows_server", "os", "Windows Server", ("microsoft", "windows-server")),
    (re.compile(r"^windows\b", re.I), "windows", "os", "Windows", None),
    (re.compile(r"^debian", re.I), "debian", "os", "Debian", ("debian", "")),
    (re.compile(r"^ubuntu", re.I), "ubuntu", "os", "Ubuntu", ("ubuntu", "")),
    (re.compile(r"sonicwall", re.I), "sonicwall", "appliance", "SonicWall", None),
    (re.compile(r"fortigate|fortios", re.I), "fortigate", "appliance", "FortiGate", ("fortinet", "fortios")),
    (re.compile(r"icecast", re.I), "icecast", "application", "Icecast", None),
    (re.compile(r"openotp|webadm|rcdevs", re.I), "openotp", "application", "RCDevs OpenOTP", None),
]

# WordPress-Themes und -Plugins, wie httpx/wappalyzer sie benennt (Kleinschreibung).
WP_THEMES = frozenset({
    "betheme", "avada", "divi", "astra", "generatepress", "oceanwp", "hello elementor", "kadence",
    "neve", "enfold", "the7", "salient", "flatsome", "bridge", "jupiter", "x theme", "twenty twenty",
    "twenty twenty-one", "twenty twenty-two", "twenty twenty-three", "twenty twenty-four",
    "twenty twenty-five", "storefront", "sydney", "hestia", "blocksy", "myknowledgebase",
})
WP_PLUGINS = frozenset({
    "contact form 7", "wp fastest cache", "complianz", "yoast seo", "elementor", "woocommerce",
    "wordfence", "jetpack", "wpml", "akismet", "wp rocket", "all in one seo", "all in one seo pack",
    "rank math", "litespeed cache", "borlabs cookie", "cookiebot", "polylang", "wpforms",
    "really simple ssl", "classic editor", "advanced custom fields", "slider revolution",
    "revslider", "wpbakery", "wp super cache", "w3 total cache", "site kit", "gravity forms",
    "ninja forms", "the events calendar", "updraftplus", "smush", "monsterinsights",
    "google analytics for wordpress", "mailchimp for wordpress", "wp-optimize", "autoptimize",
    "essential addons for elementor", "wpforms lite", "wp mail smtp", "duplicator",
})

_RANGE_RE = re.compile(r"or later|or newer|or higher|>=|<=|(?<![\w.])x(?![\w.])|\d\s*-\s*\d", re.I)
_VERSION_RE = re.compile(r"(\d+(?:\.\d+)+(?:p\d+|[a-z]\d*)?|\d+p\d+|\d+)")
_DISTRO_PATTERNS = (
    (re.compile(r"ubuntu", re.I), "ubuntu"),
    (re.compile(r"\bdebian\b|deb\d+u\d+", re.I), "debian"),
    (re.compile(r"\bel\d\b|\.el\d|red hat|rhel|centos|almalinux|rocky", re.I), "rhel"),
    (re.compile(r"\.fc\d+|\bfedora\b", re.I), "fedora"),
    (re.compile(r"\balpine\b", re.I), "alpine"),
    (re.compile(r"\bfreebsd\b", re.I), "freebsd"),
)
_MARIADB_PREFIX_RE = re.compile(r"^\s*5\.5\.5-(\d+\.\d+\.\d+)-MariaDB", re.I)
_MARIADB_RE = re.compile(r"(\d+\.\d+\.\d+)-MariaDB", re.I)
_EXCHANGE_BUILD_RE = re.compile(r"\b(1[45])\.(\d)\.(\d{3,4})(?:\.(\d+))?\b")


@dataclass
class Normalized:
    family: Optional[str] = None
    product: Optional[str] = None
    kind: str = "component"
    version: Optional[str] = None
    build: Optional[str] = None
    distro: Optional[str] = None
    edition: Optional[str] = None
    hints: list[str] = field(default_factory=list)
    confidence: float = CONFIDENCE_TOOL
    note: Optional[str] = None
    eol_key: Optional[tuple[str, str]] = None


def split_name_version(text: str | None) -> tuple[str, Optional[str], str]:
    """Namensfeld zerlegen: (Name, eingebettete Version, Rest fuer Distro-Erkennung).

    ``PHP/8.2.30\\nPleskLin`` -> (``PHP``, ``8.2.30``, ``""``);
    ``BeTheme:27.2.11`` -> (``BeTheme``, ``27.2.11``, ``""``);
    ``nginx/1.24.0 (Ubuntu)`` -> (``nginx``, ``1.24.0``, ``(Ubuntu)``).
    """
    if not text:
        return "", None, ""
    first = str(text).splitlines()[0].strip()
    m = re.match(r"^(.+?)[:/]\s*(\d[\w.+-]*)(\s.*)?$", first)
    if m:
        return m.group(1).strip(), m.group(2), (m.group(3) or "").strip()
    m = re.match(r"^(.+?)\s+(\d+(?:\.\d+)+\S*)(\s.*)?$", first)
    if m and not re.search(r"\d", m.group(1)):
        return m.group(1).strip(), m.group(2), (m.group(3) or "").strip()
    return first, None, ""


# Zusaetze, die den Produktnamen beschreiben, aber kein anderes Produkt benennen:
# nmap-Dienstbezeichnungen (``Dovecot imapd``, ``Apache HTTP Server``), Hersteller
# (``Microsoft ASP.NET``), Distributionen und beschreibende Generator-Texte
# (``Joomla! - Open Source Content Management``). Alles andere ist eine Namensgrenze.
_NEUTRAL_NAME_TOKENS = frozenset({
    "httpd", "http", "https", "server", "db", "database", "daemon", "web", "service",
    "smtpd", "imapd", "pop3d", "ftpd", "sshd",
    "microsoft",
    "streaming", "media",
    "open", "source", "content", "management", "system",
    "debian", "ubuntu", "centos", "linux",
})
_NAME_TOKEN_RE = re.compile(r"[a-z0-9]+")


def _outside_match(name: str, m: re.Match[str]) -> list[str]:
    """Woerter ausserhalb des Familientreffers; ein angeschnittenes Wort zaehlt zum
    Treffer (``PostgreSQL`` bei Muster ``postgres``, ``PleskLin`` bei ``plesk``)."""
    start, end = m.start(), m.end()
    while start > 0 and name[start - 1].isalnum():
        start -= 1
    while end < len(name) and name[end].isalnum():
        end += 1
    rest = f"{name[:start]} {name[end:]}".lower()
    return [t for t in _NAME_TOKEN_RE.findall(rest) if not t.isdigit()]


def _generic(name: str, low: str) -> tuple[Optional[str], str, Optional[str], None]:
    return re.sub(r"[^a-z0-9]+", "_", low).strip("_") or None, "component", name.strip(), None


def classify(name: str | None) -> tuple[Optional[str], str, Optional[str], Optional[tuple[str, str]]]:
    """(family, kind, canonical product, eol_key) fuer einen Produktnamen.

    Normalisiert nie ueber Namensgrenzen: traegt der Name ausserhalb des Treffers ein
    Wort, das nicht neutral ist, bleibt er ein eigenes Produkt ohne EOL-Schluessel
    (``jQuery Migrate`` -> ``jquery_migrate``, nicht ``jQuery``)."""
    if not name:
        return None, "component", None, None
    low = name.strip().lower()
    if low in WP_THEMES:
        return re.sub(r"[^a-z0-9]+", "_", low), "theme", name.strip(), None
    if low in WP_PLUGINS:
        return re.sub(r"[^a-z0-9]+", "_", low), "plugin", name.strip(), None
    for pat, family, kind, product, eol_key in _FAMILIES:
        m = pat.search(name)
        if m:
            if any(t not in _NEUTRAL_NAME_TOKENS for t in _outside_match(name, m)):
                return _generic(name, low)
            return family, kind, product, eol_key
    return _generic(name, low)


def detect_distro(text: str | None) -> Optional[str]:
    if not text:
        return None
    for pat, name in _DISTRO_PATTERNS:
        if pat.search(text):
            return name
    return None


def exchange_edition(build: str) -> tuple[Optional[str], Optional[str]]:
    """OWA-Build -> (Edition, Hinweis)."""
    m = _EXCHANGE_BUILD_RE.search(build or "")
    if not m:
        return None, None
    major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
    if major == 14:
        return "2010", None
    if major == 15 and minor == 0:
        return "2013", None
    if major == 15 and minor == 1:
        return "2016", None
    if major == 15 and minor == 2:
        return ("SE", None) if patch >= 2562 else ("2019", None)
    return None, "Exchange-Build ausserhalb der bekannten Linien"


def normalize(product_raw: str | None, version_raw: str | None = None, *,
              hints: list[str] | None = None, context: str | None = None) -> Normalized:
    """``context`` ist Zusatztext ohne Version (nmap ``extrainfo`` wie ``Ubuntu``),
    der nur fuer die Distributionserkennung gelesen wird."""
    n = Normalized(hints=list(hints or []))
    name, embedded, remainder = split_name_version(product_raw)
    version_text = (version_raw or "").strip() or (embedded or "")
    if embedded and remainder and not (version_raw or "").strip():
        version_text = f"{embedded} {remainder}"
    family, kind, product, eol_key = classify(name)
    n.family, n.kind, n.product, n.eol_key = family, kind, product, eol_key
    if not n.product and name:
        n.product = name

    combined = f"{name} {version_text}".strip()

    # Regel 1: MariaDB-Praefix
    m = _MARIADB_PREFIX_RE.match(version_text) or _MARIADB_PREFIX_RE.search(combined)
    if m:
        n.family, n.kind, n.product, n.eol_key = "mariadb", "database", "MariaDB", ("mariadb", "")
        n.version = m.group(1)
        n.distro = detect_distro(version_text) or detect_distro(context)
        n.note = "MariaDB-Kompatibilitaetspraefix 5.5.5 entfernt"
        return n
    m = _MARIADB_RE.search(combined)
    if m:
        n.family, n.kind, n.product, n.eol_key = "mariadb", "database", "MariaDB", ("mariadb", "")
        n.version = m.group(1)
        n.distro = detect_distro(version_text) or detect_distro(context)
        return n

    # Regel 2: Bereiche
    if version_text and _RANGE_RE.search(version_text):
        n.version = None
        n.note = "Bereichsangabe, Version nicht bestimmbar"
        n.confidence = CONFIDENCE_DERIVED
        n.hints.append(version_text)
        return n

    # Regel 3: Exchange
    if n.family == "exchange":
        bm = _EXCHANGE_BUILD_RE.search(version_text) or _EXCHANGE_BUILD_RE.search(combined)
        if bm:
            n.build = bm.group(0)
            edition, note = exchange_edition(n.build)
            n.edition = edition
            n.version = edition
            n.note = note
            n.confidence = CONFIDENCE_DERIVED if edition else CONFIDENCE_DERIVED
        else:
            if version_text:
                n.hints.append(version_text)
            n.version = None
            n.note = "Kein OWA-Build, Edition nicht bestimmbar"
            n.confidence = CONFIDENCE_DERIVED
        return n

    # Regel 4: Banner mit Version und Distribution
    if version_text:
        vm = _VERSION_RE.search(version_text)
        if vm and re.search(r"\d", vm.group(1)):
            n.version = vm.group(1)
            n.distro = detect_distro(version_text) or detect_distro(name) or detect_distro(context)
        else:
            n.version = None
            n.hints.append(version_text)
            n.note = "Versionsangabe nicht numerisch"
    else:
        n.distro = detect_distro(name) or detect_distro(context)
    if n.version and n.family in ("windows_server", "windows") and not re.match(r"^\d{4}$", n.version):
        n.version = None
    return n


# ------------------------------------------------------------------ EOL

def _version_tuple(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", v))


def lookup_eol(norm: Normalized, scan_date: str | None, eol_data: dict[tuple[str, str, str], dict[str, Any]] | None = None) -> Eol:
    """EOL-Status relativ zum Scan-Datum, nur bei sicherer Familie und Version."""
    if eol_data is None:
        from reporter.eol_detector import EOL_DATA
        eol_data = EOL_DATA
    if not norm.eol_key or not norm.version:
        return Eol(status="unknown")
    vendor, product = norm.eol_key
    lookup_version = norm.build if norm.family == "exchange" and norm.build else norm.version
    vt = _version_tuple(lookup_version)
    best_key: Optional[tuple[str, str, str]] = None
    best_len = -1
    for key in eol_data:
        if key[0] != vendor or key[1] != product:
            continue
        pt = _version_tuple(key[2])
        if pt and vt[: len(pt)] == pt and len(pt) > best_len:
            best_key, best_len = key, len(pt)
    if best_key is None:
        return Eol(status="unknown")
    entry = eol_data[best_key]
    date = entry.get("date")
    source = entry.get("source") or "endoflife_date"
    latest = entry.get("latest_patch")
    if norm.distro:
        return Eol(status="unknown", date=None, source=source, latest_patch=latest, upstream_eol_date=date)
    if not date or not scan_date:
        return Eol(status="unknown", date=date, source=source, latest_patch=latest)
    status = "eol" if str(date)[:10] <= str(scan_date)[:10] else "supported"
    return Eol(status=status, date=date, source=source, latest_patch=latest)
