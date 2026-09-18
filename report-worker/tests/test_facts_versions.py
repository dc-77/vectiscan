"""S1: Versionsnormalisierung mit Plausibilitaet (spec/05 B4) und EOL-Lookup."""
from __future__ import annotations

import pytest

from reporter.facts.versions import exchange_edition, lookup_eol, normalize, split_name_version

SCAN_DATE = "2026-08-31"

# Kleiner Feed fuer deterministische EOL-Tests (Struktur wie eol_detector.EOL_DATA).
FEED = {
    ("mariadb", "", "5.5"): {"date": "2020-04-11", "source": "endoflife_date", "latest_patch": "5.5.68"},
    ("mariadb", "", "10.5"): {"date": "2025-06-24", "source": "endoflife_date", "latest_patch": "10.5.29"},
    ("nginx", "", "1.24"): {"date": "2024-04-23", "source": "endoflife_date", "latest_patch": "1.24.0"},
    ("microsoft", "exchange", "15.1"): {"date": "2025-10-14", "source": "manual", "label": "Exchange Server 2016"},
    ("php", "", "8.1"): {"date": "2025-12-31", "source": "endoflife_date"},
    ("php", "", "8.3"): {"date": "2027-12-31", "source": "endoflife_date"},
}


@pytest.mark.parametrize("product,version,family,ver,distro,note_part", [
    ("MySQL", "5.5.5-10.11.18-MariaDB-0+deb12u1", "mariadb", "10.11.18", "debian", "praefix"),
    ("MySQL", "5.5.5-10.11.14-MariaDB-0ubuntu0.24.04.1-log", "mariadb", "10.11.14", "ubuntu", "praefix"),
    ("MySQL", "5.5.68-MariaDB", "mariadb", "5.5.68", None, None),
    ("PostgreSQL DB", "9.6.0 or later", "postgresql", None, None, "Bereichsangabe"),
    ("Apache httpd", "2.4.66 ((Debian))", "apache", "2.4.66", "debian", None),
    ("OpenSSH", "9.2p1 Debian 2+deb12u9", "openssh", "9.2p1", "debian", None),
    ("Exim smtpd", "4.96", "exim", "4.96", None, None),
    ("ProFTPD", "", "proftpd", None, None, None),
    ("Dovecot imapd", None, "dovecot", None, None, None),
    ("Microsoft Exchange", "EXCHANGE-SE", "exchange", None, None, "Kein OWA-Build"),
    ("Windows Server", "", "windows_server", None, None, None),
])
def test_normalize_produkt_und_version(product, version, family, ver, distro, note_part):
    n = normalize(product, version)
    assert n.family == family
    assert n.version == ver
    assert n.distro == distro
    if note_part:
        assert n.note and note_part in n.note
    else:
        assert not n.note


@pytest.mark.parametrize("name,family,ver,distro,kind", [
    ("nginx/1.24.0 (Ubuntu)", "nginx", "1.24.0", "ubuntu", "webserver"),
    ("Apache/2.4.41 (Ubuntu)", "apache", "2.4.41", "ubuntu", "webserver"),
    ("PHP/8.3.32", "php", "8.3.32", None, "language"),
    ("PHP/8.2.30\nPleskLin", "php", "8.2.30", None, "language"),
    ("Microsoft-IIS/10.0", "iis", "10.0", None, "webserver"),
    ("BeTheme:27.2.11", "betheme", "27.2.11", None, "theme"),
    ("Contact Form 7:5.8.4", "contact_form_7", "5.8.4", None, "plugin"),
    ("sw-cp-server", "plesk", None, None, "control_panel"),
])
def test_normalize_banner_im_namensfeld(name, family, ver, distro, kind):
    n = normalize(name, None)
    assert (n.family, n.version, n.distro, n.kind) == (family, ver, distro, kind)


def test_split_name_version_rest_fuer_distro():
    assert split_name_version("nginx/1.24.0 (Ubuntu)") == ("nginx", "1.24.0", "(Ubuntu)")
    assert split_name_version("PHP/8.2.30\nPleskLin") == ("PHP", "8.2.30", "")


def test_context_extrainfo_liefert_distro():
    n = normalize("nginx", "1.24.0", context="Ubuntu")
    assert n.version == "1.24.0" and n.distro == "ubuntu"


@pytest.mark.parametrize("build,edition", [
    ("15.2.2562", "SE"), ("15.2.2562.17", "SE"), ("15.2.1544", "2019"), ("15.2.2000.3", "2019"),
    ("15.1.2507", "2016"), ("15.0.1497", "2013"), ("14.3.513", "2010"),
])
def test_exchange_edition_aus_build(build, edition):
    assert exchange_edition(build)[0] == edition
    n = normalize("Outlook Web App", build)
    assert n.family == "exchange" and n.edition == edition and n.build == build and n.version == edition


def test_x_feserver_ist_nur_hinweis():
    n = normalize("Microsoft Exchange", "EXCHANGE-SE")
    assert n.version is None and n.build is None and "EXCHANGE-SE" in n.hints


def test_eol_distro_paket_bleibt_unbekannt():
    n = normalize("nginx/1.24.0 (Ubuntu)", None)
    e = lookup_eol(n, SCAN_DATE, FEED)
    assert e.status == "unknown" and e.upstream_eol_date == "2024-04-23" and e.date is None


def test_eol_ohne_distro_aus_feed():
    n = normalize("nginx", "1.24.0")
    e = lookup_eol(n, SCAN_DATE, FEED)
    assert e.status == "eol" and e.date == "2024-04-23"


def test_eol_mariadb_praefix_nicht_5_5():
    n = normalize("MySQL", "5.5.5-10.11.18-MariaDB-0+deb12u1")
    assert lookup_eol(n, SCAN_DATE, FEED).status == "unknown"
    echt = normalize("MySQL", "5.5.68-MariaDB")
    assert lookup_eol(echt, SCAN_DATE, FEED).status == "eol"


def test_eol_relativ_zum_scandatum():
    n = normalize("PHP/8.1.2", None)
    assert lookup_eol(n, "2026-08-31", FEED).status == "eol"
    assert lookup_eol(n, "2025-06-01", FEED).status == "supported"
    n83 = normalize("PHP/8.3.32", None)
    assert lookup_eol(n83, "2026-08-31", FEED).status == "supported"


def test_eol_exchange_nach_build():
    assert lookup_eol(normalize("Outlook Web App", "15.1.2507"), SCAN_DATE, FEED).status == "eol"
    assert lookup_eol(normalize("Outlook Web App", "15.2.2562"), SCAN_DATE, FEED).status == "unknown"


def test_eol_ohne_version_unbekannt():
    n = normalize("Apache/2.4.41 (Ubuntu)", None)
    assert lookup_eol(n, SCAN_DATE, FEED).status == "unknown"
    assert lookup_eol(normalize("PostgreSQL DB", "9.6.0 or later"), SCAN_DATE, FEED).status == "unknown"
