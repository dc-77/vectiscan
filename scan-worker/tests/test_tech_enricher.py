"""Tests fuer scanner.tech_enricher — Exchange/OWA-Erkennung aus Phase-2-Outputs.

Hintergrund: securess.de-Drift-Auswertung Mai 2026 — webtech sieht nur
Microsoft-IIS/10.0 + ASP.NET, Exchange-Build steht aber im
header_check.x-feserver und im zap_spider URL-Pfad. Der Enricher
schliesst diese Luecke, damit der EOL-Detector im Reporter Exchange 2016
zuverlaessig matchen kann.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest


def _write_phase2(host_dir: Path, files: dict[str, dict]) -> None:
    p2 = host_dir / "phase2"
    p2.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        (p2 / name).write_text(json.dumps(content), encoding="utf-8")


def test_phase1_technologies_from_nmap_services(tmp_path: Path) -> None:
    """build_tech_profile.technologies[] enthaelt nmap-Service-Banner."""
    from scanner.phase1 import build_tech_profile

    nmap_result = {
        "open_ports": [22, 25, 443],
        "services": [
            {"port": 443, "name": "https", "product": "Microsoft-IIS", "version": "10.0"},
            {"port": 22,  "name": "ssh",   "product": "OpenSSH",       "version": "7.4"},
            {"port": 25,  "name": "smtp",  "product": "Postfix smtpd", "version": "3.4.13"},
        ],
    }
    profile = build_tech_profile(
        ip="1.2.3.4",
        fqdns=["x.example"],
        nmap_result=nmap_result,
        webtech_result={"tech": [{"name": "ASP.NET", "version": "4.0.30319"}]},
        wafw00f_result=None,
        host_dir=str(tmp_path),
    )

    techs = {(t["name"].lower(), t["version"]) for t in profile["technologies"]}
    # nmap-Banner aller Services landen drin
    assert ("microsoft-iis", "10.0") in techs
    assert ("openssh", "7.4") in techs
    # Postfix wurde gesplittet (Versions-Tail aus "Postfix smtpd" + version="3.4.13")
    assert any(name.startswith("postfix") for name, _ in techs)
    # webtech-Eintrag ist auch drin
    assert any(name == "asp.net" for name, _ in techs)


def test_tech_enricher_exchange_from_x_feserver(tmp_path: Path) -> None:
    """x-feserver: EXCHANGE-2016 -> Microsoft Exchange / 2016 in technologies[]."""
    from scanner.tech_enricher import enrich_after_phase2

    host_dir = tmp_path / "hosts" / "85.22.47.43"
    _write_phase2(host_dir, {
        "headers.json": {
            "url": "https://owa.example/",
            "headers": {
                "server": "Microsoft-IIS/10.0",
                "x-feserver": "EXCHANGE-2016",
                "x-aspnet-version": "4.0.30319",
                "x-powered-by": "ASP.NET",
            },
            "score": "0/7",
        },
    })
    tp = {
        "ip": "85.22.47.43",
        "fqdns": ["owa.example"],
        "primary_vhost": "owa.example",
        "cms": None, "cms_version": None,
        "server": "Microsoft-IIS/10.0",
        "technologies": [{"name": "Microsoft-IIS", "version": "10.0"}],
        "vhost_results": {"owa.example": {"cms": None}},
    }
    stats = enrich_after_phase2([tp], str(tmp_path))

    assert stats["exchange_hosts"] == 1
    techs = {(t["name"], t["version"]) for t in tp["technologies"]}
    assert ("Microsoft Exchange", "2016") in techs
    # Das angereicherte CMS wurde gesetzt
    assert tp["cms"] == "Microsoft Exchange"
    assert tp["cms_version"] == "2016"
    assert tp["vhost_results"]["owa.example"]["cms"] == "Microsoft Exchange"


def test_tech_enricher_exchange_build_from_zap(tmp_path: Path) -> None:
    """zap_spider URL /owa/auth/15.1.2507/themes/... -> Build extrahiert."""
    from scanner.tech_enricher import enrich_after_phase2

    host_dir = tmp_path / "hosts" / "85.22.47.43"
    _write_phase2(host_dir, {
        "zap_spider.json": {
            "urls": [
                "https://owa.example/owa/",
                "https://owa.example/owa/auth/15.1.2507/themes/resources/favicon.ico",
                "https://owa.example/owa/auth/logon.aspx",
            ],
        },
    })
    tp = {
        "ip": "85.22.47.43",
        "fqdns": ["owa.example"],
        "primary_vhost": "owa.example",
        "cms": None, "cms_version": None,
        "technologies": [],
        "vhost_results": {},
    }
    stats = enrich_after_phase2([tp], str(tmp_path))

    assert stats["exchange_hosts"] == 1
    # Konkreter Build wurde extrahiert
    assert tp["cms"] == "Microsoft Exchange"
    assert tp["cms_version"] == "15.1.2507"
    techs = {(t["name"], t["version"]) for t in tp["technologies"]}
    assert ("Microsoft Exchange", "15.1.2507") in techs


def test_tech_enricher_does_not_overwrite_existing_cms(tmp_path: Path) -> None:
    """Wenn cms bereits gesetzt (z.B. WordPress), nicht ueberschreiben."""
    from scanner.tech_enricher import enrich_after_phase2

    host_dir = tmp_path / "hosts" / "1.2.3.4"
    _write_phase2(host_dir, {
        "headers.json": {
            "headers": {"x-feserver": "EXCHANGE-2016"},
        },
    })
    tp = {
        "ip": "1.2.3.4",
        "fqdns": ["wp.example"],
        "primary_vhost": "wp.example",
        "cms": "WordPress", "cms_version": "6.8",
        "technologies": [],
        "vhost_results": {"wp.example": {"cms": "WordPress"}},
    }
    enrich_after_phase2([tp], str(tmp_path))

    # CMS-Override wird NICHT ueberschrieben — aber Exchange landet trotzdem
    # in technologies[] (Tech-Stack-Auflistung) fuer den EOL-Detector.
    assert tp["cms"] == "WordPress"
    techs = {(t["name"], t["version"]) for t in tp["technologies"]}
    assert ("Microsoft Exchange", "2016") in techs


def test_tech_enricher_idempotent(tmp_path: Path) -> None:
    """Doppelter Aufruf fuegt keine Duplikate hinzu."""
    from scanner.tech_enricher import enrich_after_phase2

    host_dir = tmp_path / "hosts" / "1.2.3.4"
    _write_phase2(host_dir, {
        "headers.json": {"headers": {"x-feserver": "EXCHANGE-2016"}},
    })
    tp = {
        "ip": "1.2.3.4", "fqdns": ["x.example"], "primary_vhost": "x.example",
        "cms": None, "cms_version": None, "technologies": [],
        "vhost_results": {},
    }
    enrich_after_phase2([tp], str(tmp_path))
    first_count = len(tp["technologies"])
    enrich_after_phase2([tp], str(tmp_path))
    assert len(tp["technologies"]) == first_count


def test_tech_enricher_eol_detector_endtoend(tmp_path: Path) -> None:
    """End-to-end: angereichertes Profil -> EOL-Detector liefert SP-EOL-001."""
    from datetime import date
    from scanner.tech_enricher import enrich_after_phase2
    try:
        from reporter.eol_detector import detect_eol_findings
    except ImportError:
        pytest.skip("reporter package not on path in this environment")

    host_dir = tmp_path / "hosts" / "85.22.47.43"
    _write_phase2(host_dir, {
        "zap_spider.json": {
            "urls": ["https://owa.example/owa/auth/15.1.2507/themes/resources/x.png"],
        },
    })
    tp = {
        "ip": "85.22.47.43", "fqdns": ["owa.example"],
        "primary_vhost": "owa.example",
        "cms": None, "cms_version": None,
        "technologies": [], "vhost_results": {},
    }
    enrich_after_phase2([tp], str(tmp_path))

    findings = detect_eol_findings([tp], date(2026, 5, 5))
    eol = [f for f in findings if "Exchange" in f["title"]]
    assert eol, f"Erwartet ein Exchange-EOL-Finding, bekam: {findings}"
    assert eol[0]["policy_id"] == "SP-EOL-001"
    assert eol[0]["severity"] == "HIGH"
