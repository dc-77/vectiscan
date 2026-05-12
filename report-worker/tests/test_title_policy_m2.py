"""M2 Track 2b — Title-Policy haerten.

Adressiert die Defekte aus docs/report-erstellung/01_Fehleranalyse_und_Korrekturplan.md:
- P0-01: {host}-Platzhalter im Titel nicht ersetzt
- P0-03: Befundtitel passt nicht zum Inhalt (SPF vs DKIM)
- P0-04: Bareword-Numbers im Title ("WordPress-Plugin 27")
- P0-05: Doppelte Titles fuer info_disclosure_banner (SSH vs HTTP)
"""

from reporter.title_policy import (
    SERVICE_BANNER_TEMPLATES,
    MAIL_SECURITY_TEMPLATES,
    TitleVarFallbackError,
    apply_title_template,
    apply_titles,
    _resolve_host_with_fallback,
    _validate_title_tokens,
)


# ---------------------------------------------------------------------------
# P0-01: {host}-Fallback-Kette
# ---------------------------------------------------------------------------

def test_p0_01_host_fallback_from_affected():
    findings = [{
        "id": "VS-001",
        "policy_id": "SP-RDP-001",
        "finding_type": "rdp_exposed",
        "title": "RDP-Dienst auf {host}",
        "affected": "45.157.234.103, 45.157.232.12",
    }]
    apply_titles(findings, scan_context={"domain": "secumetrix.de"})
    assert "{" not in findings[0]["title"]
    assert "45.157.234.103" in findings[0]["title"]


def test_p0_01_host_fallback_from_affected_single_string():
    """Single-Host-String in affected (kein Komma) wird direkt uebernommen."""
    f = {
        "id": "VS-X",
        "title": "FTP-Dienst auf {host}",
        "affected": "secumetrix.de",
    }
    apply_titles([f], scan_context={"domain": "secumetrix.de"})
    assert f["title"] == "FTP-Dienst auf secumetrix.de"


def test_p0_01_host_fallback_from_affected_hosts_list_single():
    f = {
        "id": "VS-2",
        "title": "RDP-Dienst auf {host}",
        "affected_hosts": ["host1.de"],
    }
    apply_titles([f], scan_context=None)
    assert "host1.de" in f["title"]
    assert "{" not in f["title"]


def test_p0_01_host_fallback_multi_host_format():
    """Mehrere Hosts → 'first (+N weitere)'-Format."""
    f = {
        "id": "VS-3",
        "title": "RDP-Dienst auf {host}",
        "affected_hosts": ["45.157.234.103", "45.157.232.12", "45.157.232.13"],
    }
    apply_titles([f], scan_context=None)
    assert "45.157.234.103" in f["title"]
    assert "+2 weitere" in f["title"]


def test_host_fallback_from_tech_profiles():
    f = {
        "id": "VS-XYZ",
        "policy_id": "SP-RDP-001",
        "finding_type": "rdp_exposed",
        "title": "RDP-Dienst auf {host}",
        # affected/affected_hosts/vhost ALL missing
    }
    ctx = {"domain": "x.de",
           "tech_profiles": [{"fqdns": ["x.de", "www.x.de"], "ip": "1.2.3.4"}]}
    apply_titles([f], scan_context=ctx)
    assert "{" not in f["title"]
    # tech_profiles-Fallback griff
    assert "x.de" in f["title"]


def test_host_fallback_from_host_inventory():
    f = {
        "id": "VS-XYZ",
        "title": "RDP-Dienst auf {host}",
    }
    ctx = {
        "domain": "x.de",
        "host_inventory": {"hosts": [{"fqdns": ["a.x.de", "b.x.de"]}]},
    }
    apply_titles([f], scan_context=ctx)
    assert "{" not in f["title"]
    assert "a.x.de" in f["title"]


def test_host_fallback_to_scan_context_domain_last_resort():
    f = {
        "id": "VS-Z",
        "title": "RDP-Dienst auf {host}",
    }
    ctx = {"domain": "final.de"}
    apply_titles([f], scan_context=ctx)
    assert "final.de" in f["title"]


def test_host_fallback_raises_when_nothing_available():
    """Wenn weder affected/hosts noch ctx irgendwas haben → degraded."""
    f = {
        "id": "VS-NULL",
        "title": "Dienst auf {host}",
    }
    apply_titles([f], scan_context=None)
    assert f.get("_title_degraded") is True
    assert f.get("_title_degraded_reason", "").startswith("var_fallback_failed:host")


def test_resolve_host_with_fallback_unit():
    # 1. affected (CSV)
    f = {"affected": "a.de, b.de"}
    assert "a.de" in (_resolve_host_with_fallback(f, None) or "")
    # 2. affected_hosts (Liste)
    f = {"affected_hosts": ["a.de"]}
    assert _resolve_host_with_fallback(f, None) == "a.de"
    # 3. title_vars
    f = {"title_vars": {"host": "x.de"}}
    assert _resolve_host_with_fallback(f, None) == "x.de"
    # 4. vhost
    f = {"vhost": "v.de"}
    assert _resolve_host_with_fallback(f, None) == "v.de"
    # 5. ip
    f = {"ip": "1.2.3.4"}
    assert _resolve_host_with_fallback(f, None) == "1.2.3.4"
    # Letzte Reserve: ctx.domain
    f = {}
    assert _resolve_host_with_fallback(f, {"domain": "fb.de"}) == "fb.de"
    # Nichts → None
    f = {}
    assert _resolve_host_with_fallback(f, None) is None


# ---------------------------------------------------------------------------
# P0-05: Service-spezifische Banner-Templates
# ---------------------------------------------------------------------------

def test_p0_05_ssh_vs_http_banner_unique_titles():
    findings = [
        {"id": "VS-002", "policy_id": "SP-INFO-001",
         "finding_type": "info_disclosure_banner",
         "title_vars": {"host": "trunk.de", "service": "ssh"},
         "title": "Server-Banner mit Versions-Info auf {host}"},
        {"id": "VS-011", "policy_id": "SP-INFO-001",
         "finding_type": "info_disclosure_banner",
         "title_vars": {"host": "trunk.de", "service": "http"},
         "title": "Server-Banner mit Versions-Info auf {host}"},
    ]
    apply_titles(findings, scan_context={"domain": "trunk.de"})
    titles = {f["title"] for f in findings}
    assert len(titles) == 2  # SSH und HTTP unterschiedlich
    # Konkrete Inhalte
    assert any("SSH-Banner" in t for t in titles)
    assert any("HTTP-Header" in t for t in titles)


def test_service_banner_templates_present():
    """Sanity: alle 5 SERVICE_BANNER_TEMPLATES vorhanden."""
    for key in ("info_disclosure_banner_ssh", "info_disclosure_banner_http",
                "info_disclosure_banner_smtp", "info_disclosure_banner_ftp",
                "info_disclosure_banner_generic"):
        assert key in SERVICE_BANNER_TEMPLATES
        assert "{host}" in SERVICE_BANNER_TEMPLATES[key]


def test_smtp_ftp_banner_templates_render():
    f1 = {
        "id": "VS-SMTP",
        "finding_type": "info_disclosure_banner",
        "title_vars": {"host": "mx.de", "service": "smtp"},
        "title": "ignored",
    }
    f2 = {
        "id": "VS-FTP",
        "finding_type": "info_disclosure_banner",
        "title_vars": {"host": "ftp.de", "service": "ftp"},
        "title": "ignored",
    }
    apply_titles([f1, f2], scan_context=None)
    assert "SMTP-Banner" in f1["title"]
    assert "mx.de" in f1["title"]
    assert "FTP-Banner" in f2["title"]
    assert "ftp.de" in f2["title"]


def test_banner_generic_fallback_when_service_unknown():
    f = {
        "id": "VS-G",
        "finding_type": "info_disclosure_banner",
        "title_vars": {"host": "x.de"},  # service nicht gesetzt
        "title": "ignored",
    }
    apply_titles([f], scan_context=None)
    assert "Service-Banner" in f["title"]
    assert "x.de" in f["title"]


# ---------------------------------------------------------------------------
# P0-03: SPF vs DKIM Disambiguation via Template
# ---------------------------------------------------------------------------

def test_p0_03_spf_vs_dkim_disambiguation_via_template():
    f = {
        "id": "VS-009",
        "finding_type": "mail_security_missing_dkim",
        "title_vars": {"domain": "trunk.de"},
        "title": "{template-will-be-applied}",  # ignoriert, template gewinnt
    }
    apply_titles([f], scan_context={"domain": "trunk.de"})
    assert "DKIM" in f["title"]
    assert "SPF" not in f["title"]


def test_p0_03_mail_security_all_variants():
    """Alle 4 mail_security_*-Discriminators erzeugen disjunkte Titles."""
    base = {"title_vars": {"domain": "x.de"}, "title": "X"}
    findings = [
        {**base, "id": "F1", "finding_type": "mail_security_missing_spf"},
        {**base, "id": "F2", "finding_type": "mail_security_missing_dkim"},
        {**base, "id": "F3", "finding_type": "mail_security_missing_dmarc"},
        {**base, "id": "F4", "finding_type": "mail_security_dmarc_none"},
    ]
    apply_titles(findings, scan_context={"domain": "x.de"})
    titles = [f["title"] for f in findings]
    assert len(set(titles)) == 4
    assert "SPF" in titles[0] and "DKIM" not in titles[0]
    assert "DKIM" in titles[1]
    assert "DMARC" in titles[2]
    assert "p=none" in titles[3]


def test_mail_security_templates_present():
    for key in ("mail_security_missing_spf", "mail_security_missing_dkim",
                "mail_security_missing_dmarc", "mail_security_dmarc_none"):
        assert key in MAIL_SECURITY_TEMPLATES


# ---------------------------------------------------------------------------
# P0-04: Bareword-Number-Linter
# ---------------------------------------------------------------------------

def test_p0_04_no_naked_numbers_in_title():
    # "WordPress-Plugin 27" wird nicht akzeptiert
    f = {
        "id": "VS-003",
        "finding_type": "outdated_software",
        "title": "WordPress-Plugin 27 mit Schwachstelle auf {host}",
        "affected": "trunk.de",
    }
    apply_titles([f], scan_context={"domain": "trunk.de"})
    # Title wurde gerendert, aber Token-Linter hat die nackte 27 markiert.
    assert f.get("_title_degraded") is True
    assert "27" in f.get("_title_suspicious_tokens", [])


def test_validate_title_tokens_unit():
    # Sauber: Standard-Port
    ok, _ = _validate_title_tokens("RDP-Dienst (Port 3389) auf x.de")
    assert ok
    # Sauber: Version mit Punkt
    ok, _ = _validate_title_tokens("nginx 1.18.0 auf x.de")
    assert ok
    # Sauber: Zahl + Einheit
    ok, _ = _validate_title_tokens("27 Plugins ohne Update")
    assert ok
    ok, _ = _validate_title_tokens("Zertifikat laeuft in 30 Tagen ab")
    assert ok
    # Schmutzig: bareword
    ok, suspicious = _validate_title_tokens("WordPress-Plugin 27 mit Bug")
    assert not ok
    assert "27" in suspicious


def test_validate_title_tokens_known_port_whitelist():
    for port in ("22", "80", "443", "3389", "5432", "8443"):
        ok, _ = _validate_title_tokens(f"Dienst auf Port {port}")
        assert ok, f"port {port} sollte als Standard-Port durchgehen"


# ---------------------------------------------------------------------------
# Allgemeine Regressionen: bestehender Code muss noch funktionieren
# ---------------------------------------------------------------------------

def test_regression_dmarc_template_still_works():
    """Bisheriger Smoke-Test aus test_title_policy.py."""
    f = {"policy_id": "SP-DNS-010", "title": "KI variant 1",
         "title_vars": {"domain": "heuel.com"}}
    out = apply_title_template(f)
    assert "heuel.com" in out
    assert "quarantine" in out


def test_regression_service_template_not_triggered_for_normal_finding():
    """HSTS-Finding darf nicht ausversehen in SERVICE_BANNER_TEMPLATES landen."""
    f = {"policy_id": "SP-HDR-001", "title": "X",
         "title_vars": {"host": "a.com"}}
    out = apply_title_template(f)
    assert out == "HSTS-Header fehlt auf a.com"
