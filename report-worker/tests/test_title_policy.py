"""Tests fuer reporter.title_policy (A1 — deterministische Title-Templates)."""

import pytest

from reporter.title_policy import (
    TITLE_TEMPLATES,
    apply_title_template,
    apply_titles,
)


def test_dmarc_quarantine_template():
    f = {"policy_id": "SP-DNS-010", "title": "KI variant 1",
         "title_vars": {"domain": "heuel.com"}}
    assert apply_title_template(f) == "DMARC-Policy auf 'quarantine' statt 'reject' fuer heuel.com"


def test_dmarc_quarantine_deterministic_across_variations():
    """Der Bug-Trigger: 3 Wording-Variationen → 1 Title nach Template."""
    titles = []
    for orig in ["DMARC-Policy auf 'quarantine' statt 'reject'",
                 "DMARC-Policy auf Quarantine statt Reject",
                 "dmarc-policy quarantine statt reject"]:
        f = {"policy_id": "SP-DNS-010", "title": orig,
             "title_vars": {"domain": "heuel.com"}}
        titles.append(apply_title_template(f))
    assert len(set(titles)) == 1


def test_missing_template_keeps_original_and_flags():
    f = {"policy_id": "SP-XXX-999", "title": "Original Title"}
    assert apply_title_template(f) == "Original Title"
    assert f.get("_title_template_missing") is True


def test_missing_var_safe_fallback():
    """Fehlende Vars werden zu '?' (kein KeyError)."""
    f = {"policy_id": "SP-CVE-001"}  # vars host/cve_id/tech fehlen
    out = apply_title_template(f)
    assert "?" in out  # alle Vars zu ? gefuellt
    assert "mit aktiven Exploits" in out  # Template-Struktur erhalten


def test_no_policy_id_returns_original():
    f = {"title": "X", "policy_id": ""}
    assert apply_title_template(f) == "X"


def test_apply_titles_batch_count():
    findings = [
        {"policy_id": "SP-HDR-001", "title": "X", "title_vars": {"host": "a.com"}},
        {"policy_id": "SP-DNS-010", "title": "Y", "title_vars": {"domain": "b.com"}},
        {"policy_id": None, "title": "stays"},
        {"policy_id": "SP-XXX-999", "title": "fallback"},  # template missing
    ]
    n = apply_titles(findings)
    assert n == 2
    assert findings[0]["title"] == "HSTS-Header fehlt auf a.com"
    assert findings[1]["title"] == "DMARC-Policy auf 'quarantine' statt 'reject' fuer b.com"
    assert findings[2]["title"] == "stays"
    assert findings[3]["title"] == "fallback"  # missing -> unchanged
    assert findings[3].get("_title_template_missing") is True


def test_scan_context_provides_domain():
    f = {"policy_id": "SP-DNS-006", "title": "X"}
    out = apply_title_template(f, scan_context={"domain": "demo.de"})
    assert "demo.de" in out


def test_host_fallback_from_finding_fields():
    """Wenn host nicht in title_vars: aus vhost/fqdn/host_ip ableiten."""
    f = {"policy_id": "SP-HDR-001", "title": "X", "vhost": "ose.heuel.com"}
    out = apply_title_template(f)
    assert "ose.heuel.com" in out


def test_template_count_minimum():
    """Sanity: mindestens die ~25 wichtigsten policy_ids haben Templates."""
    assert len(TITLE_TEMPLATES) >= 25


def test_titles_aligned_with_severity_policy():
    """Regression Mai 2026: title_policy Templates waren in mehreren Familien
    versetzt zu severity_policy.finding_type-Zuordnung — DKIM-Findings bekamen
    MTA-STS-Title, phpinfo bekam ".git-Verzeichnis"-Title etc.
    Lockt 1:1-Alignment fuer ALLE Policy-Familien (nicht nur SP-DNS) ein.
    """
    from reporter.severity_policy import SEVERITY_POLICIES

    # Erwartete Korrespondenz (severity_policy.finding_type -> Substring im Title)
    expected = {
        # SP-DNS-* Mail/DNS
        "spf_missing":              "SPF-Record fehlt",
        "spf_softfail":             "SPF-Policy auf softfail",
        "dmarc_missing":            "DMARC-Record fehlt",
        "dmarc_p_none":             "DMARC-Policy auf 'none'",
        "dmarc_p_quarantine":       "DMARC-Policy auf 'quarantine'",
        "dkim_missing":             "DKIM-Record fehlt",
        "mta_sts_missing":          "MTA-STS-Policy fehlt",
        "dnssec_missing":           "DNSSEC fehlt",
        "dnssec_chain_broken":      "DNSSEC-Kette unterbrochen",
        "caa_missing":              "CAA-Record fehlt",
        # SP-DISC-* Information Disclosure
        "server_banner_with_version":   "Server-Banner mit Versions-Info",
        "server_banner_no_version":     "Server-Banner ohne Versions-Info",
        "nginx_status_endpoint_open":   "Nginx-Status-Endpoint",
        "phpinfo_exposed":              "phpinfo()-Endpoint",
        "directory_listing_enabled":    "Directory-Listing aktiv",
        "error_message_with_stack":     "Stacktrace",
        "git_directory_exposed":        ".git-Verzeichnis",
        "env_file_exposed":             ".env-Datei",
        "private_ip_disclosure":        "Private IP-Adresse",
        # SP-CSP-* Content-Security-Policy
        "csp_unsafe_inline":            "'unsafe-inline'",
        "csp_unsafe_eval":              "'unsafe-eval'",
        "csp_wildcard_source":          "Wildcard-Quelle",
        # SP-COOK-* Cookies
        "cookie_no_secure":             "ohne Secure-Flag",
        "cookie_no_httponly":           "ohne HttpOnly-Flag",
        "cookie_no_samesite":           "ohne SameSite-Attribut",
        # SP-WP-* WordPress
        "wordpress_user_enumeration":   "WordPress-User-Enumeration",
        # SP-ENUM-*
        "user_enumeration":             "User-Enumeration",
        # SP-DB-*
        "database_port_exposed":        "Datenbank-Port",
        # SP-CORS-*
        "cors_misconfiguration":        "CORS",
        # SP-JS-*
        "js_library_vulnerable":        "JavaScript",
        # SP-SRI-*
        "sri_missing":                  "Subresource-Integrity",
        # SP-SSH-*
        "ssh_no_brute_force_protection": "Brute-Force-Schutz",
        # SP-URLHAUS-*
        "urlhaus_compromise_detected":   "URLhaus",
    }
    by_finding_type: dict[str, list[str]] = {}
    for p in SEVERITY_POLICIES:
        if p.finding_type:
            by_finding_type.setdefault(p.finding_type, []).append(p.policy_id)

    for ft, expected_substr in expected.items():
        pids = by_finding_type.get(ft) or []
        assert pids, f"Severity-Policy hat keine Regel fuer finding_type={ft!r}"
        # Mindestens EINE der policy_ids fuer diesen finding_type muss ein
        # Title-Template haben das den expected_substr enthaelt. (Manche
        # finding_types haben mehrere policy_ids mit unterschiedlichen Schweren
        # — z.B. csp_missing fuer SP-CSP-001 und SP-CSP-002, aber nur eine
        # davon erscheint hier mit dem direkten substring.)
        templates = [TITLE_TEMPLATES.get(p, "") for p in pids]
        if not any(expected_substr in t for t in templates):
            pytest.fail(
                f"finding_type={ft!r} (policy_ids={pids}) hat kein Template "
                f"das '{expected_substr}' enthaelt. Templates: {templates} — "
                "title_policy.py drift?"
            )
