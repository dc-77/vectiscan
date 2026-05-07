"""Tests fuer C1+C2+C3 — EOL-Detector + CVE-Whitelist + Pipeline-Hook."""

from datetime import date

from reporter.eol_detector import (
    detect_eol_findings, merge_into_claude_findings,
    _normalize_vendor_product, _version_starts_with,
    _version_in_range,
    EOL_DATA, KNOWN_VULN_BUILDS,
)


def test_normalize_iis():
    assert _normalize_vendor_product("Microsoft-IIS/10.0") == ("microsoft", "iis", "10.0")


def test_normalize_apache():
    assert _normalize_vendor_product("Apache/2.4.49") == ("apache", "httpd", "2.4.49")


def test_normalize_nginx():
    assert _normalize_vendor_product("nginx/1.22.1") == ("nginx", "", "1.22.1")


def test_normalize_php():
    assert _normalize_vendor_product("PHP/7.4.20") == ("php", "", "7.4.20")


def test_normalize_exchange_build():
    assert _normalize_vendor_product("Microsoft Exchange/15.1.2507") == \
        ("microsoft", "exchange", "15.1.2507")


def test_version_starts_with():
    assert _version_starts_with("15.1.2507", "15.1") is True
    assert _version_starts_with("15.0.1497", "15.1") is False
    assert _version_starts_with("1.22.1", "1.20") is False
    assert _version_starts_with("1.20.5", "1.20") is True


def test_exchange_2016_detected():
    profiles = [{
        "ip": "85.22.47.43", "fqdns": ["owa.securess.de"],
        "cms": "Microsoft Exchange", "cms_version": "15.1.2507",
    }]
    findings = detect_eol_findings(profiles, date(2026, 5, 5))
    exchange = [f for f in findings if "Exchange" in f["title"]]
    assert len(exchange) >= 1
    assert exchange[0]["severity"] == "HIGH"
    assert exchange[0]["policy_id"] == "SP-EOL-001"
    assert exchange[0]["finding_type"] == "software_eol"
    assert exchange[0]["_deterministic_source"] == "eol_detector"


def test_apache_2_4_49_critical_cve():
    """Apache 2.4.49 → ProxyShell-aehnlicher Path-Traversal CVE."""
    profiles = [{
        "ip": "1.1.1.1", "fqdns": ["x.com"],
        "server": "Apache/2.4.49",
    }]
    findings = detect_eol_findings(profiles, date(2026, 5, 5))
    cve_findings = [f for f in findings
                     if f.get("_deterministic_source") == "cve_whitelist"]
    assert len(cve_findings) >= 1
    assert cve_findings[0]["severity"] == "CRITICAL"
    assert cve_findings[0]["cve"] == "CVE-2021-41773"


def test_current_versions_no_findings():
    """Future-Versions (jenseits von EOL_DATA-Eintraegen) erzeugen keine
    Findings. Wir nehmen klar future-Versions damit der Test stabil bleibt
    auch wenn endoflife.date neue EOL-Daten meldet."""
    profiles = [{
        "ip": "1.2.3.4", "fqdns": ["x.com"],
        "server": "nginx/9.99.0",  # nicht in EOL_DATA
    }]
    findings = detect_eol_findings(profiles, date(2026, 5, 5))
    assert findings == []


def test_php_7_4_eol():
    profiles = [{
        "ip": "1.1.1.1", "fqdns": ["x.com"],
        "technologies": [{"name": "PHP", "version": "7.4.21"}],
    }]
    findings = detect_eol_findings(profiles, date(2026, 5, 5))
    php_findings = [f for f in findings if "Php" in f["title"] or "PHP" in f["title"]]
    assert len(php_findings) >= 1


def test_merge_dedup_existing_finding():
    """Wenn KI denselben EOL-Befund schon hat (host_ip, finding_type, version
    matchen), wird dedupliziert — Claude wins fuer Beschreibung, aber
    _deterministic_source-Marker wird gesetzt."""
    claude = [{
        "id": "VS-001", "host_ip": "85.22.47.43",
        "finding_type": "software_eol", "title": "Exchange 2016 EOL",
        "description": "Detaillierte KI-Beschreibung",
        "title_vars": {"version": "15.1.2507"},
    }]
    eol = [{
        "host_ip": "85.22.47.43", "finding_type": "software_eol",
        "title_vars": {"version": "15.1.2507"},
        "_deterministic_source": "eol_detector",
    }]
    merged = merge_into_claude_findings(claude, eol)
    assert len(merged) == 1  # nicht verdoppelt
    assert merged[0]["_deterministic_source"] == "eol_detector"
    assert merged[0]["description"] == "Detaillierte KI-Beschreibung"  # Claude wins


def test_merge_adds_when_kid_missed():
    """KI hat den EOL-Befund NICHT → eol_detector fuegt ihn hinzu."""
    claude = [{"id": "VS-001", "host_ip": "1.1.1.1",
               "finding_type": "spf_missing", "title": "SPF fehlt"}]
    eol = [{"host_ip": "85.22.47.43", "finding_type": "software_eol",
            "title": "Exchange EOL", "title_vars": {"version": "15.1"}}]
    merged = merge_into_claude_findings(claude, eol)
    assert len(merged) == 2


def test_eol_data_has_critical_entries():
    """Sanity: wichtige EOL-Eintraege existieren."""
    assert ("microsoft", "exchange", "15.1") in EOL_DATA  # Exchange 2016
    assert ("openssl", "", "1.0") in EOL_DATA
    assert ("php", "", "7.4") in EOL_DATA


def test_known_vuln_builds_has_proxyshell_and_heartbleed():
    assert ("openssl", "", "1.0.1") in KNOWN_VULN_BUILDS
    assert ("apache", "httpd", "2.4.49") in KNOWN_VULN_BUILDS


# --- F-RPT-007: Host-Resolution + Version-Recovery ---

def _claude_finding(**kw):
    base = {
        "id": "claude-1",
        "title": "Apache 2.2 ist End-of-Life auf example.com",
        "finding_type": "software_eol",
        "host": "example.com",
        # KEIN host_ip
    }
    base.update(kw)
    return base


def _eol_finding(**kw):
    base = {
        "id": "eol-1",
        "title": "Apache 2.2 ist End-of-Life seit 999 Tagen auf example.com",
        "finding_type": "software_eol",
        "host_ip": "1.2.3.4",
        "fqdn": "example.com",
        "vhost": "example.com",
        "title_vars": {"tech": "apache", "version": "2.2"},
        "_deterministic_source": "eol_detector",
    }
    base.update(kw)
    return base


def test_merge_dedup_with_fqdn_only_claude_finding():
    """F-RPT-007: Claude-Finding ohne host_ip + EOL-Finding mit ip+fqdn -> 1 merged."""
    claude = _claude_finding(title_vars={"tech": "apache", "version": "2.2"})
    eol = _eol_finding()
    tech_profiles = [{"ip": "1.2.3.4", "fqdns": ["example.com"]}]
    merged = merge_into_claude_findings([claude], [eol], tech_profiles=tech_profiles)
    assert len(merged) == 1, "Doppel-Finding entstanden"
    assert merged[0]["id"] == "claude-1"
    assert merged[0]["_deterministic_source"] == "eol_detector"


def test_merge_recovers_version_from_title():
    """F-RPT-007: Claude-Finding ohne title_vars aber Version im Title."""
    claude = _claude_finding(
        title="Apache 2.2 ist End-of-Life auf example.com",
        # KEIN title_vars
    )
    eol = _eol_finding()
    tech_profiles = [{"ip": "1.2.3.4", "fqdns": ["example.com"]}]
    merged = merge_into_claude_findings([claude], [eol], tech_profiles=tech_profiles)
    assert len(merged) == 1


def test_merge_no_tech_profiles_falls_back():
    """F-RPT-007: tech_profiles=None -> bisheriges Verhalten (kein Crash)."""
    claude = _claude_finding(
        title_vars={"tech": "apache", "version": "2.2"},
        host_ip="1.2.3.4",  # mit host_ip damit alter Pfad matched
    )
    eol = _eol_finding()
    merged = merge_into_claude_findings([claude], [eol])  # kein tech_profiles
    assert len(merged) == 1, "ohne Cross-Mapping muessten beide host_ip=1.2.3.4 haben"


def test_merge_different_versions_stay_separate():
    """F-RPT-007: Apache 2.2 vs Apache 2.4 sollten NICHT mergen."""
    claude = _claude_finding(
        title_vars={"tech": "apache", "version": "2.2"},
    )
    eol = _eol_finding(
        title="Apache 2.4 ist End-of-Life",
        title_vars={"tech": "apache", "version": "2.4"},
    )
    tech_profiles = [{"ip": "1.2.3.4", "fqdns": ["example.com"]}]
    merged = merge_into_claude_findings([claude], [eol], tech_profiles=tech_profiles)
    assert len(merged) == 2


# --- F-RPT-001: Range-Matcher ---

def test_version_in_range_le_operator():
    """`<=2.4.55` matcht 2.4.55, 2.4.40, NICHT 2.4.56."""
    assert _version_in_range("2.4.55", "<=2.4.55") is True
    assert _version_in_range("2.4.40", "<=2.4.55") is True
    assert _version_in_range("2.4.56", "<=2.4.55") is False
    # Unterschiedliche Tuple-Laengen (Padding)
    assert _version_in_range("2.4", "<=2.4.55") is True


def test_version_in_range_lt_operator():
    """`<2.4.60` matcht 2.4.59, NICHT 2.4.60."""
    assert _version_in_range("2.4.59", "<2.4.60") is True
    assert _version_in_range("2.4.60", "<2.4.60") is False
    assert _version_in_range("2.4.61", "<2.4.60") is False


def test_version_in_range_ge_operator():
    """`>=1.23.0` matcht 1.23.0, 1.24.5, NICHT 1.22.99."""
    assert _version_in_range("1.23.0", ">=1.23.0") is True
    assert _version_in_range("1.24.5", ">=1.23.0") is True
    assert _version_in_range("1.22.99", ">=1.23.0") is False


def test_version_in_range_backwards_compat_prefix():
    """Specs ohne Operator → Prefix-Match wie heute."""
    # Backwards-Compat: "2.4.49" muss wie _version_starts_with funktionieren
    assert _version_in_range("2.4.49", "2.4.49") is True
    assert _version_in_range("2.4.49.1", "2.4.49") is True
    assert _version_in_range("2.4.50", "2.4.49") is False
    # Empty spec → False (kein Match besser als falscher Match)
    assert _version_in_range("2.4.49", "") is False


def test_known_vuln_builds_has_2024_entries():
    """Sanity: F-RPT-001 Initial-Liste enthaelt 2024-Mega-Schwachstellen."""
    # CitrixBleed
    assert ("citrix", "netscaler", "13.1-49") in KNOWN_VULN_BUILDS
    # Ivanti Connect Secure
    assert ("ivanti", "connect-secure", "22.6") in KNOWN_VULN_BUILDS
    # MOVEit
    assert ("progress", "moveit", "2023.0.6") in KNOWN_VULN_BUILDS
    # ScreenConnect
    assert ("connectwise", "screenconnect", "23.9.7") in KNOWN_VULN_BUILDS
