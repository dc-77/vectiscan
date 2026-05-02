"""Tests for scanner.packages — package configuration validation (v2: 5 packages)."""

import pytest
from scanner.packages import get_config, PACKAGE_CONFIG, resolve_package


class TestWebcheck:
    def test_phase2_tools_excludes_nikto(self):
        config = get_config("webcheck")
        assert "nikto" not in config["phase2_tools"]

    def test_phase2_has_zap_spider(self):
        config = get_config("webcheck")
        assert "zap_spider" in config["phase2_tools"]

    def test_phase2_has_zap_passive(self):
        config = get_config("webcheck")
        assert "zap_passive" in config["phase2_tools"]

    def test_phase2_excludes_zap_active(self):
        """WebCheck is passive-only — no active scan."""
        config = get_config("webcheck")
        assert "zap_active" not in config["phase2_tools"]

    def test_phase2_excludes_legacy_tools(self):
        config = get_config("webcheck")
        for tool in ("gobuster_dir", "katana", "feroxbuster", "ffuf", "nuclei", "dalfox"):
            assert tool not in config["phase2_tools"]

    def test_max_hosts(self):
        config = get_config("webcheck")
        assert config["max_hosts"] == 3

    def test_nmap_ports(self):
        config = get_config("webcheck")
        assert config["nmap_ports"] == "--top-ports 100"

    def test_phase0b_tools_limited(self):
        config = get_config("webcheck")
        assert "amass" not in config["phase0b_tools"]
        assert "gobuster_dns" not in config["phase0b_tools"]

    def test_phase0a_only_whois(self):
        config = get_config("webcheck")
        assert config["phase0a_tools"] == ["whois"]

    def test_total_timeout(self):
        config = get_config("webcheck")
        assert config["total_timeout"] == 1200  # 20 minutes

class TestPerimeter:
    def test_phase2_has_all_tools(self):
        config = get_config("perimeter")
        expected = ["zap_spider", "zap_active",
                    "ffuf", "feroxbuster", "headers", "httpx", "wpscan"]
        for tool in expected:
            assert tool in config["phase2_tools"]

    def test_phase2_excludes_disabled_tools(self):
        """nuclei, dalfox, nikto, gobuster_dir, katana removed."""
        config = get_config("perimeter")
        for tool in ("nuclei", "dalfox", "nikto", "gobuster_dir", "katana"):
            assert tool not in config["phase2_tools"]

    def test_max_hosts(self):
        config = get_config("perimeter")
        assert config["max_hosts"] == 15

    def test_nmap_ports(self):
        config = get_config("perimeter")
        assert config["nmap_ports"] == "--top-ports 1000"

    def test_phase0a_all_apis(self):
        config = get_config("perimeter")
        assert "shodan" in config["phase0a_tools"]
        assert "abuseipdb" in config["phase0a_tools"]
        assert "securitytrails" in config["phase0a_tools"]
        assert "whois" in config["phase0a_tools"]

    def test_phase0b_full_dns(self):
        config = get_config("perimeter")
        # amass v5 entfernt (2026-05-03) — siehe Kommentar in packages.py.
        # subfinder mit -all uebernimmt die Source-Coverage; certspotter +
        # securitytrails ergaenzen als CT-Quellen.
        assert "subfinder" in config["phase0b_tools"]
        assert "crtsh" in config["phase0b_tools"]
        assert "gobuster_dns" in config["phase0b_tools"]
        assert "dane_tlsa" in config["phase0b_tools"]

    def test_phase3_enrichment(self):
        config = get_config("perimeter")
        assert "nvd" in config["phase3_tools"]
        assert "epss" in config["phase3_tools"]
        assert "cisa_kev" in config["phase3_tools"]
        assert "exploitdb" in config["phase3_tools"]

class TestComplianceSupplychainInsurance:
    """Compliance, SupplyChain and Insurance share the perimeter scan config."""

    def test_compliance_identical_to_perimeter(self):
        peri = get_config("perimeter")
        comp = get_config("compliance")
        for key in ("phase0a_tools", "phase0b_tools", "phase1_tools",
                     "phase2_tools", "phase3_tools", "max_hosts",
                     "nmap_ports", "total_timeout"):
            assert peri[key] == comp[key], f"Mismatch on {key}"

    def test_supplychain_identical_to_perimeter(self):
        peri = get_config("perimeter")
        sc = get_config("supplychain")
        assert peri["phase2_tools"] == sc["phase2_tools"]
        assert peri["max_hosts"] == sc["max_hosts"]

    def test_insurance_identical_to_perimeter(self):
        peri = get_config("perimeter")
        ins = get_config("insurance")
        assert peri["phase2_tools"] == ins["phase2_tools"]
        assert peri["max_hosts"] == ins["max_hosts"]


class TestLegacyAliases:
    """v1 package names still resolve via backwards-compat aliases."""

    def test_basic_resolves_to_webcheck(self):
        config = get_config("basic")
        assert config["max_hosts"] == 3

    def test_professional_resolves_to_perimeter(self):
        config = get_config("professional")
        assert config["max_hosts"] == 15

    def test_nis2_resolves_to_compliance(self):
        config = get_config("nis2")
        assert config["max_hosts"] == 15

    def test_resolve_package_basic(self):
        assert resolve_package("basic") == "webcheck"

    def test_resolve_package_professional(self):
        assert resolve_package("professional") == "perimeter"

    def test_resolve_package_nis2(self):
        assert resolve_package("nis2") == "compliance"

    def test_resolve_package_passthrough(self):
        assert resolve_package("perimeter") == "perimeter"


class TestInvalidPackage:
    def test_raises_value_error(self):
        with pytest.raises(ValueError, match="Unknown package"):
            get_config("invalid")

    def test_error_message_lists_valid_packages(self):
        with pytest.raises(ValueError, match="webcheck"):
            get_config("enterprise")
