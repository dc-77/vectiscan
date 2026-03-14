"""Tests for scanner.packages — package configuration validation."""

import pytest
from scanner.packages import get_config, PACKAGE_CONFIG


class TestGetConfig:
    def test_basic_phase2_tools_excludes_nikto(self):
        config = get_config("basic")
        assert "nikto" not in config["phase2_tools"]

    def test_basic_phase2_tools_excludes_nuclei(self):
        config = get_config("basic")
        assert "nuclei" not in config["phase2_tools"]

    def test_basic_phase2_tools_excludes_gobuster_dir(self):
        config = get_config("basic")
        assert "gobuster_dir" not in config["phase2_tools"]

    def test_basic_max_hosts(self):
        config = get_config("basic")
        assert config["max_hosts"] == 5

    def test_basic_nmap_ports(self):
        config = get_config("basic")
        assert config["nmap_ports"] == "--top-ports 100"

    def test_basic_phase0_tools_limited(self):
        config = get_config("basic")
        assert config["phase0_tools"] == ["crtsh", "subfinder", "dnsx"]

    def test_basic_total_timeout(self):
        config = get_config("basic")
        assert config["total_timeout"] == 600

    def test_professional_phase2_has_all_tools(self):
        config = get_config("professional")
        expected = ["testssl", "nikto", "nuclei", "gobuster_dir", "gowitness", "headers"]
        for tool in expected:
            assert tool in config["phase2_tools"]
        assert len(config["phase2_tools"]) == 6

    def test_professional_max_hosts(self):
        config = get_config("professional")
        assert config["max_hosts"] == 10

    def test_professional_nmap_ports(self):
        config = get_config("professional")
        assert config["nmap_ports"] == "--top-ports 1000"

    def test_professional_phase0_all_tools(self):
        config = get_config("professional")
        assert len(config["phase0_tools"]) == 6

    def test_nis2_identical_to_professional(self):
        pro = get_config("professional")
        nis2 = get_config("nis2")
        assert pro["phase0_tools"] == nis2["phase0_tools"]
        assert pro["phase1_tools"] == nis2["phase1_tools"]
        assert pro["phase2_tools"] == nis2["phase2_tools"]
        assert pro["max_hosts"] == nis2["max_hosts"]
        assert pro["nmap_ports"] == nis2["nmap_ports"]
        assert pro["total_timeout"] == nis2["total_timeout"]

    def test_invalid_package_raises_value_error(self):
        with pytest.raises(ValueError, match="Unknown package"):
            get_config("invalid")

    def test_invalid_package_error_message(self):
        with pytest.raises(ValueError, match="Must be basic, professional, or nis2"):
            get_config("enterprise")
