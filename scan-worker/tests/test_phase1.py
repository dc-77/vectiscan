"""Tests for Phase 1 — Technology detection per host."""

import json
from pathlib import Path
from typing import Any, Optional

import pytest


def test_build_tech_profile_basic_structure(tmp_path: Path) -> None:
    """build_tech_profile returns a dict with all expected keys."""
    from scanner.phase1 import build_tech_profile

    host_dir = str(tmp_path)

    nmap_result: dict[str, Any] = {
        "open_ports": [80, 443],
        "services": [
            {"port": 80, "protocol": "tcp", "name": "http", "product": "nginx", "version": "1.24.0"},
            {"port": 443, "protocol": "tcp", "name": "https", "product": "nginx", "version": "1.24.0"},
        ],
    }
    webtech_result: dict[str, Any] = {"tech": [{"name": "PHP", "version": "8.2"}]}
    wafw00f_result: Optional[dict[str, Any]] = {"firewall": "Cloudflare"}

    profile = build_tech_profile(
        ip="1.2.3.4",
        fqdns=["example.com", "www.example.com"],
        nmap_result=nmap_result,
        webtech_result=webtech_result,
        wafw00f_result=wafw00f_result,
        host_dir=host_dir,
    )

    assert profile["ip"] == "1.2.3.4"
    assert profile["fqdns"] == ["example.com", "www.example.com"]
    assert profile["server"] == "nginx/1.24.0"
    assert profile["waf"] == "Cloudflare"
    assert profile["open_ports"] == [80, 443]


def test_has_ssl_from_port_443(tmp_path: Path) -> None:
    """has_ssl is True when port 443 is in open_ports."""
    from scanner.phase1 import build_tech_profile

    profile = build_tech_profile(
        ip="1.2.3.4",
        fqdns=["example.com"],
        nmap_result={"open_ports": [80, 443], "services": []},
        webtech_result={},
        wafw00f_result=None,
        host_dir=str(tmp_path),
    )

    assert profile["has_ssl"] is True


def test_has_ssl_false_when_no_443(tmp_path: Path) -> None:
    """has_ssl is False when port 443 is absent and no ssl service found."""
    from scanner.phase1 import build_tech_profile

    profile = build_tech_profile(
        ip="1.2.3.4",
        fqdns=["example.com"],
        nmap_result={"open_ports": [80], "services": [{"port": 80, "name": "http"}]},
        webtech_result={},
        wafw00f_result=None,
        host_dir=str(tmp_path),
    )

    assert profile["has_ssl"] is False


def test_has_ssl_from_service_name(tmp_path: Path) -> None:
    """has_ssl is True when a service named 'ssl' or 'https' exists (even without port 443)."""
    from scanner.phase1 import build_tech_profile

    profile = build_tech_profile(
        ip="1.2.3.4",
        fqdns=["example.com"],
        nmap_result={
            "open_ports": [8443],
            "services": [{"port": 8443, "name": "https", "product": "nginx"}],
        },
        webtech_result={},
        wafw00f_result=None,
        host_dir=str(tmp_path),
    )

    assert profile["has_ssl"] is True


def test_mail_services_detected_from_mail_ports(tmp_path: Path) -> None:
    """mail_services is True when any mail port (25, 465, 587, 993, 995) is open."""
    from scanner.phase1 import build_tech_profile

    for port in [25, 465, 587, 993, 995]:
        profile = build_tech_profile(
            ip="1.2.3.4",
            fqdns=["mail.example.com"],
            nmap_result={"open_ports": [80, port], "services": []},
            webtech_result={},
            wafw00f_result=None,
            host_dir=str(tmp_path),
        )
        assert profile["mail_services"] is True, f"mail_services should be True for port {port}"


def test_mail_services_false_without_mail_ports(tmp_path: Path) -> None:
    """mail_services is False when no mail ports are open."""
    from scanner.phase1 import build_tech_profile

    profile = build_tech_profile(
        ip="1.2.3.4",
        fqdns=["example.com"],
        nmap_result={"open_ports": [80, 443], "services": []},
        webtech_result={},
        wafw00f_result=None,
        host_dir=str(tmp_path),
    )

    assert profile["mail_services"] is False


def test_ftp_service_detected_from_port_21(tmp_path: Path) -> None:
    """ftp_service is True when port 21 is in open_ports."""
    from scanner.phase1 import build_tech_profile

    profile = build_tech_profile(
        ip="1.2.3.4",
        fqdns=["ftp.example.com"],
        nmap_result={"open_ports": [21, 80], "services": []},
        webtech_result={},
        wafw00f_result=None,
        host_dir=str(tmp_path),
    )

    assert profile["ftp_service"] is True


def test_ftp_service_false_without_port_21(tmp_path: Path) -> None:
    """ftp_service is False when port 21 is absent."""
    from scanner.phase1 import build_tech_profile

    profile = build_tech_profile(
        ip="1.2.3.4",
        fqdns=["example.com"],
        nmap_result={"open_ports": [80, 443], "services": []},
        webtech_result={},
        wafw00f_result=None,
        host_dir=str(tmp_path),
    )

    assert profile["ftp_service"] is False


def test_cms_detection_from_webtech_dict(tmp_path: Path) -> None:
    """CMS is detected from webtech output when tech list contains a known CMS."""
    from scanner.phase1 import build_tech_profile

    profile = build_tech_profile(
        ip="1.2.3.4",
        fqdns=["blog.example.com"],
        nmap_result={"open_ports": [80, 443], "services": []},
        webtech_result={"tech": [{"name": "WordPress", "version": "6.4"}]},
        wafw00f_result=None,
        host_dir=str(tmp_path),
    )

    assert profile["cms"] == "WordPress"
    assert profile["cms_version"] == "6.4"


def test_cms_detection_from_webtech_list(tmp_path: Path) -> None:
    """CMS is detected when webtech_result is a list of tech dicts."""
    from scanner.phase1 import build_tech_profile

    profile = build_tech_profile(
        ip="1.2.3.4",
        fqdns=["shop.example.com"],
        nmap_result={"open_ports": [443], "services": []},
        webtech_result=[{"name": "Magento", "version": "2.4"}],
        wafw00f_result=None,
        host_dir=str(tmp_path),
    )

    assert profile["cms"] == "Magento"
    assert profile["cms_version"] == "2.4"


def test_cms_detection_from_webtech_string_list(tmp_path: Path) -> None:
    """CMS is detected when webtech tech entries are plain strings."""
    from scanner.phase1 import build_tech_profile

    profile = build_tech_profile(
        ip="1.2.3.4",
        fqdns=["example.com"],
        nmap_result={"open_ports": [443], "services": []},
        webtech_result={"tech": ["nginx", "Drupal"]},
        wafw00f_result=None,
        host_dir=str(tmp_path),
    )

    assert profile["cms"] == "Drupal"


def test_cms_none_when_no_known_cms(tmp_path: Path) -> None:
    """CMS is None when webtech output does not contain a known CMS."""
    from scanner.phase1 import build_tech_profile

    profile = build_tech_profile(
        ip="1.2.3.4",
        fqdns=["example.com"],
        nmap_result={"open_ports": [80], "services": []},
        webtech_result={"tech": [{"name": "React", "version": "18"}]},
        wafw00f_result=None,
        host_dir=str(tmp_path),
    )

    assert profile["cms"] is None
    assert profile["cms_version"] is None


def test_waf_none_when_wafw00f_result_is_none(tmp_path: Path) -> None:
    """waf is None when wafw00f_result is None (no WAF detected)."""
    from scanner.phase1 import build_tech_profile

    profile = build_tech_profile(
        ip="1.2.3.4",
        fqdns=["example.com"],
        nmap_result={"open_ports": [80], "services": []},
        webtech_result={},
        wafw00f_result=None,
        host_dir=str(tmp_path),
    )

    assert profile["waf"] is None


def test_tech_profile_saved_to_disk(tmp_path: Path) -> None:
    """build_tech_profile writes tech_profile.json to host_dir/phase1/."""
    from scanner.phase1 import build_tech_profile

    host_dir = str(tmp_path)

    build_tech_profile(
        ip="10.0.0.1",
        fqdns=["example.com"],
        nmap_result={"open_ports": [80], "services": []},
        webtech_result={},
        wafw00f_result=None,
        host_dir=host_dir,
    )

    profile_path = tmp_path / "phase1" / "tech_profile.json"
    assert profile_path.exists()
    data = json.loads(profile_path.read_text())
    assert data["ip"] == "10.0.0.1"
