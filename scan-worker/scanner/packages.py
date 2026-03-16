"""Package configuration — defines tool sets and limits per scan package."""

from typing import Any

PACKAGE_CONFIG: dict[str, dict[str, Any]] = {
    "basic": {
        "phase0_tools": ["crtsh", "subfinder", "dnsx"],
        "phase0_timeout": 300,        # 5 Minuten
        "max_hosts": 5,
        "nmap_ports": "--top-ports 100",
        "phase1_tools": ["nmap", "webtech", "wafw00f"],
        "phase2_tools": ["testssl", "headers", "gowitness", "httpx", "wpscan"],
        "total_timeout": 900,         # 15 Minuten
    },
    "professional": {
        "phase0_tools": ["crtsh", "subfinder", "amass", "gobuster_dns", "axfr", "dnsx"],
        "phase0_timeout": 600,        # 10 Minuten
        "max_hosts": 10,
        "nmap_ports": "--top-ports 1000",
        "phase1_tools": ["nmap", "webtech", "wafw00f"],
        "phase2_tools": ["testssl", "nikto", "nuclei", "gobuster_dir", "gowitness", "headers", "httpx", "katana", "wpscan"],
        "total_timeout": 7200,        # 120 Minuten
    },
    "nis2": {
        "phase0_tools": ["crtsh", "subfinder", "amass", "gobuster_dns", "axfr", "dnsx"],
        "phase0_timeout": 600,
        "max_hosts": 10,
        "nmap_ports": "--top-ports 1000",
        "phase1_tools": ["nmap", "webtech", "wafw00f"],
        "phase2_tools": ["testssl", "nikto", "nuclei", "gobuster_dir", "gowitness", "headers", "httpx", "katana", "wpscan"],
        "total_timeout": 7200,
    },
}


def get_config(package: str) -> dict[str, Any]:
    """Return the configuration for a scan package.

    Args:
        package: One of 'basic', 'professional', 'nis2'.

    Returns:
        Configuration dict with tool lists, timeouts, and limits.

    Raises:
        ValueError: If package name is not recognized.
    """
    if package not in PACKAGE_CONFIG:
        raise ValueError(
            f"Unknown package: {package}. Must be basic, professional, or nis2."
        )
    return PACKAGE_CONFIG[package]
