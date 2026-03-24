"""Tool Diagnostics — tests all scan tools for availability and basic functionality.

Usage (inside scan-worker container):
    python3 -m scanner.diagnose

    # Or from host via docker exec:
    docker compose exec scan-worker python3 -m scanner.diagnose

    # Test a specific tool:
    docker compose exec scan-worker python3 -m scanner.diagnose --tool testssl

    # Test against a specific domain (quick probe):
    docker compose exec scan-worker python3 -m scanner.diagnose --probe example.com
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from typing import Any

# Tool definitions: (name, version_cmd, test_cmd_fn)
# version_cmd: command to check version/availability
# test_cmd_fn: optional function that returns a quick test command

TOOLS: list[dict[str, Any]] = [
    {
        "name": "nmap",
        "version_cmd": ["nmap", "--version"],
        "test_cmd": lambda domain: ["nmap", "-sn", "-T4", "--top-ports", "10", domain],
        "category": "phase1",
    },
    {
        "name": "webtech",
        "version_cmd": ["python3", "-c", "import webtech; print('webtech', webtech.__version__ if hasattr(webtech, '__version__') else 'OK')"],
        "test_cmd": lambda domain: ["webtech", "-u", f"https://{domain}", "--json"],
        "category": "phase1",
    },
    {
        "name": "wafw00f",
        "version_cmd": ["wafw00f", "--version"],
        "test_cmd": lambda domain: ["wafw00f", domain],
        "category": "phase1",
    },
    {
        "name": "testssl",
        "version_cmd": ["bash", "/opt/testssl.sh/testssl.sh", "--version"],
        "category": "phase2",
    },
    {
        "name": "gobuster",
        "version_cmd": ["gobuster", "--help"],
        "category": "phase2",
    },
    {
        "name": "ffuf",
        "version_cmd": ["ffuf", "-V"],
        "category": "phase2",
    },
    {
        "name": "feroxbuster",
        "version_cmd": ["feroxbuster", "--version"],
        "category": "phase2",
    },
    {
        "name": "httpx",
        "version_cmd": ["httpx", "-version"],
        "category": "phase2",
    },
    {
        "name": "wpscan",
        "version_cmd": ["wpscan", "--version"],
        "category": "phase2",
    },
    {
        "name": "subfinder",
        "version_cmd": ["subfinder", "-version"],
        "category": "phase0",
    },
    {
        "name": "amass",
        "version_cmd": ["amass", "-version"],
        "category": "phase0",
    },
    {
        "name": "dnsx",
        "version_cmd": ["dnsx", "-version"],
        "category": "phase0",
    },
    {
        "name": "searchsploit",
        "version_cmd": ["searchsploit", "--help"],
        "category": "phase3",
    },
    {
        "name": "whois",
        "version_cmd": ["whois", "--version"],
        "category": "phase0a",
    },
    {
        "name": "drill",
        "version_cmd": ["drill", "-v"],
        "category": "phase0a",
    },
    {
        "name": "chromium",
        "version_cmd": [os.environ.get("CHROME_PATH", "/usr/bin/chromium"), "--version"],
        "category": "dependency",
    },
]


def _run(cmd: list[str], timeout: int = 15) -> dict[str, Any]:
    """Run a command and return result dict."""
    try:
        start = time.monotonic()
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            start_new_session=True,
        )
        duration_ms = int((time.monotonic() - start) * 1000)
        output = (result.stdout + result.stderr).strip()
        # Extract version from first line
        first_line = output.split("\n")[0].strip() if output else ""
        return {
            "exit_code": result.returncode,
            "duration_ms": duration_ms,
            "version": first_line[:100],
            "ok": result.returncode == 0,
        }
    except FileNotFoundError:
        return {"exit_code": -1, "duration_ms": 0, "version": "NOT FOUND", "ok": False}
    except subprocess.TimeoutExpired:
        return {"exit_code": -1, "duration_ms": timeout * 1000, "version": "TIMEOUT", "ok": False}
    except Exception as e:
        return {"exit_code": -1, "duration_ms": 0, "version": f"ERROR: {e}", "ok": False}


def diagnose_tools(tool_filter: str | None = None) -> list[dict[str, Any]]:
    """Test all tools and return results."""
    results: list[dict[str, Any]] = []

    for tool in TOOLS:
        name = tool["name"]
        if tool_filter and tool_filter != name:
            continue

        print(f"  Testing {name:20s} ... ", end="", flush=True)
        result = _run(tool["version_cmd"])
        result["name"] = name
        result["category"] = tool["category"]

        if result["ok"]:
            print(f"\033[32mOK\033[0m  ({result['version'][:60]})")
        else:
            print(f"\033[31mFAIL\033[0m  exit={result['exit_code']} {result['version'][:60]}")

        results.append(result)

    return results


def probe_domain(domain: str) -> list[dict[str, Any]]:
    """Quick probe: test key tools against a real domain."""
    results: list[dict[str, Any]] = []

    probe_tools = [t for t in TOOLS if "test_cmd" in t]
    for tool in probe_tools:
        name = tool["name"]
        cmd = tool["test_cmd"](domain)
        print(f"  Probing {name:20s} → {domain} ... ", end="", flush=True)

        result = _run(cmd, timeout=30)
        result["name"] = name
        result["cmd"] = " ".join(cmd)

        if result["ok"]:
            print(f"\033[32mOK\033[0m  ({result['duration_ms']}ms)")
        else:
            print(f"\033[31mFAIL\033[0m  exit={result['exit_code']} ({result['duration_ms']}ms)")

        results.append(result)

    return results


def check_environment() -> dict[str, Any]:
    """Check environment variables and dependencies."""
    env_checks: dict[str, str] = {}

    for var in ["ANTHROPIC_API_KEY", "SHODAN_API_KEY", "ABUSEIPDB_API_KEY",
                "SECURITYTRAILS_API_KEY", "NVD_API_KEY", "WPSCAN_API_TOKEN",
                "DATABASE_URL", "REDIS_URL", "MINIO_ENDPOINT"]:
        val = os.environ.get(var, "")
        if val:
            env_checks[var] = f"SET ({len(val)} chars)"
        else:
            env_checks[var] = "NOT SET"

    # Check wordlists
    wordlists = {
        "common": "/usr/share/wordlists/common.txt",
        "subdomains": "/usr/share/wordlists/subdomains-top5000.txt",
        "wordpress": "/usr/share/wordlists/wordpress.txt",
        "api": "/usr/share/wordlists/api-endpoints.txt",
        "seclists/common": "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt",
        "seclists/params": "/usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt",
    }

    wl_checks: dict[str, str] = {}
    for name, path in wordlists.items():
        if os.path.isfile(path):
            size = os.path.getsize(path)
            lines = sum(1 for _ in open(path))
            wl_checks[name] = f"OK ({lines} lines, {size} bytes)"
        else:
            wl_checks[name] = "MISSING"

    return {"env": env_checks, "wordlists": wl_checks}


def main() -> None:
    """Entry point for diagnostics."""
    import argparse
    parser = argparse.ArgumentParser(description="VectiScan Tool Diagnostics")
    parser.add_argument("--tool", help="Test only this specific tool")
    parser.add_argument("--probe", help="Quick probe against a domain")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    print("\n\033[1m=== VectiScan Scan-Worker Diagnostics ===\033[0m\n")

    # 1. Environment
    print("\033[1m[Environment]\033[0m")
    env = check_environment()
    for var, status in env["env"].items():
        icon = "\033[32m+\033[0m" if "SET" in status else "\033[31m-\033[0m"
        print(f"  {icon} {var:30s} {status}")

    print(f"\n\033[1m[Wordlists]\033[0m")
    for name, status in env["wordlists"].items():
        icon = "\033[32m+\033[0m" if "OK" in status else "\033[31m-\033[0m"
        print(f"  {icon} {name:30s} {status}")

    # 2. Tools
    print(f"\n\033[1m[Tools]\033[0m")
    tool_results = diagnose_tools(tool_filter=args.tool)

    ok = sum(1 for r in tool_results if r["ok"])
    fail = sum(1 for r in tool_results if not r["ok"])
    print(f"\n  \033[1mResult: {ok} OK, {fail} FAILED\033[0m")

    # 3. Probe (if requested)
    probe_results: list[dict[str, Any]] = []
    if args.probe:
        print(f"\n\033[1m[Live Probe: {args.probe}]\033[0m")
        probe_results = probe_domain(args.probe)

    # 4. JSON output
    if args.json:
        output = {
            "environment": env,
            "tools": tool_results,
            "probe": probe_results,
        }
        print(f"\n{json.dumps(output, indent=2)}")

    # Exit code: 1 if any tool failed
    if fail > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
