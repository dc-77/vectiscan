"""Extended DNS security checks — DNSSEC, CAA, MTA-STS, DANE/TLSA."""

import subprocess
from typing import Any

import requests
import structlog

log = structlog.get_logger()


def _dig(query: str, record_type: str, timeout: int = 10) -> str:
    """Run dig and return stdout."""
    try:
        proc = subprocess.run(
            ["dig", query, record_type, "+short", "+time=5", "+tries=2"],
            capture_output=True, text=True, timeout=timeout,
        )
        return proc.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""


def check_dnssec(domain: str) -> dict[str, Any]:
    """Validate DNSSEC configuration for a domain."""
    dnskey = _dig(domain, "DNSKEY")
    ds = _dig(domain, "DS")
    rrsig = _dig(domain, "RRSIG")

    dnssec_signed = bool(dnskey or ds)

    # Try drill for chain-of-trust validation
    dnssec_valid = False
    ds_algorithm = None
    issues: list[str] = []

    if dnssec_signed:
        try:
            proc = subprocess.run(
                ["drill", "-S", domain],
                capture_output=True, text=True, timeout=15,
            )
            dnssec_valid = proc.returncode == 0
            # Parse algorithm from DS record
            if ds:
                parts = ds.split()
                if len(parts) >= 3:
                    algo_map = {
                        "5": "RSASHA1", "7": "RSASHA1-NSEC3-SHA1",
                        "8": "RSASHA256", "10": "RSASHA512",
                        "13": "ECDSAP256SHA256", "14": "ECDSAP384SHA384",
                        "15": "ED25519", "16": "ED448",
                    }
                    ds_algorithm = algo_map.get(parts[2], f"Algorithm {parts[2]}")
                    if parts[2] in ("5", "7"):
                        issues.append("DS Algorithm uses SHA-1 (deprecated)")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

    if not dnssec_signed:
        issues.append("Domain is not DNSSEC-signed")

    result = {
        "dnssec_signed": dnssec_signed,
        "dnssec_valid": dnssec_valid,
        "ds_algorithm": ds_algorithm,
        "dnskey_count": len(dnskey.splitlines()) if dnskey else 0,
        "issues": issues,
    }
    log.info("dnssec_check", domain=domain, signed=dnssec_signed, valid=dnssec_valid)
    return result


def check_caa(domain: str) -> dict[str, Any]:
    """Check CAA (Certificate Authority Authorization) records."""
    raw = _dig(domain, "CAA")
    records = [line.strip() for line in raw.splitlines() if line.strip()]

    has_caa = len(records) > 0
    issuers = []
    for r in records:
        parts = r.split(None, 2)
        if len(parts) >= 3 and parts[1] in ("issue", "issuewild"):
            issuers.append(parts[2].strip('"'))

    result = {
        "has_caa": has_caa,
        "records": records,
        "issuers": issuers,
    }
    log.info("caa_check", domain=domain, has_caa=has_caa, issuers=issuers)
    return result


def check_mta_sts(domain: str) -> dict[str, Any]:
    """Check MTA-STS (Mail Transport Agent Strict Transport Security)."""
    # 1. DNS TXT record
    txt = _dig(f"_mta-sts.{domain}", "TXT")
    has_dns_record = "v=STSv1" in txt

    # 2. Policy file
    policy = None
    mode = None
    try:
        resp = requests.get(
            f"https://mta-sts.{domain}/.well-known/mta-sts.txt",
            timeout=5, allow_redirects=True,
        )
        if resp.status_code == 200:
            policy = resp.text.strip()
            for line in policy.splitlines():
                if line.startswith("mode:"):
                    mode = line.split(":", 1)[1].strip()
    except Exception:
        pass

    result = {
        "has_dns_record": has_dns_record,
        "dns_txt": txt if has_dns_record else None,
        "has_policy": policy is not None,
        "mode": mode,
    }
    log.info("mta_sts_check", domain=domain,
             has_record=has_dns_record, mode=mode)
    return result


def check_dane_tlsa(domain: str) -> dict[str, Any]:
    """Check DANE/TLSA records for SMTP (port 25) and HTTPS (port 443)."""
    # Get MX records to find mail server
    mx_raw = _dig(domain, "MX")
    mx_hosts = []
    for line in mx_raw.splitlines():
        parts = line.strip().split()
        if len(parts) >= 2:
            mx_hosts.append(parts[-1].rstrip("."))

    smtp_tlsa = {}
    for mx in mx_hosts[:3]:  # Check first 3 MX hosts
        raw = _dig(f"_25._tcp.{mx}", "TLSA")
        if raw:
            smtp_tlsa[mx] = raw

    # HTTPS TLSA
    https_tlsa = _dig(f"_443._tcp.{domain}", "TLSA")

    result = {
        "smtp_tlsa": smtp_tlsa,
        "https_tlsa": https_tlsa if https_tlsa else None,
        "has_smtp_dane": len(smtp_tlsa) > 0,
        "has_https_dane": bool(https_tlsa),
    }
    log.info("dane_check", domain=domain,
             smtp_dane=result["has_smtp_dane"],
             https_dane=result["has_https_dane"])
    return result


def run_all_dns_security(domain: str, package: str) -> dict[str, Any]:
    """Run all DNS security checks based on package level.

    WebCheck: DNSSEC (basic), CAA (basic), MTA-STS (basic)
    Perimeter+: All checks including DANE/TLSA with full detail
    """
    results: dict[str, Any] = {}

    results["dnssec"] = check_dnssec(domain)
    results["caa"] = check_caa(domain)
    results["mta_sts"] = check_mta_sts(domain)

    # DANE/TLSA only for Perimeter+ packages
    if package not in ("webcheck", "basic"):
        results["dane_tlsa"] = check_dane_tlsa(domain)

    return results
