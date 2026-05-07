"""Zentrales Modul fuer Mail-/DNS-Security-Parser.

Spec: docs/scan-flow/Scan-Optimierung.md §3.2.4 (F-P0A-002).

Ein einziges Modul fuer:
    * TLS-RPT  (RFC 8460) — `_smtp._tls.<domain>` TXT
    * BIMI     (RFC 9091 draft) — `default._bimi.<domain>` TXT
    * DMARC    (RFC 7489) — `_dmarc.<domain>` TXT (strukturierter Parser)
    * NSEC3-Iterations (RFC 9276) — `<domain>` NSEC3PARAM

Reusability:
    Phase 0a (`scanner/phase0a.py` -> `dns_security.run_all_dns_security`)
    Phase 0b (Replacement der raw DMARC-Detection in `phase0.py:776-784`)
    Reporter (`reporter/severity_policy.py` -> deterministische Felder).

Determinismus: jeder Parser liefert ein Dict mit fest definierten Keys, nie
"None" als implizites Signal — fehlende Records sind `*_present: False`.
Unbekannte/private Tags werden ignoriert (RFC-strict).
"""

from __future__ import annotations

import subprocess
from typing import Any

import structlog

log = structlog.get_logger()


# ============================================================================
# DIG-HELPER
# ============================================================================
def _dig(query: str, record_type: str, timeout: int = 10) -> str:
    """Run dig and return stdout (stripped). Empty string on any error."""
    try:
        proc = subprocess.run(
            ["dig", query, record_type, "+short", "+time=5", "+tries=2"],
            capture_output=True, text=True, timeout=timeout,
        )
        return proc.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return ""


def _txt_lines(raw: str) -> list[str]:
    """Strip DNS TXT-quoting and concatenate continuation lines."""
    lines: list[str] = []
    for line in raw.splitlines():
        line = line.strip().strip('"')
        if line:
            lines.append(line)
    return lines


# ============================================================================
# TLS-RPT (RFC 8460)
# ============================================================================
def parse_tls_rpt(txt: str) -> dict[str, Any]:
    """Parse a TLS-RPT TXT-record value (`v=TLSRPTv1; rua=mailto:...`).

    Returns:
        {
          "tlsrpt_present": bool,   # True iff `v=TLSRPTv1` matched
          "rua_targets": list[str], # mailto:/https: URIs (deduped, ordered)
          "issues": list[str],      # parser-issues (e.g. unknown version)
        }
    """
    issues: list[str] = []
    rua_targets: list[str] = []

    if not txt or "v=tlsrptv1" not in txt.lower():
        return {"tlsrpt_present": False, "rua_targets": [], "issues": issues}

    # Tag-Format: "v=TLSRPTv1; rua=mailto:reports@example.com,https://..."
    seen: set[str] = set()
    for tag in txt.split(";"):
        tag = tag.strip()
        if not tag:
            continue
        key, _, value = tag.partition("=")
        key = key.strip().lower()
        value = value.strip()
        if key == "v":
            if value.lower() != "tlsrptv1":
                issues.append(f"unsupported TLS-RPT version: {value}")
        elif key == "rua":
            for target in value.split(","):
                t = target.strip()
                if t and t not in seen:
                    seen.add(t)
                    rua_targets.append(t)
        # Unknown tags ignored (RFC-strict)

    if not rua_targets:
        issues.append("TLS-RPT present but no rua targets")

    return {
        "tlsrpt_present": True,
        "rua_targets": rua_targets,
        "issues": issues,
    }


def check_tls_rpt(domain: str) -> dict[str, Any]:
    """DNS-Lookup `_smtp._tls.<domain>` TXT + parse."""
    raw = _dig(f"_smtp._tls.{domain}", "TXT")
    candidates = _txt_lines(raw)
    for line in candidates:
        if "v=tlsrptv1" in line.lower():
            result = parse_tls_rpt(line)
            log.info("tls_rpt_check", domain=domain, present=True,
                     rua_count=len(result["rua_targets"]))
            return result
    log.info("tls_rpt_check", domain=domain, present=False)
    return {"tlsrpt_present": False, "rua_targets": [], "issues": []}


# ============================================================================
# BIMI (RFC 9091 draft)
# ============================================================================
def parse_bimi(txt: str) -> dict[str, Any]:
    """Parse a BIMI TXT-record value (`v=BIMI1; l=...; a=...`).

    Returns:
        {
          "bimi_present": bool,     # True iff `v=BIMI1` matched
          "logo_url": str | None,   # `l=` value (SVG URL)
          "vmc_url": str | None,    # `a=` value (Verified Mark Cert URL)
          "issues": list[str],
        }
    """
    issues: list[str] = []
    if not txt or "v=bimi1" not in txt.lower():
        return {
            "bimi_present": False, "logo_url": None,
            "vmc_url": None, "issues": issues,
        }

    logo_url: str | None = None
    vmc_url: str | None = None
    for tag in txt.split(";"):
        tag = tag.strip()
        if not tag:
            continue
        key, _, value = tag.partition("=")
        key = key.strip().lower()
        value = value.strip()
        if key == "v":
            if value.lower() != "bimi1":
                issues.append(f"unsupported BIMI version: {value}")
        elif key == "l":
            logo_url = value or None
        elif key == "a":
            vmc_url = value or None

    if not logo_url:
        issues.append("BIMI record present but no logo URL (l=)")

    return {
        "bimi_present": True,
        "logo_url": logo_url,
        "vmc_url": vmc_url,
        "issues": issues,
    }


def check_bimi(domain: str) -> dict[str, Any]:
    """DNS-Lookup `default._bimi.<domain>` TXT + parse."""
    raw = _dig(f"default._bimi.{domain}", "TXT")
    candidates = _txt_lines(raw)
    for line in candidates:
        if "v=bimi1" in line.lower():
            result = parse_bimi(line)
            log.info("bimi_check", domain=domain, present=True,
                     has_logo=bool(result.get("logo_url")))
            return result
    log.info("bimi_check", domain=domain, present=False)
    return {
        "bimi_present": False, "logo_url": None,
        "vmc_url": None, "issues": [],
    }


# ============================================================================
# DMARC (RFC 7489) — Policy-Detail-Parser
# ============================================================================
_DMARC_DEFAULT_PCT = 100


def parse_dmarc(txt: str) -> dict[str, Any]:
    """Parse a DMARC TXT-record value into a structured policy dict.

    Returns (always present, defaults filled when tag missing):
        {
          "dmarc_present": bool,
          "raw":  str | None,
          "p":    str | None,        # required tag — None if missing
          "sp":   str | None,        # subdomain policy (None means inherits p)
          "pct":  int,               # default 100
          "rua":  list[str],         # aggregate-report URIs
          "ruf":  list[str],         # forensic-report URIs
          "aspf": str,               # alignment SPF, default "r"
          "adkim":str,               # alignment DKIM, default "r"
          "fo":   str | None,        # failure reporting options
          "issues":list[str],
        }
    """
    issues: list[str] = []
    if not txt or "v=dmarc1" not in txt.lower():
        return {
            "dmarc_present": False, "raw": None,
            "p": None, "sp": None, "pct": _DMARC_DEFAULT_PCT,
            "rua": [], "ruf": [],
            "aspf": "r", "adkim": "r", "fo": None,
            "issues": issues,
        }

    p_val: str | None = None
    sp_val: str | None = None
    pct_val: int = _DMARC_DEFAULT_PCT
    rua: list[str] = []
    ruf: list[str] = []
    aspf = "r"
    adkim = "r"
    fo: str | None = None

    for tag in txt.split(";"):
        tag = tag.strip()
        if not tag:
            continue
        key, _, value = tag.partition("=")
        key = key.strip().lower()
        value = value.strip()
        if key == "v":
            continue
        elif key == "p":
            p_val = value.lower() or None
        elif key == "sp":
            sp_val = value.lower() or None
        elif key == "pct":
            try:
                pct_val = int(value)
            except ValueError:
                issues.append(f"invalid DMARC pct: {value}")
        elif key == "rua":
            for tgt in value.split(","):
                t = tgt.strip()
                if t:
                    rua.append(t)
        elif key == "ruf":
            for tgt in value.split(","):
                t = tgt.strip()
                if t:
                    ruf.append(t)
        elif key == "aspf":
            aspf = (value.lower() or "r")[:1]
        elif key == "adkim":
            adkim = (value.lower() or "r")[:1]
        elif key == "fo":
            fo = value or None

    if p_val is None:
        issues.append("DMARC record present but no policy (p=) tag")
    if pct_val < 0 or pct_val > 100:
        issues.append(f"DMARC pct out-of-range: {pct_val}")

    return {
        "dmarc_present": True, "raw": txt,
        "p": p_val, "sp": sp_val, "pct": pct_val,
        "rua": rua, "ruf": ruf,
        "aspf": aspf, "adkim": adkim, "fo": fo,
        "issues": issues,
    }


def check_dmarc_policy(domain: str) -> dict[str, Any]:
    """DNS-Lookup `_dmarc.<domain>` TXT + structured parse."""
    raw = _dig(f"_dmarc.{domain}", "TXT")
    for line in _txt_lines(raw):
        if "v=dmarc1" in line.lower():
            result = parse_dmarc(line)
            log.info("dmarc_check", domain=domain,
                     present=True, p=result["p"],
                     sp=result["sp"], pct=result["pct"])
            return result
    log.info("dmarc_check", domain=domain, present=False)
    return parse_dmarc("")


# ============================================================================
# NSEC3-Iterations (RFC 9276)
# ============================================================================
def parse_nsec3param(raw: str) -> dict[str, Any]:
    """Parse a `dig +short NSEC3PARAM` output.

    Format (whitespace separated): "<hash-algo> <flags> <iterations> <salt>"

    Returns:
        {
          "nsec3param_present": bool,
          "iterations": int | None,
          "rfc9276_violation": bool,   # iterations > 0 — RFC 9276 says SHOULD be 0
          "issues": list[str],
        }
    """
    issues: list[str] = []
    if not raw:
        return {
            "nsec3param_present": False,
            "iterations": None,
            "rfc9276_violation": False,
            "issues": issues,
        }

    line = raw.splitlines()[0].strip()
    parts = line.split()
    if len(parts) < 3:
        issues.append("malformed NSEC3PARAM output")
        return {
            "nsec3param_present": False,
            "iterations": None,
            "rfc9276_violation": False,
            "issues": issues,
        }

    try:
        iterations = int(parts[2])
    except ValueError:
        iterations = None
        issues.append(f"unparseable iterations field: {parts[2]}")

    rfc9276_violation = bool(iterations and iterations > 0)
    if rfc9276_violation:
        issues.append(
            f"NSEC3 iterations={iterations} > 0 (RFC 9276 recommends 0)"
        )

    return {
        "nsec3param_present": True,
        "iterations": iterations,
        "rfc9276_violation": rfc9276_violation,
        "issues": issues,
    }


def check_nsec3_iterations(domain: str) -> dict[str, Any]:
    """DNS-Lookup `<domain>` NSEC3PARAM + parse iterations."""
    raw = _dig(domain, "NSEC3PARAM")
    result = parse_nsec3param(raw)
    log.info("nsec3_check", domain=domain,
             present=result["nsec3param_present"],
             iterations=result["iterations"])
    return result


__all__ = [
    "parse_tls_rpt", "check_tls_rpt",
    "parse_bimi", "check_bimi",
    "parse_dmarc", "check_dmarc_policy",
    "parse_nsec3param", "check_nsec3_iterations",
]
