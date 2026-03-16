"""Claude API Client — Aufruf + JSON-Parsing der Antwort."""

import json
import math
import os
import time
from typing import Any

import anthropic
import structlog

from reporter.prompts import get_system_prompt

log = structlog.get_logger()

# System prompt from docs/architecture.md — copy VERBATIM
SYSTEM_PROMPT = """
Du bist ein erfahrener Penetration Tester, der Scan-Rohdaten in professionelle
Befunde umwandelt. Du arbeitest nach dem PTES-Standard.

REGELN FÜR CVSS-SCORING:
- Score was du beweisen kannst, nicht was du dir vorstellst
- Exponierter Port MIT Auth = NICHT dasselbe wie OHNE Auth
- Scope Change (S:C) erfordert Nachweis
- Information Disclosure ist fast nie über LOW (3.0-3.9)
- Immer den vollständigen CVSS-Vektorstring angeben
- Der numerische cvss_score MUSS exakt zum CVSS-Vektor passen

CVSS-REFERENZWERTE (häufige Findings):
- DB-Port exponiert, Auth funktioniert: HIGH (7.0-8.5)
- DB-Port exponiert, keine Auth: CRITICAL (9.8-10.0)
- Mail-Services auf Prod-Server: MEDIUM (5.0-6.5)
- FTP exponiert mit SSL: MEDIUM (4.0-5.5)
- SSH ohne fail2ban: LOW (3.0-4.0)
- Info Disclosure (robots.txt, Banner): LOW (2.0-3.5)
- Gute Security-Header: INFORMATIONAL (positiver Befund)

CVSS-REFERENZWERTE FÜR DNS-FINDINGS:
- Kein DKIM konfiguriert (SPF und DMARC vorhanden):
  → MEDIUM 4.3, CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N
  → E-Mail-Authentifizierung ist geschwächt, Phishing-Risiko erhöht
- DMARC-Policy auf 'none' (kein Enforcement):
  → MEDIUM 5.3, CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N
  → Keine Durchsetzung, Spoofing ungehindert möglich
- DMARC-Policy auf 'quarantine' statt 'reject':
  → LOW 3.7, CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N
  → Teilweise Durchsetzung, aber nicht vollständig blockiert
- Kein SPF-Record vorhanden:
  → MEDIUM 5.3, CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N
- SPF mit ~all (Softfail) statt -all (Hardfail):
  → LOW 3.7, CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N
- Zone Transfer (AXFR) möglich:
  → HIGH 7.5, CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
  → Vollständige DNS-Zone kann abgerufen werden
- Dangling CNAME (Subdomain Takeover möglich):
  → HIGH 8.2, CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:L

WICHTIG: Jeder Finding MUSS einen cvss_score und cvss_vector haben.
Nur bei INFO-Severity (Score 0.0) darf der Vektor "N/A" sein.

HÄUFIG FALSCH BEWERTETE FINDINGS — Korrekte Scores:
- SSH Port 22 offen, Key-Auth konfiguriert, Passwort-Auth deaktiviert:
  → INFO, CVSS 0.0, kein Vektor nötig — das ist Standard-Konfiguration
- SSH Port 22 offen, Passwort-Auth erlaubt, kein fail2ban:
  → LOW 3.1, CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N
- robots.txt enthält /admin oder /backup Pfade:
  → LOW 2.5 — reine Information Disclosure ohne direkten Zugriff
  → NICHT MEDIUM — robots.txt verrät nur Pfadnamen, kein Exploit
- MySQL/PostgreSQL Port offen, Connection refused oder Auth required:
  → INFO — Port ist erreichbar aber kein unautorisierter Zugriff möglich
  → NICHT HIGH — Connection refused = kein Risiko
- HTTP statt HTTPS ohne Redirect (kein Login-Formular):
  → LOW 3.7, CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N
- Server-Version im Banner sichtbar (z.B. "nginx/1.24"):
  → INFO — reine Information, kein direkter Angriff
  → NICHT LOW — Version im Banner allein ist kein Risiko
- Port offen aber Service antwortet nicht oder lehnt ab:
  → INFO — offener Port allein ohne erreichbaren Dienst ist kein Befund

REGELN FÜR TONALITÄT:
- Professionell und sachlich, nicht alarmistisch
- Keine Superlative ("katastrophal", "existenziell")
- Positive Befunde immer einschließen
- Empfehlungen müssen konkret und umsetzbar sein
- Dringlichkeit an tatsächlichen Schweregrad koppeln:
  CRITICAL: "Sofortige Behebung (24-48 Stunden)"
  HIGH: "Behebung innerhalb weniger Tage"
  MEDIUM: "Empfohlen innerhalb 2-4 Wochen"
  LOW: "Empfohlen innerhalb 1-3 Monaten"
  INFO: "Für kontinuierliche Verbesserung berücksichtigen"

OUTPUT-FORMAT:
Antworte ausschließlich in JSON nach folgendem Schema:
{
  "overall_risk": "CRITICAL|HIGH|MEDIUM|LOW",
  "overall_description": "2-3 Sätze Gesamtbewertung",
  "findings": [
    {
      "id": "VS-2026-001",
      "title": "Kurzer, präziser Titel",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "cvss_score": "8.6",
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
      "cwe": "CWE-284",
      "affected": "88.99.35.112:3306 (beispiel.de)",
      "description": "Was wurde gefunden. Sachlich und präzise.",
      "evidence": "$ nmap -sV 88.99.35.112\\n3306/tcp open mysql MariaDB 10.11.6",
      "impact": "Mögliche Auswirkung bei Ausnutzung. Business-Kontext.",
      "recommendation": "<b>Kurzfristig (Tage):</b> Konkrete Maßnahme.\\n<b>Mittelfristig:</b> Strategische Verbesserung."
    }
  ],
  "positive_findings": [
    {
      "title": "Korrekte TLS-Konfiguration",
      "description": "Alle Hosts nutzen TLS 1.2+, keine veralteten Cipher-Suites."
    }
  ],
  "recommendations": [
    {
      "timeframe": "Sofort|Tag 1-3|Woche 1|Monat 1",
      "action": "Konkrete Maßnahme",
      "finding_refs": ["001"],
      "effort": "2-4 h"
    }
  ]
}
"""

MAX_TOKENS_BY_PACKAGE: dict[str, int] = {
    "basic": 2048,
    "professional": 4096,
    "nis2": 6144,
}


# ---------------------------------------------------------------------------
# CVSS 3.1 score calculation from vector string
# ---------------------------------------------------------------------------

# Metric value weights per CVSS 3.1 specification
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}  # Scope Unchanged
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}  # Scope Changed
_UI = {"N": 0.85, "R": 0.62}
_C = {"H": 0.56, "L": 0.22, "N": 0.0}
_I = {"H": 0.56, "L": 0.22, "N": 0.0}
_A = {"H": 0.56, "L": 0.22, "N": 0.0}

_SEVERITY_RANGES = [
    (0.0, 0.0, "INFO"),
    (0.1, 3.9, "LOW"),
    (4.0, 6.9, "MEDIUM"),
    (7.0, 8.9, "HIGH"),
    (9.0, 10.0, "CRITICAL"),
]


def _roundup(x: float) -> float:
    """CVSS 3.1 roundup function: smallest tenth >= x."""
    return math.ceil(x * 10) / 10


def compute_cvss_score(vector: str) -> float | None:
    """Compute CVSS 3.1 base score from a vector string.

    Returns None if the vector is malformed or cannot be parsed.
    """
    if not vector or not vector.startswith("CVSS:3.1/"):
        return None

    try:
        parts = {}
        for segment in vector.split("/")[1:]:  # skip "CVSS:3.1"
            key, val = segment.split(":")
            parts[key] = val

        scope_changed = parts["S"] == "C"
        pr_table = _PR_C if scope_changed else _PR_U

        iss = 1 - (1 - _C[parts["C"]]) * (1 - _I[parts["I"]]) * (1 - _A[parts["A"]])

        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impact = 6.42 * iss

        exploitability = (
            8.22 * _AV[parts["AV"]] * _AC[parts["AC"]]
            * pr_table[parts["PR"]] * _UI[parts["UI"]]
        )

        if impact <= 0:
            return 0.0

        if scope_changed:
            score = _roundup(min(1.08 * (impact + exploitability), 10.0))
        else:
            score = _roundup(min(impact + exploitability, 10.0))

        return score
    except (KeyError, ValueError, IndexError):
        return None


def _severity_for_score(score: float) -> str:
    """Return severity label for a CVSS score."""
    for low, high, label in _SEVERITY_RANGES:
        if low <= score <= high:
            return label
    return "CRITICAL"


_VALID_CVSS_METRICS = {
    "AV": {"N", "A", "L", "P"},
    "AC": {"L", "H"},
    "PR": {"N", "L", "H"},
    "UI": {"N", "R"},
    "S": {"U", "C"},
    "C": {"H", "L", "N"},
    "I": {"H", "L", "N"},
    "A": {"H", "L", "N"},
}

_REQUIRED_METRICS = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}


def validate_cvss_vector(vector: str) -> str | None:
    """Validate CVSS 3.1 vector syntax.

    Returns None if valid, or an error description if invalid.
    """
    if not vector or not vector.startswith("CVSS:3.1/"):
        return "missing CVSS:3.1/ prefix"

    try:
        parts = {}
        for segment in vector.split("/")[1:]:
            key, val = segment.split(":")
            parts[key] = val
    except ValueError:
        return "malformed metric segment"

    # Check all required metrics are present
    missing = _REQUIRED_METRICS - set(parts.keys())
    if missing:
        return f"missing metrics: {', '.join(sorted(missing))}"

    # Check for unexpected metrics
    extra = set(parts.keys()) - _REQUIRED_METRICS
    if extra:
        return f"unexpected metrics: {', '.join(sorted(extra))}"

    # Check each metric value is valid
    for metric, value in parts.items():
        valid_values = _VALID_CVSS_METRICS.get(metric)
        if valid_values and value not in valid_values:
            return f"invalid value {metric}:{value}"

    return None


def validate_cvss_scores(result: dict[str, Any]) -> dict[str, Any]:
    """Validate and correct CVSS scores in Claude's response.

    For each finding with a cvss_vector:
    - Validate vector syntax (all 8 metrics, valid values)
    - Compute the correct score from the vector
    - If the reported score diverges by > 0.1, replace it with the computed score
    - Ensure severity label matches the computed score
    """
    findings = result.get("findings", [])
    corrected_count = 0

    for finding in findings:
        vector = finding.get("cvss_vector", "")
        reported_score_str = finding.get("cvss_score", "0")

        try:
            reported_score = float(reported_score_str)
        except (ValueError, TypeError):
            reported_score = 0.0

        # Skip findings without CVSS (e.g. INFO findings, basic package)
        if not vector or vector == "N/A":
            continue

        # Validate vector syntax
        vector_error = validate_cvss_vector(vector)
        if vector_error:
            log.warning(
                "cvss_vector_invalid",
                finding_id=finding.get("id"),
                vector=vector,
                error=vector_error,
            )
            # Cannot compute score from invalid vector — keep as-is
            continue

        computed = compute_cvss_score(vector)
        if computed is None:
            continue

        if abs(computed - reported_score) > 0.1:
            log.warning(
                "cvss_score_corrected",
                finding_id=finding.get("id"),
                reported=reported_score,
                computed=computed,
                vector=vector,
            )
            finding["cvss_score"] = str(computed)
            corrected_count += 1

        # Always ensure severity matches the (possibly corrected) score
        actual_score = float(finding["cvss_score"])
        correct_severity = _severity_for_score(actual_score)
        if finding.get("severity") != correct_severity:
            log.warning(
                "cvss_severity_corrected",
                finding_id=finding.get("id"),
                old_severity=finding.get("severity"),
                new_severity=correct_severity,
                score=actual_score,
            )
            finding["severity"] = correct_severity

    if corrected_count:
        log.info("cvss_validation_complete", corrected=corrected_count)

    return result


def call_claude(
    domain: str,
    host_inventory: dict[str, Any],
    tech_profiles: list[dict[str, Any]],
    consolidated_findings: str,
    package: str = "professional",
) -> dict[str, Any]:
    """Call Claude API to analyze scan data and generate findings.

    Args:
        domain: Target domain
        host_inventory: Host inventory from phase 0
        tech_profiles: Tech profiles from phase 1
        consolidated_findings: Consolidated text from parser

    Returns:
        Parsed JSON dict with overall_risk, findings, positive_findings, recommendations

    Raises:
        RuntimeError: If Claude API call fails after retries
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY environment variable not set")

    client = anthropic.Anthropic(api_key=api_key)

    # Build user prompt (from architecture.md)
    user_prompt = f"""
Analysiere die folgenden Scan-Rohdaten für {domain}.

HOST-INVENTAR:
{json.dumps(host_inventory, indent=2)}

TECHNOLOGIE-PROFILE (pro Host):
{json.dumps(tech_profiles, indent=2)}

SCAN-ERGEBNISSE:
{consolidated_findings}

Erstelle die Befunde auf Deutsch. Finding-ID-Prefix: VS
"""

    system_prompt = get_system_prompt(package)
    max_tokens = MAX_TOKENS_BY_PACKAGE.get(package, 4096)

    # Retry logic: 3 attempts with backoff for rate limits
    max_retries = 3
    for attempt in range(max_retries):
        try:
            log.info("claude_api_call", attempt=attempt + 1, domain=domain)

            response = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=max_tokens,
                system=system_prompt,
                messages=[{"role": "user", "content": user_prompt}],
                timeout=60.0,
            )

            # Extract text from response
            response_text = response.content[0].text

            # Parse JSON from response
            # Claude may wrap JSON in markdown code blocks
            json_text = response_text.strip()
            if json_text.startswith("```"):
                # Remove markdown code block
                lines = json_text.split("\n")
                # Remove first line (```json) and last line (```)
                json_text = "\n".join(lines[1:-1])

            # Fix trailing commas before } or ] (common Claude JSON issue)
            import re
            json_text = re.sub(r',\s*([\]}])', r'\1', json_text)

            result = json.loads(json_text)
            log.info(
                "claude_api_success",
                findings=len(result.get("findings", [])),
                positive=len(result.get("positive_findings", [])),
            )
            # Post-process: validate and correct CVSS scores
            result = validate_cvss_scores(result)
            return result

        except anthropic.RateLimitError as e:
            if attempt < max_retries - 1:
                wait_time = (attempt + 1) * 10  # 10s, 20s, 30s
                log.warning("claude_rate_limit", attempt=attempt + 1, wait=wait_time)
                time.sleep(wait_time)
            else:
                raise RuntimeError(
                    f"Claude API rate limited after {max_retries} retries: {e}"
                )

        except anthropic.APITimeoutError as e:
            if attempt < max_retries - 1:
                log.warning("claude_timeout", attempt=attempt + 1)
                time.sleep(5)
            else:
                raise RuntimeError(
                    f"Claude API timeout after {max_retries} retries: {e}"
                )

        except json.JSONDecodeError as e:
            if attempt < max_retries - 1:
                log.warning("claude_json_parse_error", attempt=attempt + 1, error=str(e),
                            raw_snippet=json_text[:200] if 'json_text' in dir() else "")
                time.sleep(3)
            else:
                raise RuntimeError(f"Failed to parse Claude response as JSON: {e}")

        except Exception as e:
            raise RuntimeError(f"Claude API error: {e}")

    raise RuntimeError("Claude API call failed after all retries")
