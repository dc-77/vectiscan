"""Claude API Client — Aufruf + JSON-Parsing der Antwort."""

import json
import os
import time
from typing import Any

import anthropic
import structlog

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

CVSS-REFERENZWERTE (häufige Findings):
- DB-Port exponiert, Auth funktioniert: HIGH (7.0-8.5)
- DB-Port exponiert, keine Auth: CRITICAL (9.8-10.0)
- Mail-Services auf Prod-Server: MEDIUM (5.0-6.5)
- FTP exponiert mit SSL: MEDIUM (4.0-5.5)
- SSH ohne fail2ban: LOW (3.0-4.0)
- Info Disclosure (robots.txt, Banner): LOW (2.0-3.5)
- Gute Security-Header: INFORMATIONAL (positiver Befund)

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


def call_claude(
    domain: str,
    host_inventory: dict[str, Any],
    tech_profiles: list[dict[str, Any]],
    consolidated_findings: str,
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

    # Retry logic: 3 attempts with backoff for rate limits
    max_retries = 3
    for attempt in range(max_retries):
        try:
            log.info("claude_api_call", attempt=attempt + 1, domain=domain)

            response = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=4096,
                system=SYSTEM_PROMPT,
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

            result = json.loads(json_text)
            log.info(
                "claude_api_success",
                findings=len(result.get("findings", [])),
                positive=len(result.get("positive_findings", [])),
            )
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
            raise RuntimeError(f"Failed to parse Claude response as JSON: {e}")

        except Exception as e:
            raise RuntimeError(f"Claude API error: {e}")

    raise RuntimeError("Claude API call failed after all retries")
