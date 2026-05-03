"""Tool-Use-Definitionen + Loop fuer KI #4 (PR-KI-Optim, 2026-05-03).

Statt alle Threat-Intel-Daten (~30kB) in den KI-#4-Prompt zu packen,
geben wir der KI 3 Tools zur On-Demand-Anfrage:

- lookup_cve(cve_id)       → NVD-Entry (severity, cvss, kev_listed)
- lookup_epss(cve_id)      → EPSS-Score (Exploit-Probability)
- get_finding_corroboration(host_ip, finding_type) → andere Tool-Outputs
                                                     die selben Befund

Datenquellen (lazy):
- NVD/EPSS/KEV: aus dem threat_intel_snapshot der aktuellen Order
  (siehe scanner/threat_intel_snapshot.py)
- Finding-Corroboration: aus phase3.collected_findings_by_host
"""

from __future__ import annotations

import json
from typing import Any, Optional

import structlog

log = structlog.get_logger()


KI4_TOOLS = [
    {
        "name": "lookup_cve",
        "description": (
            "Hole NVD-Daten zu einer CVE-ID (Severity, CVSS, KEV-Listed-Status). "
            "Nutze fuer alle CVE-Findings die du genauer einschaetzen willst."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "cve_id": {
                    "type": "string",
                    "description": "CVE-ID im Format CVE-YYYY-NNNN, z.B. CVE-2024-12345",
                },
            },
            "required": ["cve_id"],
        },
    },
    {
        "name": "lookup_epss",
        "description": (
            "Hole EPSS-Score fuer eine CVE (0.0-1.0, Exploit-Probability "
            "naechste 30 Tage). Hilft Confidence-Boost fuer wahrscheinlich "
            "ausgenutzte Bugs zu rechtfertigen."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "cve_id": {"type": "string"},
            },
            "required": ["cve_id"],
        },
    },
    {
        "name": "get_finding_corroboration",
        "description": (
            "Liste alle Tool-Outputs die einen bestimmten Befund auf einem "
            "Host bestaetigen. Hilft Cross-Tool-Confidence zu beurteilen."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "host_ip": {"type": "string"},
                "finding_type": {
                    "type": "string",
                    "description": "Stichwort wie 'wordpress', 'tls_weak', 'sqli'",
                },
            },
            "required": ["host_ip", "finding_type"],
        },
    },
]


class Ki4ToolHandler:
    """Bedient Tool-Calls aus KI #4. Alle Methoden sind read-only auf
    bereits geladenen Snapshots — keine externen API-Calls zur Laufzeit.
    """

    def __init__(self, threat_intel_snapshot: Optional[dict] = None,
                 findings_by_host: Optional[dict] = None):
        self.snapshot = threat_intel_snapshot or {}
        self.findings_by_host = findings_by_host or {}

    def handle(self, name: str, input_data: dict[str, Any]) -> str:
        """Returns tool result als JSON-String (Anthropic-Convention)."""
        try:
            if name == "lookup_cve":
                return self._lookup_cve(input_data.get("cve_id", ""))
            if name == "lookup_epss":
                return self._lookup_epss(input_data.get("cve_id", ""))
            if name == "get_finding_corroboration":
                return self._corroborate(
                    input_data.get("host_ip", ""),
                    input_data.get("finding_type", ""),
                )
            return json.dumps({"error": f"unknown tool: {name}"})
        except Exception as e:
            log.warning("ki4_tool_handler_error", tool=name, error=str(e))
            return json.dumps({"error": str(e)})

    def _lookup_cve(self, cve_id: str) -> str:
        if not cve_id:
            return json.dumps({"error": "cve_id required"})
        nvd = (self.snapshot.get("nvd") or {}).get(cve_id) or {}
        kev = cve_id in (self.snapshot.get("kev_list") or [])
        if not nvd:
            return json.dumps({"cve_id": cve_id, "found": False})
        return json.dumps({
            "cve_id": cve_id,
            "found": True,
            "cvss_score": nvd.get("cvss_score"),
            "severity": nvd.get("severity"),
            "description": (nvd.get("description") or "")[:300],
            "kev_listed": kev,
        })

    def _lookup_epss(self, cve_id: str) -> str:
        if not cve_id:
            return json.dumps({"error": "cve_id required"})
        epss = (self.snapshot.get("epss") or {}).get(cve_id)
        if epss is None:
            return json.dumps({"cve_id": cve_id, "found": False})
        return json.dumps({
            "cve_id": cve_id,
            "found": True,
            "epss_score": float(epss),
            "interpretation": (
                "high" if epss > 0.7 else "medium" if epss > 0.3 else "low"
            ),
        })

    def _corroborate(self, host_ip: str, finding_type: str) -> str:
        if not host_ip or not finding_type:
            return json.dumps({"error": "host_ip + finding_type required"})
        host_findings = self.findings_by_host.get(host_ip, [])
        ft_lower = finding_type.lower()
        matches = [
            {"tool": f.get("tool"), "title": (f.get("title") or "")[:120]}
            for f in host_findings
            if ft_lower in (f.get("title") or "").lower()
            or ft_lower in (f.get("tool") or "").lower()
        ]
        return json.dumps({
            "host_ip": host_ip,
            "finding_type": finding_type,
            "matches": matches[:10],
            "total": len(matches),
        })


def run_ki4_with_tools(
    *,
    anthropic_client: Any,
    model: str,
    system_prompt: str,
    user_prompt: str,
    tool_handler: Ki4ToolHandler,
    max_tokens: int = 24576,
    thinking_budget: int = 8192,
    max_iterations: int = 5,
) -> tuple[str, dict[str, Any]]:
    """KI-#4-Loop mit Tool Use.

    Returns: (final_text_response, usage_aggregate_dict)
    """
    messages: list[dict[str, Any]] = [{"role": "user", "content": user_prompt}]
    aggregate_usage = {
        "input_tokens": 0, "output_tokens": 0,
        "cache_creation_tokens": 0, "cache_read_tokens": 0,
        "tool_iterations": 0,
    }
    final_text = ""

    for iteration in range(max_iterations):
        api_kwargs = {
            "model": model,
            "max_tokens": max_tokens,
            "system": [{
                "type": "text", "text": system_prompt,
                "cache_control": {"type": "ephemeral"},
            }] if len(system_prompt) > 8000 else system_prompt,
            "messages": messages,
            "tools": KI4_TOOLS,
            "temperature": 1.0 if thinking_budget else 0.0,
        }
        if thinking_budget:
            api_kwargs["thinking"] = {
                "type": "enabled",
                "budget_tokens": min(thinking_budget, max_tokens - 4096),
            }

        response = anthropic_client.messages.create(**api_kwargs)
        usage = getattr(response, "usage", None)
        if usage:
            aggregate_usage["input_tokens"] += getattr(usage, "input_tokens", 0) or 0
            aggregate_usage["output_tokens"] += getattr(usage, "output_tokens", 0) or 0
            aggregate_usage["cache_creation_tokens"] += getattr(
                usage, "cache_creation_input_tokens", 0) or 0
            aggregate_usage["cache_read_tokens"] += getattr(
                usage, "cache_read_input_tokens", 0) or 0

        # Sammle assistant-content + Tool-Calls
        assistant_content = []
        tool_uses = []
        for block in response.content:
            assistant_content.append(block)
            if getattr(block, "type", None) == "tool_use":
                tool_uses.append(block)
            elif getattr(block, "type", None) == "text":
                final_text = block.text  # letzter text-Block ist die finale Antwort

        if response.stop_reason != "tool_use" or not tool_uses:
            # Fertig — entweder end_turn oder max_tokens
            break

        # Tool-Results berechnen + zurueckschicken
        messages.append({"role": "assistant", "content": [
            (b.model_dump() if hasattr(b, "model_dump") else b) for b in assistant_content
        ]})
        tool_results = []
        for tu in tool_uses:
            result_str = tool_handler.handle(tu.name, tu.input)
            tool_results.append({
                "type": "tool_result",
                "tool_use_id": tu.id,
                "content": result_str,
            })
        messages.append({"role": "user", "content": tool_results})
        aggregate_usage["tool_iterations"] += 1

    return final_text, aggregate_usage


__all__ = ["KI4_TOOLS", "Ki4ToolHandler", "run_ki4_with_tools"]
