"""Evidence Layer: facts.json je Scan (spec/05 M1 und M5, Session S1).

Oeffentliche Schnittstelle:
    build_facts(scan_data_dir, host_inventory, tech_profiles, correlated_findings,
                job_payload, *, tool_runs=None, order=None) -> Facts
    Facts, FACTS_SCHEMA_VERSION
"""
from reporter.facts.schema import FACTS_SCHEMA_VERSION, Facts

__all__ = ["FACTS_SCHEMA_VERSION", "Facts", "build_facts"]


def build_facts(*args, **kwargs):  # noqa: D401 - schlanker Re-Export ohne Importzyklus
    """Siehe reporter.facts.build.build_facts."""
    from reporter.facts.build import build_facts as _impl
    return _impl(*args, **kwargs)
