"""Reportdaten v3 (Session S3): aus Fakten und Pruefkatalog wird das Datenmodell des Reports.

Oeffentliche Schnittstelle:
    build_report_data(facts, catalog_output=None, ...) -> ReportData
    check_report_data(data) -> list[str]
    ReportData
"""
from reporter.v3.models import ReportData
from reporter.v3.selfcheck import check_report_data

__all__ = ["ReportData", "build_report_data", "check_report_data"]


def build_report_data(*args, **kwargs):  # noqa: D401 - schlanker Re-Export ohne Importzyklus
    """Siehe reporter.v3.report_data.build_report_data."""
    from reporter.v3.report_data import build_report_data as _impl

    return _impl(*args, **kwargs)
