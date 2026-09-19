"""Pruefkatalog (Session S2): Regeln als YAML, Ergebnisse aus facts.json.

Oeffentliche Schnittstelle:
    load_catalog(catalog_dir=None) -> Catalog
    evaluate(facts, catalog=None) -> CatalogOutput
    CATALOG_VERSION, CatalogSpecError
"""
from reporter.catalog.expr import CatalogSpecError
from reporter.catalog.version import CATALOG_VERSION, catalog_digest

__all__ = ["CATALOG_VERSION", "CatalogSpecError", "catalog_digest", "evaluate", "load_catalog"]


def load_catalog(*args, **kwargs):  # noqa: D401 - schlanker Re-Export ohne Importzyklus
    """Siehe reporter.catalog.engine.load_catalog."""
    from reporter.catalog.engine import load_catalog as _impl
    return _impl(*args, **kwargs)


def evaluate(*args, **kwargs):  # noqa: D401
    """Siehe reporter.catalog.engine.evaluate."""
    from reporter.catalog.engine import evaluate as _impl
    return _impl(*args, **kwargs)
