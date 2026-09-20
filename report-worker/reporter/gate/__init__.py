# -*- coding: utf-8 -*-
"""Gemeinsame Defektliste beider Berichts-Engines (S5).

Es gibt zwei Gates: das alte ``ValidationGate`` fuer den v2-Strang
(``reporter/validation/gate.py``) und fuer v3 ``reporter/v3/selfcheck`` plus die
Render-Pruefungen aus ``reporter/pdf/v3``. Beide muessen ``report_blocked``
ausloesen koennen, und der Admin will eine Liste sehen, nicht zwei.

Dieses Paket fuehrt beide Formen auf einen Datensatz zusammen (Engine, Check,
Meldung, Befund-ID) und baut daraus den Inhalt von ``orders.report_defects``.
"""
from reporter.gate.defects import (
    Defect,
    from_render_result,
    from_selfcheck,
    from_validation_result,
    payload,
)

__all__ = [
    "Defect",
    "from_render_result",
    "from_selfcheck",
    "from_validation_result",
    "payload",
]
