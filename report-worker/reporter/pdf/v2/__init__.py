"""VectiScan PDF v2 Renderer (M3+).

3-Schichten-Architektur nach docs/report-erstellung/02_Report_Aufbau_Neudesign.md:
  Schicht 1 (Risiko-Frontpage)  -> layers/frontpage.py
  Schicht 2 (Strategie-Ebene)   -> layers/strategy.py
  Schicht 3 (Befund-Details)    -> layers/findings.py
"""
from reporter.pdf.v2.generate import generate_report_v2

__all__ = ["generate_report_v2"]
