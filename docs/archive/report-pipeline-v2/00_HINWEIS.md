# Archiv: Report-Pipeline bis S6 (22.09.2026)

Diese Dateien beschreiben den Weg, den VectiScan bis zur Umschaltung auf den
Prüfkatalog gegangen ist: ein Sprachmodell erzeugte aus einem Textblock die
Befunde samt CVSS-Werten, und acht nachgelagerte Stufen reparierten das
Ergebnis (`finding_type_mapper`, `ai_finding_type_fallback`, `severity_policy`,
`cvss_consistency`, `business_impact`, `selection`, `title_policy`,
`claims_guard`). Gerendert wurde mit ReportLab.

Warum das ersetzt wurde, steht in
`report-prototype/spec/05-architektur-befund-und-plan.md`: drei Läufe auf
dieselben Rohdaten wichen in 18 von 22 Sachverhalten voneinander ab, und
9 Prozent der Befunde in ausgelieferten Berichten waren belegbar falsch.

**Der aktuelle Stand steht in [`docs/report-pipeline/`](../../report-pipeline/).**

Dieses Archiv gilt weiterhin für den Legacy-Weg, der eine Release lang über
`VECTISCAN_REPORT_ENGINE=legacy` erreichbar bleibt. Danach ist es Historie und
kann mit dem Code verschwinden.
