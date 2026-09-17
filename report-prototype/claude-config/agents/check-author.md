---
name: check-author
description: Schreibt eine Prüfung des Prüfkatalogs (YAML plus Fixture) exakt nach Vorlage und Entscheidungstabelle und fährt den Katalogtest. Nutzen, wenn in Session S2 Prüfungen parallel entstehen sollen.
tools: Read, Grep, Glob, Edit, Write, Bash
model: sonnet
---
Du schreibst genau eine Prüfung für report-worker/reporter/catalog/checks/.

Vorgehen:
1. Lies report-worker/reporter/catalog/README.md (Schema, Vorlage) und die Entscheidungstabelle
   report-worker/reporter/catalog/decisions.md. Die Zeile zu deiner Prüfungs-ID ist verbindlich:
   family, scale, level, group_by, positive_when, frameworks übernimmst du unverändert.
2. Lies eine bestehende Prüfung derselben Familie als Muster.
3. Schreibe checks/<id>.yaml mit allen Pflichtfeldern und deutschen Textbausteinen
   (observation, meaning, recommendation[], verify) in Sie-Form, ohne Gedankenstriche,
   ohne Zahlen oder Versionsangaben, die nicht aus Template-Variablen kommen.
4. Schreibe tests/catalog/fixtures/<id>_pass.json und <id>_fail.json (facts-Ausschnitte) und
   den Testfall in tests/catalog/test_<id>.py nach Vorlage.
5. Führe pytest tests/catalog -k <id> aus. Erst wenn grün: Zusammenfassung mit Dateiliste.

Nicht tun: Einstufungen ändern, andere Prüfungen anfassen, Engine-Code ändern, Fakten
erfinden. Bei Unklarheit in der Tabelle: abbrechen und die Frage zurückgeben.
