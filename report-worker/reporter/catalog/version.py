"""Katalogversion und Laufzeit-Digest.

CATALOG_VERSION folgt dem Format von POLICY_VERSION (``JJJJ-MM-TT.n``). Bump-Regel
(README, Abschnitt "Versionierung"): jede Aenderung an ``checks/``, ``ignore.yaml``
oder ``tables.py`` zieht die Version hoch. Der Digest wird zur Laufzeit ueber genau
diese Dateien berechnet (CRLF-normalisiert, BOM entfernt) und steht in jeder Ausgabe,
damit eine Aenderung ohne Bump im Audit sichtbar bleibt.

Bump-Historie:
    2026-09-19.1  Erstversion (Session S2).
    2026-09-19.2  Session S3: Kundentexte auf echte Umlaute umgestellt (Titel, texts,
                  affected_template, COVERAGE_REASONS); Befund-Buendel unter bundles/
                  eingefuehrt und das Feld bundle je Pruefung gefuellt.
    2026-09-20.1  S2b: Rueckbau der sieben Gruppenregeln `zap_no_alerts`. Die
                  Abdeckung traegt den Fall seit Issue #13 selbst.
    2026-09-22.1  S6 (spec/08): `web_vulnerability_active` wird erst ab
                  ZAP-Konfidenz High ein Befund, darunter uebernimmt die neue
                  Pruefung `web_vulnerability_reported` als Werkzeugmeldung im
                  Anhang (Issue #15). Neues Feld `active_proof_when` fuer den
                  aktiven Nachweis (rot und unverzueglich) in
                  `web_vulnerability_active` und `tls_known_vulnerability`.
                  Neues Feld `evidence_detail` und befundspezifische Nachweise.
                  `wordpress_plugin_vulnerable` zaehlt ohne Singular-Fehler.
                  COVERAGE_REASONS in Kundensprache (spec/08 Punkt 11);
                  `package_<paket>` zaehlt als `not_in_package` (Punkt 9).
    2026-09-23.1  S6a (Issue #30): Positivbefund von `remote_admin_closed` heisst
                  "Keine Windows-Fernwartung (RDP) und keine Windows-Dateifreigabe
                  (SMB)"; neues Buendelfeld `positive_conflicts`, damit ein Host mit
                  FTP, Verwaltungsoberflaeche oder SSH ausserhalb Port 22 mit Befund
                  aus dem Positivbefund herausfaellt.
    2026-09-23.2  S6a (#15 Teil 2): `dkim_missing` meldet ohne gefundenen Selektor
                  nicht mehr "fehlt", sondern not_testable mit dem neuen Grund
                  `dkim_selector_unknown`; die Pruefung hat kein `when` mehr.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

CATALOG_VERSION = "2026-09-23.2"

CATALOG_DIR = Path(__file__).resolve().parent
CHECKS_DIR = CATALOG_DIR / "checks"
BUNDLES_DIR = CATALOG_DIR / "bundles"
IGNORE_FILE = CATALOG_DIR / "ignore.yaml"
TABLES_FILE = CATALOG_DIR / "tables.py"


def digest_files(catalog_dir: Path | None = None) -> list[Path]:
    """Dateien, die in den Digest eingehen, in stabiler Reihenfolge."""
    base = Path(catalog_dir) if catalog_dir else CATALOG_DIR
    files = sorted((base / "checks").glob("*.yaml"), key=lambda p: p.name)
    files.extend(sorted((base / "bundles").glob("*.yaml"), key=lambda p: p.name))
    for extra in (base / "ignore.yaml", base / "tables.py"):
        if extra.exists():
            files.append(extra)
    return files


def catalog_digest(catalog_dir: Path | None = None) -> str:
    """sha256 ueber Dateiname plus Inhalt (CRLF -> LF, BOM entfernt) aller Katalogdateien."""
    h = hashlib.sha256()
    for path in digest_files(catalog_dir):
        data = path.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        if data.startswith(b"\xef\xbb\xbf"):
            data = data[3:]
        h.update(path.name.encode("utf-8"))
        h.update(b"\0")
        h.update(data)
        h.update(b"\0")
    return h.hexdigest()
