"""Startup-Pruefung des Scan-Workers (S0a).

Hintergrund: `phase2.py` hat mit F-PH2-001 von `raft-medium-files.txt` auf
`raft-small-files.txt` umgestellt, das Image lud die Datei aber nie. `run_ffuf`
zaehlt eine fehlende Wordlist als `skipped`, nicht als Fehler -- also lief
`ffuf_sensitive` in 42 Produktionsscans kein einziges Mal, ohne dass es
irgendwo auffiel (spec/06 Abschnitt 6: 82 stille Skips).

Deshalb bricht der Worker jetzt beim Start ab, wenn eine referenzierte
Wordlist fehlt. Das ist bewusst kein fail-open wie bei `prewarm_buckets()`
oder `zap_pool.init_zap_pool()`: Buckets und ZAP-Daemons sind
Laufzeitabhaengigkeiten, die kurz weg sein duerfen. Wordlists sind
Image-Inhalt und werden beim `docker build` geladen (inkl. Build-Gate im
Dockerfile). Fehlt eine, ist das Image kaputt, und das soll im Deploy
auffallen statt im Kundenreport. Es gibt daher auch keinen Schalter, der
den Check ueberspringt -- er wuerde genau den Zustand wiederherstellen,
den diese Pruefung abschafft.

Einzige Wahrheit sind die Konstanten, die die Scan-Phasen ohnehin benutzen;
es gibt keinen zweiten, handgepflegten Pfad-Katalog.
"""

from __future__ import annotations

import os

import structlog

from scanner.phase0 import GOBUSTER_DNS_WORDLIST_PATH
from scanner.phase2 import FFUF_WORDLISTS, WORDLIST_MAP

log = structlog.get_logger()


def _required_wordlists() -> dict[str, str]:
    """Logischer Name -> Pfad, aufgeloest aus den Phase-Konstanten."""
    required: dict[str, str] = {}
    for name, path in WORDLIST_MAP.items():
        required[f"gobuster/{name}"] = path
    for name, path in FFUF_WORDLISTS.items():
        required[f"ffuf/{name}"] = path
    required["gobuster_dns/merged"] = GOBUSTER_DNS_WORDLIST_PATH
    return required


REQUIRED_WORDLISTS: dict[str, str] = _required_wordlists()


def missing_wordlists() -> dict[str, str]:
    """Liefert die Teilmenge von REQUIRED_WORDLISTS, deren Datei fehlt."""
    return {
        name: path
        for name, path in REQUIRED_WORDLISTS.items()
        if not os.path.isfile(path)
    }


def check_wordlists() -> None:
    """Prueft alle referenzierten Wordlists. Fehlt eine, SystemExit(1)."""
    missing = missing_wordlists()
    if not missing:
        log.info("wordlist_preflight_ok", count=len(REQUIRED_WORDLISTS))
        return

    for name, path in sorted(missing.items()):
        log.error("wordlist_missing", wordlist=name, path=path)
    log.error(
        "wordlist_preflight_failed",
        missing=len(missing),
        required=len(REQUIRED_WORDLISTS),
        hint="Image unvollstaendig -- scan-worker/Dockerfile Abschnitt 5 pruefen",
    )
    raise SystemExit(1)
