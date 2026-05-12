"""Screenshot-Pipeline v2 (M6 / Doc 01 Phase J).

Verfeinert die Screenshot-Liste vor dem PDF-Render:

  1. Body-Hash-Dedup (SHA256 ueber Bild-Bytes)
     - Hosts mit identischem Screenshot (Default-Plesk-Page o.ae.) erscheinen
       nur einmal, restliche Vorkommen als Caption.
  2. Limit max. 2 Screenshots im Default-Layout
     - groesste Sichtbarkeit fuer die produktivsten Hosts.
  3. Caption "Identisch auf X, Y, Z"
     - Mehrfachvorkommen werden im Bilduntertitel transparent gemacht.

Optionaler Annotation-Layer (Pillow-based, Finding-Kontext-getriggert) ist
strukturell vorbereitet, aber konservativ deaktiviert — ein falsches Highlight
schadet mehr als gar keins (siehe Master-Plan M6, Risiken).
"""

from __future__ import annotations

import hashlib
import logging
import os
from collections import defaultdict
from typing import Any

log = logging.getLogger(__name__)


# Default-Limit im neuen Layout (Doc 02). v1-Default (5 pro Host) bleibt
# unberuehrt — diese Pipeline ist v2-only.
DEFAULT_MAX_SCREENSHOTS = 2


def _hash_file(path: str) -> str | None:
    """SHA256-Hash der Bild-Bytes. None wenn nicht lesbar."""
    try:
        with open(path, "rb") as fh:
            h = hashlib.sha256()
            while True:
                chunk = fh.read(64 * 1024)
                if not chunk:
                    break
                h.update(chunk)
            return h.hexdigest()
    except Exception as exc:  # pragma: no cover - defensive
        log.warning("screenshot_hash_failed", extra={"path": path, "err": str(exc)})
        return None


def _entry_label_short(entry: dict[str, Any]) -> str:
    """Verkuerzt 'foo.example.de (Screenshot)' zu 'foo.example.de'."""
    label = entry.get("label") or ""
    if label.endswith(" (Screenshot)"):
        return label[: -len(" (Screenshot)")]
    return label


def dedup_and_cap(
    screenshots: list[dict[str, Any]],
    *,
    max_screenshots: int = DEFAULT_MAX_SCREENSHOTS,
) -> list[dict[str, Any]]:
    """Body-Hash-Dedup + Cap auf max. ``max_screenshots`` Eintraege.

    Args:
        screenshots: Liste wie aus ``report_mapper._build_screenshot_data``.
            Jeder Eintrag hat mindestens ``paths: [<single-file>]``.
        max_screenshots: harte Obergrenze nach Dedup.

    Returns:
        Neue Liste, in der jeder Eintrag eindeutig ist und ggf. eine
        zusaetzliche ``caption_dedup``-Zeile traegt
        ("Identisch auf X, Y, Z").

    Verhalten bei nicht-lesbaren Dateien:
        Eintraege ohne lesbaren Pfad werden uebersprungen.
    """
    if not screenshots:
        return []

    # 1. Hashe alle Eintraege.
    hashed: list[tuple[str | None, dict[str, Any]]] = []
    for entry in screenshots:
        paths = entry.get("paths") or []
        if not paths:
            continue
        first_path = paths[0]
        if not os.path.isfile(first_path):
            log.info(
                "screenshot_missing_file",
                extra={"path": first_path, "label": entry.get("label")},
            )
            continue
        h = _hash_file(first_path)
        hashed.append((h, entry))

    if not hashed:
        return []

    # 2. Gruppiere nach Hash. Eintraege ohne Hash bleiben singulaer (None-Bucket).
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    nonhashable: list[dict[str, Any]] = []
    for h, entry in hashed:
        if h is None:
            nonhashable.append(entry)
        else:
            groups[h].append(entry)

    # 3. Dedup: pro Gruppe das erste Vorkommen behalten, Rest in Caption.
    deduped: list[dict[str, Any]] = []
    for h, group in groups.items():
        primary = dict(group[0])  # shallow copy — wir mutieren nicht das Original
        if len(group) > 1:
            extra_labels = [_entry_label_short(g) for g in group[1:]]
            extra_labels = [l for l in extra_labels if l]
            if extra_labels:
                primary["caption_dedup"] = (
                    "Identisch auf " + ", ".join(extra_labels)
                )
                primary["dedup_count"] = len(group)
        deduped.append(primary)

    # Reihenfolge: groesste Gruppen zuerst (signalisiert breite Verteilung),
    # dann Original-Reihenfolge fuer Stabilitaet.
    insertion_index: dict[str, int] = {}
    for idx, (h, _e) in enumerate(hashed):
        if h is not None and h not in insertion_index:
            insertion_index[h] = idx

    deduped.sort(key=lambda e: (
        -int(e.get("dedup_count", 1)),
        insertion_index.get(_first_hash_of_entry(e, hashed), 9999),
    ))

    # Nicht-hashbare Eintraege hinten anhaengen (selten — nur bei Datei-Lese-
    # Problemen). Damit kein 'gueltiger' Screenshot verloren geht.
    deduped.extend(nonhashable)

    # 4. Cap auf max_screenshots.
    if max_screenshots and len(deduped) > max_screenshots:
        cut = deduped[max_screenshots:]
        deduped = deduped[:max_screenshots]
        log.info(
            "screenshot_pipeline_capped",
            extra={
                "kept": len(deduped),
                "dropped": len(cut),
                "max": max_screenshots,
            },
        )

    return deduped


def _first_hash_of_entry(
    entry: dict[str, Any],
    hashed: list[tuple[str | None, dict[str, Any]]],
) -> str:
    """Helper fuer sort-key: finde den Hash zu einem Eintrag."""
    for h, e in hashed:
        if e is entry:
            return h or ""
        # Eintrag wurde kopiert -> Vergleich ueber Pfad
        if entry.get("paths") and e.get("paths") and \
                entry["paths"][0] == e["paths"][0]:
            return h or ""
    return ""


__all__ = [
    "DEFAULT_MAX_SCREENSHOTS",
    "dedup_and_cap",
]
