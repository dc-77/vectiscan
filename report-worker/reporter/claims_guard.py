"""Verallgemeinerter Claims-Guard (VEC — Phase 1 / C1).

Erweitert den bestehenden CVE-Guard (``cve_guard.py``) um zwei Dinge, die dort
nachweislich fehlen:

  1. **Feld-Abdeckung.**  ``apply_cve_guard`` prueft nur ``findings[]``,
     ``additional_findings_summary[]`` und ``overall_description`` — NICHT die
     KI-Freitextfelder ``recommendations[].action``, ``top_recommendations``,
     ``positive_findings``, ``executive_summary``, die Compliance-scope_notes,
     ``insurance_questionnaire[].detail`` oder
     ``risk_score.premium_reduction_actions[]``.  Genau in einer Recommendation
     stand der belegte Defekt "SonicWall … (CVE-2024-40766 patchen)".
  2. **Nicht-CVE-Claim-Typen.**  Versions-/EOL-Aussagen (gegen das Evidenz-
     Inventar) sowie — im Shadow-Modus — Hostname-/Port-Behauptungen.

``cve_guard.py`` bleibt die byte-identische CVE-Autoritaet und wird hier ZUERST
aufgerufen.  Anschliessend deckt dieser Guard die restlichen Felder ab.  Weil
der CVE-Guard nicht auflösbare CVEs bereits durch einen Marker (ohne "CVE-")
ersetzt hat, findet die zweite CVE-Passage in genau diesen Feldern nichts mehr
— es gibt also keine Doppelzaehlung.

Guard-Modus (Entscheidung E1, verbindlich):
  * **CVE**: IMMER enforce, unabhaengig vom ENV-Schalter.
  * **Version/EOL**: enforce, aber NUR bei exaktem Produkt-Match gegen das
    Inventar (KI behauptet "veraltet", Inventar sagt fuer genau dieses Produkt
    "aktuell"/"latest").  Bei Unsicherheit passiert NICHTS.
  * **Hostname/Port**: shadow — nur zaehlen und loggen, Text bleibt
    byte-identisch (hohes FP-Risiko bei generischen Empfehlungssaetzen,
    Praezedenzfall consistency.py:12-19).
  * ``VECTISCAN_CLAIMS_GUARD_MODE=enforce|shadow`` steuert NUR die
    Nicht-CVE-Klassen (Default: ``enforce``).

Defensiv: ein Fehler in der Nicht-CVE-Logik darf den Report NIE kippen — das
CVE-Ergebnis bleibt in jedem Fall erhalten (try/except + Fail-open).
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any, Callable, Iterator

import structlog

from reporter.claims_inventory import EvidenceInventory
# cve_guard bleibt die CVE-Autoritaet — nur oeffentliche API importieren.
from reporter.cve_guard import (
    CVE_RE,
    UNVERIFIED_MARKER,
    apply_cve_guard,
    build_allowlist,
)

log = structlog.get_logger()


# ---------------------------------------------------------------------------
# Marker / Muster
# ---------------------------------------------------------------------------

# Teilstring des Hinweises, der an eine widerlegte Versionsaussage angehaengt
# wird (enforce-Modus).  Als Konstante exportiert, damit Tests robust darauf
# pruefen koennen.
CLAIMS_VERSION_MARKER = "laut Scan-Inventar als aktuell gefuehrt"

# Signalwoerter fuer eine "veraltet/EOL"-Behauptung.  Bewusst OHNE das bare
# Wort "aktuell" (positiv).  Wortgrenzen verhindern Teilwort-Treffer.
_OUTDATED_TOKENS: tuple[str, ...] = (
    "veraltet", "veraltete", "veralteten", "veralteter",
    "outdated", "obsolet", "obsolete", "deprecated",
    "end-of-life", "end of life", "abgekuendigt", "abgekündigt",
    "nicht mehr aktuell", "nicht aktuell", "ueberholt", "überholt",
)
_OUTDATED_RE = re.compile(
    r"(?:" + "|".join(re.escape(t) for t in _OUTDATED_TOKENS) + r"|\bEOL\b)",
    re.IGNORECASE,
)

# Port-Muster (uebernommen aus validation/checks/plan.py:16-18).
_PORT_RE_LABELED = re.compile(r"\bPort\s+(\d{2,5})\b", re.IGNORECASE)
_PORT_RE_TCP_UDP = re.compile(r"\b(\d{2,5})\s*/\s*(?:tcp|udp)\b", re.IGNORECASE)

# Host-Muster: IPv4 + FQDN.
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_FQDN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b",
    re.IGNORECASE,
)
# Datei-Endungen, die der FQDN-Regex sonst als "Host" fehldeutet ("index.php").
_HOST_TLD_BLOCKLIST: frozenset[str] = frozenset({
    "php", "html", "htm", "js", "css", "json", "xml", "txt", "aspx", "jsp",
    "png", "jpg", "jpeg", "svg", "gif", "asp", "cgi", "map", "md", "yml",
    "yaml", "ini", "log", "bak", "sql",
})

# Max. Zeichenabstand zwischen Produkt-Term und "veraltet"-Signalwort, damit
# sie als EINE Aussage gelten.  Kein Satz-Split auf "." — das zerlegt sonst
# Versionsnummern ("6.7.1") und trennt Produkt vom Signalwort.
# (Historisch; die reine Naehe genuegte fuer False Positives — siehe
# _VERSION_ATTR_WINDOW und _check_version_claims.)
_VERSION_PROXIMITY = 80

# Fensterbreite (Zeichen), in die Produkt-Voll-Name + belegte VERSIONSNUMMER +
# "veraltet"/EOL-Signalwort GEMEINSAM passen muessen, damit eine Versionswarnung
# als attribuiert (grammatikalisch auf genau dieses Produkt bezogen) gilt und
# nur dann entschaerft wird.  Approximiert "im selben Satz" deterministisch,
# ohne an Satzpunkten zu splitten (die eine Versionsnummer wie "6.7.1"
# zerreissen wuerden).  Bewusst eng gehalten — im Zweifel NICHT entschaerfen.
_VERSION_ATTR_WINDOW = 120


# ---------------------------------------------------------------------------
# Text-Zellen-Registry (TEXT_TARGETS)
# ---------------------------------------------------------------------------

@dataclass
class _TextCell:
    """Ein einzelnes veraenderbares Freitextfeld im claude_output."""
    label: str
    get: Callable[[], str]
    set: Callable[[str], None]


def _dict_str_cells(container: Any, key: str, label: str) -> Iterator[_TextCell]:
    """Zelle fuer ein String-Feld eines Dicts (nur wenn aktuell ein str)."""
    if isinstance(container, dict) and isinstance(container.get(key), str):
        yield _TextCell(
            label,
            lambda c=container, k=key: c.get(k) or "",
            lambda val, c=container, k=key: c.__setitem__(k, val),
        )


def _list_str_cells(lst: Any, label: str) -> Iterator[_TextCell]:
    """Zellen fuer eine Liste von Strings (Mutation ueber den Index)."""
    if isinstance(lst, list):
        for i, item in enumerate(lst):
            if isinstance(item, str):
                yield _TextCell(
                    label,
                    lambda l=lst, i=i: l[i],
                    lambda val, l=lst, i=i: l.__setitem__(i, val),
                )


# Subfelder eines Findings, die Freitext tragen (Deckungsgleich mit
# cve_guard._FINDING_TEXT_FIELDS — dadurch bleibt die CVE-Doppelpassage 0).
_FINDING_TEXT_FIELDS: tuple[str, ...] = (
    "title", "description", "recommendation", "impact", "evidence", "affected",
)


def iter_text_cells(claude_output: dict) -> Iterator[_TextCell]:
    """Durchlaeuft ALLE KI-Freitextfelder des claude_output als Zellen.

    Die einzige Stelle, an der die Feldabdeckung definiert ist — statt drei
    hartkodierter Stellen wie bisher.  Neue Prompt-Felder werden hier ergaenzt
    und sind damit automatisch durch den parametrisierten Coverage-Test
    abgesichert.
    """
    if not isinstance(claude_output, dict):
        return

    for f in claude_output.get("findings") or []:
        for fld in _FINDING_TEXT_FIELDS:
            yield from _dict_str_cells(f, fld, f"findings[].{fld}")

    for f in claude_output.get("additional_findings_summary") or []:
        for fld in _FINDING_TEXT_FIELDS:
            yield from _dict_str_cells(
                f, fld, f"additional_findings_summary[].{fld}")

    yield from _dict_str_cells(
        claude_output, "overall_description", "overall_description")

    for rec in claude_output.get("recommendations") or []:
        yield from _dict_str_cells(rec, "action", "recommendations[].action")

    for rec in claude_output.get("top_recommendations") or []:
        yield from _dict_str_cells(
            rec, "action", "top_recommendations[].action")

    for pf in claude_output.get("positive_findings") or []:
        yield from _dict_str_cells(pf, "title", "positive_findings[].title")
        yield from _dict_str_cells(
            pf, "description", "positive_findings[].description")

    yield from _dict_str_cells(
        claude_output, "executive_summary", "executive_summary")

    yield from _dict_str_cells(
        claude_output.get("nis2_compliance_summary"), "scope_note",
        "nis2_compliance_summary.scope_note")

    yield from _dict_str_cells(
        claude_output.get("supply_chain_summary"), "recommendation",
        "supply_chain_summary.recommendation")

    yield from _dict_str_cells(
        claude_output.get("supply_chain_attestation"), "recommendation",
        "supply_chain_attestation.recommendation")

    yield from _dict_str_cells(
        claude_output.get("iso27001_mapping"), "scope_note",
        "iso27001_mapping.scope_note")

    for q in claude_output.get("insurance_questionnaire") or []:
        yield from _dict_str_cells(q, "detail", "insurance_questionnaire[].detail")

    risk = claude_output.get("risk_score")
    if isinstance(risk, dict):
        yield from _list_str_cells(
            risk.get("premium_reduction_actions"),
            "risk_score.premium_reduction_actions[]")


# ---------------------------------------------------------------------------
# CVE-Scrub (spiegelt cve_guard._scrub_text, nur oeffentliche API)
# ---------------------------------------------------------------------------

def _scrub_cve(text: str, allowlist: set[str], removed: list[str]) -> str:
    """Ersetzt nicht auflösbare CVE-IDs durch den neutralen Marker."""
    if not isinstance(text, str) or "CVE-" not in text.upper():
        return text

    def _repl(m: re.Match) -> str:
        cve = m.group(0)
        if cve.upper() in allowlist:
            return cve
        removed.append(cve.upper())
        return UNVERIFIED_MARKER

    return CVE_RE.sub(_repl, text)


# ---------------------------------------------------------------------------
# Nicht-CVE-Claim-Extraktoren
# ---------------------------------------------------------------------------

def _has_attribution_cluster(
    name_spans: list[tuple[int, int]],
    ver_spans: list[tuple[int, int]],
    outdated_spans: list[tuple[int, int]],
) -> bool:
    """True, wenn je ein Produktname-, Versions- und Signalwort-Treffer in ein
    gemeinsames Fenster (<= ``_VERSION_ATTR_WINDOW`` Zeichen) passen.

    Das ist die deterministische Naeherung fuer "Produkt + Versionsnummer +
    veraltet stehen im selben Satz und beziehen sich aufeinander".  Nur wenn
    ein solcher Cluster existiert, gilt die Versionswarnung als attribuiert.
    """
    for ns, ne in name_spans:
        for vs, ve in ver_spans:
            for os_, oe in outdated_spans:
                lo = min(ns, vs, os_)
                hi = max(ne, ve, oe)
                if hi - lo <= _VERSION_ATTR_WINDOW:
                    return True
    return False


def _check_version_claims(text: str, inventory: EvidenceInventory,
                          unsupported: set[str]) -> tuple[str, bool, int]:
    """Prueft Versions-/EOL-Aussagen gegen als 'aktuell' belegte Produkte.

    ATTRIBUTION statt blosser Naehe (Befund-Fix): Eine Versionswarnung wird nur
    dann als unbelegt entschaerft, wenn im selben Fenster ALLE drei Bedingungen
    zusammentreffen:

      (1) der VOLLE Produktname des als aktuell belegten Produkts
          (KEIN Ersten-Token-Alias — "apache" darf nicht "Apache Tomcat"
          treffen; der Alias ist nur fuer die Inventar-Erkennung gedacht),
      (2) eine im Inventar BELEGTE Versionsnummer genau dieses Produkts, und
      (3) ein "veraltet"/EOL-Signalwort,

    und diese als Cluster (grammatikalischer Bezug) eng beieinander liegen.
    Fehlt die Versionsnummer ODER der volle Produktname im Fenster, bleibt der
    Text unveraendert — die Guard-Grundregel "lieber eine unbelegte Aussage
    stehen lassen als eine korrekte streichen" hat Vorrang.  Damit entfaellt der
    False Positive "aktueller Webserver ... unterstuetzt veraltete Cipher-
    Suites" (Naehe ja, aber keine Versionsnummer -> keine Streichung).

    Returns ``(neuer_text, veraendert, geprueft)``.  Der Text wird immer
    korrigiert zurueckgegeben; der Aufrufer nutzt ihn nur im enforce-Modus.
    """
    checked = 0
    changed = False
    if not text or not inventory.version_status:
        return text, changed, checked

    outdated_spans = [m.span() for m in _OUTDATED_RE.finditer(text)]

    for product_key in inventory.version_status:
        if not inventory.is_current(product_key):
            continue
        checked += 1
        if not outdated_spans:
            continue

        # (2) Ohne belegte Versionsnummer keine Attribution -> nie entschaerfen.
        versions = inventory.versions.get(product_key) or set()
        if not versions:
            continue

        # (1) NUR voller Produktname (product_key ist der normalisierte
        # Voll-Name), bewusst OHNE Ersten-Token-Alias aus product_terms.
        name_spans = [
            m.span() for m in re.finditer(
                rf"\b{re.escape(product_key)}\b", text, re.IGNORECASE)
        ]
        if not name_spans:
            continue

        # (2) Belegte Versionsnummer(n) im Text lokalisieren.  Lookarounds
        # verhindern Teiltreffer in laengeren Nummern ("6.7.1" nicht in
        # "6.7.10").
        ver_spans: list[tuple[int, int]] = []
        for v in versions:
            for m in re.finditer(rf"(?<![\d.]){re.escape(v)}(?![\d.])", text):
                ver_spans.append(m.span())
        if not ver_spans:
            continue

        # (3) Cluster aus Name + Versionsnummer + Signalwort im selben Fenster.
        if not _has_attribution_cluster(name_spans, ver_spans, outdated_spans):
            continue

        unsupported.add(product_key)
        if CLAIMS_VERSION_MARKER not in text:
            text = text.rstrip()
            sep = " " if text else ""
            text = (
                f"{text}{sep}[Hinweis: {product_key} wird "
                f"{CLAIMS_VERSION_MARKER}; die Einstufung als "
                f"veraltet/EOL ist nicht belegt.]"
            )
            changed = True
    return text, changed, checked


def _count_host_claims(text: str, inventory: EvidenceInventory,
                       unsupported: set[str]) -> int:
    """Zaehlt Hostnamen/IPs im Text, die NICHT im Inventar stehen (shadow)."""
    if not text:
        return 0
    checked = 0
    if inventory.hosts:
        for m in _IPV4_RE.finditer(text):
            checked += 1
            host = m.group(0).lower()
            if host not in inventory.hosts:
                unsupported.add(host)
        for m in _FQDN_RE.finditer(text):
            host = m.group(0).lower()
            tld = host.rsplit(".", 1)[-1]
            if tld in _HOST_TLD_BLOCKLIST:
                continue
            checked += 1
            if host not in inventory.hosts:
                unsupported.add(host)
    return checked


def _count_port_claims(text: str, inventory: EvidenceInventory,
                       unsupported: set[str]) -> int:
    """Zaehlt Ports im Text, die NICHT im Inventar stehen (shadow)."""
    if not text or not inventory.all_ports:
        return 0
    checked = 0
    for regex, grp in ((_PORT_RE_LABELED, 1), (_PORT_RE_TCP_UDP, 1)):
        for m in regex.finditer(text):
            try:
                port = int(m.group(grp))
            except (ValueError, TypeError):
                continue
            checked += 1
            if port not in inventory.all_ports:
                unsupported.add(str(port))
    return checked


# ---------------------------------------------------------------------------
# Modus
# ---------------------------------------------------------------------------

def _resolve_mode() -> str:
    """Nicht-CVE-Modus aus dem ENV-Schalter (Default enforce, E1)."""
    mode = (os.environ.get("VECTISCAN_CLAIMS_GUARD_MODE") or "enforce").strip().lower()
    return mode if mode in ("enforce", "shadow") else "enforce"


# ---------------------------------------------------------------------------
# Hauptfunktion
# ---------------------------------------------------------------------------

def apply_claims_guard(claude_output: dict, *,
                       inventory: EvidenceInventory | None = None,
                       enrichment: Any = None) -> dict[str, Any]:
    """Wendet CVE- + Claims-Guard auf claude_output an (in-place).

    Ablauf:
      1. ``apply_cve_guard`` (CVE-Autoritaet) fuer findings/additional/overall.
      2. CVE-Scrub der restlichen Freitextfelder (Feldabdeckung) — enforce.
      3. Versions-/EOL-Abgleich gegen das Inventar (enforce bei exaktem Match).
      4. Hostname-/Port-Abgleich (shadow — nur zaehlen/loggen).

    Rueckwaertskompatibel: die drei alten Keys (``removed_count``,
    ``distinct_removed``, ``allowlist_size``) bleiben erhalten und tragen
    weiterhin AUSSCHLIESSLICH die CVE-Statistik.
    """
    # 1. CVE-Autoritaet — mutiert findings/additional/overall + title_vars.
    cve_stats = apply_cve_guard(claude_output, enrichment=enrichment)

    removed_count = int(cve_stats.get("removed_count", 0))
    distinct: set[str] = set(cve_stats.get("distinct_removed") or [])
    allowlist_size = int(cve_stats.get("allowlist_size", 0))

    mode = _resolve_mode()
    inv = inventory if isinstance(inventory, EvidenceInventory) else EvidenceInventory()

    unsupported_cve: list[str] = []
    unsupported_version: set[str] = set()
    unsupported_host: set[str] = set()
    unsupported_port: set[str] = set()
    fields_scanned: set[str] = set()
    claims_checked = 0

    try:
        allowlist = build_allowlist(enrichment)
        for cell in iter_text_cells(claude_output):
            fields_scanned.add(cell.label)
            text = cell.get()
            if not isinstance(text, str):
                continue
            new_text = text

            # 2. CVE in den restlichen Feldern (immer enforce).
            scrubbed = _scrub_cve(new_text, allowlist, unsupported_cve)
            if scrubbed != new_text:
                new_text = scrubbed

            # 3. Versionsaussagen (enforce nur bei exaktem Produkt-Match).
            ver_text, ver_changed, ver_checked = _check_version_claims(
                new_text, inv, unsupported_version)
            claims_checked += ver_checked
            if ver_changed and mode == "enforce":
                new_text = ver_text

            # 4. Host/Port immer nur zaehlen (shadow), Text unveraendert.
            claims_checked += _count_host_claims(text, inv, unsupported_host)
            claims_checked += _count_port_claims(text, inv, unsupported_port)

            if new_text != text:
                cell.set(new_text)

        # CVE-Zusatztreffer aus den Nicht-cve_guard-Feldern verbuchen.
        if unsupported_cve:
            removed_count += len(unsupported_cve)
            distinct.update(unsupported_cve)
    except Exception as exc:  # Fail-open: CVE-Ergebnis bleibt erhalten.
        log.warning("claims_guard_failed", error=str(exc))

    distinct_sorted = sorted(distinct)
    stats: dict[str, Any] = {
        # Rueckwaertskompatibel (CVE-only):
        "removed_count": removed_count,
        "distinct_removed": distinct_sorted,
        "allowlist_size": allowlist_size,
        # Neu:
        "claims_checked": claims_checked,
        "claims_unsupported": {
            "cve": distinct_sorted,
            "version": sorted(unsupported_version),
            "host": sorted(unsupported_host),
            "port": sorted(unsupported_port),
        },
        "fields_scanned": sorted(fields_scanned),
        "mode": mode,
    }

    if (unsupported_version or unsupported_host or unsupported_port):
        log.info(
            "claims_guard_unsupported",
            mode=mode,
            version=sorted(unsupported_version),
            host_count=len(unsupported_host),
            port_count=len(unsupported_port),
        )

    return stats


__all__ = [
    "apply_claims_guard",
    "iter_text_cells",
    "CLAIMS_VERSION_MARKER",
]
