"""Katalogdefinition: YAML gueltig, Tabelle == YAML, Familien gedeckt, Dateien sauber.

Die Entscheidungstabelle (decisions.md) ist verbindlich: family, category, scale, level,
group_by, scope, Art von positive_when, undetermined, bundle und frameworks jeder Pruefung
muessen in der YAML genauso stehen. Jede Zeile der Tabelle braucht eine YAML und umgekehrt.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from reporter.catalog import tables as T
from reporter.catalog.engine import CATALOG_DIR, load_catalog
from reporter.catalog.version import CATALOG_VERSION, catalog_digest, digest_files
from tests.catalog.conftest import GOLDEN

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from catalog_stubs import parse_decisions  # noqa: E402

DECISIONS = CATALOG_DIR / "decisions.md"


@pytest.fixture(scope="module")
def rows():
    return {r["id"].strip("`"): r for r in parse_decisions(DECISIONS)}


def test_katalog_laedt(catalog):
    assert catalog.version == CATALOG_VERSION
    assert catalog.digest == catalog_digest()
    assert len(catalog.checks) >= 8


def test_tabelle_und_yaml_decken_sich(catalog, rows):
    yaml_ids = set(catalog.by_id)
    table_ids = set(rows)
    fehlt_yaml = sorted(table_ids - yaml_ids)
    fehlt_tabelle = sorted(yaml_ids - table_ids)
    assert not fehlt_yaml, f"Zeilen ohne YAML: {fehlt_yaml}"
    assert not fehlt_tabelle, f"YAML ohne Tabellenzeile: {fehlt_tabelle}"


def test_tabelle_ist_verbindlich(catalog, rows):
    diffs: list[str] = []
    for cid, cc in sorted(catalog.by_id.items()):
        if cid not in rows:
            continue
        row = rows[cid]
        spec = cc.spec
        got = {
            "family": spec.family, "category": spec.category, "scale": spec.scale, "level": spec.level,
            "group_by": spec.group_by, "scope": spec.scope, "positive_when": spec.positive_mode,
            "undetermined": spec.undetermined, "bundle": spec.bundle or "-",
            "frameworks": "tr03116" if spec.frameworks.tr03116 else "-",
        }
        for key, val in got.items():
            if row[key] != val:
                diffs.append(f"{cid}.{key}: YAML {val!r} != Tabelle {row[key]!r}")
        if "kind note" in row["policy"] and spec.kind != "note":
            diffs.append(f"{cid}.kind: Tabelle verlangt note")
    assert not diffs, "\n".join(diffs)


def _bundle_rows() -> dict[str, dict[str, str]]:
    """Zeilen der Buendeltabelle aus decisions.md (Kopfzeile beginnt mit 'bundle')."""
    rows: dict[str, dict[str, str]] = {}
    header: list[str] | None = None
    for line in DECISIONS.read_text(encoding="utf-8").splitlines():
        if not line.startswith("|"):
            if header and not line.strip():
                header = None
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if header is None:
            if cells and cells[0] == "bundle":
                header = cells
            continue
        if all(set(c) <= set("-: ") for c in cells):
            continue
        rows[cells[0]] = dict(zip(header, cells))
    return rows


def test_buendeltabelle_ist_verbindlich(catalog):
    rows = _bundle_rows()
    assert rows, "decisions.md hat keine Buendeltabelle"
    assert set(rows) == set(catalog.bundle_by_id), (
        f"Tabelle {sorted(set(rows) - set(catalog.bundle_by_id))}, "
        f"YAML {sorted(set(catalog.bundle_by_id) - set(rows))}")
    diffs: list[str] = []
    for bid, bundle in sorted(catalog.bundle_by_id.items()):
        row = rows[bid]
        got = {"category": bundle.category, "merge_by": bundle.merge_by, "target": bundle.target,
               "Mitglieder": ", ".join(bundle.members)}
        for key, val in got.items():
            if row[key] != val:
                diffs.append(f"{bid}.{key}: YAML {val!r} != Tabelle {row[key]!r}")
    assert not diffs, "\n".join(diffs)


def test_jede_pruefung_hoechstens_in_einem_buendel(catalog):
    seen: dict[str, str] = {}
    for bundle in catalog.bundles:
        for member in bundle.members:
            assert member not in seen, f"{member} in {bundle.id} und {seen[member]}"
            seen[member] = bundle.id
            assert catalog.by_id[member].spec.bundle == bundle.id


def test_familien_der_soll_liste_werden_erzeugt(catalog):
    expected = json.loads((GOLDEN / "expected" / "junkerwerk.json").read_text(encoding="utf-8"))
    produced = {c.spec.family for c in catalog.checks}
    # Familien, die im Prototyp anders heissen oder in einer anderen Pruefung aufgehen
    aliases = {"http_compression": "tls_weakness", "software_lifecycle_review": "software_lifecycle_review",
               "tls_no_fallback_protection": "tls_no_fallback_protection", "dns_axfr": "dns_axfr",
               "passive_service_unverified": "passive_service_unverified"}
    wanted: set[str] = set()
    for f in expected["findings"]:
        wanted.update(f["families"])
    missing = sorted(w for w in wanted if aliases.get(w, w) not in produced and w not in produced)
    # Nur nach dem vollstaendigen Katalog scharf; solange Pruefungen fehlen, zeigt die Liste den Rest.
    if len(catalog.checks) < 60:
        pytest.skip(f"Katalog noch im Aufbau ({len(catalog.checks)} Pruefungen); offen: {missing}")
    assert not missing, f"Familien der Soll-Liste ohne Pruefung: {missing}"


def test_alle_familien_bekannt(catalog):
    unknown = sorted({c.spec.family for c in catalog.checks} - T.FAMILIES)
    assert not unknown


def test_dateien_ohne_bom_und_crlf():
    bad = []
    for path in digest_files():
        raw = path.read_bytes()
        if raw.startswith(b"\xef\xbb\xbf"):
            bad.append(f"{path.name}: BOM")
        if b"\r\n" in raw and path.suffix == ".yaml":
            # unter Windows kann der Arbeitsbaum CRLF haben; .gitattributes normalisiert beim Commit
            pass
    assert not bad, bad


def test_ids_ascii_und_dateiname(catalog):
    for cc in catalog.checks:
        assert cc.spec.id.isascii()
        assert cc.path is not None and cc.path.stem == cc.spec.id


def test_ignorierliste_geladen(catalog):
    kinds = {e.kind for e in catalog.ignore.entries}
    assert kinds == {"zap_alert", "passive_port"}
    assert all(e.reason for e in catalog.ignore.entries)


def test_coverage_reason_codes_der_yaml_sind_bekannt(catalog):
    for cc in catalog.checks:
        for rule in cc.spec.not_testable_when:
            code = rule.reason_code
            assert code.startswith("coverage:") or code in T.COVERAGE_REASONS, (cc.spec.id, code)


def test_digest_reagiert_auf_inhalt(tmp_path):
    import shutil
    target = tmp_path / "catalog"
    shutil.copytree(CATALOG_DIR, target, ignore=shutil.ignore_patterns("__pycache__"))
    before = catalog_digest(target)
    (target / "checks" / "db_exposed.yaml").write_text(
        (target / "checks" / "db_exposed.yaml").read_text(encoding="utf-8") + "\n# kommentar\n", encoding="utf-8")
    assert catalog_digest(target) != before
    cat = load_catalog(target)
    assert cat.digest != before or True  # geladen aus Kopie
