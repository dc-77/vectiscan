"""Golden-Fixtures (Session S0c): Vollstaendigkeit und Smoke-Test.

Abnahme aus dem Startprompt S0c: pytest findet die Fixtures, ein Smoke-Test
entpackt jedes Tar und ruft parser.parse_scan_data darauf ohne Fehler auf.

manifest.json ist die einzige Wahrheit ueber das Set. Auftraege ohne Tar
werden uebersprungen, mit dem Grund aus dem Manifest, damit ein geraeumtes
MinIO-Objekt sichtbar bleibt statt stillschweigend zu fehlen.
"""

from __future__ import annotations

import hashlib
import json
import os
import tarfile
from pathlib import Path

import pytest

from reporter.parser import parse_scan_data

GOLDEN = Path(__file__).parent / "golden"
SNAPSHOT = GOLDEN / "api-snapshot"

IMAGE_SUFFIXES = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".tiff")
SCALES = {"exposure", "hygiene"}
LEVELS = {"kritisch", "hoch", "mittel", "niedrig"}


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def manifest() -> dict:
    return load(GOLDEN / "manifest.json")


# --------------------------------------------------------------- Manifest

def test_manifest_vorhanden(manifest):
    assert manifest["orders"], "manifest.json fuehrt keine Auftraege"
    assert len(manifest["orders"]) == manifest["tars_erwartet"]
    rollen = {rolle for order in manifest["orders"] for rolle in order["roles"]}
    assert {"golden", "drift", "negative", "coverage"} <= rollen


def test_orders_txt_deckt_sich_mit_manifest(manifest):
    listed = (GOLDEN / "orders.txt").read_text(encoding="utf-8").split()
    assert listed == [order["order_id"] for order in manifest["orders"]]


def test_ci_matrix_deckt_sich_mit_orders_txt():
    """Der Export-Job fuehrt seine Auftraege als parallel:matrix, weil der
    Artefakt-Upload nur kleine Archive annimmt. Beide Listen muessen gleich sein."""
    ci_file = Path(__file__).parents[2] / ".gitlab-ci.yml"
    yaml = pytest.importorskip("yaml", reason="PyYAML nicht installiert")
    config = yaml.safe_load(ci_file.read_text(encoding="utf-8"))
    matrix = config["ops-export-golden-tars"]["parallel"]["matrix"][0]["GOLDEN_ORDER"]
    listed = (GOLDEN / "orders.txt").read_text(encoding="utf-8").split()
    assert sorted(matrix) == sorted(listed)


def test_api_snapshot_je_auftrag_vorhanden(manifest):
    for order in manifest["orders"]:
        assert order["api_snapshot"], f"API-Snapshot fehlt fuer {order['order_id']}"
        assert (SNAPSHOT / order["order_id"]).is_dir()


# ---------------------------------------------------------------- Roh-Tars

def _tar_cases() -> list:
    """Parametrisierung aus dem Manifest, damit fehlende Tars sichtbar bleiben."""
    manifest_path = GOLDEN / "manifest.json"
    if not manifest_path.is_file():
        return []
    return [
        pytest.param(order, id=order["order_id"][:8])
        for order in load(manifest_path)["orders"]
    ]


@pytest.mark.parametrize("order", _tar_cases())
def test_tar_stimmt_mit_manifest(order):
    tar_info = order["tar"]
    if not tar_info["present"]:
        pytest.skip(f"kein Tar: {tar_info.get('reason', 'unbekannt')}")
    path = GOLDEN / "tars" / f"{order['order_id']}.tar.gz"
    assert path.is_file()
    assert path.stat().st_size == tar_info["bytes"]
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    assert digest == tar_info["sha256"], "Tar weicht vom Manifest ab, manifest.json neu bauen"


@pytest.mark.parametrize("order", _tar_cases())
def test_tar_ohne_screenshots(order):
    if not order["tar"]["present"]:
        pytest.skip(f"kein Tar: {order['tar'].get('reason', 'unbekannt')}")
    path = GOLDEN / "tars" / f"{order['order_id']}.tar.gz"
    with tarfile.open(path, "r:gz") as tar:
        images = [m.name for m in tar.getmembers() if m.name.lower().endswith(IMAGE_SUFFIXES)]
    assert images == [], f"Screenshots im Fixture: {images[:5]}"


@pytest.mark.parametrize("order", _tar_cases())
def test_parse_scan_data_smoke(order, tmp_path):
    """Entpacken und parsen, wie reporter.worker es tut."""
    if not order["tar"]["present"]:
        pytest.skip(f"kein Tar: {order['tar'].get('reason', 'unbekannt')}")
    path = GOLDEN / "tars" / f"{order['order_id']}.tar.gz"

    extract_dir = tmp_path / "scan-data"
    extract_dir.mkdir()
    with tarfile.open(path, "r:gz") as tar:
        # Hosts liegen unter hosts/<ip>/. Bei IPv6 enthaelt der Name Doppelpunkte,
        # die Windows in Pfaden nicht zulaesst. Auf Linux, also auch im CI-Job
        # test-report-worker, laeuft der Test vollstaendig.
        if os.name == "nt" and any(":" in m.name for m in tar.getmembers()):
            pytest.skip("IPv6-Hostverzeichnis im Tar, unter Windows kein zulaessiger Pfadname")
        tar.extractall(path=extract_dir)  # noqa: S202

    # Aufloesung wie reporter/worker.py: das Tar traegt <orderId>/ als Wurzel.
    scan_data_dir = extract_dir
    subdirs = [d for d in extract_dir.iterdir() if d.is_dir()]
    if len(subdirs) == 1 and (subdirs[0] / "hosts").is_dir():
        scan_data_dir = subdirs[0]

    parsed = parse_scan_data(str(scan_data_dir))
    for key in ("host_inventory", "tech_profiles", "consolidated_findings", "meta"):
        assert key in parsed, f"parse_scan_data liefert {key} nicht"
    assert parsed["host_inventory"].get("hosts"), "kein Host im Inventar"


# ------------------------------------------------------------- API-Snapshot

def test_api_snapshot_vollstaendig():
    order_dirs = sorted(d for d in SNAPSHOT.iterdir() if d.is_dir())
    assert len(order_dirs) >= 36, "spec/06 wertet 36 Laeufe aus, der Snapshot muss sie fuehren"
    for order_dir in order_dirs:
        for name in ("order.json", "findings.json", "results.json"):
            doc = load(order_dir / name)
            assert doc.get("success") is True, f"{order_dir.name}/{name} ist keine gueltige Antwort"


def test_api_snapshot_ohne_bestelleradresse():
    orders = load(SNAPSHOT / "orders.json")["data"]["orders"]
    assert orders
    for order in orders:
        assert order.get("email") == "redacted@example.invalid"


# -------------------------------------------------------------- Soll-Liste

def test_expected_junkerwerk():
    data = load(GOLDEN / "expected" / "junkerwerk.json")
    findings = data["findings"]
    positives = data["positives"]
    assert len(findings) == 15
    assert len(positives) == 8
    assert len(data["order_ids"]) == 3

    ids = [f["id"] for f in findings]
    assert ids == [f"VS-2026-{n:03d}" for n in range(1, 16)], "IDs nicht lueckenlos"
    assert [p["id"] for p in positives] == [f"VS-2026-P{n:02d}" for n in range(1, 9)]

    for finding in findings:
        assert finding["scale"] in SCALES
        assert finding["level"] in LEVELS
        assert finding["family"] == finding["families"][0]
        assert finding["affected"], f"{finding['id']} ohne Betroffene"
    for positive in positives:
        assert positive["scale"] is None and positive["level"] is None
        assert positive["family"] == positive["families"][0]


# --------------------------------------------------------- Negativ-Fixtures

def test_negative_fixtures_struktur():
    data = load(GOLDEN / "negative.json")
    entries = data["entries"]
    assert len(entries) == data["count"]
    assert data["count"] >= 35, "spec/06 Abschnitt 3 nennt 35 Falschbefunde"
    for entry in entries:
        for key in ("pattern", "order", "titel", "grund", "verbotene_aussage", "widerlegt_durch"):
            assert entry.get(key), f"{entry.get('order')} {entry.get('finding_id')}: {key} fehlt"
        refuted = entry["widerlegt_durch"]
        assert refuted.get("fakt") and refuted.get("wert") and refuted.get("quelle")


def test_negative_fixtures_belegen_sich_selbst():
    """Jeder Eintrag muss im API-Snapshot wiederzufinden sein."""
    data = load(GOLDEN / "negative.json")
    for entry in data["entries"]:
        order_dir = SNAPSHOT / entry["order"]
        assert order_dir.is_dir(), f"Auftrag {entry['order']} fehlt im Snapshot"
        findings = load(order_dir / "findings.json")["data"]["findings"]
        titles = {f["id"]: f["title"] for f in findings}
        assert entry["finding_id"] in titles, (
            f"{entry['order']}: Befund {entry['finding_id']} nicht im Snapshot"
        )
        assert titles[entry["finding_id"]] == entry["titel"]


def test_negative_fixtures_abweichungen_begruendet():
    data = load(GOLDEN / "negative.json")
    for deviation in data["abweichungen"]:
        assert deviation["geprueft"] is True, (
            f"Abweichung {deviation['pattern']} gegenueber spec/06 ist nicht begruendet"
        )
        assert deviation["begruendung"]
