# -*- coding: utf-8 -*-
"""S6a2 (spec/09 Q11): Dashboard-Technikzeilen und Technologietabelle des Berichts.

Die Hostkarte liest ``reports.tech_profiles[].tech_rows``. Bis S6a2 baute diese Zeilen
im Katalogweg der alte ``tech_table_builder`` aus den rohen Profilen, der Bericht las
dagegen die Fakten. Folge bei lumbeck-wolter und junkerwerk: das Dashboard zeigte
"MySQL 5.5.5-10.11.18-MariaDB" mit EOL 2018 und "PostgreSQL 9.6.0 or later" mit EOL
2021, der Bericht richtig MariaDB 10.11.18 und PostgreSQL unbekannt.

Paritaet heisst hier: fuer jeden Golden-Auftrag stimmen je Host Komponente, Version und
Patch-Status zwischen Bericht und Dashboard ueberein, in beiden Richtungen.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from reporter.facts.build import build_facts
from reporter.v3.chapters import tech_tool_findings
from reporter.v3.dashboard import tech_profiles_from_facts
from tests.v3.conftest import data_for, facts_for, order_ids

ORDERS = order_ids()

# Patch-Status im Bericht -> status im Dashboard (reporter/v3/dashboard.py _TECH_STATUS).
BERICHT_ZU_DASHBOARD = {"veraltet": "eol", "aktuell": "current", "unbekannt": "unbekannt"}
FRONTEND_STATUS = {"eol", "minor_eol", "outdated", "current", "unbekannt"}

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "facts" / "tech_quellen"

LUMBECK_WOLTER = "c3d5724c-bdbf-4da8-982f-4f1a52210e28"
JUNKERWERK = "31d67a02-b485-4d05-b228-dbdde092cc68"
DORTMUND_BEACH = "1fbc92b9-34ab-414e-8843-a1f1e9f15431"
DORTMUND_BEACH_S0B = "14272c00-1145-4675-9b4c-19ce2ead403b"
CASTENOW = "1f8bc977-39a7-47c7-b4ad-7b05dbac2d52"


def _bericht(order_id: str) -> dict[str, list[tuple[str, str, str]]]:
    out: dict[str, list[tuple[str, str, str]]] = {}
    for block in data_for(order_id).architecture.tech:
        ip = block.host.split(" ", 1)[0]
        out[ip] = [(r.c, r.v, BERICHT_ZU_DASHBOARD[r.status]) for r in block.rows]
    return out


def _dashboard(order_id: str) -> dict[str, list[tuple[str, str, str]]]:
    out: dict[str, list[tuple[str, str, str]]] = {}
    for profile in tech_profiles_from_facts(facts_for(order_id), []):
        rows = profile["tech_rows"]
        if rows:
            out[profile["ip"]] = [(r["name"], r["version"] or "unbekannt", r["status"]) for r in rows]
    return out


def _zeilen(order_id: str) -> list[dict]:
    return [r for p in tech_profiles_from_facts(facts_for(order_id), []) for r in p["tech_rows"]]


@pytest.mark.parametrize("order_id", ORDERS)
def test_komponente_version_und_patchstatus_wie_im_bericht(order_id: str) -> None:
    assert _dashboard(order_id) == _bericht(order_id)


@pytest.mark.parametrize("order_id", ORDERS)
def test_nur_status_die_das_frontend_kennt(order_id: str) -> None:
    for row in _zeilen(order_id):
        assert row["status"] in FRONTEND_STATUS, row
        # Ein EOL-Datum nur bei Status eol: TechTable.tsx zeigt jedes gesetzte Datum.
        assert not row["eol_date"] or row["status"] == "eol", row
        assert row["latest_patch"] == "" and row["cves"] == [] and row["is_mega_cve"] is False


def test_profilfelder_bleiben_und_zeilen_werden_ersetzt() -> None:
    facts = build_facts(FIXTURE)
    alt = {"ip": "203.0.113.10", "waf": "Cloudflare", "open_ports": [80], "tech_rows": [{"name": "alt"}]}
    (profil,) = tech_profiles_from_facts(facts, [alt])
    assert profil["waf"] == "Cloudflare" and profil["open_ports"] == [80]
    assert all(r["name"] != "alt" for r in profil["tech_rows"])


def test_host_ohne_profil_bekommt_ein_minimalprofil() -> None:
    facts = build_facts(FIXTURE)
    (profil,) = tech_profiles_from_facts(facts, [])
    assert profil["ip"] == "203.0.113.10" and profil["fqdns"] == ["www.example.test"]
    assert profil["tech_rows"]


# ---------------------------------------------------------------- Regressionsfaelle

def _zeilen_synthetisch() -> dict[str, dict]:
    (profil,) = tech_profiles_from_facts(build_facts(FIXTURE), [])
    return {r["name"]: r for r in profil["tech_rows"]}


def test_mariadb_praefix_ohne_eol_synthetisch() -> None:
    rows = _zeilen_synthetisch()
    assert "MySQL" not in rows
    maria = rows["MariaDB"]
    assert maria["version"].startswith("10.11.18") and maria["status"] != "eol" and maria["eol_date"] == ""


def _werkzeugmeldungen_synthetisch() -> list[str]:
    return [t.what for t in tech_tool_findings(build_facts(FIXTURE))]


def test_postgresql_or_later_ohne_version_und_eol_synthetisch() -> None:
    """S6b-2 (Entscheidung DC 25.09.): nmap mit "or later" allein hat Konfidenz mittel.

    Die Zeile steht nicht in der Technologietabelle, sondern als Werkzeugmeldung im
    Anhang, weiterhin ohne Version und ohne EOL.
    """
    assert "PostgreSQL" not in _zeilen_synthetisch()
    assert "Technik: PostgreSQL" in _werkzeugmeldungen_synthetisch()


def test_jquery_migrate_bleibt_jquery_migrate_synthetisch() -> None:
    rows = _zeilen_synthetisch()
    meldungen = _werkzeugmeldungen_synthetisch()
    assert "jQuery Migrate" not in rows and "Technik: jQuery Migrate 3.4.1" in meldungen
    assert not any(m.startswith("Technik: jQuery 3.4.1") for m in meldungen)
    assert "jQuery" not in rows or rows["jQuery"]["version"] == ""


@pytest.mark.parametrize("order_id", [LUMBECK_WOLTER, JUNKERWERK])
def test_scanrunde_mariadb_und_postgresql_ohne_eol(order_id: str) -> None:
    rows = _zeilen(order_id)
    names = {r["name"] for r in rows}
    assert "MySQL" not in names
    maria = [r for r in rows if r["name"] == "MariaDB"]
    assert maria and all(r["version"].startswith("10.11.18") and r["status"] != "eol"
                         and r["eol_date"] == "" for r in maria)
    # S6b-2: PostgreSQL "9.6.0 or later" kennt nur nmap mit Konfidenz mittel; die Zeile
    # steht als Werkzeugmeldung im Anhang, nie mit Version 9.6 oder EOL.
    assert not [r for r in rows if r["name"] == "PostgreSQL"]
    meldungen = [t.what for t in tech_tool_findings(facts_for(order_id))]
    assert "Technik: PostgreSQL" in meldungen
    assert not any("9.6" in m for m in meldungen)
    # Quelle ist nmap, webtech lieferte nichts (no_tech_signals).
    assert all("webtech" not in r["source"] for r in maria)


@pytest.mark.parametrize("order_id", [DORTMUND_BEACH, DORTMUND_BEACH_S0B, CASTENOW])
def test_scanrunde_jquery_migrate_ist_nicht_jquery(order_id: str) -> None:
    rows = _zeilen(order_id)
    # S6b-2: jQuery Migrate kennt nur httpx (Konfidenz mittel), also Anhang statt Tabelle.
    meldungen = [t.what for t in tech_tool_findings(facts_for(order_id))]
    assert "Technik: jQuery Migrate 3.4.1" in meldungen
    assert not any(m == "Technik: jQuery 3.4.1" for m in meldungen)
    assert not any(r["name"] == "jQuery" and r["version"] == "3.4.1" for r in rows)
    for tech in (data_for(order_id).architecture.tech):
        assert not any(r.c == "jQuery" and r.v == "3.4.1" for r in tech.rows)


# ---------------------------------------------------------------- S6b-2 (spec/07 Abschluss S6b-1, Frage 7)

HEUEL = "2e56abe1-c1a6-442e-b36a-dc9f83c81da8"


def test_heuel_rohbezeichner_nicht_in_tabelle_und_hostkarte() -> None:
    """www51 zeigte "Neos Flow:neos" und "Java/Servlet" in Tabelle und Hostkarte."""
    namen = {r.c for block in data_for(HEUEL).architecture.tech for r in block.rows}
    namen |= {r["name"] for r in _zeilen(HEUEL)}
    assert not any(":" in n for n in namen), namen
    assert "Neos Flow:neos" not in namen and "Java/Servlet" not in namen
    meldungen = [t.what for t in tech_tool_findings(facts_for(HEUEL))]
    assert any(m.startswith("Technik: Neos Flow") for m in meldungen), meldungen
    assert not any(":neos" in m for m in meldungen)


@pytest.mark.parametrize("order_id", ORDERS)
def test_jede_technikzeile_erreicht_die_schwelle(order_id: str) -> None:
    from reporter.v3.chapters import TECH_MIN_CONFIDENCE, TECH_MIN_SOURCES, tech_lines

    for lines in tech_lines(facts_for(order_id)).values():
        for line in lines:
            quellen = [q for q in line.sources.split(", ") if q]
            assert line.confidence >= TECH_MIN_CONFIDENCE or len(quellen) >= TECH_MIN_SOURCES, (
                order_id, line.product, line.sources, line.confidence)
