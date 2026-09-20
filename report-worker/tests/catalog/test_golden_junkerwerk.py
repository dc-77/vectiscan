"""Golden-Tests des Katalogs (Auftrag S2, Abnahme):

1. Drift: die Junkerwerk-Laeufe ergeben auf Member-Ebene dieselben Ergebnisse, bis auf
   Coverage-Unterschiede (not_testable / not_applicable), die in expected_map.json stehen.
   Seit S2c sind es vier Laeufe: die drei vom 31.08. und der Rescan 860d0d5a vom 20.09.,
   der erste mit den Scannerfixen aus S2b und mit einem AAAA-Host. Welche Laeufe verglichen
   werden, steht allein in expected_map.json unter "orders".
2. Soll-Liste: jeder Befund und jede Positivaussage aus tests/golden/expected/junkerwerk.json
   wird von den zugeordneten Pruefungen erzeugt; im strikten Modus faellt kein Check ausserhalb
   der Zuordnung.
3. Negativ-Fixtures: kein Check erzeugt die Aussagen aus tests/golden/negative.json.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path

import pytest

from reporter.catalog.engine import evaluate
from reporter.catalog.schema import CatalogOutput
from tests.catalog.conftest import GOLDEN, get_catalog
from tests.catalog.test_snapshot_orders import facts_for

HERE = Path(__file__).resolve().parent
MAP = json.loads((HERE / "expected_map.json").read_text(encoding="utf-8"))
EXPECTED = json.loads((GOLDEN / "expected" / "junkerwerk.json").read_text(encoding="utf-8"))
NEGATIVE = json.loads((GOLDEN / "negative.json").read_text(encoding="utf-8"))
RUNS = MAP["orders"]
STRICT = bool(MAP.get("strict"))
TRUNK = "45bb234c-d556-4a80-9c78-3ce221ea28a6"

_OUT: dict[str, CatalogOutput] = {}


def out_for(order_id: str) -> CatalogOutput:
    if order_id not in _OUT:
        _OUT[order_id] = evaluate(facts_for(order_id), get_catalog())
    return _OUT[order_id]


def _has(check_id: str) -> bool:
    return check_id in get_catalog().by_id


def _need(check_id: str) -> None:
    if not _has(check_id):
        if STRICT:
            pytest.fail(f"Pruefung {check_id} fehlt im Katalog")
        pytest.skip(f"Pruefung {check_id} noch nicht im Katalog")


def _fails(out: CatalogOutput, check_id: str):
    return [r for r in out.results if r.check_id == check_id and r.status == "fail"]


def _results(out: CatalogOutput, check_id: str):
    return [r for r in out.results if r.check_id == check_id]


# ------------------------------------------------------------------ Soll-Liste

@pytest.mark.parametrize("finding_id", sorted(MAP["findings"]))
def test_soll_befund_wird_erzeugt(finding_id):
    spec = MAP["findings"][finding_id]
    runs = spec.get("runs") or list(RUNS)
    for check_id in spec["checks"]:
        _need(check_id)
        hits = []
        for run in runs:
            for r in _fails(out_for(RUNS[run]), check_id):
                hits.append((run, r))
        assert hits, f"{finding_id}: {check_id} faellt in keinem Lauf {runs}"
        hosts = spec.get("hosts")
        if hosts:
            assert any(any(h in (m.host_ip or "") for m in r.members if m.status == "fail") or any(h in a for a in r.affected)
                       for _, r in hits for h in hosts), f"{finding_id}: {check_id} trifft nicht die erwarteten Hosts {hosts}"


@pytest.mark.parametrize("positive_id", sorted(MAP["positives"]))
def test_soll_positiv_wird_erzeugt(positive_id):
    spec = MAP["positives"][positive_id]
    for check_id in spec["checks"]:
        _need(check_id)
        hits = [r for run in RUNS for r in _results(out_for(RUNS[run]), check_id) if r.status == "pass" and r.positive]
        assert hits, f"{positive_id}: {check_id} besteht in keinem Lauf mit Positivbefund"
        needle = spec.get("group_contains")
        if needle:
            assert any(needle in r.group_key or needle in r.group_label for r in hits), f"{positive_id}: {check_id} positiv, aber nicht fuer {needle}"


def test_kein_fehlschlagender_check_ausserhalb_der_zuordnung():
    allowed: set[str] = set(MAP["subsumed"])
    for spec in MAP["findings"].values():
        allowed.update(spec["checks"])
        allowed.update(spec.get("also", []))
    failing = sorted({r.check_id for run in RUNS for r in out_for(RUNS[run]).results if r.status == "fail" and r.kind == "check"})
    unexpected = [c for c in failing if c not in allowed]
    if not STRICT:
        if unexpected:
            pytest.skip(f"nicht strikt; ausserhalb der Zuordnung: {unexpected}")
        return
    assert not unexpected, f"Checks fallen in Junkerwerk, stehen aber nicht in der Zuordnung: {unexpected}"


def test_alle_familien_der_soll_liste_gemappt():
    mapped = {c for spec in MAP["findings"].values() for c in spec["checks"]}
    assert len(MAP["findings"]) == len(EXPECTED["findings"]) == 15
    assert len(MAP["positives"]) == len(EXPECTED["positives"]) == 8
    assert mapped


# ------------------------------------------------------------------ Drift

def _member_table(out: CatalogOutput) -> dict[tuple[str, str], tuple[str, str]]:
    """(check_id, member_key) -> (status, label) fuer fail/pass-Member; Gruppen ohne Member als (check, group_key)."""
    table: dict[tuple[str, str], tuple[str, str]] = {}
    for r in out.results:
        if r.members:
            for m in r.members:
                table[(r.check_id, m.key)] = (m.status, m.label)
        else:
            table[(r.check_id, "group:" + r.group_key)] = (r.status, r.reason_code or "")
    return table


def _allowed_reason(check_id: str, code: str) -> bool:
    for e in MAP["expected_coverage_differences"]:
        if code == e["reason_code"] and check_id.startswith(e["check_prefix"]):
            return True
    return False


def _allowed_member(check_id: str, key: str) -> bool:
    return any(e["check"] == check_id and e["member"] == key for e in MAP["expected_member_differences"])


def _group_reason(out: CatalogOutput, check_id: str, key: str) -> str:
    for r in out.results:
        if r.check_id != check_id:
            continue
        for m in r.members:
            if m.key == key:
                return m.reason_code or r.reason_code or ""
        if "group:" + r.group_key == key:
            return r.reason_code or ""
    return ""


# Alle Paare aus expected_map.json["orders"]. Seit S2c sind das vier Laeufe
# und damit sechs Paare; frueher standen die drei Paare fest im Code.
PAARE = [(a, b) for i, a in enumerate(RUNS) for b in list(RUNS)[i + 1:]]


@pytest.mark.parametrize("pair", PAARE, ids=lambda p: f"{p[0]}-{p[1]}")
def test_drift_der_laeufe(pair):
    a, b = (out_for(RUNS[pair[0]]), out_for(RUNS[pair[1]]))
    ta, tb = _member_table(a), _member_table(b)
    drift: list[str] = []
    for key in sorted(set(ta) & set(tb)):
        (sa, la), (sb, lb) = ta[key], tb[key]
        decided = {"fail", "pass"}
        if sa in decided and sb in decided:
            if sa != sb or (sa == "fail" and la != lb):
                if _allowed_member(key[0], key[1]):
                    continue
                drift.append(f"{key[0]} {key[1]}: {pair[0]}={sa} ({la}) {pair[1]}={sb} ({lb})")
            continue
        # Coverage-Unterschied: muss begruendet sein
        for out, status in ((a, sa), (b, sb)):
            if status in ("not_testable", "not_applicable"):
                code = _group_reason(out, key[0], key[1]) or status
                if not _allowed_reason(key[0], code) and not _allowed_member(key[0], key[1]):
                    drift.append(f"{key[0]} {key[1]}: unerwarteter Coverage-Unterschied {status} ({code})")
    assert not drift, "Drift zwischen den Laeufen:\n" + "\n".join(drift)


# ------------------------------------------------------------------ Negativ-Fixtures

def _orders(pattern: str) -> list[str]:
    return sorted({e["order"] for e in NEGATIVE["entries"] if e["pattern"] == pattern})


def _all_labels(out: CatalogOutput) -> list[str]:
    labels = []
    for r in out.results:
        labels.extend(r.affected)
        labels.append(r.title)
        labels.append(r.texts.observation)
        if r.texts.positive:
            labels.append(r.texts.positive.title)
            labels.append(r.texts.positive.text)
    return labels


def test_neg_spf_missing():
    _need("spf_missing")
    for oid in _orders("NEG-SPF-MISSING"):
        out = out_for(oid)
        res = [r for r in _results(out, "spf_missing") if r.group_key == out.domain]
        assert res and res[0].status == "pass", (oid, res and res[0].status)


def test_neg_mariadb_55():
    _need("db_exposed")
    for oid in _orders("NEG-MARIADB-55"):
        out = out_for(oid)
        for label in _all_labels(out):
            assert not re.search(r"MySQL\s*5\.5", label), (oid, label)
        for r in _fails(out, "db_exposed"):
            for a in r.affected:
                if ":3306" in a:
                    assert "MariaDB" in a and "5.5" not in a, (oid, a)
        if _has("software_eol"):
            for r in _fails(out, "software_eol"):
                assert not any("MariaDB" in a or "MySQL" in a for a in r.affected), (oid, r.affected)
    if _has("software_eol"):
        trunk = out_for(TRUNK)
        assert any("MariaDB 5.5.68" in a for r in _fails(trunk, "software_eol") for a in r.affected), "trunk: echtes MariaDB 5.5.68 muss EOL sein"


def test_neg_urlhaus_policy():
    _need("urlhaus_compromise")
    for oid in _orders("NEG-URLHAUS-POLICY"):
        assert not _fails(out_for(oid), "urlhaus_compromise"), oid


def test_neg_mail_plaintext():
    _need("mail_plaintext")
    for oid in _orders("NEG-MAIL-PLAINTEXT"):
        fails = _fails(out_for(oid), "mail_plaintext")
        assert not fails, (oid, [r.affected for r in fails])


def test_neg_ftp_plaintext():
    _need("ftp_plaintext")
    for oid in _orders("NEG-FTP-PLAINTEXT"):
        fails = [r for r in _fails(out_for(oid), "ftp_plaintext") if r.group_key == "212.227.60.78"]
        assert not fails, (oid, [r.affected for r in fails])


def test_neg_webserver_eol():
    _need("software_eol")
    for oid in _orders("NEG-WEBSERVER-EOL"):
        out = out_for(oid)
        for r in _fails(out, "software_eol"):
            for a in r.affected:
                assert "1.24.0" not in a and "2.4.41" not in a, (oid, a)


def test_neg_exchange_2016():
    _need("software_eol")
    for oid in _orders("NEG-EXCHANGE-2016"):
        out = out_for(oid)
        for r in out.results:
            if r.status == "fail":
                # verboten ist die Aussage "Exchange 2016"; der Hostname rdgw-2016 ist ein Fakt
                assert not any("Exchange" in a and "2016" in a for a in r.affected), (oid, r.check_id, r.affected)
                if r.check_id in ("software_eol", "software_eol_runtime"):
                    assert not any("Exchange" in a for a in r.affected), (oid, r.affected)
        pos = [r for r in _results(out, "software_eol") if r.group_key == "217.243.248.28"]
        assert pos and pos[0].status == "pass" and pos[0].positive, oid


def test_neg_title_placeholder():
    from tests.catalog.test_snapshot_orders import snapshot_orders
    for oid in snapshot_orders():
        out = out_for(oid)
        for text in _all_labels(out):
            assert "{" not in text and "}" not in text and "[Hinweis" not in text and "?" not in text, (oid, text)


def test_neg_wp_plugin_version():
    _need("wordpress_plugin_vulnerable")
    for oid in _orders("NEG-WP-PLUGIN-VERSION"):
        for r in _fails(out_for(oid), "wordpress_plugin_vulnerable"):
            for a in r.affected:
                name = a.split(": ", 1)[1] if ": " in a else a
                assert not re.match(r"^\d", name), (oid, a)
