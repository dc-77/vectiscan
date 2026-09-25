# -*- coding: utf-8 -*-
"""Maßnahmenplan: eine Zeile je Maßnahmentext (S6a, S6b-2 spec/09 Q6).

Hündgen, Seite 11: VS-004/007 und VS-006/010 trugen denselben Maßnahmentext und
standen als zwei Planzeilen da, die sich nur im Effekt unterschieden (S6a). Die
Scan-Runde zeigte den Rest (spec/09 Q6): gleicher Text in zwei oder drei Zeilen,
verschiedene Texte in einer Zeile, der Effekt „Schützt die Authentizität der eigenen
E-Mail" bei DNSSEC und CAA, Hebeltitel mit Hostnamen. Jetzt trägt jeder Befund die
Maßnahme, Stufe, Effekt und Hebeltitel seiner führenden Regel; der Plan gruppiert nur.
Die Fixtures sind synthetisch; die Golden-Aufträge prüft test_s6b2.
"""
from __future__ import annotations

from reporter.v3 import narrative as N
from reporter.v3 import plan as P
from reporter.v3.bundles import Consolidated
from reporter.v3.models import Finding

GLEICH = "Versionsangaben in den Antworten der Dienste abschalten."
EFFEKT_BANNER = "Nimmt Angreifern die Versionsangaben für gezielte Angriffe"
EFFEKT_TLS = "Härtet die Transportverschlüsselung"


def _paar(fid: str, *, key: str, merge_key: str, cat: str, scale: str = "hygiene",
          level: str = "mittel", status: str = "gelb", stage: str = "mittelfristig",
          text: str = GLEICH, effect: str = EFFEKT_BANNER,
          lever: str = "Versionsangaben abschalten") -> tuple[Consolidated, Finding]:
    item = Consolidated(key=key, is_bundle=True, merge_key=merge_key, category=cat,
                        scale=scale, level=level, title="t", target="findings", positive=False)
    finding = Finding(id=fid, cat=cat, status=status, urgency="Mittelfristig", title=f"Titel {fid}",
                      affected="a", source="s", scale=scale, level=level, found="f",
                      plan_action=text, plan_stage=stage, plan_effect=effect, plan_lever=lever)
    return item, finding


def _huendgen_paare():
    """Zwei Gruppen mit demselben Text: je zwei Befunde auf zwei Hosts, Kategorien D und E."""
    return [
        _paar("VS-2026-004", key="web_header_hygiene", merge_key="217.160.231.238", cat="D"),
        _paar("VS-2026-007", key="tls_hardening", merge_key="217.160.231.238", cat="D", level="niedrig",
              effect=EFFEKT_TLS),
        _paar("VS-2026-006", key="banner_disclosure", merge_key="80.90.145.166", cat="E"),
        _paar("VS-2026-010", key="cert_health", merge_key="80.90.145.166", cat="E", level="niedrig"),
    ]


def test_gleicher_text_eine_zeile_mit_allen_befunden_und_effekten_der_regeln():
    plan = P.build_plan(_huendgen_paare())
    zeilen = [z for z in plan if z.action == GLEICH]
    assert len(zeilen) == 1, [z.refs for z in plan]
    (zeile,) = zeilen
    assert zeile.refs == ["VS-2026-004", "VS-2026-006", "VS-2026-007", "VS-2026-010"]
    assert zeile.effect.split(P.PLAN_EFFECT_SEP) == [EFFEKT_BANNER, EFFEKT_TLS]


def test_jeder_befund_bleibt_genau_einmal_im_plan():
    paare = _huendgen_paare() + [
        _paar("VS-2026-001", key="db_exposed", merge_key="scan", cat="A", scale="exposure",
              level="kritisch", status="rot", stage="unverzueglich", text="Datenbankports sperren.",
              effect="Nimmt die Datenbanken aus dem Internet", lever="Datenbankports sperren"),
    ]
    refs = [r for z in P.build_plan(paare) for r in z.refs]
    assert sorted(refs) == sorted(f.id for _, f in paare)
    assert len(refs) == len(set(refs))


def test_gleicher_effekt_steht_nur_einmal():
    paare = [
        _paar("VS-2026-002", key="tls_hardening", merge_key="10.0.0.1", cat="D", effect=EFFEKT_TLS),
        _paar("VS-2026-003", key="tls_hardening", merge_key="10.0.0.2", cat="D", effect=EFFEKT_TLS),
    ]
    (zeile,) = P.build_plan(paare)
    assert zeile.refs == ["VS-2026-002", "VS-2026-003"]
    assert zeile.effect == EFFEKT_TLS


def test_kein_kategorieeffekt_mehr():
    """DNSSEC und CAA bekommen den Effekt ihrer Regel, nicht den Mail-Satz der Kategorie C."""
    assert not hasattr(N, "PLAN_EFFECT")
    paare = [_paar("VS-2026-009", key="dns_integrity", merge_key="example.test", cat="C",
                   text="DNSSEC für die Zone aktivieren.", effect="Schützt DNS-Antworten vor Fälschung")]
    (zeile,) = P.build_plan(paare)
    assert zeile.effect == "Schützt DNS-Antworten vor Fälschung"
    assert "E-Mail" not in zeile.effect


def test_zusammengefuehrte_zeile_traegt_die_schwerere_farbe():
    """Mittelfristig umfasst gelb und blau; die Zeile nimmt die Farbe des schwersten Befunds."""
    paare = [
        _paar("VS-2026-008", key="dns_hygiene", merge_key="a.example.test", cat="E", level="niedrig",
              status="blau"),
        _paar("VS-2026-005", key="mail_records", merge_key="b.example.test", cat="C", level="hoch",
              status="gelb"),
    ]
    (zeile,) = [z for z in P.build_plan(paare) if z.action == GLEICH]
    assert zeile.st == "gelb"
    assert zeile.refs[0] == "VS-2026-005"


def test_spitzensatz_steht_vor_dem_effekt_der_ersten_roten_zeile():
    text = "Zugriff aus dem Internet sperren."
    paare = [
        _paar("VS-2026-001", key="db_exposed", merge_key="10.0.0.1", cat="A", scale="exposure",
              level="kritisch", status="rot", stage="unverzueglich", text=text,
              effect="Nimmt die Datenbanken aus dem Internet"),
        _paar("VS-2026-002", key="admin_access", merge_key="10.0.0.2", cat="A", scale="exposure",
              level="kritisch", status="rot", stage="unverzueglich", text=text,
              effect="Nimmt die Verwaltungsoberfläche aus dem Internet"),
    ]
    plan = P.build_plan(paare)
    assert plan[0].st == "rot"
    assert plan[0].effect.split(P.PLAN_EFFECT_SEP) == [
        N.PLAN_EFFECT_TOP, "Nimmt die Datenbanken aus dem Internet",
        "Nimmt die Verwaltungsoberfläche aus dem Internet"]


def test_verschiedene_texte_bleiben_getrennt():
    paare = [
        _paar("VS-2026-002", key="tls_hardening", merge_key="10.0.0.1", cat="D", text="TLS 1.0 abschalten."),
        _paar("VS-2026-003", key="banner_disclosure", merge_key="10.0.0.2", cat="E"),
    ]
    plan = P.build_plan(paare)
    assert len(plan) == 2
    assert all(len({z.action}) == 1 for z in plan)


def test_hebel_folgen_der_zeile_und_tragen_den_regeltitel():
    plan = P.build_plan(_huendgen_paare())
    findings = [f for _, f in _huendgen_paare()]
    (hebel,) = P.build_levers(plan, findings)
    assert hebel.refs == plan[0].refs and hebel.effect == plan[0].effect
    assert hebel.title == "Versionsangaben abschalten"
    assert "217.160.231.238" not in hebel.title
