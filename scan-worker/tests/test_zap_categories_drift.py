"""S0b: Kategorienamen duerfen nicht auseinanderlaufen.

Eine Active-Scan-Kategorie taucht an drei Stellen auf: im Katalog
``ZapClient.CATEGORY_SCANNER_IDS``, in der regelbasierten Phase-2-Konfiguration
und im Prompt fuer KI #3. Steht dort ein Name, den der Katalog nicht kennt,
liefert ``CATEGORY_SCANNER_IDS.get(cat, [])`` still eine leere Liste: die
Kategorie verspricht eine Pruefung, die nie laeuft.

Genau das war der Fall fuer "path_traversal" (der Katalog schreibt
"pathtraversal"), "auth_bypass" (gibt es nirgends) und "ssrf" (die ZAP-Regel
40046 ist im gepinnten Image nicht enthalten).
"""

import re

import pytest

from scanner import ai_strategy, phase2, phase2_config_rules
from scanner.tools.zap_client import ZapClient

RULE_LISTS = {
    "_CATEGORIES_FULL": phase2_config_rules._CATEGORIES_FULL,
    "_CATEGORIES_WAF_SAFE": phase2_config_rules._CATEGORIES_WAF_SAFE,
    "_CATEGORIES_API": phase2_config_rules._CATEGORIES_API,
}


class TestRegelkonfiguration:
    @pytest.mark.parametrize("name", sorted(RULE_LISTS))
    def test_kategorien_stehen_im_katalog(self, name):
        unbekannt = [c for c in RULE_LISTS[name]
                     if c not in ZapClient.CATEGORY_SCANNER_IDS]
        assert not unbekannt, (
            f"{name} nennt Kategorien, die der Katalog nicht kennt: {unbekannt}"
        )

    @pytest.mark.parametrize("name", sorted(RULE_LISTS))
    def test_keine_nicht_verfuegbaren_kategorien(self, name):
        blockiert = [c for c in RULE_LISTS[name]
                     if c in ZapClient.CATEGORIES_UNAVAILABLE]
        assert not blockiert, (
            f"{name} verspricht {blockiert}, im eingesetzten ZAP-Image nicht "
            f"vorhanden: {ZapClient.CATEGORIES_UNAVAILABLE}"
        )

    @pytest.mark.parametrize("name", sorted(RULE_LISTS))
    def test_jede_kategorie_hat_mindestens_eine_regel(self, name):
        leer = [c for c in RULE_LISTS[name]
                if not ZapClient.CATEGORY_SCANNER_IDS.get(c)]
        assert not leer, f"{name} enthaelt leere Kategorien: {leer}"


class TestKiPrompt:
    """Der Prompt darf KI #3 nur Kategorien anbieten, die es auch gibt."""

    def _im_prompt_genannte_kategorien(self) -> set[str]:
        block = ai_strategy.PHASE2_CONFIG_SYSTEM
        start = block.find("zap_active_categories")
        ende = block.find("- zap_rate_req_per_sec", start)
        assert start != -1 and ende != -1, "Prompt-Abschnitt nicht gefunden"
        return set(re.findall(r'^\s+- "([a-z_]+)"', block[start:ende], re.MULTILINE))

    def test_angebotene_kategorien_existieren(self):
        angeboten = self._im_prompt_genannte_kategorien()
        assert angeboten, "Prompt bietet gar keine Kategorie an"
        unbekannt = angeboten - set(ZapClient.CATEGORY_SCANNER_IDS)
        assert not unbekannt, f"Prompt bietet unbekannte Kategorien an: {unbekannt}"

    def test_nicht_verfuegbare_werden_nicht_angeboten(self):
        angeboten = self._im_prompt_genannte_kategorien()
        blockiert = angeboten & set(ZapClient.CATEGORIES_UNAVAILABLE)
        assert not blockiert, (
            f"Prompt bietet {blockiert} an, obwohl die Regel im Image fehlt"
        )

    def test_fallback_config_ist_gueltig(self):
        fallback = ai_strategy.PHASE2_CONFIG_SCHEMA
        genannt = set(re.findall(r'"([a-z_]+)"',
                                 re.search(r'"zap_active_categories": \[([^\]]*)\]',
                                           fallback).group(1)))
        assert genannt <= set(ZapClient.offered_categories())


class TestOfferedCategories:
    def test_leere_und_blockierte_fallen_raus(self):
        angeboten = ZapClient.offered_categories()
        assert "ssrf" not in angeboten
        assert "defaultlogin" not in angeboten
        assert "sqli" in angeboten
        assert "xss" in angeboten

    def test_unbekannte_kategorie_liefert_keine_ids(self):
        zap = ZapClient(base_url="http://localhost:8090")
        enabled, dropped = zap.resolve_scanner_ids(["gibtsnicht"])
        assert enabled == set()
        assert dropped == set()


class TestKiAntwortWirdGefiltert:
    """Eine gecachte KI-Antwort darf keine tote Kategorie durchreichen.

    Der Cache-Key haengt nicht am System-Prompt (ai_cache.cache_key, Modus
    content_hash und order_scope). Eine Antwort von vor der Prompt-Aenderung
    kann also weiter "ssrf" nennen.
    """

    def _lauf(self, monkeypatch, antwort):
        import scanner.phase2_config_rules as rules
        # Rule-Engine abschalten, damit der KI-Pfad genommen wird.
        monkeypatch.setattr(rules, "try_rule_based_config", lambda *a, **k: None)
        monkeypatch.setattr(ai_strategy, "_call_haiku", lambda *a, **k: dict(antwort))
        monkeypatch.setattr(ai_strategy, "_save_ai_debug", lambda *a, **k: None)
        return ai_strategy.plan_phase2_config(
            {"ip": "1.2.3.4", "fqdns": ["x.example"]}, {"domain": "example"},
            "perimeter", order_id="")

    def test_ssrf_wird_entfernt(self, monkeypatch):
        result = self._lauf(monkeypatch, {
            "zap_scan_policy": "standard",
            "zap_active_categories": ["sqli", "ssrf", "xss"],
        })
        assert result["zap_active_categories"] == ["sqli", "xss"]

    def test_unbekannter_name_wird_entfernt(self, monkeypatch):
        result = self._lauf(monkeypatch, {
            "zap_scan_policy": "standard",
            "zap_active_categories": ["xss", "auth_bypass", "path_traversal"],
        })
        assert result["zap_active_categories"] == ["xss"]

    def test_gueltige_liste_bleibt_unveraendert(self, monkeypatch):
        result = self._lauf(monkeypatch, {
            "zap_scan_policy": "standard",
            "zap_active_categories": ["sqli", "xss", "lfi", "cmdi"],
        })
        assert result["zap_active_categories"] == ["sqli", "xss", "lfi", "cmdi"]

    def test_auch_der_regelbasierte_pfad_wird_gefiltert(self, monkeypatch):
        """Die Rule-Engine kehrt frueher zurueck als der KI-Pfad."""
        import scanner.phase2_config_rules as rules
        monkeypatch.setattr(
            rules, "try_rule_based_config",
            lambda *a, **k: {"zap_scan_policy": "standard",
                             "zap_active_categories": ["sqli", "ssrf", "auth_bypass"],
                             "reasoning": "[RULE-BASED] test"},
        )
        result = ai_strategy.plan_phase2_config(
            {"ip": "1.2.3.4"}, {"domain": "example"}, "perimeter", order_id="")
        assert result["zap_active_categories"] == ["sqli"]


def test_phase2_default_kategorien_sind_gueltig():
    """Der Default in phase2 greift, wenn KI #3 nichts liefert."""
    quelle = phase2.__file__
    with open(quelle, encoding="utf-8") as fh:
        text = fh.read()
    treffer = re.findall(r'ac\.get\("zap_active_categories", \[([^\]]*)\]\)', text)
    assert treffer, "Default-Kategorienliste in phase2 nicht gefunden"
    for rohliste in treffer:
        kategorien = set(re.findall(r'"([a-z_]+)"', rohliste))
        assert kategorien <= set(ZapClient.offered_categories()), (
            f"phase2-Default nennt nicht angebotene Kategorien: "
            f"{kategorien - set(ZapClient.offered_categories())}"
        )
