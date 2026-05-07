"""Tests fuer F-KI2-001 — KI #2 Tech-Analysis Schema/System-Prompt.

Coverage:
- Schema ist Open-List (cms-Feld kann beliebige neue CMS-Strings
  aufnehmen, kein enum mehr).
- System-Prompt enthaelt Phase-1-Bestaetigungs-Regel.
- System-Prompt enthaelt DACH-CMS-Indikatoren (Pimcore, Sulu, Plone,
  Craft, Statamic).
- System-Prompt enthaelt Hosted-CMS-Hinweis (Webflow/Shopify/Wix/
  Squarespace/HubSpot).
"""

import json

from scanner.ai_strategy import TECH_ANALYSIS_SCHEMA, TECH_ANALYSIS_SYSTEM


def test_schema_open_list_no_enum_for_cms():
    """cms ist offene Liste — keine Pipe-Closed-List mehr."""
    # Alte Closed-List "WordPress|TYPO3|Shopware|Joomla|Drupal|Exchange|null"
    # darf nicht mehr als enum-Definition vorhanden sein.
    assert "WordPress|TYPO3|Shopware|Joomla|Drupal|Exchange|null" \
        not in TECH_ANALYSIS_SCHEMA, \
        "Schema enthaelt noch Closed-List-Enum fuer cms"
    # Open-List-Marker
    assert "Liste nicht abschließend" in TECH_ANALYSIS_SCHEMA \
        or "nicht abschliessend" in TECH_ANALYSIS_SCHEMA


def test_schema_lists_dach_cms_examples():
    """Schema-Beispielliste enthaelt die DACH-CMS aus F-PH1-001."""
    for cms_name in ("Pimcore", "Sulu", "Plone", "Craft CMS",
                     "Statamic", "SilverStripe"):
        assert cms_name in TECH_ANALYSIS_SCHEMA, \
            f"{cms_name} fehlt in Schema-Beispielliste"


def test_schema_lists_hosted_cms_examples():
    """Schema-Beispielliste enthaelt Hosted-CMS / Website-Builder."""
    for cms_name in ("Webflow", "Shopify", "HubSpot",
                     "Wix", "Squarespace"):
        assert cms_name in TECH_ANALYSIS_SCHEMA, \
            f"{cms_name} fehlt in Schema-Beispielliste"


def test_system_prompt_phase1_confirmation_rule():
    """System-Prompt verlangt Phase-1-Bestaetigung bei hoher Konfidenz."""
    # Mindestens eines der Schluesselwoerter zur Phase-1-Bestaetigung
    p = TECH_ANALYSIS_SYSTEM.lower()
    assert "phase-1" in p
    assert ("0.85" in TECH_ANALYSIS_SYSTEM
            or ">= 0.85" in TECH_ANALYSIS_SYSTEM
            or ">=0.85" in TECH_ANALYSIS_SYSTEM)
    assert "bestätig" in p or "bestaetig" in p


def test_system_prompt_dach_indicators():
    """System-Prompt enthaelt DACH-CMS-Detection-Marker."""
    # Pimcore-Marker
    assert "pimcore" in TECH_ANALYSIS_SYSTEM.lower()
    assert "/var/areas/" in TECH_ANALYSIS_SYSTEM
    # Sulu-Marker
    assert "sulu" in TECH_ANALYSIS_SYSTEM.lower()
    # Plone-Marker
    assert "plone" in TECH_ANALYSIS_SYSTEM.lower()
    # Craft + Statamic
    assert "craft" in TECH_ANALYSIS_SYSTEM.lower()
    assert "statamic" in TECH_ANALYSIS_SYSTEM.lower()


def test_system_prompt_hosted_cms_hint():
    """Hosted-CMS-Hinweis vorhanden (kein Server-Side-Scan-Wert)."""
    p = TECH_ANALYSIS_SYSTEM.lower()
    assert "hosted" in p or "website-builder" in p or "website builder" in p
    # mindestens 3 der 5 Hosted-Plattformen erwaehnt
    hosted = ["webflow", "shopify", "hubspot", "wix", "squarespace"]
    found = sum(1 for h in hosted if h in p)
    assert found >= 3, f"nur {found}/5 Hosted-CMS erwaehnt"


def test_schema_is_renderable_in_user_prompt():
    """Schema-String muss sich in einen User-Prompt einfuegen lassen
    ohne JSON-Strukturkonflikte (Smoke-Test)."""
    # Der Schema-String ist Teil des Haiku-User-Prompts via f-String.
    # Sicherstellen, dass keine Python-Format-Marker drin sind.
    rendered = f"Antwort: {TECH_ANALYSIS_SCHEMA}"
    assert "{" in rendered and "}" in rendered
    # Keine doppelten {{ }} (was auf alte format-Strings hindeutet).
    assert "{{" not in rendered
    # Schema enthaelt ein cms-Feld.
    assert '"cms"' in rendered
    # Validitaets-Check: das umgebende Objekt parsed zumindest nicht
    # als JSON, weil es ein Doku-Schema mit Pipe-Beispielen ist — wir
    # erwarten also bewusst KEINEN Parse. Stattdessen: Felder vorhanden.
    assert '"cms_confidence"' in TECH_ANALYSIS_SCHEMA
    assert '"is_spa"' in TECH_ANALYSIS_SCHEMA
    # Sentinel: json.dumps des Strings darf nicht crashen.
    assert json.dumps(TECH_ANALYSIS_SCHEMA)
