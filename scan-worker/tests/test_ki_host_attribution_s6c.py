"""S6c/8, N4 (spec/09, spec/11 Teil 6): KI-Regelwahl und Tech nur vom eigenen Host.

- "or later" wird als Untergrenze normalisiert (JW PostgreSQL).
- Exchange-Build nur aus Spider-URLs des eigenen Hosts (JW Hetzner).
- Seiten-Signale (Webflow) einer Weiterleitung fallen nicht dem Ausgangshost zu (BS).
"""

from scanner import phase1
from scanner.phase0a import build_passive_intel_for_ai
from scanner.tech_enricher import _exchange_build_from_zap


def test_passive_intel_behaelt_rohwert() -> None:
    """S6c/8: der Rohwert bleibt im KI-#1-Input, die S6a2-Prompt-Regel wirkt."""
    results = {"shodan_hosts": {"116.202.77.64": {
        "ports": [5432],
        "services": [{"port": 5432, "product": "PostgreSQL", "version": "9.6.0 or later"}],
    }}}
    intel = build_passive_intel_for_ai(results, "116.202.77.64")
    assert intel["shodan_services"]["5432"] == "PostgreSQL 9.6.0 or later"


def test_exchange_build_nur_vom_eigenen_host() -> None:
    """JW: Spider-URL von autodiscover (Fremdhost) traegt keinen Build am Hetzner-Host."""
    zap = {"urls": [
        "https://autodiscover.junkerwerk.de/owa/auth/15.2.2562/logon.aspx",
    ]}
    # Fremder Host: kein Build fuer 188.40.3.130.
    assert _exchange_build_from_zap(zap, own_hosts={"cloud.junkerwerk.de"}) is None
    # Eigener Host: Build kommt an.
    assert _exchange_build_from_zap(zap, own_hosts={"autodiscover.junkerwerk.de"}) == "15.2.2562"


def test_tech_signals_ohne_weiterleitungsziel() -> None:
    """BS: ftp leitet auf die Webflow-www weiter; Webflow darf nicht dem Host zufallen."""
    redirect_data = {
        "ftp.bergersysteme.com": {
            "is_cross_domain": True,
            "final_url": "https://www.bergersysteme.com/",
            "response_headers": {"server": "Apache"},
            "tech_info": {"generator": "Webflow", "scripts": ["https://assets.website-files.com/x.js"]},
        },
    }
    techs = {t["name"].lower() for t in phase1._extract_all_tech_signals(redirect_data)}
    assert "webflow" not in techs
    assert "apache" in techs


def test_tech_signals_gleicher_host_bleibt() -> None:
    redirect_data = {
        "www.kunde.de": {
            "is_cross_domain": False,
            "final_url": "https://www.kunde.de/",
            "response_headers": {"server": "nginx"},
            "tech_info": {"generator": "WordPress 6.5"},
        },
    }
    techs = {t["name"].lower() for t in phase1._extract_all_tech_signals(redirect_data)}
    assert "wordpress" in techs
