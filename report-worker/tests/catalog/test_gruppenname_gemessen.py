"""Der Namensgeber einer Gruppe muss im jeweiligen Scope selbst gemessen sein.

Bei lumbeck-wolter (Auftrag 0dc64a85, 26.10.2026) wies der Host die
Webverbindungen nach dem Portscan ab. testssl lief deshalb nur an den Mail- und
FTP-Ports, und diese Fakten haengen am Aliasnamen lumbeck-wolter.de. Die Gruppe
trug trotzdem den kanonischen Webnamen, und ein Befund, dessen einziger Beleg
Port 21 war, las sich als Aussage ueber die Website:
"Transportverschluesselung auf www.lumbeck-wolter.de: kein TLS 1.3".

Gegenprobe heuel: dort liegt der TLS-Fakt am kanonischen Namen und der Alias
teilt sich das Zertifikat. Dieser Name darf sich nicht aendern.
"""

from reporter.catalog.scope import FactsIndex, build_groups

from .conftest import make_facts


def _label(facts, scope, name):
    gruppen = {g.key: g for g in build_groups(FactsIndex(facts), scope, "fqdn")}
    return gruppen[name].label


def test_tls_gruppe_nennt_den_gemessenen_aliasnamen():
    """Ohne TLS am Webnamen benennt die Gruppe den Namen mit der Messung."""
    facts = make_facts({
        "fqdns": [
            {"name": "www.example.test", "host_ip": "10.0.0.1", "http_status": 200,
             "aliases": [{"fqdn": "example.test", "status": 200, "reason": "body-hash-dup"}]},
            {"name": "example.test", "host_ip": "10.0.0.1"},
        ],
        # Nur der Aliasname hat eine Messung, und zwar an einem Mailport.
        "tls": [
            {"fqdn": "example.test", "host_ip": "10.0.0.1", "port": 993, "source": "testssl",
             "protocols": {"TLS1.2": True, "TLS1.3": False}},
        ],
    }, coverage_default="ok")

    assert _label(facts, "tls", "www.example.test@10.0.0.1") == "example.test"


def test_tls_gruppe_behaelt_den_kanonischen_namen_mit_eigener_messung():
    """Gegenprobe heuel: kanonischer Name gemessen, Alias bleibt im Namen."""
    facts = make_facts({
        "fqdns": [
            {"name": "edi.example.test", "host_ip": "10.0.0.1", "http_status": 200,
             "aliases": [{"fqdn": "mail.example.test", "status": 200, "reason": "body-hash-dup"}]},
            {"name": "mail.example.test", "host_ip": "10.0.0.1"},
        ],
        "tls": [
            {"fqdn": "edi.example.test", "host_ip": "10.0.0.1", "port": 443, "source": "testssl",
             "protocols": {"TLS1.2": True, "TLS1.3": True}},
        ],
    }, coverage_default="ok")

    assert _label(facts, "tls", "edi.example.test@10.0.0.1") == "edi.example.test (+mail.example.test)"


def test_ohne_jede_messung_bleibt_der_kanonische_name():
    """Nichts gemessen: der Name bleibt, wie er war (keine stille Umbenennung)."""
    facts = make_facts({
        "fqdns": [
            {"name": "www.example.test", "host_ip": "10.0.0.1", "http_status": 200,
             "aliases": [{"fqdn": "example.test", "status": 200, "reason": "body-hash-dup"}]},
            {"name": "example.test", "host_ip": "10.0.0.1"},
        ],
    }, coverage_default="ok")

    assert _label(facts, "tls", "www.example.test@10.0.0.1").startswith("www.example.test")


def test_scope_ohne_messindex_bleibt_unveraendert():
    """Ein Scope ohne eigenen Messindex (fqdn) benennt weiter kanonisch."""
    facts = make_facts({
        "fqdns": [
            {"name": "www.example.test", "host_ip": "10.0.0.1", "http_status": 200,
             "aliases": [{"fqdn": "example.test", "status": 200, "reason": "body-hash-dup"}]},
            {"name": "example.test", "host_ip": "10.0.0.1"},
        ],
        "tls": [
            {"fqdn": "example.test", "host_ip": "10.0.0.1", "port": 993, "source": "testssl",
             "protocols": {"TLS1.2": True, "TLS1.3": False}},
        ],
    }, coverage_default="ok")

    assert _label(facts, "fqdn", "www.example.test@10.0.0.1") == "www.example.test (+example.test)"
