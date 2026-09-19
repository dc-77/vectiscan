"""Ausdruckssprache: Whitelist, Dreiwertigkeit, statische Pruefung, Funktionen."""
from __future__ import annotations

import pytest

from reporter.catalog import tables as T
from reporter.catalog.expr import CALLABLE, CatalogSpecError, compile_expr
from reporter.facts import schema as FS

TYPES = {"service": FS.ServiceFact, "tls": FS.TlsFact, "http": FS.HttpFact, "dns": FS.DnsFact, "host": FS.HostFact,
         "services": list, "ports": set, "coverage_ok": CALLABLE, "alert": FS.WebAlert}


def comp(text: str):
    return compile_expr(text, where="test", types_=TYPES, tables=T.EXPR_TABLES)


def svc(**kw) -> FS.ServiceFact:
    base = dict(id="svc:1", source="nmap", mode="active", confidence=1.0, host_ip="10.0.0.1", port=21, proto="tcp", state="open")
    base.update(kw)
    return FS.ServiceFact(**base)


def test_vergleich_mit_none_ist_false():
    e = comp("service.tls_required is True")
    assert e.test({"service": svc(tls_required=None)}) is False
    assert e.test({"service": svc(tls_required=True)}) is True
    e2 = comp("service.version_norm != '1.0'")
    assert e2.test({"service": svc(version_norm=None)}) is False
    e3 = comp("service.port not in [21]")
    assert e3.test({"service": svc(port=22)}) is True


def test_none_propagation_und_dict_get():
    e = comp('tls.cert.mismatch is True')
    tls = FS.TlsFact(id="tls:1", source="httpx", mode="active", confidence=1.0, host_ip="10.0.0.1", port=443, cert=None)
    assert e.test({"tls": tls}) is False
    e2 = comp('http.security_headers["x-frame-options"].present is False')
    http = FS.HttpFact(id="http:1", source="header_check", mode="active", confidence=1.0, host_ip="10.0.0.1")
    assert e2.test({"http": http}) is False


def test_optional_bool_ohne_is_ist_ladefehler():
    with pytest.raises(CatalogSpecError):
        comp("not service.starttls")
    with pytest.raises(CatalogSpecError):
        comp("service.starttls == True")
    with pytest.raises(CatalogSpecError):
        comp("service.starttls and service.port == 21")
    with pytest.raises(CatalogSpecError):
        comp("service.starttls")
    comp("service.starttls is not True")  # erlaubt
    comp("service.tunnel_ssl")            # bool ohne Optional ist erlaubt


def test_tippfehler_im_feld_ist_ladefehler():
    with pytest.raises(CatalogSpecError):
        comp("service.prot == 'tcp'")
    with pytest.raises(CatalogSpecError):
        comp("tls.cert.mismatched is True")


def test_verbotene_syntax():
    for text in ("__import__('os')", "service.port + 1", "[x for x in services]", "service.product.lower()",
                 "lambda: 1", "service.port == None", "foo(1)", "unbekannt == 1", "ports[0:2]"):
        with pytest.raises(CatalogSpecError):
            comp(text)


def test_funktionen():
    services = [svc(port=80), svc(port=443, id="svc:2")]
    ctx = {"services": services, "host": None, "service": svc(product="Apache httpd 2.4.41", version_raw="2.4.41")}
    assert comp("has_port(services, 80) and not has_port(services, 8080)").test(ctx)
    assert comp("len(services) == 2").test(ctx)
    assert comp("matches(service.product, 'apache')").test(ctx)
    assert comp("matches(service.product, ADMIN_PRODUCTS)").test(ctx) is False
    assert comp("has_version(service.version_raw)").test(ctx)
    assert comp("any_in([\"3des\", \"cbc\"], TLS_WEAK_CIPHER_KEYS)").test(ctx)
    assert comp("any_attr(services, 'port', [443])").test(ctx)
    assert comp("service.port in DB_PORTS").test({"service": svc(port=3306)})
    assert comp("startswith(service.service, 'http')").test({"service": svc(service="https-alt")})
    assert comp("matches(None, ADMIN_TITLES)").test({}) is False


def test_zap_match_name_und_id():
    a = FS.WebAlert(plugin_id="10020", name="Multiple X-Frame-Options Header Entries", risk="Medium")
    b = FS.WebAlert(plugin_id="10020", name="Missing Anti-clickjacking Header", risk="Medium")
    c = FS.WebAlert(plugin_id=None, name="Absence of Anti-CSRF Tokens", risk="Medium")
    e = comp("zap_match(alert, ZAP_CSRF)")
    assert e.test({"alert": c}) is True
    assert e.test({"alert": a}) is False
    dup = [("10020", r"multiple x-frame-options")]
    assert compile_expr("zap_match(alert, [('10020', 'multiple x-frame-options')])", where="t", types_=TYPES) is not None
    from reporter.catalog.expr import f_zap_match
    assert f_zap_match(a, dup) is True
    assert f_zap_match(b, dup) is False


def test_kontextfunktion():
    e = comp("coverage_ok('nmap')")
    assert e.test({"coverage_ok": lambda tool: tool == "nmap"}) is True
    with pytest.raises(CatalogSpecError):
        e.test({})


def test_vergleichskette_und_in():
    e = comp("1 <= service.port <= 1024")
    assert e.test({"service": svc(port=443)})
    assert not e.test({"service": svc(port=8443)})
    assert comp("service.port in [80, 443]").test({"service": svc(port=80)})
