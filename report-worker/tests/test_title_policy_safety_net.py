"""Tests fuer A1+A2 — Title-?-Sicherheitsnetz + Smart-Var-Fallback."""

from reporter.title_policy import apply_title_template, _derive_var_from_finding


def test_safety_net_kicks_in_when_var_missing():
    """A1: rendered hat ?, KI-Original nicht → KI-Original gewinnt."""
    f = {"policy_id": "SP-COOK-004",
         "title": "Original-KI-Title-vollstaendig",
         "title_vars": {"host": "x.com"}}  # cookie_name fehlt
    out = apply_title_template(f)
    assert out == "Original-KI-Title-vollstaendig"
    assert f["_title_template_incomplete"] is True


def test_no_safety_net_when_original_also_has_question_mark():
    """Wenn auch KI-Original ? hat → Template gewinnt trotzdem (kein
    Schaden weil beide gleich schlecht)."""
    f = {"policy_id": "SP-COOK-004",
         "title": "Original ? Title",
         "title_vars": {"host": "x.com"}}
    out = apply_title_template(f)
    # Template wird genommen, da beide ? haben
    assert "?" in out


def test_smart_fallback_cookie_name_from_evidence():
    """A2: cookie_name aus evidence-Header extrahieren."""
    f = {"policy_id": "SP-COOK-004",
         "title": "Session-Cookie ohne Secure",
         "title_vars": {"host": "webmail.x.com"},
         "evidence": "Set-Cookie: roundcube_sessid=abc; Path=/"}
    out = apply_title_template(f)
    assert "roundcube_sessid" in out


def test_smart_fallback_private_ip_from_description():
    f = {"policy_id": "SP-DISC-009",
         "title": "Private IP leakt",
         "vhost": "owa.x.com",
         "description": "Server-Header enthaelt 10.0.0.42 als Private-IP"}
    out = apply_title_template(f)
    assert "10.0.0.42" in out


def test_smart_fallback_directive_from_description():
    """CSP-Directive aus description extrahieren."""
    val = _derive_var_from_finding(
        "directive",
        {"description": "CSP enthaelt unsafe-inline in script-src"},
    )
    assert val == "script-src"


def test_smart_fallback_days_from_description():
    val = _derive_var_from_finding(
        "days",
        {"description": "Cert laeuft in 14 Tagen ab"},
    )
    assert val == "14"


def test_tech_from_tech_profiles_in_scan_context():
    f = {"policy_id": "SP-EOL-001",
         "title": "EOL Software",
         "host_ip": "1.2.3.4"}
    ctx = {"tech_profiles": [
        {"ip": "1.2.3.4", "cms": "WordPress", "server": "nginx/1.20"}
    ]}
    val = _derive_var_from_finding("tech", f, ctx)
    assert val == "WordPress"


def test_complete_template_no_question_mark():
    """Standard-Pfad: alle Vars da → kein ? im Output, kein Flag."""
    f = {"policy_id": "SP-DNS-010",
         "title": "Original",
         "title_vars": {"domain": "x.com"}}
    out = apply_title_template(f)
    assert "?" not in out
    assert "x.com" in out
    assert f.get("_title_template_incomplete") is None
