"""Tests fuer reporter.title_policy (A1 — deterministische Title-Templates)."""

from reporter.title_policy import (
    TITLE_TEMPLATES,
    apply_title_template,
    apply_titles,
)


def test_dmarc_quarantine_template():
    f = {"policy_id": "SP-DNS-010", "title": "KI variant 1",
         "title_vars": {"domain": "heuel.com"}}
    assert apply_title_template(f) == "DMARC-Policy auf 'quarantine' statt 'reject' fuer heuel.com"


def test_dmarc_quarantine_deterministic_across_variations():
    """Der Bug-Trigger: 3 Wording-Variationen → 1 Title nach Template."""
    titles = []
    for orig in ["DMARC-Policy auf 'quarantine' statt 'reject'",
                 "DMARC-Policy auf Quarantine statt Reject",
                 "dmarc-policy quarantine statt reject"]:
        f = {"policy_id": "SP-DNS-010", "title": orig,
             "title_vars": {"domain": "heuel.com"}}
        titles.append(apply_title_template(f))
    assert len(set(titles)) == 1


def test_missing_template_keeps_original_and_flags():
    f = {"policy_id": "SP-XXX-999", "title": "Original Title"}
    assert apply_title_template(f) == "Original Title"
    assert f.get("_title_template_missing") is True


def test_missing_var_safe_fallback():
    """Fehlende Vars werden zu '?' (kein KeyError)."""
    f = {"policy_id": "SP-CVE-001"}  # vars host/cve_id/tech fehlen
    out = apply_title_template(f)
    assert "?" in out  # alle Vars zu ? gefuellt
    assert "mit aktiven Exploits" in out  # Template-Struktur erhalten


def test_no_policy_id_returns_original():
    f = {"title": "X", "policy_id": ""}
    assert apply_title_template(f) == "X"


def test_apply_titles_batch_count():
    findings = [
        {"policy_id": "SP-HDR-001", "title": "X", "title_vars": {"host": "a.com"}},
        {"policy_id": "SP-DNS-010", "title": "Y", "title_vars": {"domain": "b.com"}},
        {"policy_id": None, "title": "stays"},
        {"policy_id": "SP-XXX-999", "title": "fallback"},  # template missing
    ]
    n = apply_titles(findings)
    assert n == 2
    assert findings[0]["title"] == "HSTS-Header fehlt auf a.com"
    assert findings[1]["title"] == "DMARC-Policy auf 'quarantine' statt 'reject' fuer b.com"
    assert findings[2]["title"] == "stays"
    assert findings[3]["title"] == "fallback"  # missing -> unchanged
    assert findings[3].get("_title_template_missing") is True


def test_scan_context_provides_domain():
    f = {"policy_id": "SP-DNS-006", "title": "X"}
    out = apply_title_template(f, scan_context={"domain": "demo.de"})
    assert "demo.de" in out


def test_host_fallback_from_finding_fields():
    """Wenn host nicht in title_vars: aus vhost/fqdn/host_ip ableiten."""
    f = {"policy_id": "SP-HDR-001", "title": "X", "vhost": "ose.heuel.com"}
    out = apply_title_template(f)
    assert "ose.heuel.com" in out


def test_template_count_minimum():
    """Sanity: mindestens die ~25 wichtigsten policy_ids haben Templates."""
    assert len(TITLE_TEMPLATES) >= 25
