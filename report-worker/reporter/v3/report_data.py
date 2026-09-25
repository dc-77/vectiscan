# -*- coding: utf-8 -*-
"""Reportdaten v3: aus Fakten und Prüfergebnis wird das Datenmodell des Prototyps.

Reihenfolge: konsolidieren, Befunde und Positivbefunde bauen, IDs vergeben, daraus
Kapitel, Plan, Hebel und Anhang. Die vier Prosa-Felder werden zuletzt eingesetzt, und
nur, wenn sie das Gate passiert haben; sonst bleibt der deterministische Text stehen.
"""
from __future__ import annotations

from typing import Any, Optional

from reporter.catalog import evaluate as evaluate_catalog
from reporter.catalog.schema import CatalogOutput
from reporter.catalog.version import CATALOG_VERSION
from reporter.facts import schema as FS
from reporter.v3 import chapters as C
from reporter.v3 import coverage as COV
from reporter.v3 import findings as F
from reporter.v3 import ids as IDS
from reporter.v3 import narrative as N
from reporter.v3 import plan as P
from reporter.v3 import research as RESEARCH
from reporter.v3 import tables as T
from reporter.v3.appendix import build_appendix
from reporter.v3.bundles import consolidate
from reporter.v3.models import Meta, OrderRef, ReportData

# Platzhalter, solange kein Kundenname vorliegt; das Gate meldet ihn (S5/S6).
DEFAULT_CUSTOMER = "Auftraggeber"


def _counts(facts: FS.Facts, output: CatalogOutput, n_findings: int, n_positives: int,
            runs: int, model: COV.Model) -> N.Counts:
    members = sum(
        1 for r in output.results if r.status == "fail" for m in r.members if m.status == "fail")
    raw = members + sum(u.count for u in output.unprocessed) + sum(i.count for i in output.ignored)
    fails = output.summary.by_status.get("fail", 0)
    # Je System eine Zeile in 2.1 (IPv4 und IPv6 mit gleichem rDNS); der Satz ueber
    # Luecken zaehlt dieselben Zeilen, sonst widersprechen sich Satz und Tabelle.
    cov = [model.system_status(ips) for ips in model.system_rows()]
    # S6b-1 (spec/09 Q16): Hostnamen eindeutig zaehlen (IPv4 und IPv6 zaehlten doppelt);
    # Drittanbieter-Adressen und ihre Namen sind kein Host des Kunden.
    eigene = [h for h in facts.hosts if h.third_party is None]
    eigene_ips = {h.ip for h in eigene}
    return N.Counts(
        domains=list(facts.scan.domains) or [facts.scan.domain],
        scan_date=C.format_date(facts.scan.finished_at or facts.scan.started_at),
        hosts_total=len(eigene),
        hosts_ipv4=sum(1 for h in eigene if h.family == 4),
        hosts_ipv6=sum(1 for h in eigene if h.family == 6),
        fqdns_total=len({f.name.lower() for f in facts.fqdns if not f.wildcard and f.host_ip in eigene_ips}),
        runs=runs,
        tool_runs=len(facts.coverage),
        raw_findings=raw,
        findings=n_findings,
        positives=n_positives,
        coverage_full=cov.count("voll"),
        coverage_partial=cov.count("teil"),
        coverage_none=cov.count("keine") + cov.count("unerreichbar"),
        duplicates=max(raw - fails, 0),
        not_testable=output.summary.by_status.get("not_testable", 0),
    )


def _context_sources(context: dict[str, Any]) -> dict[str, str]:
    """Herkunft je Kontextfeld (kunde, recherche, admin) fuer die Reportdaten (Q15)."""
    sources = context.get("sources") if isinstance(context.get("sources"), dict) else {}
    out: dict[str, str] = {}
    for name, entry in sorted(sources.items()):
        if isinstance(entry, dict) and entry.get("source") and context.get(name):
            out[str(name)] = str(entry["source"])
    return out


def build_report_data(
    facts: FS.Facts | dict[str, Any],
    catalog_output: CatalogOutput | dict[str, Any] | None = None,
    *,
    order: dict[str, Any] | None = None,
    customer_context: dict[str, Any] | None = None,
    report_version: str = "1.0",
    report_date: Optional[str] = None,
    prose: dict[str, Any] | None = None,
) -> ReportData:
    """Datenmodell des Reports.

    ``order`` traegt Kundenname und die Liste der zusammengefuehrten Auftraege,
    ``customer_context`` den optionalen Kundenkontext aus ``orders.customer_context``
    (S5): Kuerzel, Branche, Mitarbeiterzahl und Zweck je System, je Feld mit Quelle.
    Fehlt er, bleibt der Kontextabsatz generisch, und der Bericht sagt das nicht.
    """
    if isinstance(facts, dict):
        facts = FS.Facts.from_dict(facts)
    if catalog_output is None:
        output = evaluate_catalog(facts)
    elif isinstance(catalog_output, dict):
        output = CatalogOutput.model_validate(catalog_output)
    else:
        output = catalog_output

    order = dict(order or {})
    context = dict(customer_context or {})
    kuerzel = IDS.normalize_kuerzel(context.get("kuerzel") or order.get("kuerzel"))

    scan_end = facts.scan.finished_at or facts.scan.started_at
    scan_date = C.format_date(scan_end)
    year = int(scan_date.rsplit(".", 1)[-1]) if scan_date != C.UNKNOWN else 0

    items, positive_items = consolidate(output, facts)
    finding_items = [i for i in items if i.target == "findings"]
    finding_list, cve_refs, tool_findings = F.build_findings(
        output, items, facts, kuerzel=kuerzel, year=year)
    positives = F.build_positives(positive_items)

    orders = order.get("orders") or [{"label": "Lauf 1", "id": facts.scan.order_id}]
    runs = len(orders)
    model = C.coverage_model(facts)
    counts = _counts(facts, output, len(finding_list), len(positives), runs, model)

    pairs = list(zip(finding_items, finding_list))
    plan = P.build_plan(pairs)
    levers = P.build_levers(plan, finding_list)

    # S6 (spec/08 Punkt 10): Der Hinweis auf Seite 3 haengt an den
    # Leitwerkzeugen des Pakets, nicht an jeder Luecke. Die Abdeckungstabelle
    # in Kapitel 2 zeigt weiterhin jede Luecke.
    # S6b-1: dieselbe Regel wie die Abdeckung in Kapitel 2.1 (coverage.py).
    gap_hosts = model.gaps()
    glance = C.build_glance(finding_items, finding_list, counts, gap_hosts)
    glance.levers = levers
    business = C.build_business(facts, C.observed_systems(facts))
    scope = C.build_scope(facts, output, counts, model)
    architecture = C.build_architecture(facts, output, finding_items, finding_list, model)

    package_name, package_label = T.package_labels(facts.scan.package)
    # S5: der Firmenname steht im Kundenkontext unter "firmenname" (Migration 045,
    # Quelle kunde, recherche oder admin). Ohne ihn bleibt "Auftraggeber" stehen
    # und das Gate meldet es als Warnung. "customer" bleibt als Schluessel
    # bestehen, weil die Golden-Testdaten den Auftraggeber so mitgeben.
    customer = str(order.get("customer") or context.get("firmenname")
                   or context.get("customer") or DEFAULT_CUSTOMER)
    # S6 (spec/08 Punkt 8): Der Kurzname fuer Fusszeile und PDF-Titel ist ein
    # eigenes Feld, sonst der Firmenname ohne Rechtsform. Er war vorher das erste
    # Wort, und "Dortmund Beach Design" wurde damit zu "Dortmund".
    customer_short = str(order.get("customer_short") or context.get("kurzname") or "").strip()
    if not customer_short and customer != DEFAULT_CUSTOMER:
        customer_short = RESEARCH.kurzname_aus(customer)
    if not customer_short:
        customer_short = kuerzel or customer
    month_day = "".join(reversed(scan_date.split(".")[:2])) if scan_date != C.UNKNOWN else "0000"
    meta = Meta(
        customer=customer,
        customer_short=customer_short,
        domains=list(facts.scan.domains) or [facts.scan.domain],
        package=package_name,
        package_label=package_label,
        scan_date=scan_date,
        scan_window=C.format_window(facts.scan.started_at, facts.scan.finished_at),
        report_date=report_date or C.today(),
        report_version=report_version,
        report_id=IDS.report_id(facts.scan.order_id or orders[0].get("id"), year, month_day),
        orders=[OrderRef(label=str(o.get("label", "Lauf")), id=str(o.get("id", ""))) for o in orders],
        hosts_total=counts.hosts_total,
        hosts_ipv4=counts.hosts_ipv4,
        hosts_ipv6=counts.hosts_ipv6,
        fqdns_total=counts.fqdns_total,
        tool_runs=counts.tool_runs,
        raw_findings=counts.raw_findings,
        after_fp=output.summary.by_status.get("fail", 0),
        consolidated=len(finding_list),
        positives=len(positives),
        policy_version=CATALOG_VERSION,
        catalog_version=output.catalog_version,
        catalog_digest=output.catalog_digest,
        facts_schema_version=output.facts_schema_version,
        context_sources=_context_sources(context),
        **T.PROVIDER,
    )

    data = ReportData(
        meta=meta,
        glance=glance,
        business=business,
        scope=scope,
        architecture=architecture,
        landscape_lead=N.landscape_lead(counts),
        positives=positives,
        plan=plan,
        findings=finding_list,
        appendix=build_appendix(facts, output, finding_list, cve_refs, tool_findings,
                                counts, scan_date, T.PROVIDER["provider"],
                                port_refs=C.finding_ports(facts, finding_items, finding_list)),
    )

    if prose:
        from reporter.v3.prose import apply_prose

        apply_prose(data, prose)
    return data
