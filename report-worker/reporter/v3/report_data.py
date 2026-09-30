# -*- coding: utf-8 -*-
"""Reportdaten v3: aus Fakten und Prüfergebnis wird das Datenmodell des Prototyps.

Reihenfolge: konsolidieren, Befunde und Positivbefunde bauen, IDs vergeben, daraus
Kapitel, Plan, Hebel und Anhang. Die Prosa-Felder werden zuletzt eingesetzt, und
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
    # S6b-3 (spec/10 R14): Einzelmeldungen und Doppelmeldungen aus der Bilanz der
    # Phase-3-Korrelation; ohne Bilanz entfallen beide Zahlen (0).
    bilanz = next((d.payload for d in facts.decisions if d.source == "phase3_correlation"), {})
    raw = int(bilanz.get("total_findings") or 0)
    doppelt = sum(int(v) for k, v in (bilanz.get("fp_by_reason") or {}).items()
                  if "dedup" in str(k).lower() and isinstance(v, int))
    # S6b-4n (spec/11 N12): Doppelmeldungen je Grund der Korrelation ("Header-Dedup": gleiche
    # Meldungen der Webanalyse an vielen Adressen, "SSL-Dedup": der TLS-Pruefung).
    je_grund = {str(k): int(v) for k, v in (bilanz.get("fp_by_reason") or {}).items()
                if "dedup" in str(k).lower() and isinstance(v, int) and v > 0}
    # Je System eine Zeile in 2.1 (IPv4 und IPv6 mit gleichem rDNS); der Satz ueber
    # Luecken zaehlt dieselben Zeilen, sonst widersprechen sich Satz und Tabelle.
    rows = model.system_rows()
    cov = [model.system_status(ips) for ips in rows]
    # S6b-1 (spec/09 Q16): Hostnamen eindeutig zaehlen (IPv4 und IPv6 zaehlten doppelt);
    # Drittanbieter-Adressen und ihre Namen sind kein Host des Kunden.
    eigene = [h for h in facts.hosts if h.third_party is None]
    eigene_ips = {h.ip for h in eigene}
    # S6b-4 (spec/11 T7): AAAA-Adressen derselben Namen ohne Inventareintrag zaehlen mit.
    # S6b-4n (spec/11 N5, N13): ebenso weitere A-Eintraege; beide stehen in der Zaehlung als
    # "nur aus DNS", zusammen mit den Adressen ohne Antwort.
    zusatz = [a for h in eigene for a in h.additional_ips if a.ip not in eigene_ips]
    ohne_antwort = sum(1 for h in eigene if h.reach is not None
                       and h.reach.status in ("no_response", "unreachable_from_scanner", "no_ipv6_route"))
    return N.Counts(
        domains=list(facts.scan.domains) or [facts.scan.domain],
        scan_date=C.format_date(facts.scan.finished_at or facts.scan.started_at),
        hosts_total=len(eigene) + len(zusatz),
        systems_total=len(rows),
        gap_addresses=sum(len(ips) for ips, status in zip(rows, cov) if status != "voll"),
        hosts_ipv4=sum(1 for h in eigene if h.family == 4) + sum(1 for a in zusatz if a.family == 4),
        hosts_ipv6=sum(1 for h in eigene if h.family == 6) + sum(1 for a in zusatz if a.family == 6),
        hosts_dns_only=len({a.ip for a in zusatz}) + ohne_antwort,
        # S6b-4 (spec/11 T8): die Verzeichnis-Enumeration steht nur mit einem belastbaren Lauf in 2.3.
        path_search_ok=any(p.verdict == "reliable" for p in facts.path_search if p.host_ip in eigene_ips),
        path_search_known=bool(facts.path_search),
        fqdns_total=len({f.name.lower() for f in facts.fqdns if not f.wildcard and f.host_ip in eigene_ips}),
        runs=runs,
        # S6b-3 (spec/10 R3): nur gelaufene Werkzeuge, ohne uebersprungene und KI-Schritte.
        tool_runs=sum(1 for c in facts.coverage if c.status != "skipped" and not c.tool.startswith("ai_")),
        raw_findings=raw,
        findings=n_findings,
        positives=n_positives,
        coverage_full=cov.count("voll"),
        coverage_partial=cov.count("teil"),
        coverage_none=cov.count("keine") + cov.count("unerreichbar"),
        duplicates=doppelt if raw else 0,
        duplicates_by=je_grund if raw else {},
        not_testable=output.summary.by_status.get("not_testable", 0),
        names_found=COV.names_found(facts),
        names_checked=COV.names_checked(facts),
        betriebsformen=sorted({h.betriebsform for h in eigene if h.betriebsform}),
    )


def _context_fields(context: dict[str, Any]) -> list[dict[str, str]]:
    """Wert und Quelle je Kontextfeld (spec/10 R13); dieselben Felder wie ``facts.context``."""
    from reporter.facts.build import context_from_customer_context

    kontext = context_from_customer_context(context)
    if kontext is None:
        return []
    return [{"name": f.name, "value": f.value, "source": f.source or ""} for f in kontext.fields]


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
    report_version: str = "1",
    report_date: Optional[str] = None,
    prose: dict[str, Any] | None = None,
    generation: Optional[int] = None,
    excluded_keys: set[str] | None = None,
) -> ReportData:
    """Datenmodell des Reports.

    ``order`` traegt Kundenname und die Liste der zusammengefuehrten Auftraege,
    ``customer_context`` den optionalen Kundenkontext aus ``orders.customer_context``
    (S5): Kuerzel, Branche, Mitarbeiterzahl und Zweck je System, je Feld mit Quelle.
    Fehlt er, bleibt der Kontextabsatz generisch, und der Bericht sagt das nicht.

    S6b-2: ``report_version`` ist die Auslieferungsversion (Deckblatt), ``generation`` die
    Erzeugungsnummer aus ``reports.version`` (nur in der Fusszeile). ``excluded_keys``
    sind die stabilen Schluessel der vom Admin ausgeschlossenen Befunde (#28).
    """
    if isinstance(facts, dict):
        facts = FS.Facts.from_dict(facts)
    if catalog_output is None:
        # S6b-3 (spec/10 R18): Fristen im Text beziehen sich auf den Berichtstag.
        output = evaluate_catalog(facts, report_date=C.iso_date(report_date or C.today()))
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
    excluded_keys = set(excluded_keys or ())
    excluded_ids: list[str] = []
    finding_items = [i for i in items if i.target == "findings" and i.stable_key not in excluded_keys]
    finding_list, cve_refs, tool_findings = F.build_findings(
        output, items, facts, kuerzel=kuerzel, year=year, excluded_keys=excluded_keys,
        excluded_ids=excluded_ids)
    # Nachtrag S6b-2 (Entscheidung DC 26.09.): im Anhang eine Zeile je Meldung mit Anzahl
    # und Betroffenen, die Einzelmeldungen bleiben fuer den Export in ``tool_messages``.
    tool_messages = tool_findings + C.tech_tool_findings(facts)
    tool_findings = F.summarize_tool_messages(tool_messages)
    positives = F.build_positives(positive_items)

    orders = order.get("orders") or [{"label": "Lauf 1", "id": facts.scan.order_id}]
    runs = len(orders)
    model = C.coverage_model(facts)
    counts = _counts(facts, output, len(finding_list), len(positives), runs, model)
    # S6b-4 (spec/11 T10): "n Befunde in m von 5 Kategorien" aus den Befunden dieses Berichts.
    counts.categories = len({f.cat for f in finding_list if f.cat})

    pairs = list(zip(finding_items, finding_list))
    plan = P.build_plan(pairs)
    levers = P.build_levers(plan, finding_list)

    # S6 (spec/08 Punkt 10): Der Hinweis auf Seite 3 haengt an den
    # Leitwerkzeugen des Pakets, nicht an jeder Luecke. Die Abdeckungstabelle
    # in Kapitel 2 zeigt weiterhin jede Luecke.
    # S6b-1: dieselbe Regel wie die Abdeckung in Kapitel 2.1 (coverage.py).
    glance = C.build_glance(finding_items, finding_list, counts, model.system_gaps(), facts, output)
    glance.levers = levers
    business = C.build_business(facts, C.observed_systems(facts))
    scope = C.build_scope(facts, output, counts, model, finding_list)
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
    kurzname = str(context.get("kurzname") or "").strip()
    if kurzname and _context_sources(context).get("kurzname") == RESEARCH.SOURCE_RESEARCH:
        # S6b-1 (spec/09 Q15): ein Kurzname aus der Recherche ist nur ein Vorschlag.
        # Aeltere Laeufe haben ihn mit der alten Rechtsformliste gespeichert
        # ("Junkerwerk Linder GmbH + Co."); Werte von Kunde oder Admin bleiben, wie sie sind.
        kurzname = RESEARCH.kurzname_aus(kurzname)
    customer_short = str(order.get("customer_short") or kurzname or "").strip()
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
        generation=generation,
        generated_on=C.report_day() if generation else None,
        excluded_ids=excluded_ids,
        report_id=IDS.report_id(facts.scan.order_id or orders[0].get("id"), year, month_day),
        orders=[OrderRef(label=str(o.get("label", "Lauf")), id=str(o.get("id", ""))) for o in orders],
        hosts_total=counts.hosts_total,
        systems_total=counts.systems_total,
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
        context_fields=_context_fields(context),
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
        appendix=build_appendix(facts, output, finding_list, cve_refs, tool_findings, tool_messages,
                                counts, scan_date, T.PROVIDER["provider"],
                                port_refs=C.finding_ports(facts, finding_items, finding_list),
                                plan_stages=[row.prio for row in plan]),
    )

    if prose:
        from reporter.v3.prose import apply_prose

        apply_prose(data, prose)
    # S6b-4 (spec/11 T9, E11): Fremddomains stehen nicht im Kundentext.
    from reporter.v3.foreign import mask_report

    return mask_report(data, facts)
