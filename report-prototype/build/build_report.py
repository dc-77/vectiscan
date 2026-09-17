#!/usr/bin/env python3
"""Rendert den Junkerwerk-Report-Prototyp: report_data.py -> template.html.j2 -> HTML -> PDF.

Aufruf (im Ordner build/):
    python3 build_report.py [--out ../out] [--raster]

Voraussetzungen: weasyprint (69.x), jinja2, Inter-Fonts (rsms Static-TTF) und DejaVu Sans Mono
im System. Optional: poppler-utils (pdfinfo, pdftotext, pdftoppm).
"""
import argparse, json, os, re, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from report_data import DATA  # noqa: E402


def check_data(d):
    """Deterministische Gate-Prüfungen vor dem Rendern (Auszug aus 01_Fehleranalyse, Phase A)."""
    errors = []
    ids = [f["id"] for f in d["findings"]]
    # lückenlose IDs
    nums = [int(i.split("-")[-1]) for i in ids]
    if nums != list(range(1, len(nums) + 1)):
        errors.append(f"IDs nicht lückenlos: {ids}")
    # eindeutige Titel, keine Platzhalter, keine Klammer-Hinweise
    titles = [f["title"] for f in d["findings"]]
    if len(set(titles)) != len(titles):
        errors.append("doppelte Titel")
    for f in d["findings"]:
        if re.search(r"\{.*?\}|\[Hinweis", f["title"]):
            errors.append(f"Platzhalter/Hinweis im Titel {f['id']}")
        if f["scale"] not in ("exposure", "hygiene") or not f.get("level"):
            errors.append(f"Einstufung fehlt oder unbekannt bei {f['id']}")
    # Keine eigenen CVSS-Vektoren; zitierte CVE-Scores muessen mit der Referenztabelle (Anhang A.3) uebereinstimmen
    refs = {c["cve"]: c for c in d["appendix"]["cve_refs"]}
    for f in d["findings"]:
        if "vector" in f or "cvss" in f:
            errors.append(f"eigener CVSS-Wert in {f['id']} (Policy: nur Fremdreferenz)")
        for c in (f.get("threat") or {}).get("cves", []):
            m = re.match(r"(CVE-\d{4}-\d+)", c)
            if not m or m.group(1) not in refs:
                errors.append(f"CVE ohne Referenzeintrag in {f['id']}: {c[:30]}")
                continue
            sc = re.search(r"Basiswert (\d+\.\d)", c)
            if sc and sc.group(1) != refs[m.group(1)]["score"]:
                errors.append(f"CVE-Score-Mismatch {f['id']}: {sc.group(1)} vs. Referenz {refs[m.group(1)]['score']}")
            if refs[m.group(1)]["ref"] != f["id"]:
                errors.append(f"CVE-Referenz zeigt auf {refs[m.group(1)]['ref']}, zitiert in {f['id']}")
    # Plan referenziert nur existierende Befunde, jeder Befund ist im Plan
    plan_refs = {r for p in d["plan"] for r in p["refs"]}
    if plan_refs - set(ids):
        errors.append(f"Plan referenziert unbekannte IDs: {plan_refs - set(ids)}")
    if set(ids) - plan_refs:
        errors.append(f"Befunde ohne Maßnahme: {set(ids) - plan_refs}")
    # Werkzeugliste ohne Versionsnummern (Kundenvorgabe)
    for t in d["appendix"]["tools"]:
        if re.search(r"\d+\.\d+", t["t"]):
            errors.append(f"Versionsnummer in Werkzeugliste: {t['t']}")
    # Kategorien der Befunde existieren
    cats = {c["key"] for c in d["glance"]["categories"]}
    for f in d["findings"]:
        if f["cat"] not in cats:
            errors.append(f"unbekannte Kategorie {f['cat']} in {f['id']}")
    # Zähler auf dem Cover/in der Methodik stimmen mit den Listen überein
    if d["meta"]["consolidated"] != len(d["findings"]):
        errors.append("meta.consolidated != Anzahl Befunde")
    if d["meta"]["positives"] != len(d["positives"]):
        errors.append("meta.positives != Anzahl positive Befunde")
    return errors


def dash_check(html):
    """Keine Gedankenstriche im Fließtext (Kundenvorgabe)."""
    body = re.sub(r"<style>.*?</style>", "", html, flags=re.S)
    return len(re.findall("[–—]", body))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(HERE, "..", "out"))
    ap.add_argument("--raster", action="store_true")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    errs = check_data(DATA)
    if errs:
        print("GATE-FEHLER:\n  " + "\n  ".join(errs))
        sys.exit(2)
    print("Gate: OK")

    from jinja2 import Environment, FileSystemLoader
    env = Environment(loader=FileSystemLoader(HERE), autoescape=False, trim_blocks=False, lstrip_blocks=False)
    tpl = env.get_template("template.html.j2")
    html = tpl.render(m=DATA["meta"], g=DATA["glance"], b=DATA["business"], s=DATA["scope"],
                      a=DATA["architecture"], landscape_lead=DATA["landscape_lead"],
                      positives=DATA["positives"], plan=DATA["plan"], findings=DATA["findings"],
                      ap=DATA["appendix"], assets=os.path.join(HERE, "assets"))
    n_dash = dash_check(html)
    if n_dash:
        print(f"WARNUNG: {n_dash} Gedankenstrich(e) im Text")
    base = f"vectiscan-{DATA['meta']['customer_short'].lower()}-perimeter-2026-08-31-v{DATA['meta']['report_version']}"
    html_path = os.path.join(args.out, base + ".html")
    pdf_path = os.path.join(args.out, base + ".pdf")
    json_path = os.path.join(args.out, "report-data.json")
    open(html_path, "w", encoding="utf-8").write(html)
    json.dump(DATA, open(json_path, "w", encoding="utf-8"), ensure_ascii=False, indent=1)

    from weasyprint import HTML
    HTML(html_path).write_pdf(pdf_path)
    pages = int(subprocess.run(["pdfinfo", pdf_path], capture_output=True, text=True).stdout.split("Pages:")[1].split()[0])
    print(f"gerendert: {pdf_path} ({pages} Seiten)")
    sparse = []
    for p in range(1, pages + 1):
        txt = subprocess.run(["pdftotext", "-f", str(p), "-l", str(p), pdf_path, "-"], capture_output=True, text=True).stdout
        wc = len(txt.split())
        flag = "  <== SPARSE" if wc < 90 else ""
        if wc < 90:
            sparse.append(p)
        print(f"  S{p:02d}: {wc:4d} Wörter{flag}")
    inner = [p for p in sparse if p not in (1,)]
    print("Seitenbild:", "OK" if not inner else f"halbleere Seiten {inner}")
    if args.raster:
        subprocess.run(["pdftoppm", "-jpeg", "-r", "70", pdf_path, os.path.join(args.out, "page")])
        print("Raster: out/page-*.jpg")


if __name__ == "__main__":
    main()
