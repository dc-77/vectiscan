"""Katalogversion und Laufzeit-Digest.

CATALOG_VERSION folgt dem Format von POLICY_VERSION (``JJJJ-MM-TT.n``). Bump-Regel
(README, Abschnitt "Versionierung"): jede Aenderung an ``checks/``, ``ignore.yaml``
oder ``tables.py`` zieht die Version hoch. Der Digest wird zur Laufzeit ueber genau
diese Dateien berechnet (CRLF-normalisiert, BOM entfernt) und steht in jeder Ausgabe,
damit eine Aenderung ohne Bump im Audit sichtbar bleibt.

Bump-Historie:
    2026-09-19.1  Erstversion (Session S2).
    2026-09-19.2  Session S3: Kundentexte auf echte Umlaute umgestellt (Titel, texts,
                  affected_template, COVERAGE_REASONS); Befund-Buendel unter bundles/
                  eingefuehrt und das Feld bundle je Pruefung gefuellt.
    2026-09-20.1  S2b: Rueckbau der sieben Gruppenregeln `zap_no_alerts`. Die
                  Abdeckung traegt den Fall seit Issue #13 selbst.
    2026-09-22.1  S6 (spec/08): `web_vulnerability_active` wird erst ab
                  ZAP-Konfidenz High ein Befund, darunter uebernimmt die neue
                  Pruefung `web_vulnerability_reported` als Werkzeugmeldung im
                  Anhang (Issue #15). Neues Feld `active_proof_when` fuer den
                  aktiven Nachweis (rot und unverzueglich) in
                  `web_vulnerability_active` und `tls_known_vulnerability`.
                  Neues Feld `evidence_detail` und befundspezifische Nachweise.
                  `wordpress_plugin_vulnerable` zaehlt ohne Singular-Fehler.
                  COVERAGE_REASONS in Kundensprache (spec/08 Punkt 11);
                  `package_<paket>` zaehlt als `not_in_package` (Punkt 9).
    2026-09-23.1  S6a (Issue #30): Positivbefund von `remote_admin_closed` heisst
                  "Keine Windows-Fernwartung (RDP) und keine Windows-Dateifreigabe
                  (SMB)"; neues Buendelfeld `positive_conflicts`, damit ein Host mit
                  FTP, Verwaltungsoberflaeche oder SSH ausserhalb Port 22 mit Befund
                  aus dem Positivbefund herausfaellt.
    2026-09-23.2  S6a (#15 Teil 2): `dkim_missing` meldet ohne gefundenen Selektor
                  nicht mehr "fehlt", sondern not_testable mit dem neuen Grund
                  `dkim_selector_unknown`; die Pruefung hat kein `when` mehr.
    2026-09-25.1  S6b-1 (spec/09 Q3, Q9, Q10, Teil 3): `no_open_ports` ist nicht
                  pruefbar statt "ok", neu `unreachable_from_scanner`,
                  `tls_protocols_partial` und `tls_ciphers_partial`; Drittanbieter-
                  Adressen fallen aus dem Katalog; Passivports, die eine Einschraenkung
                  traegt, sind keine unverarbeitete Beobachtung mehr; Numerus
                  `{n:Einzahl|Mehrzahl}` in den Texten; Zustaendigkeit auf geteilten
                  Systemen je Pruefung (`SHARED_OPERATOR_CHECKS`).
    2026-09-25.2  S6b-2 (spec/09 Q4 bis Q7, Q12 bis Q14, Q18, spec/08 Teil 2): Texte je
                  Regel. Buendel tragen nur den Sammeltitel (`{rules}`) und
                  `positive_title`; jede Textaussage kann eine Fakten-Bedingung (`when`,
                  `quantor`) tragen, Pruefungen tragen `short` und `plan` (Hebeltitel,
                  Effekt). Neu `urgent_when` (E2, Zertifikat bis sieben Tage), neue
                  Pruefungen `admin_panel_hoster`, `admin_service_unconfirmed`,
                  `admin_port_passive_unidentified` (E1, Buendel `admin_access`),
                  `cert_expiring_later`, `mail_spoofing_unprotected` (spec/08 Punkt 6),
                  `tls_weakness_reported` (BREACH, LUCKY13 im Anhang); ZAP-Regeln nur
                  ab Konfidenz High (Q14); `dane_missing` nur bei MX in eigener,
                  signierter Zone; `service_banner_version` ohne SSH- und
                  MariaDB-Handshake; `ftp_plaintext` nur mit Beleg (spec/08 Punkt 4);
                  `waf_present` und `ip_reputation` positiv nur mit tragfaehigem Fakt
                  (Q12); `wordpress_core_outdated` nur mit Kern-Schwachstelle (Q18).
                  Neue Tabellen `HOSTING_PANELS`, `BANNER_FIXED`, `WAF_GENERIC`,
                  `ZAP_RATED`, `ZAP_COOKIE`, `TLS_REPORTED_VULNS`, `CERT_URGENT_DAYS`,
                  `CERT_SOON_DAYS`, `VERSION_LOWER_BOUND`; `http_trace_enabled` als
                  Werkzeugmeldung (nur OPTIONS), ZAP-Cookie-Meldungen nicht mehr ignoriert.
                  Ein neues Datum waere erst morgen; die zweite Version desselben Tages
                  folgt der Regel "jede Aenderung bumpt".
    2026-09-26.1  Nachtrag S6b-2 (Entscheidung DC 26.09. Frage 1): der Seitentitel eines
                  Hosting-Panels (`panel_title`, froxlor, Plesk, cPanel ...) ist ein
                  Fingerabdruck nach Q13 und steht fuer seine Anmeldeseite; auf einem
                  System des Kunden `admin_service_exposed` (kritisch), beim Hoster
                  `admin_panel_hoster` (erhoeht). Neue Aussagen fuer die Standardseite des
                  Webservers (Port 80/443 ueber die IP). Mitglieder tragen Name und
                  Kennung der Werkzeugmeldung (`message`, `message_id`) fuer den Anhang.
    2026-09-26.2  S6b-3 (spec/10 R1 bis R19): Header-Regeln lesen `http.header_eval` und sind
                  an Weiterleitung, Fehlerseite oder Sicherheitsabfrage nicht pruefbar
                  (`headers_redirect_only`, `headers_error_only`, `headers_challenge_only`),
                  Parkname `parked_name`; Aussagen je fehlendem Header
                  (`missing_header_names`), CSP je Direktive; `hsts_short` im Buendel
                  `web_header_hygiene`, `max-age=0` als "HSTS abgeschaltet" unter
                  `hsts_missing` (Entscheidung DC 3). Neue Pruefungen
                  `service_cert_expired`, `service_unidentified`, `smtp_vrfy_enabled`,
                  `smtp_vrfy_enabled_passive`, `wordpress_xmlrpc_enabled`,
                  `login_over_http_passive`, `spf_authorizes_shared_host`; Buendel
                  `smtp_commands`. Positivaussagen nur mit tragendem Fakt (CBC, POP3-TLS-Zwang,
                  Lebenszyklusquelle, Zonentransfer je Domain); `remote_admin_closed` ohne die
                  S6a-Konflikte (Entscheidung DC 2). `not_applicable` mit eigenem Grund
                  (`mx_external`, `zone_unsigned`), Faktenfamilien (`families.py`),
                  Berichtstag als Bezug fuer Fristen (`report_date`), Effekt je Empfehlungsstufe
                  (`Recommendation.effect`), Ignorierliste mit `covered_by`, Texte nach
                  Betriebsform statt "Anschluss" (R13).
    2026-09-27.1  S6b-4 (spec/11 T1 bis T16): Varianten fuer Kurztitel, Hebel und Effekt
                  (`texts.short_variants`, `plan.lever_variants`, `plan.effect_variants`),
                  Planzeile je Regel (`plan.per_rule_action`), blauer Hinweis fuer
                  Passivbefunde ohne erreichbaren Host (`hint_when`, E22), gesammelte
                  Gruppenvariablen `valid_elsewhere` und `target_versions`, Numerus
                  `{m:Einzahl|Mehrzahl}` nach der Zahl der Betroffenen, Bindung
                  `port_scanned`. `hsts_missing` nicht pruefbar an Fehlerseite und
                  Sicherheitsabfrage, Titel "HSTS fehlt" oder "HSTS abgeschaltet
                  (max-age=0)" (E20); `cert_expiring` "am Berichtsdatum abgelaufen, sofern
                  nicht erneuert" (T14); VRFY "angeboten"; `http_alt_port` auf einer
                  Mandantenplattform ohne "Port schliessen". Die Regel der Gesamtbewertung
                  (schlechteste Kategorieampel, `reporter/v3/levels.py::OVERALL_RULE`) ist
                  seit S3 unveraendert; DB und CA stehen seit 2026-09-25.2 durch E1 und E2
                  (Verwaltungsoberflaeche kritisch, Zertifikat bis sieben Tage rot) auf
                  HOCH, nicht durch den Schritt 2026-09-26.1 auf 2026-09-26.2 (spec/11 T6).
    2026-09-27.2  Nachtrag S6b-4 (spec/11 N1 bis N15, E24, E25): `csp_missing` schlaegt auch
                  bei einer Richtlinie ohne script-src und default-src an (Variante "nur mit
                  frame-ancestors"), positiv nur mit Skriptregel; `ip_reputation` nicht
                  anwendbar auf CDN- und Plattformadressen, positiv nur ohne Meldung im
                  Abfragefenster (`ABUSEIPDB_WINDOW_DAYS`); `dmarc_none` trennt Meldeadressen
                  der eigenen und fremder Domains, der Betreiber-Satz nur bei Delegation per
                  CNAME oder SPF `mx` (neue Funktionen `rua_own`, `dmarc_delegated`,
                  `spf_has_mx`); `cert_expiring` "am Berichtsdatum abgelaufen, sofern nicht
                  erneuert" auch in Hebel, Effekt und Auswirkung; `wordpress_plugin_vulnerable`
                  mit Produktnamen (`PRODUCT_NAMES`), "fehlerbereinigt ab" getrennt von "neueste
                  laut wpscan"; Baustein-Schluessel `key` fuer gleiche Aussagen mehrerer Regeln
                  (Versionspreisgabe in Header und Banner); `http_header_disclosure` nennt
                  X-FEServer nicht mehr unter "Version"; `service_cert_expired` nennt das
                  Zertifikat einmal, "Mailclients" und Hebel "fuer die Maildienste" bei
                  Mailports; `admin_panel_hoster` mit Zahl und Quelle der weiteren Domains und
                  Satzfolge der Auswirkung; `service_unidentified` Numerus nach Ports;
                  `security_headers_incomplete` Referrer-Policy nach der Voreinstellung der
                  Browser; `tls_weakness_reported` nur mit eigenem testssl-Lauf; Passivregeln
                  "Hosteintrag aktualisiert am" statt "gesehen am" ohne Zeitstempel des Dienstes;
                  `wordpress_user_enumeration` nur Anzahl und Fundweg der Anmeldenamen (E25);
                  Lebenszyklus in der LTS-Phase "in Langzeitpflege bis <Datum> laut <Quelle>"
                  ohne zweite Klammer. Einstufungen unveraendert.
    2026-09-29.1  S6d (S6c-Rohfelder, Fakten 1.4.0): neue Pruefungen
                  `smtp_auth_before_starttls` und `smtp_auth_before_starttls_passive` im Buendel
                  `smtp_auth` (Familie `smtp_auth_cleartext`, hygiene mittel, Gelb/Mittelfristig,
                  Entscheidung DC 29.09.2026; ersetzt die unprocessed-Art); `wordpress_xmlrpc_enabled`
                  auch aus der XML-RPC-Sonde (`http.xmlrpc_probe`, Nachweis `http.xmlrpc`); ZAP-Regeln
                  mit Befund (`csrf_token_missing`, `session_in_url`, `sri_missing`,
                  `cors_misconfiguration`, `directory_listing`) nur an der Zielseite
                  (`alert.location`); `ip_reputation` nennt das Abfragefenster aus dem Rohdatum
                  (`reputation_window`); neue Abdeckungsgruende `provider_block_after_portscan`,
                  `no_tls_on_port`, `tls_connect_refused`, `starttls_failed`, `incomplete`,
                  `whois_no_data`. Einstufungen der bestehenden Pruefungen unveraendert.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

CATALOG_VERSION = "2026-09-29.1"

CATALOG_DIR = Path(__file__).resolve().parent
CHECKS_DIR = CATALOG_DIR / "checks"
BUNDLES_DIR = CATALOG_DIR / "bundles"
IGNORE_FILE = CATALOG_DIR / "ignore.yaml"
TABLES_FILE = CATALOG_DIR / "tables.py"


def digest_files(catalog_dir: Path | None = None) -> list[Path]:
    """Dateien, die in den Digest eingehen, in stabiler Reihenfolge."""
    base = Path(catalog_dir) if catalog_dir else CATALOG_DIR
    files = sorted((base / "checks").glob("*.yaml"), key=lambda p: p.name)
    files.extend(sorted((base / "bundles").glob("*.yaml"), key=lambda p: p.name))
    for extra in (base / "ignore.yaml", base / "tables.py"):
        if extra.exists():
            files.append(extra)
    return files


def catalog_digest(catalog_dir: Path | None = None) -> str:
    """sha256 ueber Dateiname plus Inhalt (CRLF -> LF, BOM entfernt) aller Katalogdateien."""
    h = hashlib.sha256()
    for path in digest_files(catalog_dir):
        data = path.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        if data.startswith(b"\xef\xbb\xbf"):
            data = data[3:]
        h.update(path.name.encode("utf-8"))
        h.update(b"\0")
        h.update(data)
        h.update(b"\0")
    return h.hexdigest()
