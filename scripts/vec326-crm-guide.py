"""
VEC-326: Send VectiScan CRM guide email to daniel.czischke@bs-consulting-gmbh.de.
Called from ops-twenty-admin-invite CI job.
Reads env vars: TARGET_EMAIL, TRAEFIK_USER, TRAEFIK_PASS, INVITE_STATUS, RESEND_API_KEY.
"""
import os
import json
import urllib.request
import urllib.error
import sys

target = os.environ["TARGET_EMAIL"]
traefik_user = os.environ.get("TRAEFIK_USER", "intern")
traefik_pass = os.environ.get("TRAEFIK_PASS", "(bitte beim Admin erfragen)")
invite_status = os.environ.get("INVITE_STATUS", "UNKNOWN")
resend_key = os.environ["RESEND_API_KEY"]

if invite_status in ("OK_METADATA", "OK_GRAPHQL"):
    invite_note = (
        "<p>Eine Einladungs-E-Mail von Twenty CRM wurde an Ihre Adresse gesendet. "
        "Klicken Sie darin auf den Link, um Ihr Passwort zu setzen und sich einzuloggen.</p>"
    )
elif invite_status == "SKIPPED_NO_KEY":
    invite_note = (
        "<p><strong>Hinweis:</strong> Automatische Twenty-Einladung nicht moeglich "
        "(CRM_API_KEY nicht konfiguriert). Bitte IT-Admin kontaktieren.</p>"
    )
else:
    invite_note = (
        "<p><strong>Hinweis:</strong> Die Twenty-Einladungs-E-Mail konnte nicht "
        "automatisch versendet werden. Der Admin wird Ihnen separat einen "
        "Einladungslink zusenden.</p>"
    )

html = f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:20px;color:#333">
<h2 style="color:#1a1a2e">Ihr VectiScan CRM Admin-Zugang</h2>
<p>Sehr geehrter Herr Czischke,</p>
<p>Ihr Admin-Zugang fuer das VectiScan CRM (Twenty) ist eingerichtet.
Unten finden Sie alle notwendigen Informationen.</p>

<h3>1. Zugangs-URL</h3>
<p>
  <a href="https://crm.vectigal.tech" style="font-size:16px;font-weight:bold">
    https://crm.vectigal.tech
  </a>
</p>

<h3>2. Erster Schritt: Browser-Zugangssperre ("Vectigal Intern")</h3>
<p>Beim Aufrufen der URL erscheint ein Browser-Anmeldefenster.
Geben Sie dort diese Zugangsdaten ein:</p>
<table style="border-collapse:collapse;width:100%;margin:10px 0">
  <tr>
    <td style="padding:10px;border:1px solid #ddd;background:#f5f5f5;width:40%">
      <strong>Benutzername</strong>
    </td>
    <td style="padding:10px;border:1px solid #ddd;font-family:monospace">
      {traefik_user}
    </td>
  </tr>
  <tr>
    <td style="padding:10px;border:1px solid #ddd;background:#f5f5f5">
      <strong>Passwort</strong>
    </td>
    <td style="padding:10px;border:1px solid #ddd;font-family:monospace">
      {traefik_pass}
    </td>
  </tr>
</table>

<h3>3. Twenty-Workspace-Login</h3>
{invite_note}
<p>Ihre Workspace-E-Mail-Adresse: <strong>{target}</strong></p>
<p>Nach dem Klick auf den Einladungslink koennen Sie Ihr eigenes Passwort setzen.</p>

<h3>4. Was Sie im CRM sehen werden</h3>
<ul>
  <li><strong>Leads / Kontakte:</strong> Nach jeder DOI-Bestaetigung eines VectiScan-Nutzers
  wird automatisch ein Lead-Datensatz angelegt (VEC-301).</li>
  <li><strong>Navigation:</strong> Links-Sidebar &rarr; "People" (Kontakte) oder
  "Companies" fuer Unternehmens-Leads.</li>
  <li><strong>Ihre Rolle:</strong> Workspace Admin &mdash; Sie haben vollen Zugriff
  auf alle Einstellungen und koennen weitere Nutzer einladen.</li>
</ul>

<h3>5. Erreichbarkeit (kein VPN noetig)</h3>
<p>Das CRM ist ueber normale HTTPS von ueberall erreichbar. Sie benoetigen
<strong>kein VPN</strong> &mdash; der Browser-Prompt (Schritt 2) ersetzt die
IP-Beschraenkung.</p>

<hr style="border:none;border-top:1px solid #eee;margin:24px 0">
<p style="color:#888;font-size:12px">
  VectiScan &mdash; Vectigal GmbH &mdash;
  <a href="mailto:support@vectiscan.de">support@vectiscan.de</a>
</p>
</body>
</html>"""

payload = json.dumps(
    {
        "from": "VectiScan <noreply@vectiscan.de>",
        "to": [target],
        "subject": "Ihr VectiScan CRM Admin-Zugang",
        "html": html,
    }
).encode()

import subprocess

result = subprocess.run(
    [
        "curl", "-sf", "-X", "POST", "https://api.resend.com/emails",
        "-H", f"Authorization: Bearer {resend_key}",
        "-H", "Content-Type: application/json",
        "-d", payload.decode(),
    ],
    capture_output=True,
    text=True,
    timeout=30,
)

if result.returncode != 0:
    print(f"ERROR curl failed: {result.stderr}", file=sys.stderr)
    sys.exit(1)

try:
    resp = json.loads(result.stdout)
    if resp.get("id"):
        print(f"OK Anleitung-Email zugestellt Resend-ID={resp.get('id')}")
    else:
        print(f"ERROR Resend response: {result.stdout}", file=sys.stderr)
        sys.exit(1)
except json.JSONDecodeError:
    print(f"ERROR Cannot parse Resend response: {result.stdout}", file=sys.stderr)
    sys.exit(1)
