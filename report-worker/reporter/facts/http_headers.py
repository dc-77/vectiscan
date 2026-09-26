"""An welcher Antwort die Sicherheits-Header gemessen sind (S6b-3, spec/10 R1, R4).

header_check misst die erste Antwort eines Namens und speichert keinen Statuscode. An einer
Weiterleitung, einer Fehler- oder einer Abwehrseite (Vercel-Challenge) fehlen die Header der
eigentlichen Seite oft, obwohl die Endseite sie setzt (Junkerwerk outlook: 302 ohne Inhalt,
``logon.aspx`` mit ``X-Frame-Options: SAMEORIGIN``). Dieses Modul legt fest, welche Antwort
bewertet wird, und haelt fest, woher Status und Header stammen:

1. header_check, wenn die erste Antwort eine Endseite ist (2xx, HTML, ohne ``location``,
   ohne Challenge-Merkmal). Status aus der httpx-Kette, sonst testssl, sonst ``location``,
   sonst Inventar.
2. redirect_probe, wenn header_check eine Weiterleitung auf demselben Host sah und die
   Probe die Endseite belegt (kein ``location``, HTML, gleicher Host, kein Fehlertitel,
   andere Header als header_check). Der Status der Probe allein ist nicht verlaesslich
   (bergersysteme ftp: 200 bei Titel "403 Forbidden").
3. testssl-HTTP-Abschnitt, wenn header_check nichts lieferte und testssl fuer denselben
   Namen 200 sah (castenow bitwarden).
4. Teilbelege an der Endseite desselben Hosts: wpscan ``interesting_findings`` belegt einen
   gesetzten Header, ZAP-Regeln belegen fehlende (10020, 10021, 10038, 10063) oder eine
   gesetzte CSP (10055). Nur die belegten Header gelten, der Rest bleibt unbekannt.

Sonst bleibt die Messung an der ersten Antwort, und die Header-Regeln (ausser HSTS) sind
nicht pruefbar; der Bericht sagt, an welcher Antwort gemessen wurde.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlsplit

from reporter.facts import schema as S

BASIC_HEADERS = ("x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy")
CANONICAL = BASIC_HEADERS + ("content-security-policy",)
# ZAP-Passivregeln, die das Fehlen eines Headers an einer URL melden.
ZAP_MISSING = {"10020": "x-frame-options", "10021": "x-content-type-options",
               "10038": "content-security-policy", "10063": "permissions-policy"}
ZAP_CSP_PRESENT = {"10055"}
_ERROR_TITLE_RE = re.compile(r"^\s*\d{3}\b|forbidden|not found|bad request|just a moment|"
                             r"security checkpoint|attention required|access denied", re.I)
_CHALLENGE_HEADERS = ("x-vercel-mitigated", "cf-mitigated")
_VOLATILE = {"date", "age", "expires", "set-cookie", "request-id", "x-requestid", "cf-ray",
             "x-request-id", "x-vercel-id", "etag", "last-modified"}


@dataclass
class Measured:
    measurement: S.HeaderMeasurement
    headers: dict[str, str] = field(default_factory=dict)
    security_headers: dict[str, S.SecHeader] = field(default_factory=dict)
    csp: Optional[S.Csp] = None


def _lower(headers: Any) -> dict[str, str]:
    if not isinstance(headers, dict):
        return {}
    return {str(k).lower(): str(v) for k, v in headers.items()}


def _host(url: Any) -> Optional[str]:
    try:
        return (urlsplit(str(url or "")).hostname or "").lower() or None
    except ValueError:
        return None


def _path(url: Any) -> str:
    try:
        return urlsplit(str(url or "")).path or "/"
    except ValueError:
        return "/"


def _int(v: Any) -> Optional[int]:
    try:
        return int(v) if v is not None and not isinstance(v, bool) and int(v) > 0 else None
    except (TypeError, ValueError):
        return None


def _html(content_type: Optional[str]) -> Optional[bool]:
    if not content_type:
        return None
    return "html" in content_type.lower()


def _challenge(headers: dict[str, str], title: Optional[str]) -> Optional[str]:
    for key in _CHALLENGE_HEADERS:
        if headers.get(key):
            return f"{key}: {headers[key]}"
    if title and re.search(r"security checkpoint|just a moment|attention required", title, re.I):
        return f"Titel {title}"
    return None


def _basis_of(resp: S.HttpResponse) -> S.HeaderBasis:
    if resp.challenge:
        return "challenge"
    st = resp.status_code
    if resp.location or (st is not None and 300 <= st < 400):
        return "redirect"
    if st is not None and 400 <= st < 500:
        return "client_error"
    if st is not None and st >= 500:
        return "server_error"
    if _html(resp.content_type) is False:
        return "non_html"
    return "final"


def parse_csp(value: Optional[str]) -> Optional[S.Csp]:
    """CSP in Direktiven zerlegen (spec/10 R1: script-src und style-src getrennt).

    ``script_*`` liest script-src, sonst default-src. Ein Nonce, Hash oder
    ``strict-dynamic`` hebt ``unsafe-inline`` fuer Skripte auf (CSP Level 2 und 3); eine
    Wildcard-Quelle ist ``*`` allein oder ein Schema ohne Host (``https:``, ``*.`` zaehlt
    nicht, das ist eine Unterdomain-Liste).
    """
    if not value:
        return None
    directives: dict[str, list[str]] = {}
    for part in value.split(";"):
        toks = part.strip().split()
        if not toks:
            continue
        name = toks[0].lower()
        directives.setdefault(name, [t for t in toks[1:]])
    script = directives.get("script-src", directives.get("default-src", []))
    style = directives.get("style-src", directives.get("default-src", []))
    low_script = [t.lower() for t in script]
    nonce_hash = any(t.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) or t == "'strict-dynamic'"
                     for t in low_script)
    # Wildcard-Quelle: "*", "https://*" oder ein blosses http(s)-Schema. data:, blob: und wss:
    # sind eng umrissene Schemata, keine Freigabe beliebiger Ursprünge (castenow www).
    wild = sorted(name for name, toks in directives.items()
                  if any(re.fullmatch(r"\*|(?:https?|\*)://\*|https?:", t.lower()) for t in toks)
                  and name not in ("frame-ancestors", "report-uri", "report-to", "upgrade-insecure-requests"))
    fa = directives.get("frame-ancestors")
    return S.Csp(
        present=True, value=value[:500],
        unsafe_inline="'unsafe-inline'" in value, unsafe_eval="'unsafe-eval'" in value,
        wildcard=bool(wild),
        directives={k: v[:30] for k, v in sorted(directives.items())},
        script_unsafe_inline=("'unsafe-inline'" in low_script) and not nonce_hash,
        script_unsafe_eval="'unsafe-eval'" in low_script,
        style_unsafe_inline="'unsafe-inline'" in [t.lower() for t in style],
        nonce_or_hash=nonce_hash, wildcard_directives=wild,
        frame_ancestors=" ".join(fa) if fa is not None else None,
    )


def _status_of_first(vh: str, res: dict, headers: dict[str, str], line: Optional[dict],
                     ts: Any, inv_status: Optional[int]) -> tuple[Optional[int], Optional[str]]:
    chain = (line or {}).get("chain_status_codes")
    if isinstance(chain, list) and chain and _int(chain[0]):
        return _int(chain[0]), "httpx_chain"
    if line and not chain and not headers.get("location") and _int(line.get("status_code")):
        # Ohne Kette hat httpx genau eine Antwort gesehen: die erste.
        return _int(line.get("status_code")), "httpx_chain"
    if ts is not None and getattr(ts, "http_status", None) and (getattr(ts, "fqdn", None) or "") == vh:
        return int(ts.http_status), "testssl"
    if headers.get("location"):
        return None, "location"
    if inv_status:
        return inv_status, "inventory"
    return None, None


def _rd_final(vh: str, rd: Optional[dict], hc_headers: dict[str, str]) -> Optional[dict[str, str]]:
    """Header der Endseite laut redirect_probe, wenn die Probe sie belegt (sonst None)."""
    if not isinstance(rd, dict):
        return None
    rh = _lower(rd.get("response_headers"))
    if not rh or rh.get("location") or _html(rh.get("content-type")) is not True:
        return None
    if rd.get("is_cross_domain") or _host(rd.get("final_url")) != vh.lower():
        return None
    if _ERROR_TITLE_RE.search(str(rd.get("page_title") or "")):
        return None
    stable = lambda h: {k: v for k, v in h.items() if k not in _VOLATILE}  # noqa: E731
    if hc_headers and stable(rh) == stable(hc_headers):
        return None
    return rh


def _partial(vh: str, final_url: Optional[str], wp: Optional[dict],
             zap_raw: list[dict]) -> tuple[dict[str, S.HeaderValue], Optional[S.HeaderTool]]:
    """Teilbelege an der Endseite (spec/10 R1): wpscan belegt gesetzt, ZAP belegt fehlend."""
    out: dict[str, S.HeaderValue] = {}
    tool: Optional[S.HeaderTool] = None
    if not final_url or _host(final_url) != vh.lower():
        return out, tool
    fpath = _path(final_url)
    for item in (wp or {}).get("interesting_findings") or []:
        if not isinstance(item, dict) or str(item.get("type")) != "headers":
            continue
        if _host(item.get("url")) != vh.lower() or _path(item.get("url")) != fpath:
            continue
        for entry in item.get("interesting_entries") or []:
            name, _, val = str(entry).partition(":")
            name = name.strip().lower()
            if name in CANONICAL and val.strip():
                out[name] = S.HeaderValue(present=True, value=val.strip()[:300], tool="wpscan",
                                          url=str(item.get("url"))[:300])
                tool = tool or "wpscan"
    for a in zap_raw:
        if not isinstance(a, dict):
            continue
        url = str(a.get("url") or "")
        if _host(url) != vh.lower() or _path(url) != fpath:
            continue
        pid = str(a.get("pluginId") or "")
        if pid in ZAP_MISSING and ZAP_MISSING[pid] not in out:
            out[ZAP_MISSING[pid]] = S.HeaderValue(present=False, tool="zap", url=url[:300])
            tool = tool or "zap"
        elif pid in ZAP_CSP_PRESENT and "content-security-policy" not in out:
            out["content-security-policy"] = S.HeaderValue(present=True, value=str(a.get("evidence") or "")[:300] or None,
                                                           tool="zap", url=url[:300])
            tool = tool or "zap"
    return out, tool


def measure(vh: str, res: Optional[dict], line: Optional[dict], rd: Optional[dict], ts: Any,
            wp: Optional[dict], zap_raw: list[dict], inv_status: Optional[int]) -> Optional[Measured]:
    """Messbasis der Sicherheits-Header fuer einen Namen. None ohne jede Messung."""
    # API-Snapshot (Golden ohne Tar): die header_check-Zeile traegt kein "reachable"; eine
    # Antwort mit Headern ist dann eine Messung (castenow-Vorlauf 4e6b6883).
    if isinstance(res, dict) and isinstance(res.get("reachable"), bool):
        reachable = res["reachable"]
    else:
        reachable = isinstance(res, dict) and bool(res.get("headers"))
    hc_headers = _lower((res or {}).get("headers")) if reachable else {}
    title = (line or {}).get("title")

    if not reachable:
        # Stufe 3: testssl-HTTP-Abschnitt fuer genau diesen Namen mit Status 200.
        if ts is not None and getattr(ts, "http_status", None) == 200 and getattr(ts, "http_headers_listed", False) \
                and (getattr(ts, "fqdn", None) or "") == vh:
            headers = dict(ts.http_headers)
            ev = S.HttpResponse(tool="testssl", url=f"https://{vh}/", status_code=200, status_basis="testssl")
            return _complete(ev, None, headers, "final")
        if res is None and not line and not rd:
            return None
        return Measured(measurement=S.HeaderMeasurement(basis="unreachable"))

    status, basis_src = _status_of_first(vh, res, hc_headers, line, ts, inv_status)
    first = S.HttpResponse(tool="header_check", url=str((res or {}).get("url") or "")[:300] or None,
                           status_code=status, status_basis=basis_src,
                           location=hc_headers.get("location") or None,
                           content_type=hc_headers.get("content-type") or None,
                           challenge=_challenge(hc_headers, title))
    basis = _basis_of(first)
    if basis == "final":
        # Clientseitige Weiterleitung: header_check sah 200, die Probe endet auf einer
        # anderen Seite desselben Hosts mit anderem Titel (heuel ose "Redirector").
        if isinstance(rd, dict) and _host(rd.get("final_url")) == vh.lower() \
                and _path(rd.get("final_url")) != _path(first.url) \
                and title and rd.get("page_title") and str(rd.get("page_title")) != str(title):
            basis = "redirect"
            first = first.model_copy(update={"location": str(rd.get("final_url"))[:300]})
        else:
            return _complete(first, first, hc_headers, "final")

    if basis == "redirect":
        rh = _rd_final(vh, rd, hc_headers)
        if rh is not None:
            ev = S.HttpResponse(tool="redirect_probe", url=str(rd.get("final_url"))[:300],
                                status_code=_int(rd.get("status_code")), status_basis="claimed",
                                content_type=rh.get("content-type"))
            return _complete(ev, first, rh, "final")
        final_url = None
        for cand in ((line or {}).get("final_url"), (rd or {}).get("final_url"), first.location):
            if cand and _host(cand) == vh.lower():
                final_url = str(cand)
                break
        values, tool = _partial(vh, final_url, wp, zap_raw)
        if values and tool:
            ev = S.HttpResponse(tool=tool, url=final_url[:300] if final_url else None,
                                status_code=None, status_basis="claimed")
            return _partial_result(ev, first, values)
    return Measured(measurement=S.HeaderMeasurement(basis=basis, first=first))


def _complete(evaluated: S.HttpResponse, first: Optional[S.HttpResponse], headers: dict[str, str],
              basis: S.HeaderBasis) -> Measured:
    csp = parse_csp(headers.get("content-security-policy")) or S.Csp(present=False)
    values: dict[str, S.HeaderValue] = {}
    for name in CANONICAL:
        present = name in headers
        values[name] = S.HeaderValue(present=present, value=headers.get(name, None) and headers[name][:300],
                                     tool=evaluated.tool, url=evaluated.url)
    return _finish(evaluated, first, values, basis, complete=True, csp=csp, headers=headers)


def _partial_result(evaluated: S.HttpResponse, first: S.HttpResponse,
                    values: dict[str, S.HeaderValue]) -> Measured:
    cv = values.get("content-security-policy")
    csp = None
    if cv is not None:
        csp = parse_csp(cv.value) if cv.present and cv.value else S.Csp(present=bool(cv.present))
    return _finish(evaluated, first, values, "final", complete=False, csp=csp, headers={})


def _finish(evaluated: S.HttpResponse, first: Optional[S.HttpResponse], values: dict[str, S.HeaderValue],
            basis: S.HeaderBasis, *, complete: bool, csp: Optional[S.Csp], headers: dict[str, str]) -> Measured:
    framing = None
    xfo = values.get("x-frame-options")
    if xfo is not None and xfo.present:
        framing = True
    elif csp is not None and csp.frame_ancestors:
        framing = True
    elif xfo is not None and xfo.present is False and (csp is None or csp.present is False or complete):
        framing = False
    sec: dict[str, S.SecHeader] = {}
    for name in BASIC_HEADERS:
        v = values.get(name)
        if v is None or v.present is None:
            continue
        present = bool(v.present)
        value = v.value
        if name == "x-frame-options" and not present and framing:
            # Framing-Schutz ueber frame-ancestors der CSP (spec/10 R2, huendgen www).
            present, value = True, f"frame-ancestors {csp.frame_ancestors}" if csp else None
        sec[name] = S.SecHeader(present=present, value=value)
    missing = [n for n in CANONICAL if (n in sec and not sec[n].present)
               or (n == "content-security-policy" and csp is not None and csp.present is False)]
    unknown = [n for n in CANONICAL if n not in missing
               and not (n in sec and sec[n].present)
               and not (n == "content-security-policy" and csp is not None and csp.present)]
    m = S.HeaderMeasurement(basis=basis, first=first, evaluated=evaluated, complete=complete,
                            headers=values, missing=missing, unknown=unknown, framing_protected=framing)
    return Measured(measurement=m, headers=headers, security_headers=sec, csp=csp)


__all__ = ["BASIC_HEADERS", "CANONICAL", "Measured", "measure", "parse_csp"]
