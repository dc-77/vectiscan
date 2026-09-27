# -*- coding: utf-8 -*-
"""Fremddomains im Kundentext (S6b-4, spec/11 T9, Entscheidung E11).

Auf einem geteilten Server stehen Namen anderer Domains in Zertifikaten, Passivquellen und
Stream-Kennungen (castenow: netscope-media.de im Standardzertifikat des Plesk-Servers,
tonausstrom.de als Shoutcast-Stream). Die Fakten behalten sie, weil daraus Zählung und
Zuständigkeit folgen; im Bericht steht an ihrer Stelle "Fremddomain". Die Domains des Kunden
und des Hosters sind nie fremd.
"""
from __future__ import annotations

import re
from typing import Any, Callable

from reporter.facts import schema as FS
from reporter.facts import systems as SYS

FREMD = "Fremddomain"


def foreign_domain_names(facts: FS.Facts) -> list[str]:
    """Registrierbare Fremddomains aller geteilten Server und fremden Dienste des Auftrags."""
    domains = list(facts.scan.domains) or ([facts.scan.domain] if facts.scan.domain else [])
    out: set[str] = set()
    for h in facts.hosts:
        out.update(SYS.foreign_domains(h.shared))
    for s in facts.services:
        if not s.foreign or s.cert is None:
            continue
        for name in [s.cert.cn, *s.cert.san]:
            if name and SYS.is_dns_name(name.lstrip("*.")) and not SYS.under(name.lstrip("*."), domains):
                out.add(SYS.registrable(name.lstrip("*.")))
    return sorted((d for d in out if d and not SYS.under(d, domains) and d not in SYS.HOSTER_DOMAINS),
                  key=len, reverse=True)


def masker(facts: FS.Facts) -> Callable[[str], str] | None:
    """Ersetzt jede Fremddomain samt Unternamen ("www.", "*.") durch "Fremddomain"."""
    names = foreign_domain_names(facts)
    if not names:
        return None
    pattern = re.compile(r"(?<![\w.-])(?:\*\.)?(?:[a-z0-9-]+\.)*(?:"
                         + "|".join(re.escape(n) for n in names) + r")(?![\w-])", re.I)

    def mask(text: str) -> str:
        return pattern.sub(FREMD, text)

    return mask


def _walk(value: Any, fn: Callable[[str], str]) -> Any:
    if isinstance(value, str):
        return fn(value)
    if isinstance(value, list):
        return [_walk(v, fn) for v in value]
    if isinstance(value, dict):
        return {k: _walk(v, fn) for k, v in value.items()}
    return value


def mask_report(data: Any, facts: FS.Facts) -> Any:
    """Reportdaten mit maskierten Fremddomains; ohne Fremddomain unverändert."""
    fn = masker(facts)
    if fn is None:
        return data
    dumped = data.model_dump()
    meta = dumped.pop("meta")
    masked = _walk(dumped, fn)
    masked["meta"] = meta
    return type(data).model_validate(masked)


__all__ = ["FREMD", "foreign_domain_names", "masker", "mask_report"]
