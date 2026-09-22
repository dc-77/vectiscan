"""Deterministische Serialisierung und kleine Helfer fuer das Facts-Paket.

Alles, was zwischen zwei Builds oder zwischen Windows, Linux und CI abweichen
koennte, laeuft ueber diese Funktionen: Zeitstempel (immer UTC, ohne Bruchteile),
Nachweis-Ausschnitte (ANSI und Zeilenumbrueche entfernt, Laenge gekappt),
Sortierschluessel (None-sicher) und die JSON-Ausgabe (utf-8, LF, sortierte
Schluessel, fester Einzug).
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_WS_RE = re.compile(r"\s+")

EXCERPT_MAX = 300


def strip_ansi(text: str) -> str:
    """ANSI-Steuersequenzen (testssl-Farben) entfernen."""
    return ANSI_RE.sub("", text or "")


def excerpt(text: str | None, limit: int = EXCERPT_MAX) -> str:
    """Nachweis-Ausschnitt: ANSI raus, Whitespace kollabiert, Laenge gekappt."""
    if not text:
        return ""
    cleaned = strip_ansi(str(text)).replace("\r", "")
    cleaned = _WS_RE.sub(" ", cleaned).strip()
    if len(cleaned) > limit:
        return cleaned[: limit - 3].rstrip() + "..."
    return cleaned


def kv(pairs: list[tuple[str, Any]], limit: int = EXCERPT_MAX) -> str:
    """Nachweiszeile aus Schluessel-Wert-Paaren, ohne Python-Darstellungen.

    Bis S6 wurden diese Zeilen mit f-Strings gebaut, und damit standen
    ``None``, ``True`` und Listen in eckigen Klammern im Kundentext
    (``x-feserver=None``, ``reachable=True``, ``dkim=False``, spec/08 Punkt 3).
    Hier gilt: ein leerer Wert faellt weg, Wahrheitswerte werden ``ja`` und
    ``nein``, eine Liste wird zur Aufzaehlung mit Komma.
    """
    parts: list[str] = []
    for name, value in pairs:
        if value is None or value == "" or value == [] or value == {}:
            continue
        if isinstance(value, bool):
            text = "ja" if value else "nein"
        elif isinstance(value, (list, tuple, set)):
            items = [str(v) for v in value if v not in (None, "")]
            if not items:
                continue
            text = ", ".join(items)
        else:
            text = str(value)
        parts.append(f"{name}={text}" if name else text)
    return excerpt(" ".join(parts), limit)


def iso_utc(value: Any) -> str | None:
    """Beliebigen Zeitwert auf ``YYYY-MM-DDTHH:MM:SSZ`` normalisieren.

    Akzeptiert ISO-8601-Strings mit ``Z`` oder Offset (auch mit neun
    Nachkommastellen wie bei httpx), ``datetime``-Objekte und Unix-Epochen
    (int/float/Ziffernstring). Unbekanntes ergibt ``None``.
    """
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        dt = datetime.fromtimestamp(float(value), tz=timezone.utc)
    else:
        text = str(value).strip()
        if re.fullmatch(r"\d{9,11}(\.\d+)?", text):
            dt = datetime.fromtimestamp(float(text), tz=timezone.utc)
        else:
            # Bruchteile auf sechs Stellen kappen, Python 3.11 kann nicht mehr.
            text = re.sub(r"(\.\d{6})\d+", r"\1", text)
            if text.endswith("Z"):
                text = text[:-1] + "+00:00"
            try:
                dt = datetime.fromisoformat(text)
            except ValueError:
                return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def iso_date(value: Any) -> str | None:
    """Nur das Datum (``YYYY-MM-DD``) eines Zeitwerts."""
    full = iso_utc(value)
    return full[:10] if full else None


def days_between(later: str | None, earlier: str | None) -> int | None:
    """Ganze Tage von ``earlier`` bis ``later`` (beide ISO), sonst None."""
    a = iso_utc(later)
    b = iso_utc(earlier)
    if not a or not b:
        return None
    da = datetime.strptime(a, "%Y-%m-%dT%H:%M:%SZ")
    db = datetime.strptime(b, "%Y-%m-%dT%H:%M:%SZ")
    return (da - db).days


def sort_key(*parts: Any) -> tuple:
    """None-sicherer Sortierschluessel: None sortiert vor allem anderen."""
    key: list[tuple[int, Any]] = []
    for p in parts:
        if p is None:
            key.append((0, ""))
        elif isinstance(p, bool):
            key.append((1, int(p)))
        elif isinstance(p, (int, float)):
            key.append((1, p))
        else:
            key.append((2, str(p)))
    return tuple(key)


def ip_family(ip: str) -> int:
    return 6 if ":" in (ip or "") else 4


def ip_token(ip: str | None) -> str:
    """IP fuer IDs: IPv6 in eckigen Klammern, damit der Doppelpunkt kein Trenner ist."""
    if not ip:
        return "-"
    return f"[{ip}]" if ":" in ip else ip


def short_hash(text: str, length: int = 8) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:length]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text_file(path: Path) -> str:
    """Hash einer Textdatei mit normalisierten Zeilenenden (CRLF -> LF).

    Quellcode wie ``eol_data_generated.py`` liegt unter Windows mit CRLF, in CI mit LF
    im Arbeitsbaum; der Hash muss auf beiden Seiten gleich sein.
    """
    data = path.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return hashlib.sha256(data).hexdigest()


def dumps(data: Any) -> str:
    """Deterministisches JSON: sortierte Schluessel, Einzug 1, kein ASCII-Escaping."""
    return json.dumps(data, ensure_ascii=False, sort_keys=True, indent=1) + "\n"


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(dumps(data))


def load_json(path: Path) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def try_json(text: str | None) -> Any | None:
    """JSON parsen, bei Fehler None (nie werfen)."""
    if text is None:
        return None
    text = text.strip()
    if not text or text[0] not in "[{":
        return None
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


def jsonl(text: str | None) -> list[Any]:
    """JSON-Lines zeilenweise parsen; unparsbare Zeilen werden uebersprungen."""
    out: list[Any] = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


def unique_sorted(items: Iterable[Any]) -> list[Any]:
    seen: set = set()
    out: list[Any] = []
    for it in items:
        if it in seen:
            continue
        seen.add(it)
        out.append(it)
    return sorted(out, key=lambda x: sort_key(x))
