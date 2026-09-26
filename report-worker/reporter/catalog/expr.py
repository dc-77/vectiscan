"""Kleine Ausdruckssprache fuer die Pruefungen. Kein eval, kein exec.

Ein Ausdruck wird mit ``ast.parse(..., mode="eval")`` gelesen und einmal beim Laden in
verschachtelte Python-Closures uebersetzt. Erlaubt sind nur: Boolesche Verknuepfung
(``and``/``or``), ``not``, Vergleiche (``== != < <= > >= in not in is is not``),
Namen aus dem Kontext (Scope-Bindungen, Tabellen aus ``tables.py``), Attributzugriff,
Subscript mit konstantem Schluessel, Literale, Listen/Tupel und Aufrufe registrierter
Funktionen. Alles andere ist ein Ladefehler (``CatalogSpecError``).

Dreiwertigkeit: Vergleiche mit ``None`` ergeben ``False`` (auch ``!=`` und ``not in``);
``is None``, ``is True``, ``is False`` bleiben exakt. Attributzugriff auf ``None``
ergibt ``None`` (None-Propagation), Subscript auf Dicts ist ``get``.

Statische Pruefung beim Laden: Attributpfade werden gegen die pydantic-Felder des
Scopes aufgeloest (Tippfehler sind Ladefehler). Felder vom Typ ``Optional[bool]``
duerfen nur mit ``is True``/``is False``/``is None`` verglichen werden, nie als nackter
Operand oder unter ``not`` (verhindert Klartext-Befunde aus "unbekannt").
"""
from __future__ import annotations

import ast
import re
import types as _types
import typing
from typing import Any, Callable

from reporter.facts.serialize import days_between

Ctx = dict[str, Any]
Fn = Callable[[Ctx], Any]


class CatalogSpecError(Exception):
    """Fehler in einer Katalogdefinition (YAML, Ausdruck, Template)."""


CALLABLE = object()  # Markierung fuer Kontextfunktionen in der Typtabelle


# ---------------------------------------------------------------- Funktionen

_REGEX_CACHE: dict[str, re.Pattern[str]] = {}


def _pattern(pattern: Any) -> re.Pattern[str]:
    if isinstance(pattern, re.Pattern):
        return pattern
    key = str(pattern)
    if key not in _REGEX_CACHE:
        _REGEX_CACHE[key] = re.compile(key, re.I)
    return _REGEX_CACHE[key]


def f_len(x: Any) -> int:
    return 0 if x is None else len(x)


def f_count(x: Any) -> int:
    return f_len(x)


def f_any_in(seq: Any, values: Any) -> bool:
    if not seq or values is None:
        return False
    vs = set(values)
    return any(item in vs for item in seq)


def f_matches(text: Any, pattern: Any) -> bool:
    if text is None or pattern is None:
        return False
    return bool(_pattern(pattern).search(str(text)))


def f_any_match(seq: Any, pattern: Any) -> bool:
    """True, wenn mindestens ein Element der Liste auf das Muster passt."""
    if not seq or pattern is None:
        return False
    rx = _pattern(pattern)
    return any(item is not None and rx.search(str(item)) for item in seq)


def f_startswith(text: Any, prefix: Any) -> bool:
    if text is None or prefix is None:
        return False
    return str(text).lower().startswith(str(prefix).lower())


def f_contains(text: Any, sub: Any) -> bool:
    if text is None or sub is None:
        return False
    return str(sub).lower() in str(text).lower()


def f_lower(text: Any) -> str:
    return "" if text is None else str(text).lower()


def f_ports(services: Any) -> set[int]:
    if not services:
        return set()
    return {s.port for s in services if getattr(s, "state", "open") == "open"}


def f_has_port(services: Any, port: Any) -> bool:
    return port in f_ports(services)


def f_days_until(date: Any, ref: Any) -> int | None:
    if date is None or ref is None:
        return None
    return days_between(date, ref)


def f_has_version(text: Any) -> bool:
    return bool(text) and bool(re.search(r"\d+\.\d+", str(text)))


def f_spf_shared_ips(dns: Any, hosts: Any) -> list[str]:
    """Adressen geteilter Server beim Hoster, die der SPF-Eintrag als Absender freigibt
    (S6b-3, spec/10 R19: castenow ``a`` auf den Agenturserver 159.69.143.80)."""
    if dns is None or getattr(dns, "spf", None) is None:
        return []
    shared = {h.ip for h in hosts or [] if getattr(h, "shared", None) is not None and h.shared.kind == "hoster"}
    out: list[str] = []
    for mech in dns.spf.mechanisms:
        if getattr(mech, "qualifier", "+") in ("-", "~"):
            continue
        for ip in getattr(mech, "ips", []) or []:
            if ip in shared and ip not in out:
                out.append(ip)
    return out


def f_is_cdn(host: Any, services: Any) -> bool:
    from reporter.catalog.tables import CDN_PRODUCTS
    if host is not None and getattr(host, "cdn_provider", None):
        return True
    for s in services or []:
        if CDN_PRODUCTS.search(str(getattr(s, "product", "") or "")):
            return True
    return False


def f_any_attr(seq: Any, attr: Any, values: Any) -> bool:
    if not seq:
        return False
    vs = set(values or [])
    for item in seq:
        v = item.get(attr) if isinstance(item, dict) else getattr(item, str(attr), None)
        if v in vs:
            return True
    return False


def f_all_attr(seq: Any, attr: Any, values: Any) -> bool:
    if not seq:
        return False
    vs = set(values or [])
    for item in seq:
        v = item.get(attr) if isinstance(item, dict) else getattr(item, str(attr), None)
        if v not in vs:
            return False
    return True


def f_get(obj: Any, key: Any) -> Any:
    if obj is None:
        return None
    if isinstance(obj, dict):
        return obj.get(key)
    return getattr(obj, str(key), None)


def f_first(seq: Any) -> Any:
    if not seq:
        return None
    return seq[0]


def f_zap_match(alert: Any, pairs: Any) -> bool:
    """ZAP-Alert gegen eine Liste (plugin_id, Namensmuster) aus tables.py.

    Das Namensmuster muss immer passen; die plugin_id engt nur ein (dieselbe ID 10020
    traegt zwei verschiedene Alertnamen). Alerts ohne plugin_id matchen nur ueber den Namen.
    """
    if alert is None or not pairs:
        return False
    pid = getattr(alert, "plugin_id", None)
    name = getattr(alert, "name", "") or ""
    for ppid, pat in pairs:
        if not _pattern(pat).search(name):
            continue
        if pid is None or ppid is None or str(pid) == str(ppid):
            return True
    return False


def f_has_enrichment(seq: Any) -> bool:
    """Traegt mindestens ein Threat einen Fremdwert (NVD-Basiswert oder KEV)?

    Ohne Anreicherung aus Phase 3 sind die CVE-Pruefungen nicht beantwortbar:
    ihre Bedingungen fragen nach Werten, die dann nirgends stehen. Vor S5b
    liefen sie deshalb still auf "bestanden" durch, obwohl nichts geprueft war.
    """
    for item in seq or []:
        cvss = getattr(item, "cvss_nvd", None)
        if cvss is not None and getattr(cvss, "score", None) is not None:
            return True
        kev = getattr(item, "kev", None)
        if kev is not None and getattr(kev, "listed", False):
            return True
    return False


def f_admin_fp(obj: Any) -> bool:
    """Gibt sich der Dienst als Verwaltungsoberflaeche zu erkennen (S6b-2, spec/09 Q13)?

    Fingerabdruck ist das Produkt aus nmap, die Server-Kennung oder der Seitentitel aus der
    Antwort des Dienstes (``fp_server``, ``fp_title``) und bei Passivquellen das Banner. Ein
    Port allein ist kein Fingerabdruck.
    """
    from reporter.catalog.tables import ADMIN_PRODUCTS, ADMIN_TITLES
    if obj is None:
        return False
    for attr in ("product", "fp_server", "banner_excerpt"):
        if ADMIN_PRODUCTS.search(str(getattr(obj, attr, "") or "")):
            return True
    return bool(ADMIN_TITLES.search(str(getattr(obj, "fp_title", "") or "")) or f_panel_title(obj))


def f_any_admin_fp(services: Any) -> bool:
    """Gibt sich ein Dienst des Hosts als Verwaltungsoberflaeche zu erkennen (S6b-3, spec/10 R9)?
    Dann ist ein weiterer, nur passiv gemeldeter Port derselben Oberflaeche kein unbekanntes
    Produkt mehr."""
    return any(f_admin_fp(s) for s in services or [])


def f_panel_title(obj: Any) -> bool:
    """Nennt der Seitentitel des Dienstes ein Hosting-Panel (froxlor, Plesk, cPanel ...)?

    Entscheidung DC 26.09. (Nachtrag S6b-2): der Titel eines Hosting-Panels ist ein
    Fingerabdruck nach Q13, und die Startseite eines Hosting-Panels ist seine Anmeldung.
    dortmund-beach zeigt ueber die IP auf Port 443 den Titel "froxlor" (Standard-VHost).
    Ein Produkt allein (nmap "sw-cp-server" ohne Titel) belegt keine Anmeldung.
    """
    from reporter.catalog.tables import HOSTING_PANELS
    if obj is None:
        return False
    return bool(HOSTING_PANELS.search(str(getattr(obj, "fp_title", "") or "")))


def f_hosting_panel(obj: Any) -> bool:
    """Hosting-Verwaltung eines Hosters (Plesk, cPanel, froxlor ...) laut Fingerabdruck."""
    from reporter.catalog.tables import HOSTING_PANELS
    if obj is None:
        return False
    return any(HOSTING_PANELS.search(str(getattr(obj, attr, "") or ""))
               for attr in ("product", "fp_server", "fp_title", "banner_excerpt"))


def f_mx_in_own_zone(dns: Any, domains: Any) -> bool:
    """Liegen alle MX-Ziele unter einer der beauftragten Domains (S6b-2, spec/09 Q4)?

    DANE kann nur umsetzen, wer die Zone des Mailservers pflegt; bei Hornetsecurity oder
    einem Hoster-Mailserver liegt der MX in einer fremden Zone.
    """
    mx = [str(m).rstrip(".").lower() for m in (getattr(dns, "mx", None) or [])]
    doms = [str(d).rstrip(".").lower() for d in (domains or [])]
    if not mx or not doms:
        return False
    return all(any(m == d or m.endswith("." + d) for d in doms) for m in mx)


def f_redirects_elsewhere(fqdn: Any) -> bool:
    """Endet der Aufruf eines Namens auf einem anderen Host (Weiterleitung)?"""
    if fqdn is None:
        return False
    ziel = getattr(fqdn, "final_url", None)
    name = str(getattr(fqdn, "name", "") or "").lower()
    if not ziel or not name:
        return False
    from urllib.parse import urlsplit
    host = (urlsplit(str(ziel)).hostname or "").lower()
    return bool(host) and host != name


FUNCS: dict[str, Callable[..., Any]] = {
    "admin_fp": f_admin_fp, "any_admin_fp": f_any_admin_fp, "hosting_panel": f_hosting_panel, "panel_title": f_panel_title, "mx_in_own_zone": f_mx_in_own_zone,
    "redirects_elsewhere": f_redirects_elsewhere,
    "has_enrichment": f_has_enrichment,
    "len": f_len, "count": f_count, "any_in": f_any_in, "matches": f_matches, "any_match": f_any_match, "startswith": f_startswith,
    "contains": f_contains, "lower": f_lower, "ports": f_ports, "has_port": f_has_port,
    "days_until": f_days_until, "has_version": f_has_version, "is_cdn": f_is_cdn, "any_attr": f_any_attr,
    "all_attr": f_all_attr, "get": f_get, "first": f_first, "zap_match": f_zap_match,
    "spf_shared_ips": f_spf_shared_ips,
}

# ---------------------------------------------------------------- Typhilfen

_NONE = type(None)


def _union_args(ann: Any) -> tuple | None:
    origin = typing.get_origin(ann)
    if origin is typing.Union or origin is _types.UnionType:
        return typing.get_args(ann)
    return None


def unwrap_optional(ann: Any) -> Any:
    args = _union_args(ann)
    if args is None:
        return ann
    rest = tuple(a for a in args if a is not _NONE)
    return rest[0] if len(rest) == 1 else ann


def is_optional_bool(ann: Any) -> bool:
    args = _union_args(ann)
    return args is not None and set(args) == {bool, _NONE}


def is_model(ann: Any) -> bool:
    return isinstance(ann, type) and hasattr(ann, "model_fields")


def field_annotation(model: Any, attr: str) -> Any:
    """Annotation eines Feldes; ``None`` wenn der Typ keine Felder kennt, Fehler wenn das Feld fehlt."""
    base = unwrap_optional(model)
    if is_model(base):
        info = base.model_fields.get(attr)
        if info is None:
            raise CatalogSpecError(f"Feld {attr!r} gibt es in {base.__name__} nicht")
        return info.annotation
    return None


def subscript_annotation(ann: Any) -> Any:
    base = unwrap_optional(ann)
    origin = typing.get_origin(base)
    if origin is dict:
        return typing.get_args(base)[1]
    if origin is list:
        return typing.get_args(base)[0]
    return None


# ---------------------------------------------------------------- Compiler

def _truthy(v: Any) -> bool:
    return False if v is None else bool(v)


def _cmp(op: type, a: Any, b: Any) -> bool:
    if op is ast.Is:
        return a is b
    if op is ast.IsNot:
        return a is not b
    if a is None or b is None:
        return False
    try:
        if op is ast.Eq:
            return a == b
        if op is ast.NotEq:
            return a != b
        if op is ast.Lt:
            return a < b
        if op is ast.LtE:
            return a <= b
        if op is ast.Gt:
            return a > b
        if op is ast.GtE:
            return a >= b
        if op is ast.In:
            return a in b
        if op is ast.NotIn:
            return a not in b
    except TypeError:
        return False
    raise CatalogSpecError(f"Vergleichsoperator {op.__name__} nicht erlaubt")


_ALLOWED_CMP = (ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.In, ast.NotIn, ast.Is, ast.IsNot)


class Expr:
    """Kompilierter Ausdruck. ``expr(ctx)`` liefert den Wert, ``expr.test(ctx)`` den Wahrheitswert."""

    def __init__(self, text: str, fn: Fn, names: set[str], paths: frozenset[str] = frozenset()):
        self.text = text
        self._fn = fn
        self.names = names
        # S6b-2 (spec/09 Q7): Attributpfade, auf die der Ausdruck sieht ("dns.dnssec.signed",
        # "tls.cert.days_left"); der Nachweis eines Treffers zeigt genau diese Fakten.
        self.paths = paths

    def __call__(self, ctx: Ctx) -> Any:
        return self._fn(ctx)

    def test(self, ctx: Ctx) -> bool:
        return _truthy(self._fn(ctx))

    def __repr__(self) -> str:
        return f"Expr({self.text!r})"


class _Compiler:
    def __init__(self, text: str, where: str, types_: dict[str, Any], tables: dict[str, Any]):
        self.text = text
        self.where = where
        self.types = types_
        self.tables = tables
        self.names: set[str] = set()

    def err(self, msg: str) -> CatalogSpecError:
        return CatalogSpecError(f"{self.where}: {msg} in Ausdruck {self.text!r}")

    # -- Typen (statisch) -------------------------------------------------
    def infer(self, node: ast.AST) -> Any:
        """Annotation eines Knotens oder None, wenn nicht bestimmbar."""
        if isinstance(node, ast.Name):
            if node.id in self.types:
                t = self.types[node.id]
                return None if t is CALLABLE else t
            if node.id in self.tables:
                return type(self.tables[node.id])
            return None
        if isinstance(node, ast.Attribute):
            base = self.infer(node.value)
            if base is None:
                return None
            try:
                return field_annotation(base, node.attr)
            except CatalogSpecError as exc:
                raise self.err(str(exc)) from None
        if isinstance(node, ast.Subscript):
            base = self.infer(node.value)
            return subscript_annotation(base) if base is not None else None
        if isinstance(node, ast.Constant):
            return type(node.value)
        return None

    def check_operand(self, node: ast.AST) -> None:
        if isinstance(node, (ast.Attribute, ast.Subscript, ast.Name)) and is_optional_bool(self.infer(node)):
            raise self.err(f"'{ast.unparse(node)}' ist Optional[bool] und muss mit 'is True', 'is False' oder 'is None' verglichen werden")

    # -- Bauen --------------------------------------------------------------
    def build(self, node: ast.AST) -> Fn:
        if isinstance(node, ast.Expression):
            self.check_operand(node.body)
            return self.build(node.body)
        if isinstance(node, ast.BoolOp):
            parts = []
            for v in node.values:
                self.check_operand(v)
                parts.append(self.build(v))
            if isinstance(node.op, ast.And):
                def fn_and(ctx: Ctx, parts=parts) -> bool:
                    return all(_truthy(p(ctx)) for p in parts)
                return fn_and
            if isinstance(node.op, ast.Or):
                def fn_or(ctx: Ctx, parts=parts) -> bool:
                    return any(_truthy(p(ctx)) for p in parts)
                return fn_or
            raise self.err("unbekannte Verknuepfung")
        if isinstance(node, ast.UnaryOp):
            if isinstance(node.op, ast.Not):
                self.check_operand(node.operand)
                inner = self.build(node.operand)
                return lambda ctx, inner=inner: not _truthy(inner(ctx))
            if isinstance(node.op, ast.USub) and isinstance(node.operand, ast.Constant):
                value = -node.operand.value
                return lambda ctx, value=value: value
            raise self.err("nur 'not' und negative Zahlen sind erlaubt")
        if isinstance(node, ast.Compare):
            operands = [node.left, *node.comparators]
            for i, op in enumerate(node.ops):
                if not isinstance(op, _ALLOWED_CMP):
                    raise self.err(f"Vergleich {type(op).__name__} nicht erlaubt")
                left, right = operands[i], operands[i + 1]
                if isinstance(right, ast.Constant) and right.value is None and not isinstance(op, (ast.Is, ast.IsNot)):
                    raise self.err("Vergleich mit None nur ueber 'is None' / 'is not None'")
                for side in (left, right):
                    if isinstance(side, (ast.Attribute, ast.Subscript, ast.Name)) and is_optional_bool(self.infer(side)) \
                            and not isinstance(op, (ast.Is, ast.IsNot)):
                        raise self.err(f"'{ast.unparse(side)}' ist Optional[bool] und darf nur mit 'is' verglichen werden")
            fns = [self.build(o) for o in operands]
            ops = [type(o) for o in node.ops]

            def fn_cmp(ctx: Ctx, fns=fns, ops=ops) -> bool:
                left_v = fns[0](ctx)
                for op, right_fn in zip(ops, fns[1:]):
                    right_v = right_fn(ctx)
                    if not _cmp(op, left_v, right_v):
                        return False
                    left_v = right_v
                return True
            return fn_cmp
        if isinstance(node, ast.Name):
            name = node.id
            if name in self.types:
                self.names.add(name)
                return lambda ctx, name=name: ctx.get(name)
            if name in self.tables:
                value = self.tables[name]
                return lambda ctx, value=value: value
            if name in FUNCS:
                raise self.err(f"Funktion {name!r} muss aufgerufen werden")
            raise self.err(f"unbekannter Name {name!r}")
        if isinstance(node, ast.Attribute):
            self.infer(node)  # statische Feldpruefung
            base = self.build(node.value)
            attr = node.attr

            def fn_attr(ctx: Ctx, base=base, attr=attr) -> Any:
                obj = base(ctx)
                if obj is None:
                    return None
                if isinstance(obj, dict):
                    return obj.get(attr)
                try:
                    return getattr(obj, attr)
                except AttributeError:
                    raise CatalogSpecError(f"{attr!r} gibt es an {type(obj).__name__} nicht") from None
            return fn_attr
        if isinstance(node, ast.Subscript):
            if not isinstance(node.slice, ast.Constant):
                raise self.err("Subscript nur mit konstantem Schluessel")
            key = node.slice.value
            base = self.build(node.value)

            def fn_sub(ctx: Ctx, base=base, key=key) -> Any:
                obj = base(ctx)
                if obj is None:
                    return None
                if isinstance(obj, dict):
                    return obj.get(key)
                if isinstance(obj, (list, tuple)) and isinstance(key, int):
                    return obj[key] if -len(obj) <= key < len(obj) else None
                return None
            return fn_sub
        if isinstance(node, ast.Constant):
            if isinstance(node.value, (str, int, float, bool)) or node.value is None:
                value = node.value
                return lambda ctx, value=value: value
            raise self.err("nur Zeichenketten, Zahlen, True/False/None als Literale")
        if isinstance(node, (ast.List, ast.Tuple)):
            parts = [self.build(e) for e in node.elts]
            return lambda ctx, parts=parts: [p(ctx) for p in parts]
        if isinstance(node, ast.Call):
            if not isinstance(node.func, ast.Name) or node.keywords:
                raise self.err("Aufrufe nur als name(arg, ...) ohne Schluesselwortargumente")
            fname = node.func.id
            args = [self.build(a) for a in node.args]
            if fname in FUNCS:
                func = FUNCS[fname]
                return lambda ctx, func=func, args=args: func(*[a(ctx) for a in args])
            if self.types.get(fname) is CALLABLE:
                self.names.add(fname)

                def fn_ctxcall(ctx: Ctx, fname=fname, args=args) -> Any:
                    func = ctx.get(fname)
                    if not callable(func):
                        raise CatalogSpecError(f"Kontextfunktion {fname!r} fehlt")
                    return func(*[a(ctx) for a in args])
                return fn_ctxcall
            raise self.err(f"unbekannte Funktion {fname!r}")
        raise self.err(f"Syntax {type(node).__name__} nicht erlaubt")


def compile_expr(text: str, *, where: str, types_: dict[str, Any], tables: dict[str, Any] | None = None) -> Expr:
    """Ausdruck kompilieren. ``types_`` bildet Kontextnamen auf Typen ab (pydantic-Klasse,
    ``list``, ``dict`` oder ``CALLABLE``); ``tables`` sind Konstanten."""
    if not isinstance(text, str) or not text.strip():
        raise CatalogSpecError(f"{where}: leerer Ausdruck")
    try:
        tree = ast.parse(text.strip(), mode="eval")
    except SyntaxError as exc:
        raise CatalogSpecError(f"{where}: Syntaxfehler {exc.msg} in Ausdruck {text!r}") from None
    comp = _Compiler(text, where, types_, tables or {})
    fn = comp.build(tree)
    return Expr(text, fn, comp.names, attribute_paths(tree, set(types_)))


def attribute_paths(tree: ast.AST, bindings: set[str]) -> frozenset[str]:
    """Laengste Attributketten eines Ausdrucks, die an einer Bindung beginnen.

    ``http.security_headers["x-frame-options"].present`` ergibt genau diesen Pfad, nicht
    zusaetzlich ``http.security_headers``. Konstante Schluessel stehen in eckigen Klammern.
    """
    kinder: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            kinder.add(id(node.value))
    out: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Attribute, ast.Subscript)) or id(node) in kinder:
            continue
        root = node
        while isinstance(root, (ast.Attribute, ast.Subscript)):
            root = root.value
        if isinstance(root, ast.Name) and root.id in bindings:
            out.add(ast.unparse(node).replace("'", '"'))
    return frozenset(out)


__all__ = ["CatalogSpecError", "Expr", "compile_expr", "FUNCS", "CALLABLE", "is_optional_bool",
           "unwrap_optional", "field_annotation", "subscript_annotation"]
