"""Playwright-based redirect prober — follows HTTP + JS + meta-refresh redirects.

Visits each FQDN with a real headless Chromium browser, follows all redirects,
and returns the final URL, redirect chain, page title, and cross-domain flag.
Also collects response headers, tech info (via JS evaluation), and screenshots.
Probes CMS-specific paths to detect WordPress, TYPO3, Joomla, etc.
"""

from __future__ import annotations

import os
from typing import Any
from urllib.parse import urlparse

import structlog

log = structlog.get_logger()

CMS_PROBE_PATHS: dict[str, str] = {
    "wp-login": "/wp-login.php",
    "wp-admin": "/wp-admin/",
    "wp-content": "/wp-content/",
    "typo3": "/typo3/",
    "joomla": "/administrator/",
    "drupal": "/user/login",
    "shopware": "/admin",
}

_TECH_DETECT_JS = """() => {
    const meta = document.querySelector('meta[name="generator"]');
    const poweredBy = document.querySelector('meta[http-equiv="X-Powered-By"]');
    const cookies = document.cookie;
    return {
        generator: meta ? meta.content : null,
        powered_by: poweredBy ? poweredBy.content : null,
        title: document.title || '',
        scripts: [...document.querySelectorAll('script[src]')].map(s => s.src).slice(0, 20),
        stylesheets: [...document.querySelectorAll('link[rel="stylesheet"]')].map(l => l.href).slice(0, 20),
        meta_tags: [...document.querySelectorAll('meta')].map(m => ({
            name: m.name || m.httpEquiv || '',
            content: (m.content || '').substring(0, 200)
        })).filter(m => m.name).slice(0, 20),
        cookies: cookies || '',
        body_classes: document.body ? document.body.className : '',
        html_lang: document.documentElement.lang || '',
    };
}"""


def _is_playwright_available() -> bool:
    """Check whether the playwright package is importable."""
    try:
        from playwright.sync_api import sync_playwright  # noqa: F401
        return True
    except ImportError:
        return False


def _extract_domain(url: str) -> str:
    """Return the hostname portion of a URL, or empty string on failure."""
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""


def _collect_tech_info(page: Any, fqdn: str) -> dict[str, Any]:
    """Run JS evaluation to collect tech info from the loaded page."""
    try:
        tech_info = page.evaluate(_TECH_DETECT_JS)
        return tech_info if isinstance(tech_info, dict) else {}
    except Exception as exc:
        log.debug("tech_info_eval_failed", fqdn=fqdn, error=str(exc))
        return {}


def _take_screenshot(
    page: Any,
    fqdn: str,
    scan_dir: str,
    ip: str,
) -> str | None:
    """Take a viewport screenshot and return the path, or None on failure."""
    try:
        screenshot_dir = os.path.join(scan_dir, "hosts", ip, "phase2") if scan_dir and ip else None
        if not screenshot_dir:
            return None
        os.makedirs(screenshot_dir, exist_ok=True)
        safe_fqdn = fqdn.replace(".", "_").replace("/", "")[:50]
        screenshot_path = os.path.join(screenshot_dir, f"screenshot_{safe_fqdn}.png")
        page.screenshot(path=screenshot_path, full_page=False)
        return screenshot_path
    except Exception as exc:
        log.debug("screenshot_failed", fqdn=fqdn, error=str(exc))
        return None


def probe_redirects(
    fqdns: list[str],
    order_id: str = "",
    timeout_per_page: int = 10,
    scan_dir: str = "",
    ip: str = "",
) -> dict[str, dict[str, Any]]:
    """Visit each FQDN with Playwright headless Chromium.

    Returns dict keyed by FQDN with:
    {
        "final_url": "https://securess.de/login",
        "final_domain": "securess.de",
        "redirect_chain": ["https://connect.securess.de/", "https://securess.de/login"],
        "is_cross_domain": True,
        "page_title": "Login - Securess",
        "status_code": 200,
        "error": None,
        "response_headers": {"server": "nginx/1.22", ...},
        "tech_info": {"generator": "WordPress 6.8", ...},
        "screenshot_path": "/tmp/scan-xxx/hosts/1.2.3.4/phase2/screenshot_securess_de.png",
    }
    """
    if not _is_playwright_available():
        log.warning("playwright_not_available", hint="pip install playwright && playwright install chromium")
        return {}

    from playwright.sync_api import sync_playwright

    results: dict[str, dict[str, Any]] = {}
    browser = None
    pw = None

    try:
        pw = sync_playwright().start()
        browser = pw.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage"],
        )

        for fqdn in fqdns:
            result = _probe_single_fqdn(
                browser, fqdn, timeout_per_page,
                scan_dir=scan_dir, ip=ip,
            )
            results[fqdn] = result
            log.info(
                "redirect_probe_done",
                fqdn=fqdn,
                final_url=result.get("final_url"),
                is_cross_domain=result.get("is_cross_domain"),
                chain_len=len(result.get("redirect_chain", [])),
                has_tech_info=bool(result.get("tech_info")),
                has_screenshot=result.get("screenshot_path") is not None,
                order_id=order_id,
            )

    except Exception as exc:
        log.error("redirect_probe_fatal", error=str(exc), order_id=order_id)
    finally:
        if browser is not None:
            try:
                browser.close()
            except Exception:
                pass
        if pw is not None:
            try:
                pw.stop()
            except Exception:
                pass

    return results


def _probe_single_fqdn(
    browser: Any,
    fqdn: str,
    timeout_per_page: int,
    scan_dir: str = "",
    ip: str = "",
) -> dict[str, Any]:
    """Probe a single FQDN and return its redirect result."""
    url = f"https://{fqdn}/"
    redirect_chain: list[str] = []
    final_status_code: int = 0
    response_headers: dict[str, str] = {}
    page = None

    try:
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()

        # Collect redirect chain and response headers from response events
        def on_response(response: Any) -> None:
            nonlocal final_status_code, response_headers
            redirect_chain.append(response.url)
            final_status_code = response.status
            # Capture headers from the first response matching our FQDN
            if not response_headers and response.url.startswith(f"https://{fqdn}"):
                try:
                    response_headers = dict(response.headers) if hasattr(response, "headers") else {}
                except Exception:
                    pass

        page.on("response", on_response)

        page.goto(url, wait_until="networkidle", timeout=timeout_per_page * 1000)

        final_url = page.url
        final_domain = _extract_domain(final_url)
        is_cross_domain = final_domain.lower() != fqdn.lower()

        try:
            page_title = page.title() or ""
        except Exception:
            page_title = ""

        # Tech detection via JS evaluation
        tech_info = _collect_tech_info(page, fqdn)

        # Take screenshot (best effort)
        screenshot_path = _take_screenshot(page, fqdn, scan_dir, ip)

        return {
            "final_url": final_url,
            "final_domain": final_domain,
            "redirect_chain": redirect_chain,
            "is_cross_domain": is_cross_domain,
            "page_title": page_title,
            "status_code": final_status_code,
            "error": None,
            "response_headers": response_headers,
            "tech_info": tech_info,
            "screenshot_path": screenshot_path,
        }

    except Exception as exc:
        error_msg = str(exc)
        log.warning("redirect_probe_error", fqdn=fqdn, error=error_msg)
        return {
            "final_url": url,
            "final_domain": fqdn,
            "redirect_chain": redirect_chain,
            "is_cross_domain": False,
            "page_title": "",
            "status_code": final_status_code,
            "error": error_msg,
            "response_headers": response_headers,
            "tech_info": {},
            "screenshot_path": None,
        }
    finally:
        if page is not None:
            try:
                page.close()
            except Exception:
                pass


def probe_cms_paths(
    fqdns: list[str],
    timeout_per_page: int = 8,
) -> dict[str, dict[str, Any]]:
    """Probe CMS-specific paths (/wp-login.php, /wp-admin/, /typo3/) for each FQDN.

    Returns dict keyed by FQDN with:
    {
        "wp-login": {
            "final_url": "https://connect.securess.de/seite-nicht-gefunden",
            "status_code": 200,
            "is_cross_domain": False,
            "body_snippet": "Seite nicht gefunden...",  # first 300 chars
            "page_title": "Seite nicht gefunden",
            "tech_info": { ... },
        },
        "typo3": { ... },
    }
    """
    if not _is_playwright_available():
        log.warning("playwright_not_available", hint="pip install playwright && playwright install chromium")
        return {}

    from playwright.sync_api import sync_playwright

    results: dict[str, dict[str, Any]] = {}
    browser = None
    pw = None

    try:
        pw = sync_playwright().start()
        browser = pw.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage"],
        )

        for fqdn in fqdns:
            fqdn_results: dict[str, Any] = {}

            for probe_name, path in CMS_PROBE_PATHS.items():
                fqdn_results[probe_name] = _probe_single_cms_path(
                    browser, fqdn, probe_name, path, timeout_per_page,
                )

            results[fqdn] = fqdn_results
            log.info(
                "cms_probe_done",
                fqdn=fqdn,
                paths_probed=len(CMS_PROBE_PATHS),
            )

    except Exception as exc:
        log.error("cms_probe_fatal", error=str(exc))
    finally:
        if browser is not None:
            try:
                browser.close()
            except Exception:
                pass
        if pw is not None:
            try:
                pw.stop()
            except Exception:
                pass

    return results


def _probe_single_cms_path(
    browser: Any,
    fqdn: str,
    probe_name: str,
    path: str,
    timeout_per_page: int,
) -> dict[str, Any]:
    """Probe a single CMS path on a single FQDN."""
    url = f"https://{fqdn}{path}"
    final_status_code: int = 0
    page = None

    try:
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()

        def on_response(response: Any) -> None:
            nonlocal final_status_code
            final_status_code = response.status

        page.on("response", on_response)

        page.goto(url, wait_until="networkidle", timeout=timeout_per_page * 1000)

        final_url = page.url
        final_domain = _extract_domain(final_url)
        is_cross_domain = final_domain.lower() != fqdn.lower()

        try:
            page_title = page.title() or ""
        except Exception:
            page_title = ""

        try:
            body_snippet = page.content()[:300]
        except Exception:
            body_snippet = ""

        # Tech detection for CMS path probes
        tech_info = _collect_tech_info(page, f"{fqdn}{path}")

        return {
            "final_url": final_url,
            "status_code": final_status_code,
            "is_cross_domain": is_cross_domain,
            "body_snippet": body_snippet,
            "page_title": page_title,
            "tech_info": tech_info,
            "error": None,
        }

    except Exception as exc:
        error_msg = str(exc)
        log.debug("cms_probe_error", fqdn=fqdn, probe=probe_name, error=error_msg)
        return {
            "final_url": url,
            "status_code": final_status_code,
            "is_cross_domain": False,
            "body_snippet": "",
            "page_title": "",
            "tech_info": {},
            "error": error_msg,
        }
    finally:
        if page is not None:
            try:
                page.close()
            except Exception:
                pass
