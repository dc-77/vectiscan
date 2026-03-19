"""Playwright-based redirect prober — follows HTTP + JS + meta-refresh redirects.

Visits each FQDN with a real headless Chromium browser, follows all redirects,
and returns the final URL, redirect chain, page title, and cross-domain flag.
Also probes CMS-specific paths to detect WordPress, TYPO3, Joomla, etc.
"""

from __future__ import annotations

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


def probe_redirects(
    fqdns: list[str],
    order_id: str = "",
    timeout_per_page: int = 10,
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
            result = _probe_single_fqdn(browser, fqdn, timeout_per_page)
            results[fqdn] = result
            log.info(
                "redirect_probe_done",
                fqdn=fqdn,
                final_url=result.get("final_url"),
                is_cross_domain=result.get("is_cross_domain"),
                chain_len=len(result.get("redirect_chain", [])),
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
) -> dict[str, Any]:
    """Probe a single FQDN and return its redirect result."""
    url = f"https://{fqdn}/"
    redirect_chain: list[str] = []
    final_status_code: int = 0
    page = None

    try:
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()

        # Collect redirect chain from response events
        def on_response(response: Any) -> None:
            nonlocal final_status_code
            redirect_chain.append(response.url)
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

        return {
            "final_url": final_url,
            "final_domain": final_domain,
            "redirect_chain": redirect_chain,
            "is_cross_domain": is_cross_domain,
            "page_title": page_title,
            "status_code": final_status_code,
            "error": None,
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

        return {
            "final_url": final_url,
            "status_code": final_status_code,
            "is_cross_domain": is_cross_domain,
            "body_snippet": body_snippet,
            "page_title": page_title,
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
            "error": error_msg,
        }
    finally:
        if page is not None:
            try:
                page.close()
            except Exception:
                pass
