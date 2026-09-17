import asyncio, sys
from playwright.async_api import async_playwright
TARGETS = [
 ("www.junkerwerk.de", "https://www.junkerwerk.de/", True),
 ("www.junkerwerk.hu", "https://www.junkerwerk.hu/", True),
 ("nachhaltigkeit.junkerwerk.de", "https://nachhaltigkeit.junkerwerk.de/", True),
 ("openotp.junkerwerk.hu", "https://openotp.junkerwerk.hu/", False),
 ("cloud.junkerwerk.de", "https://cloud.junkerwerk.de/", True),
]
async def main():
    async with async_playwright() as p:
        b = await p.chromium.launch(executable_path="/opt/pw-browsers/chromium", args=["--lang=de-DE"])
        for name, url, ignore in TARGETS:
            ctx = await b.new_context(viewport={"width":1280,"height":800}, ignore_https_errors=ignore, locale="de-DE",
                                      user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36")
            page = await ctx.new_page()
            try:
                await page.goto(url, wait_until="networkidle", timeout=45000)
                # cookie banner: try to dismiss common consent buttons quietly
                for sel in ["text=Alle akzeptieren","text=Akzeptieren","text=Alle ablehnen","text=Ablehnen","button:has-text('OK')"]:
                    try:
                        el = page.locator(sel).first
                        if await el.is_visible(timeout=800):
                            await el.click(timeout=1500); await page.wait_for_timeout(800); break
                    except Exception: pass
                await page.wait_for_timeout(1200)
                print(name, "->", page.url, await page.title())
            except Exception as e:
                print(name, "ERROR", str(e)[:120])
            try:
                await page.screenshot(path=f"../build/shots/{name}.png", full_page=False)
                print("  saved", name)
            except Exception as e:
                print("  screenshot failed", str(e)[:120])
            await ctx.close()
        await b.close()
asyncio.run(main())
