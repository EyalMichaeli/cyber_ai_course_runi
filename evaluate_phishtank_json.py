#!/usr/bin/env python3
"""
evaluate_extension.py – live-phishing tester + HTML snapshotter
Sources URLs from a PHP‐serialized file (all entries are phishing ⇒ label=1)
"""

import asyncio, json, time, tempfile, shutil, os, re, traceback
from pathlib import Path
from playwright.async_api import async_playwright, TimeoutError as PWTimeout
from playwright._impl._errors import TargetClosedError
import phpserialize

# ─── CONFIG ───────────────────────────────────────────────────────────────
SERIALIZED_FILE = "verified_online.php_serialized"
EXT_PATH        = Path("PhishingExtension").resolve()
PRED_ACTION     = "PredictionReady"
CONCURRENCY     = 13
PAGE_TIMEOUT    = 50_000      # ms
RESULT_TIMEOUT  = 40          # s
LOAD_DEADLINE   = 15          # s
PAGE_LIMIT      = 1_000
REPORT_EVERY    = 50
START_ROW       = 0
SNAP_DIR        = Path("snapshots")
# ──────────────────────────────────────────────────────────────────────────
SNAP_DIR.mkdir(parents=True, exist_ok=True)

# ─── helper functions ─────────────────────────────────────────────────────
def safe_detach(emitter, event, handler):
    try:
        (emitter.off if hasattr(emitter, "off")
         else emitter.remove_listener)(event, handler)
    except (TargetClosedError, KeyError, RuntimeError):
        pass

def sanitize(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", name)[:60]

# ─── load URLs from PHP-serialized file ────────────────────────────────────
with open(SERIALIZED_FILE, "rb") as f:
    raw = f.read()
entries = phpserialize.loads(raw, decode_strings=True)
# entries may be dict or list
if isinstance(entries, dict):
    urls = list(entries.values())
elif isinstance(entries, (list, tuple)):
    urls = list(entries)
else:
    raise ValueError(f"Unexpected format in {SERIALIZED_FILE}")
print(f"Loaded {len(urls)} URLs from {SERIALIZED_FILE}")

async def main():
    profile = tempfile.mkdtemp(prefix="pw-prof-")
    try:
        async with async_playwright() as p:
            ctx = await p.chromium.launch_persistent_context(
                profile,
                headless=False,
                args=[
                    f"--disable-extensions-except={EXT_PATH}",
                    f"--load-extension={EXT_PATH}",
                    "--ignore-certificate-errors",
                    "--disable-client-side-phishing-detection",
                    "--safebrowsing-disable-auto-update",
                    "--disable-features="
                    "SafeBrowsingEnhancedProtection,SafetyTips,SafeBrowsingUrlRealTimeCheck",
                ],
                ignore_https_errors=True,
            )

            # wait for extension SW
            try:
                await ctx.wait_for_event(
                    "serviceworker",
                    predicate=lambda w: w.url.endswith("background.js"),
                    timeout=10_000)
            except PWTimeout:
                print("❌ Extension SW not found; exiting")
                return

            # counters
            TP = FN = 0
            url_hits = html_hits = 0
            processed = tot_lat = tot_mem = 0.0
            lock = asyncio.Lock()
            sem  = asyncio.Semaphore(CONCURRENCY)

            async def report(tag):
                recall  = TP / (TP + FN) if TP + FN else 0
                fn_rate = FN / (TP + FN) if TP + FN else 0
                avg_lat = tot_lat / processed if processed else 0
                avg_mem = tot_mem / processed if processed else 0
                print(f"\n— {tag} ({processed} verdicts) —")
                print(f"Coverage (Recall)       : {recall:.3f}")
                print(f"False-Negative Rate     : {fn_rate:.3f} ({FN} missed)")
                print(f"URL-model detections    : {url_hits}")
                print(f"HTML-model detections   : {html_hits}")
                print(f"Avg latency (ms)        : {avg_lat:.1f}")
                print(f"Avg JS heap (MB)        : {avg_mem:.1f}\n")

            async def evaluate(idx, url):
                nonlocal TP, FN, url_hits, html_hits, processed, tot_lat, tot_mem
                label = 1

                async with sem:
                    verdict_fut = asyncio.get_event_loop().create_future()
                    page = await ctx.new_page()

                    # console listener
                    async def maybe(msg):
                        if verdict_fut.done(): return
                        data = None
                        try:
                            data = json.loads(msg.text)
                        except:
                            pass
                        if data is None and msg.args:
                            try:
                                data = await msg.args[0].json_value()
                            except:
                                pass
                        if isinstance(data, dict) and data.get("action") == PRED_ACTION:
                            safe_detach(page, "console", on_console)
                            verdict_fut.set_result(data)

                    def on_console(m): asyncio.create_task(maybe(m))
                    page.on("console", on_console)

                    # navigate
                    try:
                        resp = await page.goto(url, timeout=PAGE_TIMEOUT)
                    except Exception as e:
                        await page.close(run_before_unload=False)
                        print(f"[{idx}] ⚠️ nav fail ({type(e).__name__})")
                        return False
                    if not resp or resp.status >= 400:
                        await page.close(run_before_unload=False)
                        print(f"[{idx}] ⚠️ HTTP {resp.status if resp else 'n/a'} → skip")
                        return False

                    # wait load
                    try:
                        await page.wait_for_load_state("load", timeout=LOAD_DEADLINE*1000)
                    except PWTimeout:
                        await page.close(run_before_unload=False)
                        print(f"[{idx}] ⚠️ load timeout")
                        return False

                    # snapshot
                    try:
                        html_str = await page.evaluate("document.documentElement.outerHTML")
                        fname = SNAP_DIR / f"{idx}_{sanitize(page.url.split('://')[-1])}.html"
                        fname.write_text(html_str, encoding="utf-8", errors="ignore")
                    except Exception as e:
                        print(f"[{idx}] ⚠️ snapshot fail ({type(e).__name__})")

                    # verdict
                    start = time.perf_counter()
                    try:
                        res = await asyncio.wait_for(verdict_fut, timeout=RESULT_TIMEOUT)
                        lat = (time.perf_counter() - start) * 1000
                    except:
                        await page.close(run_before_unload=False)
                        print(f"[{idx}] ⚠️ verdict timeout")
                        return False

                    # memory
                    try:
                        heap = await page.evaluate("performance.memory.usedJSHeapSize")
                    except:
                        heap = 0
                    mem_mb = heap / 1_048_576

                    pred  = bool(res.get("verdict"))
                    stage = res.get("stage", "unknown")
                    prob_url  = res.get("probUrl",  'n.a')
                    prob_html = res.get("probHtml", 'n.a')

                    async with lock:
                        if pred and label == 1:
                            TP += 1
                            url_hits  += (stage == "urlModel")
                            html_hits += (stage != "urlModel")
                        else:
                            FN += 1
                        processed += 1
                        tot_lat   += lat
                        tot_mem   += mem_mb
                        if processed % REPORT_EVERY == 0:
                            await report("Interim")

                    print(f"[{idx}] ✓ pred={pred} stage={stage} prob_url={prob_url} "
                          f"prob_html={prob_html} lat={lat:.0f}ms mem={mem_mb:.1f}MB url={url}")

                    await page.close(run_before_unload=False)
                    return True

            # ─── producer ──────────────────────────────────────
            successes = 0
            pending   = set()

            def inc_ok(task):
                nonlocal successes
                if task.result():
                    successes += 1

            async def reader():
                for idx, url in enumerate(urls, 1):
                    if idx < START_ROW:
                        continue
                    if successes >= PAGE_LIMIT:
                        break
                    t = asyncio.create_task(evaluate(idx, url["url"]))
                    pending.add(t)
                    t.add_done_callback(pending.discard)
                    t.add_done_callback(inc_ok)
                    while len(pending) >= CONCURRENCY * 3:
                        await asyncio.sleep(0.2)

            await reader()
            while successes < PAGE_LIMIT and pending:
                await asyncio.sleep(0.2)
            await asyncio.gather(*pending, return_exceptions=True)

            if processed % REPORT_EVERY:
                await report("Interim")
            await report("Final Report")
            await ctx.close()

    finally:
        shutil.rmtree(profile, ignore_errors=True)

if __name__ == "__main__":
    asyncio.run(main())
