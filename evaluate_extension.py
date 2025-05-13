#!/usr/bin/env python3
"""
evaluate_extension.py – offline snapshot tester
• Closes every tab safely
• Counts only successful verdicts toward PAGE_LIMIT
• Uses keyword args with Route.fulfill (no TypeError)
"""

import asyncio, csv, json, time, tempfile, shutil, traceback
from pathlib import Path
from playwright.async_api import async_playwright, TimeoutError as PWTimeout
from playwright._impl._errors import TargetClosedError

# ─── CONFIG ───────────────────────────────────────────────
CSV_PATH      = "data/index.csv"
HTML_BASE_DIR = Path("data/dataset-part-1")
EXT_PATH      = Path("PhishingExtension").resolve()

PRED_ACTION    = "PredictionReady"
CONCURRENCY    = 13
PAGE_TIMEOUT   = 50_000   # ms
RESULT_TIMEOUT = 40       # s
LOAD_DEADLINE  = 40       # s
PAGE_LIMIT     = 1_000
REPORT_EVERY   = 50
START_ROW      = 50_000
# ──────────────────────────────────────────────────────────


def safe_detach(emitter, event, handler):
    try:
        (emitter.off if hasattr(emitter, "off") else emitter.remove_listener)(event, handler)
    except (TargetClosedError, KeyError, RuntimeError):
        pass


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
                ],
                ignore_https_errors=True,
            )

            try:
                await ctx.wait_for_event(
                    "serviceworker",
                    predicate=lambda w: w.url.endswith("background.js"),
                    timeout=10_000)
            except PWTimeout:
                print("❌ Extension SW not found"); return

            # metrics
            TP=FP=TN=FN=0
            processed=tot_lat=tot_mem=0.0
            lock=asyncio.Lock()
            sem = asyncio.Semaphore(CONCURRENCY)

            async def report(tag):
                recall    = TP/(TP+FN) if TP+FN else 0
                precision = TP/(TP+FP) if TP+FP else 0
                avg_lat   = tot_lat/processed if processed else 0
                avg_mem   = tot_mem/processed if processed else 0
                print(f"\n— {tag} ({processed} verdicts) —")
                print(f"Coverage (Recall): {recall:.3f}")
                print(f"Precision        : {precision:.3f}")
                print(f"Avg Latency (ms) : {avg_lat:.1f}")
                print(f"Avg Mem (MB)     : {avg_mem:.1f}\n")

            # ---------- single page ----------
            async def evaluate(idx, url, html_path, label):
                nonlocal TP,FP,TN,FN,processed,tot_lat,tot_mem

                try:
                    html_bytes = html_path.read_bytes()
                except Exception as e:
                    print(f"[{idx}] ❌ read fail ({e})")
                    return False

                async with sem:
                    verdict_fut = asyncio.get_event_loop().create_future()
                    page = await ctx.new_page()

                    # intercept main doc – ✨ keyword args only ✨
                    async def route_h(route):
                        await route.fulfill(
                            status=200,
                            body=html_bytes,
                            headers={"Content-Type": "text/html; charset=UTF-8"}
                        )
                    try:
                        await page.route(url, route_h, times=1)
                    except TypeError:                # for old Playwright
                        await page.route(url, route_h)

                    # listen for PredictionReady
                    async def maybe(msg):
                        if verdict_fut.done(): return
                        data=None
                        try: data=json.loads(msg.text)
                        except json.JSONDecodeError: pass
                        if data is None and msg.args:
                            try: data=await msg.args[0].json_value()
                            except: pass
                        if isinstance(data,dict) and data.get("action")==PRED_ACTION:
                            safe_detach(page,"console",on_console)
                            verdict_fut.set_result(data)

                    def on_console(m): asyncio.create_task(maybe(m))
                    page.on("console", on_console)

                    try:
                        await page.goto(url, timeout=PAGE_TIMEOUT)
                        await page.wait_for_load_state("load", timeout=LOAD_DEADLINE*1000)
                        start=time.perf_counter()
                        result=await asyncio.wait_for(verdict_fut, timeout=RESULT_TIMEOUT)
                        lat=(time.perf_counter()-start)*1000
                    except Exception as e:
                        print(f"[{idx}] ⚠️ skipped ({type(e).__name__})")
                        safe_detach(page,"console",on_console)
                        try: await page.close(run_before_unload=False)
                        except: pass
                        return False

                    # memory
                    try: heap=await page.evaluate("performance.memory.usedJSHeapSize")
                    except: heap=0
                    mem_mb=heap/1_048_576

                    pred=bool(result.get("verdict"))
                    prob_url=result.get("probUrl", 'n.a') 
                    prob_html = result.get("probHtml", "n.a")

                    async with lock:
                        if pred and label=="1": TP+=1
                        elif pred and label=="0": FP+=1
                        elif not pred and label=="0": TN+=1
                        else: FN+=1
                        processed+=1
                        tot_lat+=lat
                        tot_mem+=mem_mb
                        if processed%REPORT_EVERY==0:
                            await report("Interim")

                    print(f"[{idx}] ✓ label= {label} pred={pred} prob_url={prob_url} prob_html={prob_html} "
                          f"lat={lat:.0f}ms mem={mem_mb:.1f}MB res={result}")

                    # always close tab
                    try: await page.close(run_before_unload=False)
                    except: pass
                    return True

            # ---------- driver ----------
            successes=0
            idx=0
            pending=set()

            async def reader():
                nonlocal idx,successes
                with open(CSV_PATH,newline="",encoding="utf-8") as f:
                    for idx,row in enumerate(csv.DictReader(f),1):
                        if idx<START_ROW: continue
                        if successes>=PAGE_LIMIT: break
                        html_path=HTML_BASE_DIR/row["website"]
                        if not html_path.is_file():
                            print(f"[{idx}] ❌ missing HTML")
                            continue
                        t=asyncio.create_task(
                            evaluate(idx,row["url"],html_path,row["result"])
                        )
                        pending.add(t)
                        t.add_done_callback(pending.discard)
                        # keep successes count updated
                        def _cb(task):
                            nonlocal successes
                            if task.result(): successes+=1
                        t.add_done_callback(_cb)
                        while len(pending)>=CONCURRENCY*3:
                            await asyncio.sleep(0.2)

            await reader()
            while successes < PAGE_LIMIT and pending:
                await asyncio.sleep(0.2)

            await asyncio.gather(*pending, return_exceptions=True)

            if processed%REPORT_EVERY:
                await report("Interim")
            await report("Final Report")
            await ctx.close()
    finally:
        shutil.rmtree(profile, ignore_errors=True)


if __name__ == "__main__":
    asyncio.run(main())
