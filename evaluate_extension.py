#!/usr/bin/env python3
"""
evaluate_extension.py – offline replay tester for your extension.
Always closes each page in Python, prints interim rubric reports, and never aborts.
"""

import asyncio, csv, json, time, tempfile, shutil, traceback
from pathlib import Path
from playwright.async_api import async_playwright, TimeoutError as PWTimeout
from playwright._impl._errors import TargetClosedError

# ─── CONFIG ───────────────────────────────────────────────
CSV_PATH      = "data/index.csv"
HTML_BASE_DIR = Path("data/dataset-part-1")
EXT_PATH      = Path(
    "/Users/alongerby/Library/CloudStorage/OneDrive-ReichmanUniversity/"
    "Year 3/Semester B/Cyber/cyber_ai_course_runi/PhishingExtension"
).resolve()

PRED_ACTION    = "PredictionReady"
CONCURRENCY    = 20
PAGE_TIMEOUT   = 50_000   # ms – navigation
RESULT_TIMEOUT = 40      # s  – wait for verdict
LOAD_DEADLINE  = 40        # s  – wait for load
PAGE_LIMIT     = 3_500    # successful verdicts desired
REPORT_EVERY   = 50       # interim report cadence
# ──────────────────────────────────────────────────────────


def detach(emitter, event, handler):
    if hasattr(emitter, "off"):
        emitter.off(event, handler)
    else:
        emitter.remove_listener(event, handler)


def safe_detach(emitter, event, handler):
    try:
        detach(emitter, event, handler)
    except (TargetClosedError, KeyError, RuntimeError):
        pass


async def main():
    profile_dir = tempfile.mkdtemp(prefix="pw-profile-")
    try:
        async with async_playwright() as p:
            ctx = await p.chromium.launch_persistent_context(
                profile_dir,
                headless=False,
                args=[
                    f"--disable-extensions-except={EXT_PATH}",
                    f"--load-extension={EXT_PATH}",
                    "--ignore-certificate-errors",
                    "--disable-client-side-phishing-detection",
                    "--safebrowsing-disable-auto-update",
                    "--disable-features=SafetyTips,SafeBrowsingEnhancedProtection",
                ],
                ignore_https_errors=True,
            )

            # wait for extension SW
            try:
                await ctx.wait_for_event(
                    "serviceworker",
                    predicate=lambda w: w.url.endswith("background.js"),
                    timeout=10_000,
                )
            except PWTimeout:
                print("❌ Extension SW not found; aborting")
                return

            # metrics
            TP = FP = TN = FN = processed = 0
            total_latency = 0.0
            total_heap_mb = 0.0
            sem = asyncio.Semaphore(CONCURRENCY)
            lock = asyncio.Lock()

            async def mini_report(tag):
                nonlocal TP, FP, TN, FN, processed, total_latency, total_heap_mb
                # Recall
                coverage = TP / (TP + FN) if (TP + FN) else 0
                # Precision
                precision = TP / (TP + FP) if (TP + FP) else 0
                # Response time (ms)
                avg_lat = total_latency / processed if processed else 0
                # Memory (MB)
                avg_mem = total_heap_mb / processed if processed else 0

                print(f"\n— {tag} ({processed} verdicts) —")
                print(f"Coverage (Recall) : {coverage:.3f}")
                print(f"Precision         : {precision:.3f}")
                print(f"Avg Latency (ms)  : {avg_lat:.1f}")
                print(f"Avg Mem (MB)      : {avg_mem:.1f}\n")


            async def evaluate(idx, url, html_path, label):
                nonlocal TP, FP, TN, FN, processed, total_latency, total_heap_mb
                try:
                    html_bytes = html_path.read_bytes()
                except Exception as e:
                    print(f"[{idx}] ❌ HTML read failed ({e}) – skipped")
                    return

                async with sem:
                    verdict_fut = asyncio.get_event_loop().create_future()
                    page = await ctx.new_page()

                    # route main document once
                    async def route_handler(route):
                        await route.fulfill(
                            status=200,
                            body=html_bytes,
                            headers={
                                "Content-Type": "text/html; charset=UTF-8",
                                "Cache-Control": "no-store",
                            },
                        )
                    try:
                        await page.route(url, route_handler, times=1)
                    except TypeError:
                        await page.route(url, route_handler)

                    # listen for PredictionReady
                    async def maybe_resolve(msg):
                        if verdict_fut.done():
                            return
                        data = None
                        try:
                            data = json.loads(msg.text)
                        except json.JSONDecodeError:
                            pass
                        if data is None and msg.args:
                            try:
                                data = await msg.args[0].json_value()
                            except Exception:
                                pass
                        if isinstance(data, dict) and data.get("action") == PRED_ACTION:
                            safe_detach(page, "console", page_handler)
                            verdict_fut.set_result(data)

                    def page_handler(m): asyncio.create_task(maybe_resolve(m))
                    page.on("console", page_handler)

                    # navigate & wait for load + verdict
                    try:
                        await page.goto(url, timeout=PAGE_TIMEOUT)
                        await page.wait_for_load_state("load", timeout=LOAD_DEADLINE * 1000)
                        load_ts = time.perf_counter()
                        result = await asyncio.wait_for(verdict_fut, timeout=RESULT_TIMEOUT)
                        latency = (time.perf_counter() - load_ts) * 1000
                    except Exception as e:
                        safe_detach(page, "console", page_handler)
                        try:
                            await page.close()
                        except Exception:
                            pass
                        print(f"[{idx}] ⚠️ Skipped ({type(e).__name__})")
                        return

                    # measure JS heap
                    try:
                        heap = await page.evaluate("performance.memory.usedJSHeapSize")
                    except Exception:
                        heap = 0
                    heap_mb = heap / (1024 * 1024)

                    # metrics update
                    pred = bool(result.get("verdict"))
                    prob = (result.get("probUrl") if result.get("stage") == "urlModel"
                            else result.get("probHtml", None))
                    if isinstance(prob, (int, float)):
                        prob_str = f"{prob:.3f}"
                    else:
                        prob_str = f"n/a full={json.dumps(result)}"

                    async with lock:
                        if pred and label == "1":
                            TP += 1
                        elif pred and label == "0":
                            FP += 1
                        elif not pred and label == "0":
                            TN += 1
                        else:
                            FN += 1
                        processed += 1
                        total_latency += latency
                        total_heap_mb += heap_mb
                        if processed % REPORT_EVERY == 0:
                            await mini_report("Interim Report")

                    print(f"[{idx}] ✓ pred={pred} label={label} prob={prob_str}"
                          f" lat={latency:.0f}ms mem={heap_mb:.1f}MB url={url}")

                    # finally close the page
                    try:
                        await page.close()
                    except Exception:
                        pass

            # schedule tasks (skip missing HTML, up to PAGE_LIMIT)
            tasks = []
            scheduled = 0
            START_ROW = 30_000

            with open(CSV_PATH, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for idx, row in enumerate(reader, 1):
                    # skip until we reach START_ROW
                    if idx < START_ROW:
                        continue

                    if scheduled >= PAGE_LIMIT:
                        break

                    html_path = HTML_BASE_DIR / row["website"]
                    if not html_path.is_file():
                        print(f"[{idx}] ❌ missing HTML → skipped ({html_path})")
                        continue

                    tasks.append(asyncio.create_task(
                        evaluate(idx, row["url"], html_path, row["result"])
                    ))
                    scheduled += 1


            # gather with exception capture
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, Exception):
                    print("⚠️ Task error:", ''.join(traceback.format_exception_only(type(r), r)).strip())

            # final mini-report if needed
            if processed % REPORT_EVERY != 0:
                await mini_report("Interim Report")

            # final summary
            await mini_report("Final Report")

            try:
                await ctx.close()
            except Exception:
                pass
    finally:
        shutil.rmtree(profile_dir, ignore_errors=True)


if __name__ == "__main__":
    asyncio.run(main())
