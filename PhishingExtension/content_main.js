import { predictUrl } from "./url_prediction.mjs";
import { predictHtml } from "./html_prediction.mjs";
import { scorePhishingURL } from "./heuristic_prediction.mjs";

/* ──────────  2 & 3. model cascade  ────────── */
export async function main() {
  const url = location.href;
  const html = document.documentElement.outerHTML;
  const host = location.hostname;

  /* 1 ▸ heuristic */
  const hScore = scorePhishingURL(url);
  if (hScore >= 31) {
    report({ stage: "heuristic", probHeur: hScore, verdict: true });
    return;
  }

  /* 2 ▸ URL model */
  const pUrl = await predictUrl(url);
  if (pUrl >= 0.85) {
    report({ stage: "urlModel", probUrl: pUrl, verdict: true });
    return;
  } else if (pUrl <= 0.1) {
    report({ stage: "urlModel", probUrl: pUrl, verdict: false });
    return;
  }

  const pHtml = await predictHtml(html, host);

  const finalVerdict = pHtml >= 0.6513 ? true : false;

  report({
    stage: "htmlModel",
    probUrl: pUrl,
    probHtml: pHtml,
    verdict: finalVerdict,
  });
}

/* ────────── helper to send result to background / popup ────────── */
function report(payload) {
  console.log("[PhishCascade]", payload);
  chrome.runtime.sendMessage({ action: "PredictionReady", result: payload });
}
