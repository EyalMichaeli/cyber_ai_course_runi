import { predictUrl } from "./url_prediction.mjs";
import { predictHtml } from "./html_prediction.mjs";
import { scorePhishingURL } from "./heuristic_prediction.mjs";


function getFinalVerdict(probUrl, probHtml) {
  // Model reliability weights (adjust based on validation performance if available)
  const wUrl = 0.5;   // weight for URL-based model
  const wHtml = 0.5;  // weight for HTML-based model

  // Compute confidence of each model's prediction (distance from 0.5)
  const confUrl = Math.abs(probUrl - 0.5);
  const confHtml = Math.abs(probHtml - 0.5);

  // Optionally incorporate confidence into weights
  let effectiveWUrl = wUrl * confUrl;
  let effectiveWHtml = wHtml * confHtml;
  if (effectiveWUrl + effectiveWHtml === 0) {
    // If both scores are exactly 0.5 (no confidence), fall back to equal weights
    effectiveWUrl = effectiveWHtml = 1;
  }

  // Calculate combined probability (weighted average)
  const combinedProb = (effectiveWUrl * probUrl + effectiveWHtml * probHtml) / (effectiveWUrl + effectiveWHtml);

  // Final decision based on combined probability and chosen threshold
  const threshold = 0.5;  // can be tuned higher or lower based on desired sensitivity
  return combinedProb >= threshold ? true : false;
}

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
  if (pUrl >= 0.8) {
    report({ stage: "urlModel", probUrl: pUrl, verdict: true });
    return;
  } else if (pUrl <= 0.1) {
    report({ stage: "urlModel", probUrl: pUrl, verdict: false });
    return;
  }
  const pHtml = await predictHtml(html, host);
  if (pHtml >= 0.8) {
    report({ stage: "htmlModel", pHtml: pHtml, verdict: true });
    return;
  } else if (pHtml <= 0.1) {
    report({ stage: "htmlModel", probHtml: pHtml, verdict: false });
    return;
  }
  const finalVerdict = getFinalVerdict(pUrl, pHtml);

  report({
    stage: "finalVerdict",
    probUrl: pUrl,
    probHtml: pHtml,
    probHeur: hScore,
    verdict: finalVerdict,
  });
}

/* ────────── helper to send result to background / popup ────────── */
function report(payload) {
  console.log("[PhishCascade]", payload);
  chrome.runtime.sendMessage({ action: "PredictionReady", result: payload });
  console.log(
    JSON.stringify({
      action: "PredictionReady",
      verdict: payload.verdict,
      probHeur: payload.probHeur,
      probUrl: payload.probUrl,
      probHtml: payload.probHtml,
      stage: payload.stage,
    })
  );
}
