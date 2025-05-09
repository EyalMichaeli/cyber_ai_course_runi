import { predictUrl } from "./url_prediction.mjs";
import { predictHtml } from "./html_prediction.mjs";

/* ──────────  1. lightweight heuristic  ────────── */
function heuristicScore(url) {
  const u = new URL(url);
  const sub = u.hostname.split(".").slice(0, -2).join(".");

  const freeHosts = [
    "000webhost",
    "freehostia",
    "neocities",
    "wordpress",
    "blogspot",
    "netlify",
    "weebly",
    "github",
    "weeblysite",
  ];
  const hasHyphen = url.includes("-");
  const isFree = freeHosts.some((d) => u.hostname.endsWith(d));

  let score = 0;
  if (sub.length > 5) score += 0.5;
  if (isFree || hasHyphen) score += 0.5;

  return score;
}

/* ──────────  2 & 3. model cascade  ────────── */
export async function main() {
  const url = location.href;
  const html = document.documentElement.outerHTML;
  const host = location.hostname;

  /* 1 ▸ heuristic */
  const hScore = heuristicScore(url);
  if (hScore >= 0.95) {
    report({ stage: "heuristic", probHeur: hScore, verdict: true });
    return;
  } else if (hScore <= 0.05) {
    report({ stage: "heuristic", probHeur: hScore, verdict: false });
    return;
  }

  /* 2 ▸ URL model */
  const pUrl = await predictUrl(url);
  if (pUrl >= 0.9) {
    report({ stage: "urlModel", probUrl: pUrl, verdict: true });
    return;
  } else if (pUrl <= 0.1) {
    report({ stage: "urlModel", probUrl: pUrl, verdict: false });
    return;
  }

  const pHtml = await predictHtml(html, host);

  const finalVerdict = pHtml >= 0.5 ? true : false;

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
