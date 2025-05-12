/* ──────────  html_prediction.mjs  ────────── */

import { extractHtmlFeatures, FEATURE_COUNT } from "./html_feature_extract.mjs";


/* ---------- lazy caches ---------- */
let jsBoosterPromise = null;

/* ---------- helper: pure‑JS booster ---------- */
function loadJsBooster() {
  if (jsBoosterPromise) return jsBoosterPromise;
  jsBoosterPromise = fetch(chrome.runtime.getURL("models/html_xgb.json"))
    .then((r) => r.json())
    .then((json) => buildPureJsBooster(json));
  return jsBoosterPromise;
}

/* ---------- flat‑array tree evaluator ---------- */
function buildPureJsBooster(modelJson) {
  const trees =
    modelJson.learner?.gradient_booster?.model?.trees ?? modelJson.trees;

  if (!Array.isArray(trees))
    throw new Error("Unsupported XGBoost JSON: no 'trees' array found");

  const forest = trees.map((t) => ({
    L: t.left_children, // int[]  left child (‑1 → leaf)
    R: t.right_children, // int[]  right child (‑1 → leaf)
    F: t.split_indices, // int[]  feature index
    T: t.split_conditions, // float[] threshold
    W: t.base_weights, // float[] leaf value (log‑odds)
    D: t.default_left, // bool[] missing→left?
  }));

  function evalTree(tree, feats) {
    let n = 0; // root node
    while (tree.L[n] !== -1) {
      // until leaf
      const fIdx = tree.F[n];
      const thresh = tree.T[n];
      const val = feats[fIdx];
      const goLeft = Number.isNaN(val) ? tree.D[n] : val < thresh;
      n = goLeft ? tree.L[n] : tree.R[n];
    }
    return tree.W[n];
  }

  return {
    /** @param {Float32Array} feats */
    predict(feats) {
      let score = 0;
      for (const tree of forest) score += evalTree(tree, feats);
      return 1 / (1 + Math.exp(-score)); // logistic ↦ probability
    },
  };
}

/* ---------- public API ---------- */
export async function predictHtml(html, domain) {
  const featsArr = extractHtmlFeatures(html, domain); // Float32Array
  const booster = await loadJsBooster();
  return booster.predict(featsArr); // same 0‑1 scale
}
