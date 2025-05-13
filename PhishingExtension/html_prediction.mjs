/* ────────── html_prediction.mjs ────────── */

import { extractHtmlFeatures } from "./html_feature_extract.mjs";

/* ---------- lazy-load model ---------- */
let boosterP = null;
function loadBooster() {
  if (boosterP) return boosterP;
  boosterP = fetch(chrome.runtime.getURL("models/xgb_final_model.json"))
    .then((r) => r.json())
    .then(buildPureJsBooster);
  return boosterP;
}

/* ---------- pure-JS XGBoost evaluator ---------- */
function buildPureJsBooster(modelJson) {
  const trees =
    modelJson.learner?.gradient_booster?.model?.trees ?? modelJson.trees;
  if (!Array.isArray(trees)) throw new Error("Bad XGB JSON: no trees array");

  const forest = trees.map((t) => ({
    L: t.left_children,
    R: t.right_children,
    F: t.split_indices,
    T: t.split_conditions,
    W: t.base_weights,
    D: t.default_left,
  }));

  function evalTree(tree, feats) {
    let n = 0;
    while (tree.L[n] !== -1) {
      const f = tree.F[n],
        th = tree.T[n],
        v = feats[f];
      n = (Number.isNaN(v) ? tree.D[n] : v < th) ? tree.L[n] : tree.R[n];
    }
    return tree.W[n];
  }

  return {
    /** @param {Float32Array} feats */
    predict(feats) {
      let logOdds = 0;
      for (const tr of forest) logOdds += evalTree(tr, feats);
      return 1 / (1 + Math.exp(-logOdds));
    },
  };
}

/* ---------- public API ---------- */
export async function predictHtml(html, domain = "") {
  const feats = extractHtmlFeatures(html, domain);
  const booster = await loadBooster();
  return booster.predict(feats); // probability 0-1
}
