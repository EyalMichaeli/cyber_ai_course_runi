import {
  extractUrlFeatures_v4,
  FEATURE_ORDER,
} from "./url_feature_extract.mjs";

let jsBoosterPromise = null; 

/* ---------- helper: JS booster (no WASM) ---------- */
function loadJsBooster() {
  if (jsBoosterPromise) return jsBoosterPromise;
  jsBoosterPromise = fetch(chrome.runtime.getURL("models/url_xgb.json"))
    .then((r) => r.json())
    .then((json) => buildPureJsBooster(json));
  return jsBoosterPromise;
}

/* ---------- minimal tree-evaluator ---------- */
function buildPureJsBooster(modelJson) {
  // 1. locate the array of trees regardless of wrapper nesting
  const trees =
    modelJson.learner?.gradient_booster?.model?.trees ?? modelJson.trees;

  if (!Array.isArray(trees))
    throw new Error("Unsupported XGBoost JSON: no 'trees' array found");

  // 2. flatten each tree’s parallel arrays into an object we can traverse
  const forest = trees.map((t) => ({
    L: t.left_children, // int[]  index of left child  (-1 => leaf)
    R: t.right_children, // int[]  index of right child (-1 => leaf)
    F: t.split_indices, // int[]  feature index (as number)
    T: t.split_conditions, // float[] threshold
    W: t.base_weights, // float[] leaf value
    D: t.default_left, // bool[]  “missing? go left”
  }));

  // 3. helper to walk one tree using the flat arrays
  function evalTree(tree, feats) {
    let n = 0; // start at root
    while (tree.L[n] !== -1) {
      // while not at a leaf
      const fIdx = tree.F[n];
      const thresh = tree.T[n];
      const val = feats[fIdx];

      const goLeft = Number.isNaN(val)
        ? tree.D[n] // follow default branch
        : val < thresh;

      n = goLeft ? tree.L[n] : tree.R[n];
    }
    return tree.W[n]; // leaf value (log-odds)
  }

  // 4. return a closure that evaluates every tree, then applies logistic
  return {
    /**
     * @param {Float32Array} feats – feature vector in FEATURE_ORDER order
     * @returns {number} – probability (0-1) that the URL is phishing
     */
    predict(feats) {
      let score = 0;
      for (const tree of forest) score += evalTree(tree, feats);
      return 1 / (1 + Math.exp(-score)); // logistic transform
    },
  };
}

export async function predictUrl(urlString) {
  const feats = Float32Array.from(extractUrlFeatures_v4(urlString));

  /* ②   Pure-JS fallback (cannot throw) */
  const booster = await loadJsBooster();
  return booster.predict(feats); // same scale 0-1
}
