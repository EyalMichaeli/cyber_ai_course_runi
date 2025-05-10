import * as ort from "./libs/onnxruntime-web/ort.wasm.min.js"; // ← namespace
const { InferenceSession, Tensor } = ort; // classes

import { extractHtmlFeatures, FEATURE_COUNT } from "./html_feature_extract.mjs";

ort.env.wasm.proxy = false;
ort.env.wasm.numThreads = 1;

let htmlSess;
async function getHtmlSession() {
  if (!htmlSess) {
    const buf = await fetch(chrome.runtime.getURL("models/html_xgb.onnx")).then(
      (r) => r.arrayBuffer()
    );
    htmlSess = await ort.InferenceSession.create(buf);
  }
  return htmlSess;
}

export async function predictHtml(html, domain) {
  const s = await getHtmlSession();
  const feats = extractHtmlFeatures(html, domain);
  const input = new ort.Tensor("float32", feats, [1, FEATURE_COUNT]);
  const { probabilities } = await s.run({ input });
  return 1 - probabilities.data[0];
}
