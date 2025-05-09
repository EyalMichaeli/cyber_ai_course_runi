import * as ort from "./libs/onnxruntime-web/dist/ort.wasm.min.mjs"; // ← namespace
const { InferenceSession, Tensor } = ort; // classes

// wasm-backend flags must be set *before* you create the first session
ort.env.wasm.simd = false; // avoid SIMD+threads binary
ort.env.wasm.numThreads = 1; // single-thread works in extensions
ort.env.wasm.wasmPaths = chrome.runtime.getURL(
  "libs/onnxruntime-web/dist/" // folder that contains ort-wasm.wasm
);
import { extractHtmlFeatures, FEATURE_COUNT } from "./html_feature_extract.mjs";

ort.env.wasm.simd = false;
ort.env.wasm.numThreads = 1;
ort.env.wasm.wasmPaths = chrome.runtime.getURL("libs/onnxruntime-web/dist/");

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
