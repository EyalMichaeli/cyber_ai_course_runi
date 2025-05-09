import {
  extractUrlFeatures_v4,
  FEATURE_ORDER,
} from "./url_feature_extract.mjs";
import * as ort from "./libs/onnxruntime-web/dist/ort.wasm.min.mjs"; // ← namespace
const { InferenceSession, Tensor } = ort; // classes

// wasm-backend flags must be set *before* you create the first session
ort.env.wasm.simd = false; // avoid SIMD+threads binary
ort.env.wasm.numThreads = 1; // single-thread works in extensions
ort.env.wasm.wasmPaths = chrome.runtime.getURL(
  "libs/onnxruntime-web/dist/" // folder that contains ort-wasm.wasm
);

let session;
async function getSession() {
  if (session) return session;
  const buf = await fetch(chrome.runtime.getURL("models/url_xgb.onnx")).then(
    (r) => r.arrayBuffer()
  );
  session = await InferenceSession.create(buf);
  return session;
}

export async function predictUrl(urlString) {
  const s = await getSession();
  const feats = Float32Array.from(extractUrlFeatures_v4(urlString));
  const input = new Tensor("float32", feats, [1, FEATURE_ORDER.length]);
  const { probabilities } = await s.run({ input });
  return 1 - probabilities.data[0];
}
