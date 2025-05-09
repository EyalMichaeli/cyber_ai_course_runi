/*****************************************************************
 *  HTML → dense vector   (19 numeric + 2¹⁷ word-hash + 2¹⁶ char-hash)
 *  Mirrors the Python training code that used HashingVectorizer.
 *****************************************************************/

/* ---------- numeric feature order (MUST stay exactly as trained) */
export const NUM_ORDER = Object.freeze([
  "forms",
  "inputs",
  "iframes",
  "links",
  "imgs",
  "scripts",
  "html_len",
  "js_len",
  "entropy",
  "js_eval_cnt",
  "base64_cnt",
  "link_ip",
  "link_at",
  "kw_cnt",
  "inputs_per_form",
  "iframe_ratio",
  "js_html_ratio",
  "ext_link_ratio",
  "form_ext_action",
]); // 19 items

/* ---------- final vector length ---------- */
export const WORD_BITS = 1 << 17; // 131 072
export const CHAR_BITS = 1 << 16; // 65 536
export const FEATURE_COUNT = NUM_ORDER.length + WORD_BITS + CHAR_BITS; // 196 627

/* ---------- MurmurHash3 (32-bit) — minimal JS port -------------- */
function murmur32(str, seed = 0) {
  let h = seed ^ str.length;
  for (let i = 0, k; i < str.length; i++) {
    k = str.charCodeAt(i);
    k =
      ((k & 0xffff) * 0xcc9e2d51 +
        ((((k >>> 16) * 0xcc9e2d51) & 0xffff) << 16)) >>>
      0;
    k = (k << 15) | (k >>> 17);
    k =
      ((k & 0xffff) * 0x1b873593 +
        ((((k >>> 16) * 0x1b873593) & 0xffff) << 16)) >>>
      0;
    h ^= k;
    h = (h << 13) | (h >>> 19);
    h = (h * 5 + 0xe6546b64) >>> 0;
  }
  h ^= str.length;
  h ^= h >>> 16;
  h = (h * 0x85ebca6b) >>> 0;
  h ^= h >>> 13;
  h = (h * 0xc2b2ae35) >>> 0;
  h ^= h >>> 16;
  return h >>> 0;
}

/* ---------- helper regex / keyword lists (same as Python) -------- */
const rxIP = /https?:\/\/\d{1,3}(?:\.\d{1,3}){3}/i;
const rxAT = /https?:\/\/[^ ]+@/i;
const rxB64 = /[A-Za-z0-9+/]{40,}={0,2}/g;
const rxEval = /\b(eval|atob|document\.write|innerHTML\s*=)\b/gi;
const KW = [
  "account",
  "bank",
  "confirm",
  "password",
  "login",
  "verify",
  "credit card",
  "ssn",
  "urgent",
  "immediately",
  "click here",
  "update",
];

/* ---------- Shannon entropy (first 20 kB only, like training) --- */
export function shannonEntropy(str) {
  if (!str) return 0;
  const freq = {};
  for (const c of str) freq[c] = (freq[c] || 0) + 1;
  let ent = 0,
    len = str.length;
  for (const k in freq) {
    const p = freq[k] / len;
    ent -= p * Math.log2(p);
  }
  return ent;
}

/* ---------- main extractor -------------------------------------- */
export function extractHtmlFeatures(html, domain = "") {
  /* 1 ▸ DOM parsing */
  const dom = new DOMParser().parseFromString(html, "text/html");
  const bodyText = dom.body ? dom.body.innerText.toLowerCase() : "";
  const scripts = [...dom.getElementsByTagName("script")]
    .map((t) => (t.textContent || "").toLowerCase())
    .join(" ");

  /* 2 ▸ numeric features */
  const num = {
    forms: dom.getElementsByTagName("form").length,
    inputs: dom.getElementsByTagName("input").length,
    iframes: dom.getElementsByTagName("iframe").length,
    links: dom.getElementsByTagName("a").length,
    imgs: dom.getElementsByTagName("img").length,
    scripts: dom.getElementsByTagName("script").length,
    html_len: html.length,
    js_len: scripts.length,
    entropy: shannonEntropy(html.slice(0, 20000)),
    js_eval_cnt: (scripts.match(rxEval) || []).length,
    base64_cnt: (scripts.match(rxB64) || []).length,
    link_ip: +rxIP.test(html),
    link_at: +rxAT.test(html),
    kw_cnt: KW.reduce((s, k) => s + bodyText.includes(k), 0),
    inputs_per_form: 0,
    iframe_ratio: 0,
    js_html_ratio: 0,
    ext_link_ratio: 0,
    form_ext_action: 0,
  };
  num.inputs_per_form = num.inputs / Math.max(num.forms, 1);
  num.iframe_ratio = num.iframes / Math.max(num.links + 1, 1);
  num.js_html_ratio = num.js_len / Math.max(num.html_len, 1);

  if (domain) {
    const aTags = [...dom.getElementsByTagName("a")];
    const ext = aTags.filter(
      (a) => a.href.startsWith("http") && !a.href.includes(domain)
    ).length;
    num.ext_link_ratio = ext / Math.max(num.links, 1);

    for (const f of dom.getElementsByTagName("form")) {
      const act = f.getAttribute("action") || "";
      if (act.startsWith("http") && !act.includes(domain)) {
        num.form_ext_action = 1;
        break;
      }
    }
  }

  /* 3 ▸ build dense Float32Array */
  const vec = new Float32Array(FEATURE_COUNT);

  /* numeric (0-18) */
  NUM_ORDER.forEach((k, i) => {
    vec[i] = num[k] || 0;
  });

  /* 4 ▸ word hashing: unigrams & bigrams → 2¹⁷ buckets */
  const wordOff = NUM_ORDER.length;
  const tokens = bodyText.split(/\W+/).filter(Boolean);
  for (let i = 0; i < tokens.length; ++i) {
    const uni = murmur32(tokens[i], 1) & (WORD_BITS - 1);
    vec[wordOff + uni] += 1;
    if (i + 1 < tokens.length) {
      const bi = murmur32(tokens[i] + " " + tokens[i + 1], 2) & (WORD_BITS - 1);
      vec[wordOff + bi] += 1;
    }
  }

  /* 5 ▸ char hashing: 4-6-grams → 2¹⁶ buckets */
  const charOff = wordOff + WORD_BITS;
  const fullTxt = (bodyText + scripts).toLowerCase();
  for (let n = 4; n <= 6; ++n) {
    for (let i = 0; i + n <= fullTxt.length; ++i) {
      const gram = fullTxt.slice(i, i + n);
      const h = murmur32(gram, n) & (CHAR_BITS - 1);
      vec[charOff + h] += 1;
    }
  }

  return vec;
}
