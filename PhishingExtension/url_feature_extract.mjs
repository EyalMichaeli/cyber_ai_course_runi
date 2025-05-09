/*****************************************************************
 *  URL-only feature extractor — JS port of extract_url_features_v3
 *****************************************************************/
export const TOP_DOMAINS = new Set([
  "google.com",
  "bing.com",
  "yahoo.com",
  "duckduckgo.com",
  "facebook.com",
  "instagram.com",
  "x.com",
  "twitter.com",
  "youtube.com",
  "netflix.com",
  "amazon.com",
  "ebay.com",
  "paypal.com",
  "apple.com",
  "microsoft.com",
  "office.com",
  "github.com",
  "stackoverflow.com",
  "wikipedia.org",
  "linkedin.com",
  "spotify.com",
  "openai.com",
  "gmail.com",
  "outlook.com",
]);

const pathKeywords = ["reset", "secure", "auth", "confirm"];
const suspiciousExt = [".php", ".asp", ".cgi", ".jsp", ".exe"];
const shorteners = ["bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co"];
const suspiciousTLDs = /(tk|ml|ga|cf|gq)$/;
const popular5 = [
  "google.com",
  "paypal.com",
  "facebook.com",
  "amazon.com",
  "apple.com",
];

/* ------------ tiny helpers ------------ */
export function shannonEntropy(str) {
  if (!str) return 0;
  const freq = {};
  for (const c of str) freq[c] = (freq[c] || 0) + 1;
  const len = str.length;
  let ent = 0;
  for (const k in freq) {
    const p = freq[k] / len;
    ent -= p * Math.log2(p);
  }
  return ent;
}
function isSubdomain(host, parent) {
  return host === parent || host.endsWith("." + parent);
}
function levenshtein(a, b) {
  // fast ≤64-char Levenshtein
  const m = a.length,
    n = b.length;
  if (!m) return n;
  if (!n) return m;
  const v = Array.from({ length: n + 1 }, (_, i) => i);
  for (let i = 0; i < m; i++) {
    let prev = i + 1;
    for (let j = 0; j < n; j++) {
      const cur = prev;
      prev = v[j + 1];
      v[j + 1] = a[i] === b[j] ? cur : 1 + Math.min(cur, prev, v[j]);
    }
  }
  return v[n];
}

/* ------------ main export ------------ */
export const FEATURE_ORDER = Object.freeze([
  /* numerics first (order matters for model) */
  "url_length",
  "hostname_length",
  "subdomain_length",
  "num_digits",
  "num_hyphens",
  "num_tokens",
  "num_slashes",
  "has_at_symbol",
  "has_ip_address",
  "is_free_hosting",
  "has_suspicious_port",
  "has_exe_or_zip",
  "has_long_query",
  "has_keywords",
  "has_suspicious_tld",
  "high_entropy_domain",
  "is_numeric_domain",
  "domain_ends_with_number",
  "path_contains_keywords",
  "filename_suspicious_ext",
  "num_query_params",
  "repeated_chars",
  "is_punycode",
  "excess_subdomains",
  "url_shortener",
  "non_https",
  "levenshtein_flag",
  "path_entropy",
  "query_entropy",
  "ratio_digits_hostname",
  "ratio_special_chars_hostname",
  "unique_token_ratio",
  "has_many_subdirectories",
  "contains_encoded_chars",
  "num_query_equals",
  "is_top_domain",
  "is_exact_top_domain",
]);

export function extractUrlFeatures_v4(url) {
  try {
    const u = new URL(url);
    const host = (u.hostname || "").toLowerCase();
    const tokens = host.split(".");
    const tld = tokens.at(-1) || "";
    const subdom = tokens.length >= 3 ? tokens.slice(0, -2).join(".") : "";
    const q = u.search.slice(1);
    const path = u.pathname || "";

    const feats = {
      url_length: url.length,
      hostname_length: host.length,
      subdomain_length: subdom.length,
      num_digits: (host.match(/\d/g) || []).length,
      num_hyphens: (host.match(/-/g) || []).length,
      num_tokens: tokens.length,
      num_slashes: (url.match(/\//g) || []).length,
      has_at_symbol: +url.includes("@"),
      has_ip_address: +/^\d{1,3}(\.\d{1,3}){3}$/.test(host),
      is_free_hosting: +/(weebly|netlify|000webhost|github)/.test(host),
      has_suspicious_port: +(u.port && u.port !== "80" && u.port !== "443"),
      has_exe_or_zip: +/\.(exe|zip|rar)$/i.test(url),
      has_long_query: +(q.length > 50),
      has_keywords: +/(login|verify|account|secure|update|bank)/.test(url),
      has_suspicious_tld: +suspiciousTLDs.test(tld),
      high_entropy_domain: +(shannonEntropy(host) > 4.3),
      is_numeric_domain: +/^[\d.-]+$/.test(host.replace(/\./g, "")),
      domain_ends_with_number: +(
        tokens.length > 1 && /\d$/.test(tokens[tokens.length - 2])
      ),
      path_contains_keywords: +pathKeywords.some((k) =>
        path.toLowerCase().includes(k)
      ),
      filename_suspicious_ext: +suspiciousExt.some((ext) =>
        path.toLowerCase().endsWith(ext)
      ),
      num_query_params: q ? q.split("&").length : 0,
      repeated_chars: +/(.)\1{4,}/.test(host),
      is_punycode: +host.startsWith("xn--"),
      excess_subdomains: +(host.split(".").length - 1 > 3),
      url_shortener: +shorteners.some((s) => url.includes(s)),
      non_https: +(u.protocol !== "https:"),
      levenshtein_flag: +(
        Math.min(...popular5.map((d) => levenshtein(host, d))) <= 2
      ),
      path_entropy: shannonEntropy(path),
      query_entropy: shannonEntropy(q),
      ratio_digits_hostname: host
        ? (host.match(/\d/g) || []).length / host.length
        : 0,
      ratio_special_chars_hostname: host
        ? (host.match(/[^a-z0-9.-]/gi) || []).length / host.length
        : 0,
      unique_token_ratio: tokens.length
        ? new Set(tokens).size / tokens.length
        : 0,
      has_many_subdirectories: +(path.split("/").length - 1 > 3),
      contains_encoded_chars: +url.includes("%"),
      num_query_equals: (q.match(/=/g) || []).length,
      is_top_domain: +[...TOP_DOMAINS].some((d) => isSubdomain(host, d)),
      is_exact_top_domain: +TOP_DOMAINS.has(host),
    };
    /* return as ordered numeric array */
    return FEATURE_ORDER.map((k) => feats[k] || 0);
  } catch (e) {
    // fallback: all zeros, correct length
    return FEATURE_ORDER.map(() => 0);
  }
}
