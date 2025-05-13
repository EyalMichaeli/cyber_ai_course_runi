const TOP_DOMAINS = new Set([
  "google.com",
  "google.com/maps",
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
  "chatgpt.com",
]);

// ---------- extra allow-list (high-traffic but not in TOP_DOMAINS) -----
const TOP_TRANCO = new Set([
  "reddit.com",
  "nytimes.com",
  "bbc.com",
  "cnn.com",
  "whatsapp.com",
  "tiktok.com",
  "pinterest.com",
  "imdb.com",
  "dailymotion.com",
  "tripadvisor.com",
]);

// ---------- known free-hosting & abused TLDs ---------------------------
const FREE_HOSTS = [
  "000webhost",
  "freehostia",
  "neocities",
  "weebly",
  "netlify",
  "blogspot",
  "wordpress",
  "github",
  "wix",
  "web.app",
];

const BAD_TLDS = [
  "tk",
  "xyz",
  "top",
  "shop",
  "info",
  "buzz",
  "cc",
  "cyou",
  "click",
  "cam",
  "kim",
  "gq",
  "cf",
  "ml",
];

// ---------- scoring constants (tweak to taste) -------------------------
const BONUS_CLEAN_DOMAIN = -25; // subtract if in TOP_DOMAINS / TOP_TRANCO
const PENALTY_BRAND_MISMATCH = 8;
const MAX_PATH_DEPTH_SAFE = 5;

/* helper: get registrable domain (very coarse) */
function regDomain(host) {
  const parts = host.split(".");
  return parts.slice(-2).join(".");
}

/* helper: is `host` a sub-domain of any domain in a Set */
function isSubOrExact(host, set) {
  return [...set].some((d) => host === d || host.endsWith("." + d));
}

/* helper: detect Google-Maps coordinate pattern in path */
function isGoogleMapsCoords(path) {
  return /@-?\d{1,3}\.\d+,-?\d{1,3}\.\d+/.test(path);
}

/* MAIN -----------------------------------------------------------------*/
export function scorePhishingURL(url) {
  let score = 1;
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return 1;
  }

  const host = parsed.hostname.toLowerCase();
  const full = url.toLowerCase();
  const path = parsed.pathname + parsed.search;

  /* ─── 0. instant whitelist ───────────────────────────────────────── */
  if (isSubOrExact(host, TOP_DOMAINS) || isSubOrExact(host, TOP_TRANCO)) {
    score += BONUS_CLEAN_DOMAIN; // negative → lowers final risk
  }

  /* ─── 1. hostname features ───────────────────────────────────────── */
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host) || /^[0-9a-f:]+$/i.test(host))
    score += 20; // raw IP

  if (host.startsWith("xn--") || /[^\x00-\x7F]/.test(host)) score += 25;

  const tld = host.split(".").pop();
  if (BAD_TLDS.includes(tld)) score += 10;

  const subCount = Math.max(host.split(".").length - 2, 0);
  if (subCount > 1) score += 5 * (subCount - 1);

  const hyphens = (host.match(/-/g) || []).length;
  if (hyphens > 1) score += (hyphens - 1) * 5;

  if (url.includes("@")) score += 20;

  if (FREE_HOSTS.some((fh) => host.includes(fh))) score += 15;

  /* brand-name lure */
  const BRANDS = [
    "paypal",
    "google",
    "apple",
    "facebook",
    "bank",
    "icloud",
    "microsoft",
    "amazon",
  ];
  if (BRANDS.some((b) => full.includes(b) && !host.includes(b + ".")))
    score += PENALTY_BRAND_MISMATCH;

  /* ─── 2. path / query heuristics ─────────────────────────────────── */
  if (url.length > 75) score += 5 + (url.length > 120 ? 5 : 0);

  const depth = (parsed.pathname.match(/\//g) || []).length;
  if (depth > MAX_PATH_DEPTH_SAFE) score += (depth - MAX_PATH_DEPTH_SAFE) * 2;

  if ((parsed.pathname.match(/\./g) || []).length > 1) score += 3;

  // encoded junk
  if (/%20|%25|%00/i.test(path)) score += 5;

  // single-character dirs
  if (parsed.pathname.split("/").some((seg) => seg.length === 1)) score += 5;

  const SUSPECT = [
    "login",
    "signin",
    "secure",
    "account",
    "update",
    "verify",
    "confirm",
    "suspend",
  ];
  if (SUSPECT.some((w) => full.includes(w))) score += 10;

  const params = [...parsed.searchParams.keys()].length;
  if (params > 3) score += (params - 3) * 2;

  /* special-case Google Maps coords → relax numeric ratio penalties */
  const isMaps = host.endsWith("google.com") && isGoogleMapsCoords(path);

  /* ─── 3. protocol & char-ratio ──────────────────────────────────── */
  if (parsed.protocol === "http:") score += 5;

  if (!isMaps) {
    const letters = (full.match(/[a-z]/g) || []).length;
    const digits = (full.match(/\d/g) || []).length;
    if (letters && digits / letters > 0.3) score += 5;
  }

  return Math.max(score, 0); // never negative
}
