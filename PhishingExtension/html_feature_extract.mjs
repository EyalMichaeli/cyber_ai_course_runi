/* ────────── html_feature_extract.mjs ────────── */

const { DOMParser } = window;

/* keep EXACT order for model (34 features) */
export const NUM_ORDER = [
  "forms","inputs","hidden_inputs","iframes","links","imgs","data_uri_imgs","scripts",
  "html_len","inline_js_len","entropy_html","entropy_js",
  "js_eval_cnt","js_suspicious_fn_cnt","num_event_handlers",
  "base64_cnt",
  "link_ip","link_at","punycode_link","js_href_link","num_ext_links","ext_link_ratio",
  "form_empty_action","form_external_action","form_mailto",
  "inputs_per_form","iframe_ratio","js_html_ratio",
  "domain_len","domain_hyphen","domain_digit","tld_suspicious","favicon_ext","kw_cnt"
];
export const FEATURE_COUNT = NUM_ORDER.length;

const KW_EN = ["account","bank","confirm","password","passw0rd","p@ssword","p@55w0rd","paxxword",
  "login","verify","credit card","ssn","social security","urgent","immediately","click here",
  "security","update","alert","expired","limited"];
const KW_PT = ["conta","banco","confirmar","senha","iniciar sessão","verificar","urgente","clique aqui","atualize","segurança","aviso"];
const KW_ES = ["cuenta","banco","confirmar","contraseña","iniciar sesión","verificar","urgente","haz clic aquí","actualiza","seguridad","aviso"];
const KW_RU = ["аккаунт","банк","подтвердите","пароль","срочно","нажмите здесь","обновите","безопасность","ограничено"];
const KW_ZH = ["账户","帐号","密码","登录","立即","点击","安全","验证","更新","警告"];
const SUSPICIOUS_KW = [...KW_EN, ...KW_PT, ...KW_ES, ...KW_RU, ...KW_ZH];

const SUSPICIOUS_FUNCS = ["eval(","atob(","unescape(","fromcharcode(","document.write(","settimeout(","setinterval("];
const RISKY_TLDS = new Set([".xyz",".top",".pw",".kim",".buzz",".click",".loan",".work",
  ".ru",".cn",".zip",".mov",".bond",".lol"]);

const regexEscape = s => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const entropy = s => {
  if (!s) return 0;
  const freq = {};
  for (const ch of s) freq[ch] = (freq[ch] || 0) + 1;
  let h = 0, n = s.length;
  for (const k in freq) {
    const p = freq[k] / n;
    h -= p * Math.log2(p);
  }
  return h;
};

/** @returns {Float32Array} features */
export function extractHtmlFeatures(html, domain = "") {
  const doc = new DOMParser().parseFromString(html, "text/html");

  // counts
  const forms = doc.querySelectorAll("form").length;
  const inputs = doc.querySelectorAll("input").length;
  const hidden = doc.querySelectorAll("input[type='hidden']").length;
  const ifrs = doc.querySelectorAll("iframe").length;
  const links = doc.querySelectorAll("a").length;
  const imgs = doc.querySelectorAll("img").length;
  const dataUri = [...doc.querySelectorAll("img[src^='data:image']")].length;
  const scripts = doc.querySelectorAll("script").length;

  // raw texts
  const htmlLower = html.toLowerCase();
  const inlineJs = [...doc.querySelectorAll("script:not([src])")]
    .map(s => s.textContent || "").join(" ").toLowerCase();

  // link features
  let ext = 0, linkIp = 0, linkAt = 0, jsHref = 0, puny = 0;
  doc.querySelectorAll("a[href]").forEach(a => {
    const h = a.getAttribute("href").toLowerCase();
    if (domain && h.startsWith("http") && !h.includes(domain)) ext++;
    if (/https?:\/\/\d{1,3}(?:\.\d{1,3}){3}/.test(h)) linkIp = 1;
    if (h.includes("@") && !h.startsWith("mailto:")) linkAt = 1;
    if (h.startsWith("javascript:")) jsHref = 1;
    if (h.includes("xn--")) puny = 1;
  });
  const extRatio = links ? ext / links : 0;

  // forms
  let emptyAct = 0, mailAct = 0, extAct = 0;
  Array.from(doc.forms).forEach(f => {
    const act = (f.getAttribute("action") || "").toLowerCase();
    if (!act || act === "about:blank") emptyAct = 1;
    if (act.startsWith("mailto:")) mailAct = 1;
    if (domain && act.startsWith("http") && !act.includes(domain)) extAct = 1;
  });

  // favicon
  let favExt = 0;
  const icon = doc.querySelector("link[rel~='icon']");
  if (icon && icon.href && domain) {
    const h = icon.href.toLowerCase();
    if (h.startsWith("http") && !h.includes(domain)) favExt = 1;
  }

  // JS & obfuscation
  const jsEvalCnt = (inlineJs.match(/eval\s*\(/g) || []).length;
  const fnCnt = SUSPICIOUS_FUNCS.reduce((sum, fn) => {
    const esc = regexEscape(fn);
    const re = new RegExp(esc, "g");
    return sum + (inlineJs.match(re) || []).length;
  }, 0);
  const evtCnt = (htmlLower.match(/\son\w+\s*=/g) || []).length;
  const b64Cnt = (htmlLower.match(/base64[,;]/g) || []).length;

  // ratios
  const inputsPer = forms ? inputs / forms : 0;
  const totalTags = doc.getElementsByTagName("*").length || 1;
  const iframeRat = ifrs / totalTags;
  const jsHtmlRat = html.length ? inlineJs.length / html.length : 0;

  // domain features
  let dLen = 0, dHy = 0, dDig = 0, tldSus = 0;
  if (domain) {
    const dm = domain.toLowerCase();
    dLen = dm.length;
    dHy = dm.includes("-") ? 1 : 0;
    dDig = /\d/.test(dm) ? 1 : 0;
    const tld = "." + dm.split(".").pop();
    tldSus = RISKY_TLDS.has(tld) ? 1 : 0;
  }

  // keywords
  const text = doc.body ? doc.body.innerText.toLowerCase() : "";
  const kwCnt = SUSPICIOUS_KW.reduce((sum, kw) => sum + (text.includes(kw) ? 1 : 0), 0);

  // assemble
  const obj = {
    forms, inputs, hidden_inputs: hidden, iframes: ifrs, links, imgs,
    data_uri_imgs: dataUri, scripts,
    html_len: html.length, inline_js_len: inlineJs.length,
    entropy_html: entropy(htmlLower), entropy_js: entropy(inlineJs),
    js_eval_cnt: jsEvalCnt, js_suspicious_fn_cnt: fnCnt, num_event_handlers: evtCnt,
    base64_cnt: b64Cnt,
    link_ip: linkIp, link_at: linkAt, punycode_link: puny, js_href_link: jsHref,
    num_ext_links: ext, ext_link_ratio: extRatio,
    form_empty_action: emptyAct, form_external_action: extAct, form_mailto: mailAct,
    inputs_per_form: inputsPer, iframe_ratio: iframeRat, js_html_ratio: jsHtmlRat,
    domain_len: dLen, domain_hyphen: dHy, domain_digit: dDig, tld_suspicious: tldSus,
    favicon_ext: favExt, kw_cnt: kwCnt
  };
  const vec = new Float32Array(FEATURE_COUNT);
  NUM_ORDER.forEach((k,i) => vec[i] = obj[k] || 0);
  return vec;
}
