# updated_html_feature_extract.py  – parity with extension JS extractor
from bs4 import BeautifulSoup
import re, math
from urllib.parse import urlparse

# ─── feature order (use exactly this for training) ───────────────────
NUM_ORDER = [
    # structural counts
    "forms","inputs","hidden_inputs","iframes","links","imgs","data_uri_imgs","scripts",
    # length & entropy
    "html_len","inline_js_len","entropy_html","entropy_js",
    # JavaScript red-flags
    "js_eval_cnt","js_suspicious_fn_cnt","num_event_handlers",
    # encoded / obfuscation
    "base64_cnt",
    # link-level flags & ratios
    "link_ip","link_at","punycode_link","js_href_link",
    "num_ext_links","ext_link_ratio",
    # form/action issues
    "form_empty_action","form_external_action","form_mailto",
    # iframe ratio etc.
    "inputs_per_form","iframe_ratio","js_html_ratio",
    # domain/TLD
    "domain_len","domain_hyphen","domain_digit","tld_suspicious","favicon_ext",
    # keyword stats
    "kw_cnt"
]

# ─── multilingual phishing vocab ─────────────────────────────────────
KW_EN = [
    "account","bank","confirm","password","passw0rd","p@ssword","p@55w0rd", "paxxword",
    "login","verify","credit card","ssn","social security","urgent",
    "immediately","click here","security","update","alert","expired","limited"
]
KW_PT = ["conta","banco","confirmar","senha","iniciar sessão","verificar",
         "urgente","clique aqui","atualize","segurança","aviso"]
KW_ES = ["cuenta","banco","confirmar","contraseña","iniciar sesión","verificar",
         "urgente","haz clic aquí","actualiza","seguridad","aviso"]
KW_RU = ["аккаунт","банк","подтвердите","пароль","срочно","нажмите здесь",
         "обновите","безопасность","ограничено"]
KW_ZH = ["账户","帐号","密码","登录","立即","点击","安全","验证","更新","警告"]
SUSPICIOUS_KW = KW_EN + KW_PT + KW_ES + KW_RU + KW_ZH

SUSPICIOUS_FUNCS = [
    "eval(", "atob(", "unescape(", "fromcharcode(", "document.write(",
    "settimeout(", "setinterval("
]

SUSPICIOUS_TLDS = {
    ".xyz",".top",".pw",".kim",".buzz",".click",".loan",".work",
    ".ru",".cn",".zip",".mov",".bond",".lol"
}

# ─── helpers ─────────────────────────────────────────────────────────
def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    return -sum((c/len(text))*math.log2(c/len(text)) for c in freq.values())

# ─── main extractor ─────────────────────────────────────────────────
def extract_features(html: str, page_domain: str | None = None):
    soup = BeautifulSoup(html, "html.parser")
    feats = dict.fromkeys(NUM_ORDER, 0)

    # counts
    feats["forms"]   = len(soup.find_all("form"))
    feats["inputs"]  = len(soup.find_all("input"))
    feats["hidden_inputs"] = len(soup.find_all("input", {"type":"hidden"}))
    feats["iframes"] = len(soup.find_all("iframe"))
    feats["links"]   = len(soup.find_all("a"))
    feats["imgs"]    = len(soup.find_all("img"))
    feats["data_uri_imgs"] = len([img for img in soup.find_all("img", src=True)
                                  if img["src"].startswith("data:image")])
    feats["scripts"] = len(soup.find_all("script"))

    # raw strings
    html_lower = html.lower()
    inline_js  = " ".join(
        s.string or "" for s in soup.find_all("script") if not s.get("src")
    ).lower()

    # link flags
    num_ext = 0
    for a in soup.find_all("a", href=True):
        href = a["href"].lower()
        if page_domain and href.startswith("http") and page_domain not in href:
            num_ext += 1
        if re.search(r"http[s]?://\d{1,3}(?:\.\d{1,3}){3}", href):
            feats["link_ip"] = 1
        if "@" in href and not href.startswith("mailto:"):
            feats["link_at"] = 1
        if href.startswith("javascript:"):
            feats["js_href_link"] = 1
        if "xn--" in href:
            feats["punycode_link"] = 1
    feats["num_ext_links"] = num_ext
    feats["ext_link_ratio"] = num_ext / feats["links"] if feats["links"] else 0

    # forms
    for f in soup.find_all("form"):
        act = (f.get("action") or "").lower()
        if act in ("", "about:blank"):
            feats["form_empty_action"] = 1
        if act.startswith("mailto:"):
            feats["form_mailto"] = 1
        if page_domain and act.startswith("http") and page_domain not in urlparse(act).netloc:
            feats["form_external_action"] = 1

    # favicon origin
    icon = soup.find("link", rel=re.compile("icon", re.I))
    if icon and icon.get("href") and page_domain:
        href = icon["href"].lower()
        if href.startswith("http") and page_domain not in href:
            feats["favicon_ext"] = 1

    # JS red-flags
    feats["inline_js_len"]        = len(inline_js)
    feats["js_eval_cnt"]          = inline_js.count("eval(")
    feats["js_suspicious_fn_cnt"] = sum(inline_js.count(fn) for fn in SUSPICIOUS_FUNCS)
    feats["num_event_handlers"]   = len(re.findall(r"\son\w+\s*=", html_lower))
    feats["base64_cnt"]           = len(re.findall(r"base64[,;]", html_lower))

    # entropy / length
    feats["html_len"]     = len(html)
    feats["entropy_html"] = shannon_entropy(html_lower)
    feats["entropy_js"]   = shannon_entropy(inline_js)

    # ratios
    feats["inputs_per_form"] = feats["inputs"] / feats["forms"] if feats["forms"] else 0
    total_tags = len(soup.find_all(True)) or 1
    feats["iframe_ratio"]  = feats["iframes"] / total_tags
    feats["js_html_ratio"] = feats["inline_js_len"] / feats["html_len"] if feats["html_len"] else 0

    # domain-level
    if page_domain:
        dom = page_domain.lower()
        feats["domain_len"]    = len(dom)
        feats["domain_hyphen"] = int("-" in dom)
        feats["domain_digit"]  = int(any(c.isdigit() for c in dom))
        tld = "." + dom.split(".")[-1]
        feats["tld_suspicious"] = int(tld in SUSPICIOUS_TLDS)

    # keyword hits
    vis = soup.get_text(" ").lower()
    feats["kw_cnt"] = sum(int(kw in vis) for kw in SUSPICIOUS_KW)

    # return dict aligned with NUM_ORDER
    return {k: feats[k] for k in NUM_ORDER}, vis
