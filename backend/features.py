"""
features.py

URL feature extraction utilities for PhishGuard.
- extract_features(url, do_whois=False)
    Returns a dict of numeric features for the given URL, including heuristic_score.
- fallback_rules(url)
    Lightweight heuristic rules (brand-in-subdomain, suspicious keywords, typosquat if Levenshtein available).
- FEATURE_ORDER
    A recommended fixed order of feature names (use when saving feature_order.json during training).
"""

import re
import math
import urllib.parse
import socket
from datetime import datetime
from collections import Counter

try:
    import tldextract
except Exception:
    raise ImportError("tldextract is required. Install with `pip install tldextract`")

# optional libraries (not required)
try:
    import whois as whois_lib
except Exception:
    whois_lib = None

try:
    import Levenshtein
except Exception:
    Levenshtein = None

# Suspicious tokens often found in phishing domains/hosts
SUSPICIOUS_WORDS = [
    "login", "secure", "verify", "update", "free", "claim",
    "password", "signin", "bank", "account", "confirm", "ebayisapi",
    "webscr", "paypal", "security", "support", "reset"
]

# Trusted brands mapping
TRUSTED_BRANDS = {
    "facebook": "facebook.com",
    "google": "google.com",
    "paypal": "paypal.com",
    "amazon": "amazon.com",
    "apple": "apple.com",
    "bankofamerica": "bankofamerica.com",
    "microsoft": "microsoft.com",
}

FEATURE_ORDER = [
    "url_length",
    "host_length",
    "path_length",
    "num_query_params",
    "num_fragments",
    "count_dot",
    "count_dash",
    "count_at",
    "count_question",
    "count_equal",
    "count_percent",
    "count_hash",
    "num_digits_in_host",
    "num_digits_total",
    "num_special_chars",
    "has_https",
    "starts_with_ip",
    "entropy",
    "domain_age_days",
    "suspicious_words_count",
    "suspicious_keyword",
    "num_subdomains",
    "has_long_subdomain",
    "has_long_tld",
    "heuristic_score"   # <-- new feature added
]

# ---------- Utility helpers ----------
def calculate_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    probs = [float(v) / len(s) for v in counts.values()]
    entropy = -sum(p * math.log(p, 2) for p in probs if p > 0)
    return entropy

_ip_regex = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
def is_ip_address(host: str) -> bool:
    if not host:
        return False
    host = host.strip()
    if _ip_regex.match(host):
        return True
    try:
        socket.inet_aton(host)
        return True
    except Exception:
        return False

def safe_int(v, default=0):
    try:
        return int(v)
    except Exception:
        try:
            return int(float(v))
        except Exception:
            return default

# ---------- WHOIS / domain age ----------
def get_domain_age_days(registered_domain: str, do_whois: bool = False) -> int:
    if not do_whois or whois_lib is None:
        return -1
    try:
        w = whois_lib.whois(registered_domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0] if creation else None
        if creation is None:
            return -1
        if not isinstance(creation, datetime):
            try:
                creation = datetime.fromisoformat(str(creation))
            except Exception:
                return -1
        age_days = (datetime.now() - creation).days
        return max(age_days, 0)
    except Exception:
        return -1

# ---------- Feature extraction ----------
def extract_features(url: str, do_whois: bool = False) -> dict:
    if not url or not isinstance(url, str):
        url = ""

    try:
        parsed = urllib.parse.urlparse(url if "://" in url else "http://" + url)
    except Exception:
        parsed = urllib.parse.urlparse("http://" + url.replace("[", "").replace("]", ""))

    scheme = (parsed.scheme or "").lower()
    netloc = parsed.netloc or parsed.path
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""

    try:
        ext = tldextract.extract(url if "://" in url else "http://" + url)
        subdomain = ext.subdomain or ""
        domain = ext.domain or ""
        suffix = ext.suffix or ""
        registered_domain = ext.registered_domain or ""
    except Exception:
        subdomain = domain = suffix = registered_domain = ""

    host = ".".join(p for p in [subdomain, domain, suffix] if p)

    url_length = len(url)
    host_length = len(host)
    path_length = len(path)
    num_query_params = query.count("&") + 1 if "=" in query else 0
    num_fragments = 1 if fragment else 0
    count_dot = url.count(".")
    count_dash = url.count("-")
    count_at = url.count("@")
    count_question = url.count("?")
    count_equal = url.count("=")
    count_percent = url.count("%")
    count_hash = url.count("#")
    num_digits_in_host = sum(c.isdigit() for c in host)
    num_digits_total = sum(c.isdigit() for c in url)
    num_special_chars = sum(1 for c in url if (not c.isalnum() and c not in ".-/:?=&_%#"))
    has_https = 1 if scheme == "https" else 0
    starts_with_ip = 1 if is_ip_address(domain) or is_ip_address(host) else 0
    entropy = calculate_entropy(url)
    domain_age_days = get_domain_age_days(registered_domain, do_whois=do_whois)

    host_and_path = (host + " " + path + " " + query).lower()
    suspicious_hits = [w for w in SUSPICIOUS_WORDS if w in host_and_path]
    suspicious_words_count = len(suspicious_hits)
    suspicious_keyword = 1 if suspicious_words_count > 0 else 0
    subdomain_parts = [p for p in (subdomain.split(".") if subdomain else []) if p]
    num_subdomains = len(subdomain_parts)
    has_long_subdomain = 1 if any(len(p) >= 20 for p in subdomain_parts) else 0
    has_long_tld = 1 if len(suffix) >= 6 else 0

    # ---------- Add heuristic_score directly ----------
    label_h, score_h, reasons = fallback_rules(url)

    features = {
        "url_length": url_length,
        "host_length": host_length,
        "path_length": path_length,
        "num_query_params": num_query_params,
        "num_fragments": num_fragments,
        "count_dot": count_dot,
        "count_dash": count_dash,
        "count_at": count_at,
        "count_question": count_question,
        "count_equal": count_equal,
        "count_percent": count_percent,
        "count_hash": count_hash,
        "num_digits_in_host": num_digits_in_host,
        "num_digits_total": num_digits_total,
        "num_special_chars": num_special_chars,
        "has_https": has_https,
        "starts_with_ip": starts_with_ip,
        "entropy": round(float(entropy), 6),
        "domain_age_days": domain_age_days,
        "suspicious_words_count": suspicious_words_count,
        "suspicious_keyword": suspicious_keyword,
        "num_subdomains": num_subdomains,
        "has_long_subdomain": has_long_subdomain,
        "has_long_tld": has_long_tld,
        "heuristic_score": round(float(score_h), 4),
        "extracted": {
            "subdomain": subdomain,
            "domain": domain,
            "suffix": suffix,
            "registered_domain": registered_domain,
            "suspicious_hits": suspicious_hits,
            "heuristic_label": label_h,
            "heuristic_reasons": reasons
        }
    }

    for k, v in list(features.items()):
        if isinstance(v, bool):
            features[k] = int(v)

    return features

# ---------- Fallback rules ----------
def fallback_rules(url: str):
    try:
        feats = {}
        ext = tldextract.extract(url if "://" in url else "http://" + url)
        extracted = {
            "subdomain": ext.subdomain or "",
            "domain": ext.domain or "",
            "suffix": ext.suffix or "",
        }

        # 1) brand-in-subdomain
        subdomain = extracted["subdomain"].lower()
        domain = extracted["domain"].lower()
        suffix = extracted["suffix"].lower()
        registered = f"{domain}.{suffix}" if suffix else domain
        reasons = []
        label = 0
        score = 0.1

        for brand, official in TRUSTED_BRANDS.items():
            if brand in subdomain or brand == domain:
                if registered != official:
                    label = 1
                    score = max(score, 0.95)
                    reasons.append(f"Brand '{brand}' appears but registered domain is '{registered}', not '{official}'")

        # 2) typosquat
        if Levenshtein:
            for brand, official in TRUSTED_BRANDS.items():
                dist = Levenshtein.distance(domain, official.split(".")[0])
                thr = 1 if len(official) <= 4 else 2 if len(official) <= 7 else 3
                if 0 < dist <= thr:
                    label = 1
                    score = max(score, 0.9)
                    reasons.append(f"Domain '{registered}' similar to brand '{official}' (lev={dist})")

        # 3) suspicious keywords
        host_full = f"{subdomain} {domain} {suffix}".lower()
        hits = [w for w in SUSPICIOUS_WORDS if w in host_full]
        if hits:
            label = 1
            score = max(score, 0.8)
            reasons.append(f"Suspicious words in host: {', '.join(hits)}")

        # 4) IP host
        if is_ip_address(domain) or is_ip_address(subdomain):
            label = 1
            score = max(score, 0.9)
            reasons.append("Host is an IP address")

        return int(label), float(score), reasons

    except Exception:
        return 0, 0.0, []

# ---------- Quick demo ----------
if __name__ == "__main__":
    demo_urls = [
        "http://secure-update-facebook.com",
        "https://accounts.google.com/signin",
        "http://192.168.0.1/login/verify.php?user=admin",
        "http://free-gift-card.win/claim",
        "https://example.com"
    ]
    for u in demo_urls:
        feats = extract_features(u)
        print(f"URL: {u}\nHeuristic score: {feats['heuristic_score']}\nSome features: { {k: feats[k] for k in ['url_length','host_length','entropy','suspicious_words_count']} }\n{'-'*60}")
