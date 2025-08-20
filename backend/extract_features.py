# backend/extract_features.py
import re
import math
from urllib.parse import urlparse
import tldextract

SUSPICIOUS_WORDS = [
    "login","verify","update","secure","account","bank","free","win","bonus",
    "click","confirm","password","claim","security","reset"
]

_ipv4_re = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    from collections import Counter
    counts = Counter(s)
    n = len(s)
    return -sum((c/n) * math.log2(c/n) for c in counts.values())

def is_ip(host: str) -> bool:
    if not host:
        return False
    return bool(_ipv4_re.match(host))

def extract_url_features(url: str) -> dict:
    """
    Returns a dictionary of numeric features extracted from the url string.
    These are simple, fast features that work well for phishing detection baselines.
    """
    try:
        if "://" not in url:
            parsed = urlparse("http://" + url)
        else:
            parsed = urlparse(url)
        host = parsed.hostname or ""
        path = parsed.path or ""
        query = parsed.query or ""
        full = parsed.geturl()

        ext = tldextract.extract(host)
        subdomain = ext.subdomain or ""
        domain = ext.domain or ""
        suffix = ext.suffix or ""  # top-level domain

        url_len = len(full)
        host_len = len(host)
        path_len = len(path)

        num_dots = full.count(".")
        num_hyphens = full.count("-")
        num_at = full.count("@")
        num_digits = sum(ch.isdigit() for ch in full)
        num_alpha = sum(ch.isalpha() for ch in full)
        num_special = sum(not ch.isalnum() for ch in full)

        digits_ratio = (num_digits / max(1, url_len))
        special_ratio = (num_special / max(1, url_len))

        suspicious_hits = sum(1 for w in SUSPICIOUS_WORDS if w in full.lower())

        features = {
            "url_length": url_len,
            "host_length": host_len,
            "path_length": path_len,
            "num_dots": num_dots,
            "num_hyphens": num_hyphens,
            "num_at": num_at,
            "has_https": 1 if parsed.scheme.lower() == "https" else 0,
            "starts_with_ip": 1 if is_ip(host) else 0,
            "tld_length": len(suffix),
            "num_subdomains": 0 if not subdomain else len(subdomain.split(".")),
            "digits_ratio": digits_ratio,
            "special_char_ratio": special_ratio,
            "entropy": shannon_entropy(host),
            "suspicious_words_count": suspicious_hits,
            "has_long_tld": 1 if len(suffix) > 3 else 0,
            "has_long_subdomain": 1 if len(subdomain) > 10 else 0,
        }
        return features
    except Exception:
        # conservative fallback
        return {
            "url_length": len(url),
            "host_length": 0,
            "path_length": 0,
            "num_dots": url.count("."),
            "num_hyphens": url.count("-"),
            "num_at": url.count("@"),
            "has_https": 0,
            "starts_with_ip": 0,
            "tld_length": 0,
            "num_subdomains": 0,
            "digits_ratio": 0.0,
            "special_char_ratio": 0.0,
            "entropy": 0.0,
            "suspicious_words_count": 0,
            "has_long_tld": 0,
            "has_long_subdomain": 0,
        }

# Keep a stable order for model inference
FEATURE_ORDER = [
    "url_length","host_length","path_length","num_dots","num_hyphens","num_at",
    "has_https","starts_with_ip","tld_length","num_subdomains","digits_ratio",
    "special_char_ratio","entropy","suspicious_words_count","has_long_tld","has_long_subdomain"
]
