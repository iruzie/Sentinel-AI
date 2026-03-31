"""
phishing_features.py
====================
Pure-Python URL feature extractor used by both the training script and the
FastAPI inference endpoint.  No external network calls — all analysis is local.

Features (25 total)
-------------------
 0  url_length              Total character count of the raw URL
 1  hostname_length         Character count of just the hostname
 2  dots_in_hostname        Number of '.' found in the hostname
 3  subdomain_count         Subdomain segments excluding 'www' and the apex
 4  has_ip_hostname         1 if hostname is a bare IPv4 address
 5  has_hyphen              1 if '-' appears anywhere in the hostname
 6  hyphen_count            Total '-' in hostname
 7  has_at_symbol           1 if '@' in URL (tricks browsers into ignoring prefix)
 8  has_double_slash_path   1 if '//' appears in the URL path (after scheme)
 9  has_port                1 if a non-standard port is explicitly specified
10  suspicious_keyword_cnt  Count of phishing-related words found in lowercased URL
11  risky_tld               1 if the TLD is on the high-abuse list
12  is_url_shortener        1 if the hostname belongs to a known shortener service
13  path_length             Character count of the URL path
14  query_length            Character count of the query string
15  equals_count            Number of '=' in URL (form/redirect parameter signals)
16  ampersand_count         Number of '&' in URL
17  percent_encoded_count   Number of '%' (URL-encoded characters)
18  digit_ratio_hostname    Fraction of characters in hostname that are digits
19  hostname_entropy        Shannon entropy of the hostname string
20  has_https               1 if scheme is https
21  dots_outside_hostname   Total dots in URL minus dots in hostname
22  domain_parts_count      Number of dot-separated parts in the hostname
23  path_depth              Number of '/' in the URL path
24  query_param_count       Number of key=value pairs in the query string
"""

import re
import math
from urllib.parse import urlparse
from collections import Counter

# ---------------------------------------------------------------------------
# Reference data
# ---------------------------------------------------------------------------

SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'sign-in', 'verify', 'verification',
    'update', 'secure', 'security', 'account', 'banking', 'bank',
    'password', 'passwd', 'credential', 'paypal', 'ebay', 'amazon',
    'apple', 'microsoft', 'google', 'payment', 'confirm', 'support',
    'alert', 'suspended', 'unlock', 'restore', 'identity', 'validate',
    'wallet', 'crypto', 'invoice', 'refund', 'winner', 'prize',
    'click', 'bonus', 'free', 'urgent', 'notice', 'limited',
]

RISKY_TLDS = {
    '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.xyz', '.pw',
    '.cc', '.su', '.buzz', '.click', '.link', '.gdn', '.icu',
    '.rest', '.cam', '.monsters', '.cfd', '.sbs',
}

SHORTENER_DOMAINS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
    'buff.ly', 'adf.ly', 'tiny.cc', 'tr.im', 'rebrand.ly',
    'short.io', 'cutt.ly', 'rb.gy', 'shorturl.at',
}

_IP_RE = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _shannon_entropy(s: str) -> float:
    """Return the Shannon entropy (bits) of a string."""
    if not s:
        return 0.0
    freq = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

FEATURE_NAMES = [
    'url_length', 'hostname_length', 'dots_in_hostname', 'subdomain_count',
    'has_ip_hostname', 'has_hyphen', 'hyphen_count', 'has_at_symbol',
    'has_double_slash_path', 'has_port', 'suspicious_keyword_cnt',
    'risky_tld', 'is_url_shortener', 'path_length', 'query_length',
    'equals_count', 'ampersand_count', 'percent_encoded_count',
    'digit_ratio_hostname', 'hostname_entropy', 'has_https',
    'dots_outside_hostname', 'domain_parts_count', 'path_depth',
    'query_param_count',
]


def extract_features(url: str) -> list:
    """
    Given a raw URL string return a list of 25 numeric features.
    Never raises — falls back to zeroes on malformed input.
    """
    try:
        normalized = url if re.match(r'^https?://', url, re.I) else 'http://' + url
        parsed     = urlparse(normalized)
        hostname   = (parsed.hostname or '').lower()
        path       = parsed.path or ''
        query      = parsed.query or ''
        full_lower = url.lower()
    except Exception:
        return [0.0] * len(FEATURE_NAMES)

    # --- hostname parts ---
    parts = hostname.split('.')
    tld   = ('.' + parts[-1]) if len(parts) > 1 else ''

    non_www_subdomains = [p for p in parts[:-2] if p not in ('www', 'ww', 'mail')]
    n_subdomains = len(non_www_subdomains)

    # --- individual signals ---
    has_ip         = 1 if _IP_RE.match(hostname) else 0
    has_hyphen     = 1 if '-' in hostname else 0
    hyphen_count   = hostname.count('-')
    has_at         = 1 if '@' in url else 0
    has_dbl_slash  = 1 if '//' in path else 0
    has_port       = 1 if parsed.port and parsed.port not in (80, 443) else 0

    kw_count    = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in full_lower)
    risky_tld   = 1 if tld in RISKY_TLDS else 0
    shortener   = 1 if any(sd in hostname for sd in SHORTENER_DOMAINS) else 0

    path_len    = len(path)
    query_len   = len(query)
    eq_count    = url.count('=')
    amp_count   = url.count('&')
    pct_count   = url.count('%')

    hn_len          = len(hostname)
    digit_ratio     = sum(c.isdigit() for c in hostname) / max(hn_len, 1)
    entropy         = _shannon_entropy(hostname)
    has_https       = 1 if parsed.scheme == 'https' else 0
    dots_outside    = url.count('.') - hostname.count('.')
    path_depth      = path.count('/')
    query_params    = len([p for p in query.split('&') if '=' in p]) if query else 0

    return [
        len(url),        # 0
        hn_len,          # 1
        hostname.count('.'),  # 2
        n_subdomains,    # 3
        has_ip,          # 4
        has_hyphen,      # 5
        hyphen_count,    # 6
        has_at,          # 7
        has_dbl_slash,   # 8
        has_port,        # 9
        kw_count,        # 10
        risky_tld,       # 11
        shortener,       # 12
        path_len,        # 13
        query_len,       # 14
        eq_count,        # 15
        amp_count,       # 16
        pct_count,       # 17
        digit_ratio,     # 18
        entropy,         # 19
        has_https,       # 20
        dots_outside,    # 21
        len(parts),      # 22
        path_depth,      # 23
        query_params,    # 24
    ]
