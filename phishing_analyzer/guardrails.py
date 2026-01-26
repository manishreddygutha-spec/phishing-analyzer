
# guardrails.py
# Safety & Guardrails for the phishing detector project.
# Author: Manish Reddy
# Purpose: Harden data handling, HTTP usage, logging, and runtime limits.

import os
import re
import time
import json
import logging
import threading
import html
from dataclasses import dataclass
from typing import Optional, List, Dict, Any, Tuple
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# =========================
# Global policy knobs
# =========================
@dataclass
class SafetyPolicy:
    # Workload caps (anti-DoS / quota protection)
    MAX_URLS_PER_EMAIL: int = 20
    MAX_ATTS_PER_EMAIL: int = 10
    MAX_REDIRECT_HOPS: int = 6
    REQ_TIMEOUT_SEC: int = 10
    TOTAL_DOWNLOAD_CAP_BYTES: int = 2_000_000  # 2 MB cap for fetches
    whois_ttl = 86400  # cache WHOIS results for 24 hours

    # Fail-safe: elevate risk when certain signals fail
    ELEVATE_ON_DNS_FAILURE: bool = True
    ELEVATE_ON_VT_FAILURE: bool = True
    ELEVATE_ON_WHOIS_FAILURE: bool = True

    # Redaction toggles
    REDACT_EMAIL: bool = True
    REDACT_URL: bool = True
    REDACT_IP: bool = True

    # DNS / cache
    dns_ttl: int = 3600

    #---- Risk weights (REQUIRED by RiskScorerAgent) ----
    w_header: float = 0.25
    w_content: float = 0.35
    w_domain: float = 0.25
    w_auth: float = 0.15

    # Thresholds
    risk_threshold: float = 0.6
    block_threshold: float = 0.8

    # Domain hygiene
    DENY_TLDS: Tuple[str, ...] = (".top", ".xyz", ".link")
    SHORTENER_HOSTS: Tuple[str, ...] = ("bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd")

    # Circuit breaker
    CB_FAILURE_THRESHOLD: int = 5
    CB_RESET_TIMEOUT_SEC: int = 60

# Singleton default policy
POLICY = SafetyPolicy()

# =========================
# PII Redaction & Sanitization
# =========================
EMAIL_RE = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
CC_RE = re.compile(r'\b(?:\d[ -]*?){13,19}\b')  # coarse; we redact anyway
PHONE_RE = re.compile(r'\+?\d[\d -]{7,}\d')

def redact_pii(text: str) -> str:
    if not text:
        return text
    s = text
    s = EMAIL_RE.sub("[email_redacted]", s)
    s = IP_RE.sub("[ip_redacted]", s)
    s = CC_RE.sub("[card_redacted]", s)
    s = PHONE_RE.sub("[phone_redacted]", s)
    return s

SCRIPT_TAG_RE = re.compile(r'(?is)<script.*?>.*?</script>')
STYLE_TAG_RE = re.compile(r'(?is)<style.*?>.*?</style>')
HTML_TAG_RE = re.compile(r'(?s)<[^>]+>')

def sanitize_text(text: str) -> str:
    """Strip scripts/HTML, collapse whitespace, unescape HTML entities."""
    if not text:
        return ""
    s = html.unescape(text)
    s = SCRIPT_TAG_RE.sub(" ", s)
    s = STYLE_TAG_RE.sub(" ", s)
    s = HTML_TAG_RE.sub(" ", s)
    s = re.sub(r'\s+', ' ', s).strip()
    return s

CONTROL_CHARS_RE = re.compile(r'[\x00-\x08\x0B\x0C\x0E-\x1F]')

def sanitize_header_value(v: str) -> str:
    if not v:
        return ""
    v = CONTROL_CHARS_RE.sub("", v)
    return v.strip()

def sanitize_headers(h: Dict[str, str]) -> Dict[str, str]:
    return {k: sanitize_header_value(str(v)) for k, v in (h or {}).items()}

# =========================
# Domain/URL Validation
# =========================
def is_punycode(host: str) -> bool:
    return "xn--" in (host or "").lower()

def is_shortener(host: str) -> bool:
    host = (host or "").lower()
    return any(host == sh or host.endswith("." + sh) for sh in POLICY.SHORTENER_HOSTS)

def risky_tld(host: str) -> bool:
    host = (host or "").lower()
    return any(host.endswith(tld) for tld in POLICY.DENY_TLDS)

def validate_url(u: str) -> bool:
    if not u:
        return False
    try:
        p = urlparse(u)
        if p.scheme not in ("http", "https"):
            return False
        if not p.netloc:
            return False
        return True
    except Exception:
        return False

def cap_list(items: List[Any], cap: int) -> List[Any]:
    return items[:cap] if items and cap > 0 else items or []

# =========================
# Safe HTTP Client (timeouts, retries, capped redirects)
# =========================
class SafeHTTPClient:
    def __init__(self, timeout_sec: int = POLICY.REQ_TIMEOUT_SEC, max_redirects: int = POLICY.MAX_REDIRECT_HOPS):
        self.timeout = timeout_sec
        self.max_redirects = max_redirects
        self.session = requests.Session()
        retry = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS")
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

    def get(self, url: str, **kwargs) -> requests.Response:
        if not validate_url(url):
            raise ValueError("invalid_url")
        resp = self.session.get(url, timeout=self.timeout, allow_redirects=True, **kwargs)
        # Cap redirect chain
        if len(resp.history) > self.max_redirects:
            raise RuntimeError(f"too_many_redirects({len(resp.history)})")
        # Cap download size defensively (if content-length present)
        cl = resp.headers.get("Content-Length")
        if cl and int(cl) > POLICY.TOTAL_DOWNLOAD_CAP_BYTES:
            raise RuntimeError("response_too_large")
        return resp

# =========================
# Circuit Breaker
# =========================
class CircuitBreaker:
    def __init__(self, failure_threshold: int = POLICY.CB_FAILURE_THRESHOLD, reset_timeout: int = POLICY.CB_RESET_TIMEOUT_SEC):
        self.failure_threshold = failure_threshold
        self.reset_timeout = reset_timeout
        self.fail_count = 0
        self.open_until = 0.0
        self._lock = threading.Lock()

    def allow(self) -> bool:
        with self._lock:
            now = time.time()
            if now < self.open_until:
                return False
            return True

    def record_success(self):
        with self._lock:
            self.fail_count = 0
            self.open_until = 0.0

    def record_failure(self):
        with self._lock:
            self.fail_count += 1
            if self.fail_count >= self.failure_threshold:
                self.open_until = time.time() + self.reset_timeout

# =========================
# Logging with redaction
# =========================
class RedactionFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact_pii(record.msg)
        elif isinstance(record.msg, (dict, list)):
            try:
                record.msg = redact_pii(json.dumps(record.msg, ensure_ascii=False))
            except Exception:
                record.msg = "[redacted]"
        return True

def setup_safe_logging(level=logging.INFO):
    logger = logging.getLogger()
    logger.setLevel(level)
    for h in logger.handlers:
        h.addFilter(RedactionFilter())
    if not logger.handlers:
        ch = logging.StreamHandler()
        ch.setLevel(level)
        ch.addFilter(RedactionFilter())
        fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
        ch.setFormatter(fmt)
        logger.addHandler(ch)
    return logger

# =========================
# Secrets management (env)
# =========================
def get_secret(name: str, required: bool = True, default: Optional[str] = None) -> Optional[str]:
    val = os.getenv(name, default)
    if required and not val:
        raise RuntimeError(f"missing_secret:{name}")
    return val

# =========================
# Fail-safe policy helpers
# =========================
def elevate_on_error(existing_risk: int, category: str, policy: SafetyPolicy = POLICY) -> int:
    """Elevate risk when critical dependencies fail, respecting policy."""
    inc = 0
    if category == "dns" and policy.ELEVATE_ON_DNS_FAILURE:
        inc = 15
    elif category == "vt" and policy.ELEVATE_ON_VT_FAILURE:
        inc = 15
    elif category == "whois" and policy.ELEVATE_ON_WHOIS_FAILURE:
        inc = 10
    return max(0, min(100, existing_risk + inc))

# =========================
# Reporter redaction helpers
# =========================
def redact_report_text(md: str) -> str:
    return redact_pii(md or "")

import time


class SimpleCache:
    def __init__(self, cfg):
        self.cfg = cfg
        self._store = {}

    def get(self, key):
        entry = self._store.get(key)
        if not entry:
            return None

        value, expires_at = entry
        if expires_at < time.time():
            del self._store[key]
            return None

        return value

    def set(self, key, value, ttl):
        expires_at = time.time() + ttl
        self._store[key] = (value, expires_at)

