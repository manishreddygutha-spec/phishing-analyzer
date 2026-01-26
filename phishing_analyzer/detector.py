import re
import time
import hashlib
import requests
import dns.resolver
import whois

from dataclasses import dataclass
from typing import List, Tuple
from datetime import datetime, timezone
from email.utils import parseaddr
from urllib.parse import urlparse

from .guardrails import (
    POLICY,
    SafeHTTPClient,
    sanitize_text,
    sanitize_headers,
    cap_list,
    validate_url,
    elevate_on_error,
    redact_report_text,
)

# =========================================================
# Utility
# =========================================================

def clamp(x, lo=0, hi=100):
    return max(lo, min(hi, x))


# =========================================================
# Risk Config
# =========================================================

@dataclass
class RiskConfig:
    w_header: float = 0.30
    w_content: float = 0.25
    w_domain: float = 0.30
    w_auth: float = 0.15
    block_threshold: int = 85
    quarantine_threshold: int = 70
    flag_threshold: int = 50
    recent_domain_days: int = 30


# =========================================================
# Cache (Memory Only)
# =========================================================

@dataclass
class CacheConfig:
    default_ttl: int = 3600
    vt_ttl: int = 12 * 3600
    talos_ttl: int = 12 * 3600
    whois_ttl: int = 24 * 3600
    dns_ttl: int = 6 * 3600


class Cache:
    def __init__(self, cfg: CacheConfig):
        self.cfg = cfg
        self._store = {}
        self._expiry = {}

    def get(self, key: str):
        now = time.time()
        if key in self._store and self._expiry.get(key, 0) > now:
            return self._store[key]
        self._store.pop(key, None)
        self._expiry.pop(key, None)
        return None

    def set(self, key: str, value, ttl: int):
        self._store[key] = value
        self._expiry[key] = time.time() + ttl


# =========================================================
# Email Ingestion
# =========================================================

import email
from email import policy
from email.parser import BytesParser


@dataclass
class IngestionOutput:
    raw_headers: str
    headers: dict
    body_text: str
    urls: List[str]
    attachments: List[Tuple[str, bytes]]
    from_email: str
    from_domain: str


class EmailIngestionAgent:
    def parse_eml_path(self, path: str) -> IngestionOutput:
        with open(path, "rb") as f:
            msg = BytesParser(policy=policy.default).parsebytes(f.read())

        headers = sanitize_headers(dict(msg.items()))
        raw_headers = "\n".join(f"{k}: {v}" for k, v in msg.items())

        _, from_email = parseaddr(headers.get("From", ""))
        from_domain = from_email.split("@")[-1].lower() if "@" in from_email else ""

        body, attachments = "", []

        if msg.is_multipart():
            for part in msg.walk():
                disp = (part.get("Content-Disposition") or "").lower()
                if part.get_content_type() == "text/plain" and "attachment" not in disp:
                    body += part.get_content()
                elif "attachment" in disp:
                    attachments.append((part.get_filename(), part.get_payload(decode=True)))
        else:
            body = msg.get_content()

        body = sanitize_text(body)
        urls = cap_list(
            [u for u in re.findall(r"https?://[^\s]+", body) if validate_url(u)],
            POLICY.MAX_URLS_PER_EMAIL
        )

        return IngestionOutput(
            raw_headers, headers, body, urls, attachments, from_email, from_domain
        )


# =========================================================
# Header Analyzer
# =========================================================

@dataclass
class HeaderOutput:
    from_email: str
    from_domain: str
    spf_result: str
    dkim_result: str
    dmarc_result: str
    anomalies: List[str]
    risk: int


class HeaderAnalyzerAgent:
    def run(self, raw_headers: str) -> HeaderOutput:
        headers = {}
        for l in raw_headers.splitlines():
            if ":" in l:
                k, v = l.split(":", 1)
                headers[k.lower()] = v.strip()

        anomalies, risk = [], 0

        from_header = headers.get("from", "")
        return_path = headers.get("return-path", "")

        _, from_email = parseaddr(from_header)
        from_domain = from_email.split("@")[-1] if "@" in from_email else ""

        spf = headers.get("received-spf", "unknown")
        dkim = headers.get("dkim-signature", "missing")
        dmarc = headers.get("authentication-results", "unknown")

        if return_path and from_domain not in return_path:
            anomalies.append("From/Return-Path mismatch")
            risk += 20
        if "fail" in spf.lower():
            anomalies.append("SPF failed")
            risk += 25
        if "dmarc=fail" in dmarc.lower():
            anomalies.append("DMARC failed")
            risk += 25

        return HeaderOutput(from_email, from_domain, spf, dkim, dmarc, anomalies, clamp(risk))


# =========================================================
# Content Analyzer
# =========================================================

@dataclass
class ContentOutput:
    indicators: List[str]
    risk: int


class ContentAnalyzerAgent:
    def run(self, email):
        # Runtime validation (early, explicit)
        if not hasattr(email, "body_text"):
            raise TypeError(
                f"ContentAnalyzerAgent expected IngestionOutput with body_text, "
                f"got {type(email).__name__}"
            )

        body = email.body_text or ""

        indicators = []
        risk = 0

        if re.search(r"urgent|verify|password|login|reset|suspended", body, re.I):
            indicators.append("Urgent or credential-harvesting language detected")
            risk += 40

        if email.urls:
            indicators.append("Contains URLs in body")
            risk += 20

        return ContentOutput(
            indicators=indicators,
            risk=min(risk, 100)
        )

# =========================================================
# DNS Checker
# =========================================================

class DNSChecker:
    def __init__(self, cache: Cache):
        self.cache = cache

    def _query(self, name, rtype):
        key = f"dns:{rtype}:{name}"
        cached = self.cache.get(key)
        if cached is not None:
            return cached
        try:
            ans = [str(r) for r in dns.resolver.resolve(name, rtype, lifetime=5)]
        except Exception:
            ans = None
        self.cache.set(key, ans, self.cache.cfg.dns_ttl)
        return ans

    def has_mx(self, domain): return bool(self._query(domain, "MX"))
    def has_spf(self, domain):
        return any("v=spf1" in r.lower() for r in (self._query(domain, "TXT") or []))
    def has_dmarc(self, domain):
        return any("v=dmarc1" in r.lower() for r in (self._query(f"_dmarc.{domain}", "TXT") or []))


# =========================================================
# SPF / DMARC / DKIM Agent (FIXES YOUR ERROR)
# =========================================================

@dataclass
class SPFDMARCDKIMOutput:
    spf_present: bool
    dmarc_present: bool
    dkim_present: bool
    risk: int
    issues: List[str]


class SPFDMARCDKIMAgent:
    def __init__(self, dns_checker: DNSChecker):
        self.dns = dns_checker

    def run(self, domain: str, header_out: HeaderOutput) -> SPFDMARCDKIMOutput:
        issues, risk = [], 0

        spf = self.dns.has_spf(domain)
        dmarc = self.dns.has_dmarc(domain)
        dkim = header_out.dkim_result not in ("missing", "", None)

        if not spf:
            issues.append("SPF missing")
            risk += 15
        if not dmarc:
            issues.append("DMARC missing")
            risk += 15
        if not dkim:
            issues.append("DKIM missing")
            risk += 20

        return SPFDMARCDKIMOutput(spf, dmarc, dkim, clamp(risk), issues)


# =========================================================
# Domain Analyzer (WHOIS only – VT/Talos optional)
# =========================================================

@dataclass
class DomainOutput:
    domain_age_days: int
    risk: int


class DomainCheckerAgent:
    def run(self, domain, whois_tool, cfg: RiskConfig):
        risk, age_days = 0, -1
        res = whois_tool.lookup(domain)
        if not res.get("unavailable") and res.get("creation_date"):
            created = res["creation_date"]
            if isinstance(created, list):
                created = created[0]
            if created and created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - created).days
            if age_days < cfg.recent_domain_days:
                risk += 25
        else:
            risk = elevate_on_error(risk, "whois")
        return DomainOutput(age_days, clamp(risk))


# =========================================================
# WHOIS Tool
# =========================================================

class WhoisTool:
    def __init__(self, cache: Cache):
        self.cache = cache

    def lookup(self, domain):
        key = f"whois:{domain}"
        cached = self.cache.get(key)
        if cached is not None:
            return cached
        try:
            w = whois.whois(domain)
            result = {"creation_date": w.creation_date}
        except Exception as e:
            result = {"unavailable": True, "error": str(e)}
        self.cache.set(key, result, self.cache.cfg.whois_ttl)
        return result


# =========================================================
# Risk Scorer
# =========================================================

@dataclass
class RiskOutput:
    score: int
    severity: str
    action: str


class RiskScorerAgent:
    def run(self, header, content, domain, auth, cfg: RiskConfig):
        score = (
            header.risk * cfg.w_header +
            content.risk * cfg.w_content +
            domain.risk * cfg.w_domain +
            auth.risk * cfg.w_auth
        )

        if score >= cfg.block_threshold:
            return RiskOutput(int(score), "High", "Block")
        if score >= cfg.quarantine_threshold:
            return RiskOutput(int(score), "Medium", "Quarantine")
        if score >= cfg.flag_threshold:
            return RiskOutput(int(score), "Low", "Flag")
        return RiskOutput(int(score), "Info", "Allow")


# =========================================================
# Reporter
# =========================================================

class ReporterAgent:
    def run(self, risk: RiskOutput, auth: SPFDMARCDKIMOutput) -> str:
        lines = [
            "# Phishing Analysis Report",
            f"Score: {risk.score}",
            f"Severity: {risk.severity}",
            f"Action: {risk.action}",
            "",
            "## Authentication Findings",
        ]
        for i in auth.issues:
            lines.append(f"- {i}")
        return redact_report_text("\n".join(lines))
