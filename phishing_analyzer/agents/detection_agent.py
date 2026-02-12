"""
Detection Agent
Responsible for full phishing technical analysis.
"""

from phishing_analyzer.detector import (
    HeaderAnalyzerAgent,
    ContentAnalyzerAgent,
    DomainCheckerAgent,
    SPFDMARCDKIMAgent,
    DNSChecker,
    WhoisTool,
)
from phishing_analyzer.guardrails import POLICY, SimpleCache


class DetectionAgent:
    """
    Multi-stage phishing detection agent.
    """

    def run(self, email):
        header_out = HeaderAnalyzerAgent().run(email.raw_headers)
        content_out = ContentAnalyzerAgent().run(email)

        # Domain analysis
        whois_cache = SimpleCache(POLICY)
        whois_tool = WhoisTool(cache=whois_cache)
        domain_out = DomainCheckerAgent().run(
            email.from_domain,
            whois_tool,
            POLICY
        )

        # Auth analysis
        dns_cache = SimpleCache(POLICY)
        dns_checker = DNSChecker(dns_cache)
        auth_agent = SPFDMARCDKIMAgent(dns_checker)
        auth_out = auth_agent.run(email.from_domain, header_out)

        return {
            "header": header_out,
            "content": content_out,
            "domain": domain_out,
            "auth": auth_out
        }
