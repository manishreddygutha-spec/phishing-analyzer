from phishing_analyzer.detector import DomainCheckerAgent, RiskConfig

class FakeWhoisTool:
    def lookup(self, domain):
        return {"unavailable": True}

def test_domain_analysis_whois_unavailable():
    agent = DomainCheckerAgent()
    cfg = RiskConfig()

    out = agent.run("example.com", FakeWhoisTool(), cfg)

    assert out.risk > 0
