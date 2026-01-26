from phishing_analyzer.detector import ContentAnalyzerAgent

def test_content_detects_phishing_language():
    body = "Urgent! Verify your password immediately."

    agent = ContentAnalyzerAgent()
    out = agent.run(body)

    assert out.risk > 0
    assert len(out.indicators) > 0
