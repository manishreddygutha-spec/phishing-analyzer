from phishing_analyzer.detector import EmailIngestionAgent

def test_email_ingestion_basic(tmp_path):
    eml = tmp_path / "test.eml"
    eml.write_text(
        "From: test@example.com\n"
        "To: user@test.com\n"
        "Subject: Test\n\n"
        "Hello world"
    )

    agent = EmailIngestionAgent()
    out = agent.parse_eml_path(str(eml))

    assert out.from_email == "test@example.com"
    assert out.from_domain == "example.com"
    assert "Hello world" in out.body_text
