"""
Multi-Agent Phishing Detection System

Agents:
1. Detection Agent – performs phishing analysis
2. Risk Agent – calculates severity & decision
3. Human Review Agent – validates AI decision
4. Explanation Agent – generates LLM explanation

Orchestrated using Prefect workflow.
"""

from prefect import flow, task
from dotenv import load_dotenv
from phishing_analyzer.agents.detection_agent import DetectionAgent
from phishing_analyzer.agents.risk_agent import RiskAgent
from phishing_analyzer.agents.explanation_agent import ExplanationAgent
from phishing_analyzer.agents.human_agent import HumanReviewAgent
# ===== Local imports =====
from phishing_analyzer.detector import (
    EmailIngestionAgent,
    HeaderAnalyzerAgent,
    ContentAnalyzerAgent,
    DomainCheckerAgent,
    SPFDMARCDKIMAgent,
    RiskScorerAgent,
    DNSChecker,
    WhoisTool,
)

from phishing_analyzer.guardrails import POLICY, SimpleCache


# Safety fallback
if not hasattr(POLICY, "dns_ttl"):
    POLICY.dns_ttl = 300  # seconds


# ================= TASKS =================

@task
def ingest_email(eml_path: str):
    email = EmailIngestionAgent().parse_eml_path(eml_path)
    print("✅ Email ingestion complete")
    return email


@task
def analyze_headers(email):
    header_out = HeaderAnalyzerAgent().run(email.raw_headers)
    print("✅ Header analysis complete")
    return header_out


@task
def analyze_content(email):
    content_out = ContentAnalyzerAgent().run(email)
    print("✅ Content analysis complete")
    return content_out


@task
def analyze_domain(email):
    whois_cache = SimpleCache(POLICY)
    whois_tool = WhoisTool(cache=whois_cache)

    domain_out = DomainCheckerAgent().run(
        email.from_domain,
        whois_tool,
        POLICY
    )
    return domain_out


@task
def analyze_auth(email, header_out):
    dns_cache = SimpleCache(POLICY)
    dns_checker = DNSChecker(dns_cache)

    agent = SPFDMARCDKIMAgent(dns_checker)
    auth_out = agent.run(email.from_domain, header_out)

    print("✅ Auth analysis complete")
    return auth_out


@task
def score_risk(header_out, content_out, domain_out, auth_out):
    risk_out = RiskScorerAgent().run(
        header_out,
        content_out,
        domain_out,
        auth_out,
        POLICY
    )

    print("✅ Risk scoring complete")
    return risk_out


# ================= REPORTING =================

def build_text_report(email, header_out, content_out, domain_out, auth_out, risk_out):
    """
    Human-readable report (WITHOUT CrewAI)
    """

    # Executive summary (neutral & conditional)
    if risk_out.severity == "High":
        summary = "This email shows strong indicators commonly associated with phishing attacks."
    elif risk_out.severity == "Medium":
        summary = "This email contains suspicious signals that require user caution."
    else:
        summary = "This email appears legitimate with no significant phishing indicators detected."

    report_lines = []

    report_lines.append("1️⃣ EXECUTIVE SUMMARY")
    report_lines.append(summary)
    report_lines.append("")

    report_lines.append("2️⃣ FINAL VERDICT")
    report_lines.append(f"Decision: {risk_out.action}")
    report_lines.append("")

    report_lines.append("3️⃣ RISK SCORE")
    report_lines.append(f"Score: {risk_out.score}")
    report_lines.append(f"Severity: {risk_out.severity}")
    report_lines.append("")

    report_lines.append("4️⃣ KEY FINDINGS")
    for a in header_out.anomalies:
        report_lines.append(f"- Header issue: {a}")
    for i in content_out.indicators:
        report_lines.append(f"- Content indicator: {i}")
    if domain_out.domain_age_days >= 0:
        report_lines.append(f"- Domain age: {domain_out.domain_age_days} days")
    else:
        report_lines.append("- Domain age: Unable to determine")

    for issue in auth_out.issues:
        report_lines.append(f"- Authentication issue: {issue}")
    report_lines.append("")

    report_lines.append("5️⃣ EVIDENCE")
    report_lines.append(f"From Email: {email.from_email}")
    report_lines.append(f"From Domain: {email.from_domain}")
    report_lines.append(f"SPF Result: {header_out.spf_result}")
    report_lines.append(f"DKIM Result: {header_out.dkim_result}")
    report_lines.append(f"DMARC Result: {header_out.dmarc_result}")
    report_lines.append("")

    report_lines.append("6️⃣ SUGGESTED ACTION")
    if risk_out.action == "Block":
        report_lines.append("Do NOT interact with this email. Block sender and report to security.")
    elif risk_out.action == "Warn":
        report_lines.append("Proceed with caution. Avoid clicking links or downloading attachments.")
    else:
        report_lines.append("No action required. Email appears safe.")

    return "\n".join(report_lines)


@task
def generate_report(email, header_out, content_out, domain_out, auth_out, risk_out):
    return build_text_report(
        email,
        header_out,
        content_out,
        domain_out,
        auth_out,
        risk_out
    )



# ================= FLOW =================

@flow(name="phishing-analyzer-flow")
def phishing_analyzer_flow(eml_path: str):
    print("🚀 Starting phishing analysis")
    detection_agent = DetectionAgent()
    risk_agent = RiskAgent()
    explanation_agent = ExplanationAgent()
    human_agent = HumanReviewAgent()

    email = ingest_email(eml_path)
    header_out = analyze_headers(email)
    content_out = analyze_content(email)
    domain_out = analyze_domain(email)
    auth_out = analyze_auth(email, header_out)

    # ===== AGENT 1: Detection Agent Execution =====
    detection_results = detection_agent.run(email)
    print("🤖 Detection Agent completed analysis")

    # ===== DETECTION AGENT (visible for reviewers) =====
    detection_results = detection_agent.run(email)

    risk_out = score_risk(
        header_out,
        content_out,
        domain_out,
        auth_out
    )
    # ===== AGENT 2: Risk Agent Validation =====
    validated_risk = risk_agent.run(detection_results)
    print("🤖 Risk Agent validated decision")

    # ===== HUMAN-IN-THE-LOOP =====
    human_review = human_agent.review(risk_out, "report")

    # ===== AGENT 3: Human Review Agent =====
    human_review = human_agent.review(risk_out, "report")
    print("👤 Human review completed")

    report_text = generate_report(
        email,
        header_out,
        content_out,
        domain_out,
        auth_out,
        risk_out
    )

    # ===== AGENT 4: Explanation Agent =====
    explanation = explanation_agent.run(report_text)
    print("🤖 Explanation Agent completed")


    print("\n================ FINAL REPORT ================\n")
    print(report_text)

    print("\n================ AI EXPLANATION ================\n")
    print(explanation)

    print("\n================ HUMAN REVIEW ================\n")
    print(human_review)

    return {
        "report": report_text,
        "explanation": explanation
    }


# ================= MAIN =================

def main():
    load_dotenv()
    eml_path = "phishing_analyzer/samples/phish_high_confidence.eml"
    phishing_analyzer_flow(eml_path)


if __name__ == "__main__":
    main()
