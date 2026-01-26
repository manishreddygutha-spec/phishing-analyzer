"""
Optional CrewAI-based explanation layer.

Design rule:
- This module MUST NOT affect detection or scoring.
- If CrewAI is not installed, the explainer is skipped gracefully.
"""

from typing import Dict, Any

# CrewAI is OPTIONAL
try:
    from crewai import Agent, Task, Crew, Process
except ImportError:
    Agent = Task = Crew = Process = None


def run_crewai_explainer(report: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate an analyst-style explanation using CrewAI.

    If CrewAI is not installed, this function returns a skipped status
    without raising any errors.
    """

    if Agent is None:
        return {
            "status": "skipped",
            "reason": "CrewAI not installed",
        }

    analyst = Agent(
        role="SOC Security Analyst",
        goal="Explain why the email was classified with the given risk level",
        backstory=(
            "You are a senior SOC analyst experienced in phishing detection, "
            "email authentication failures, and social engineering tactics."
        ),
        verbose=False,
    )

    task = Task(
        description=(
            "Analyze the structured phishing detection report below and "
            "provide a clear explanation for both technical analysts and "
            "non-technical stakeholders.\n\n"
            f"Report:\n{report}"
        ),
        expected_output=(
            "A concise analyst explanation and an executive summary explaining "
            "the phishing risk and recommended action."
        ),
        agent=analyst,
    )

    crew = Crew(
        agents=[analyst],
        tasks=[task],
        process=Process.sequential,
        verbose=False,
    )

    result = crew.kickoff()

    return {
        "status": "success",
        "explanation": str(result),
    }
