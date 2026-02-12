"""
Human-in-the-loop Agent
Allows analyst validation before final output.
"""

class HumanReviewAgent:

    def review(self, risk_out, report_text: str):
        print("\n=========== HUMAN REVIEW REQUIRED ===========")
        print(f"Risk Score : {risk_out.score}")
        print(f"Severity   : {risk_out.severity}")
        print(f"AI Action  : {risk_out.action}")
        print("============================================")

        try:
            decision = input(
                "\nHuman decision (approve/block/escalate) [default=approve]: "
            ).strip().lower()

            if decision == "":
                decision = "approve"

        except Exception:
            decision = "approve"

        print(f"\nHuman decision recorded: {decision}")

        return {
            "human_decision": decision,
            "final_action": decision.upper()
        }
