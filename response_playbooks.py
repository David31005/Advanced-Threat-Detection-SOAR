import json
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
INPUT_FILE = BASE_DIR / "incident_report.json"
OUTPUT_FILE = BASE_DIR / "response_report.json"


PLAYBOOKS = {
    "CRITICAL": [
        "Escalate incident to the security response team",
        "Review recent authentication and account activity",
        "Investigate whether the successful login was authorized",
        "Recommend session revocation after validation",
        "Request analyst approval before containment"
    ],
    "HIGH": [
        "Investigate the source IP and authentication timeline",
        "Review related failed login events",
        "Check for additional suspicious account activity",
        "Recommend temporary restrictions if justified",
        "Document findings for analyst review"
    ]
}


def execute_playbooks(incidents):
    responses = []

    for incident in incidents:
        severity = incident.get("severity", "UNKNOWN").upper()
        actions = PLAYBOOKS.get(
            severity,
            ["Refer incident for manual security review"]
        )

        responses.append({
            "incident_id": incident.get("incident_id"),
            "severity": severity,
            "source_ip": incident.get("source_ip"),
            "username": incident.get("username"),
            "playbook": f"{severity}_INCIDENT_RESPONSE",
            "recommended_actions": actions,
            "containment_executed": False,
            "approval_required": True,
            "response_status": "PENDING_ANALYST_REVIEW"
        })

    return responses


def main():
    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            "incident_report.json not found. Run soar_engine.py first."
        )

    with INPUT_FILE.open(encoding="utf-8") as file:
        report = json.load(file)

    responses = execute_playbooks(report["incidents"])

    output = {
        "project": "Advanced SOAR Automated Response Simulation",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "simulation_only": True,
        "total_responses": len(responses),
        "responses": responses
    }

    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        json.dump(output, file, indent=2)

    print("=== SOAR RESPONSE PLAYBOOK ENGINE ===")
    print(f"Playbooks generated: {len(responses)}")

    for response in responses:
        print(
            f"[{response['severity']}] "
            f"{response['incident_id']} | "
            f"{response['playbook']}"
        )

    print("Response report saved: response_report.json")


if __name__ == "__main__":
    main()
