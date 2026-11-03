import csv
import json
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = BASE_DIR / "security_events.csv"
REPORT_FILE = BASE_DIR / "incident_report.json"

FAILED_LOGIN_THRESHOLD = 4
WINDOW_SECONDS = 60


def load_events(path=LOG_FILE):
    events = []
    with open(path, newline="", encoding="utf-8-sig") as file:
        reader = csv.DictReader(file)
        required = {"timestamp", "source_ip", "username", "event_type"}

        if not required.issubset(reader.fieldnames or []):
            raise ValueError("CSV is missing required columns")

        for row in reader:
            try:
                event = {
                    "timestamp": datetime.strptime(
                        row["timestamp"].strip(),
                        "%Y-%m-%d %H:%M:%S"
                    ),
                    "source_ip": row["source_ip"].strip(),
                    "username": row["username"].strip(),
                    "event_type": row["event_type"].strip().upper()
                }
                if not event["source_ip"] or not event["username"]:
                    raise ValueError("Missing IP or username")
                events.append(event)
            except (ValueError, AttributeError, KeyError):
                print("Skipping invalid security event")

    return sorted(events, key=lambda e: e["timestamp"])


def detect_threats(events):
    groups = defaultdict(list)

    for event in events:
        key = (event["source_ip"], event["username"])
        groups[key].append(event)

    incidents = []

    for (ip, username), records in groups.items():
        records = sorted(records, key=lambda e: e["timestamp"])
        failures = [
            e for e in records
            if e["event_type"] == "LOGIN_FAILED"
        ]

        for i in range(len(failures) - FAILED_LOGIN_THRESHOLD + 1):
            window = failures[i:i + FAILED_LOGIN_THRESHOLD]
            duration = (
                window[-1]["timestamp"] - window[0]["timestamp"]
            ).total_seconds()

            if duration > WINDOW_SECONDS:
                continue

            last_failure = window[-1]["timestamp"]
            success = any(
                e["event_type"] == "LOGIN_SUCCESS"
                and last_failure < e["timestamp"]
                <= last_failure + timedelta(seconds=WINDOW_SECONDS)
                for e in records
            )

            critical = bool(success)
            incidents.append({
                "incident_id": f"INC-{len(incidents) + 1:04d}",
                "type": (
                    "BRUTE_FORCE_WITH_SUCCESS"
                    if critical else "BRUTE_FORCE_ATTEMPT"
                ),
                "severity": "CRITICAL" if critical else "HIGH",
                "risk_score": 95 if critical else 75,
                "source_ip": ip,
                "username": username,
                "first_seen": window[0]["timestamp"].isoformat(),
                "last_seen": window[-1]["timestamp"].isoformat(),
                "mitre_attack": (
                    ["T1110", "T1078"] if critical else ["T1110"]
                ),
                "recommended_actions": [
                    "Review related authentication events",
                    "Verify whether the login was authorized",
                    "Investigate recent account activity",
                    "Consider account restrictions after validation",
                    "Escalate to an incident response analyst"
                ],
                "response_status": "PENDING_ANALYST_REVIEW"
            })
            break

    return incidents


def generate_report(events, incidents):
    report = {
        "project": "Advanced Threat Detection and SOAR Simulation",
        "total_events": len(events),
        "total_incidents": len(incidents),
        "simulation_only": True,
        "incidents": incidents
    }

    with REPORT_FILE.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)

    return report


def main():
    events = load_events()
    incidents = detect_threats(events)
    report = generate_report(events, incidents)

    print("=== ADVANCED SOAR SECURITY ENGINE ===")
    print(f"Events analyzed: {report['total_events']}")
    print(f"Incidents detected: {report['total_incidents']}")

    for incident in incidents:
        print(
            f"[{incident['severity']}] "
            f"{incident['type']} | "
            f"{incident['source_ip']} | "
            f"{incident['username']}"
        )

    print("Incident report saved: incident_report.json")


if __name__ == "__main__":
    main()
