import csv
import json
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
INPUT_FILE = BASE_DIR / "security_events.csv"
OUTPUT_FILE = BASE_DIR / "correlation_report.json"

TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
WINDOW = timedelta(seconds=60)
BRUTE_FORCE_THRESHOLD = 4
SPRAY_ACCOUNT_THRESHOLD = 3


def load_events(path=INPUT_FILE):
    events = []

    with path.open(newline="", encoding="utf-8-sig") as file:
        reader = csv.DictReader(file)
        required = {"timestamp", "source_ip", "username", "event_type"}

        if not required.issubset(reader.fieldnames or []):
            raise ValueError("Missing required CSV columns")

        for row in reader:
            try:
                event = {
                    "timestamp": datetime.strptime(
                        row["timestamp"].strip(), TIME_FORMAT
                    ),
                    "source_ip": row["source_ip"].strip(),
                    "username": row["username"].strip(),
                    "event_type": row["event_type"].strip().upper()
                }
                if not event["source_ip"] or not event["username"]:
                    continue
                events.append(event)
            except (ValueError, KeyError, AttributeError):
                print("Skipping invalid event")

    return sorted(events, key=lambda e: e["timestamp"])


def build_finding(kind, severity, score, ip, accounts, start, end, mitre):
    return {
        "finding_type": kind,
        "severity": severity,
        "risk_score": score,
        "source_ip": ip,
        "accounts": sorted(accounts),
        "first_seen": start.isoformat(),
        "last_seen": end.isoformat(),
        "mitre_attack": mitre,
        "status": "PENDING_ANALYST_REVIEW"
    }


def correlate_events(events):
    findings = []
    by_account = defaultdict(list)
    by_ip = defaultdict(list)

    for event in events:
        by_account[(event["source_ip"], event["username"])].append(event)
        by_ip[event["source_ip"]].append(event)

    # Rule 1: Brute-force and success correlation
    for (ip, username), records in by_account.items():
        failures = [
            e for e in records if e["event_type"] == "LOGIN_FAILED"
        ]

        for i in range(len(failures) - BRUTE_FORCE_THRESHOLD + 1):
            window = failures[i:i + BRUTE_FORCE_THRESHOLD]
            if window[-1]["timestamp"] - window[0]["timestamp"] > WINDOW:
                continue

            last_failure = window[-1]["timestamp"]
            success = any(
                e["event_type"] == "LOGIN_SUCCESS"
                and last_failure < e["timestamp"] <= last_failure + WINDOW
                for e in records
            )

            findings.append(build_finding(
                "BRUTE_FORCE_WITH_SUCCESS" if success else "BRUTE_FORCE",
                "CRITICAL" if success else "HIGH",
                95 if success else 75,
                ip,
                [username],
                window[0]["timestamp"],
                last_failure,
                ["T1110", "T1078"] if success else ["T1110"]
            ))
            break

    # Rule 2: Password spraying across multiple accounts
    for ip, records in by_ip.items():
        failures = [
            e for e in records if e["event_type"] == "LOGIN_FAILED"
        ]

        for i, start_event in enumerate(failures):
            end_time = start_event["timestamp"] + WINDOW
            window = [
                e for e in failures[i:]
                if e["timestamp"] <= end_time
            ]
            accounts = {e["username"] for e in window}

            if len(accounts) >= SPRAY_ACCOUNT_THRESHOLD:
                findings.append(build_finding(
                    "PASSWORD_SPRAYING",
                    "HIGH",
                    85,
                    ip,
                    accounts,
                    start_event["timestamp"],
                    window[-1]["timestamp"],
                    ["T1110.003"]
                ))
                break

    findings.sort(
        key=lambda f: (-f["risk_score"], f["source_ip"])
    )

    for index, finding in enumerate(findings, start=1):
        finding["finding_id"] = f"CORR-{index:04d}"

    return findings


def main():
    events = load_events()
    findings = correlate_events(events)

    report = {
        "project": "Advanced SOAR Event Correlation",
        "simulation_only": True,
        "total_events": len(events),
        "total_findings": len(findings),
        "findings": findings
    }

    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)

    print("=== SECURITY EVENT CORRELATION ===")
    print(f"Events analyzed: {len(events)}")
    print(f"Correlated findings: {len(findings)}")

    for finding in findings:
        print(
            f"[{finding['severity']}] "
            f"{finding['finding_type']} | "
            f"{finding['source_ip']} | "
            f"Risk: {finding['risk_score']}"
        )

    print("Report saved: correlation_report.json")


if __name__ == "__main__":
    main()
