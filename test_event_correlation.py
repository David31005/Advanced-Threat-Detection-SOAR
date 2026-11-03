import unittest
from datetime import datetime, timedelta

from event_correlation import correlate_events


BASE_TIME = datetime(2026, 11, 3, 12, 0, 0)


def make_event(seconds, ip, username, event_type):
    return {
        "timestamp": BASE_TIME + timedelta(seconds=seconds),
        "source_ip": ip,
        "username": username,
        "event_type": event_type
    }


class TestSecurityEventCorrelation(unittest.TestCase):

    def test_brute_force_detection(self):
        events = [
            make_event(i * 5, "192.0.2.10", "admin", "LOGIN_FAILED")
            for i in range(4)
        ]
        findings = correlate_events(events)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["finding_type"], "BRUTE_FORCE")
        self.assertEqual(findings[0]["severity"], "HIGH")
        self.assertEqual(findings[0]["risk_score"], 75)

    def test_brute_force_followed_by_success(self):
        events = [
            make_event(i * 5, "192.0.2.20", "admin", "LOGIN_FAILED")
            for i in range(4)
        ]
        events.append(
            make_event(20, "192.0.2.20", "admin", "LOGIN_SUCCESS")
        )
        findings = correlate_events(events)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["finding_type"], "BRUTE_FORCE_WITH_SUCCESS")
        self.assertEqual(findings[0]["severity"], "CRITICAL")
        self.assertEqual(findings[0]["risk_score"], 95)
        self.assertIn("T1078", findings[0]["mitre_attack"])

    def test_password_spraying(self):
        usernames = ["alice", "bob", "charlie", "diana", "eric"]
        events = [
            make_event(i * 6, "203.0.113.77", username, "LOGIN_FAILED")
            for i, username in enumerate(usernames)
        ]
        findings = correlate_events(events)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["finding_type"], "PASSWORD_SPRAYING")
        self.assertEqual(findings[0]["risk_score"], 85)
        self.assertEqual(len(findings[0]["accounts"]), 5)
        self.assertIn("T1110.003", findings[0]["mitre_attack"])

    def test_normal_activity(self):
        events = [
            make_event(0, "198.51.100.10", "employee1", "LOGIN_SUCCESS"),
            make_event(10, "198.51.100.11", "employee2", "LOGIN_SUCCESS"),
            make_event(20, "198.51.100.12", "employee3", "LOGIN_FAILED")
        ]
        findings = correlate_events(events)
        self.assertEqual(findings, [])

    def test_failures_outside_time_window(self):
        events = [
            make_event(0, "192.0.2.30", "admin", "LOGIN_FAILED"),
            make_event(70, "192.0.2.30", "admin", "LOGIN_FAILED"),
            make_event(140, "192.0.2.30", "admin", "LOGIN_FAILED"),
            make_event(210, "192.0.2.30", "admin", "LOGIN_FAILED")
        ]
        findings = correlate_events(events)
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
