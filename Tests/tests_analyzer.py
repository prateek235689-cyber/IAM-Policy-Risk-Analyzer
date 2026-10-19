import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from analyzer import analyze_policy


class TestIAMPolicyAnalyzer(unittest.TestCase):

    def test_detects_wildcard_action(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            }]
        }

        findings = analyze_policy(policy)
        issues = [finding["issue"] for finding in findings]

        self.assertIn("Wildcard action permission", issues)

    def test_detects_wildcard_resource(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*"
            }]
        }

        findings = analyze_policy(policy)
        issues = [finding["issue"] for finding in findings]

        self.assertIn("Wildcard resource permission", issues)

    def test_scoped_resource_wildcard_is_informational(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::example-training-bucket/*"
            }]
        }

        findings = analyze_policy(policy)
        scoped_findings = [
            finding for finding in findings
            if finding["issue"] == "Scoped resource wildcard"
        ]

        self.assertEqual(len(scoped_findings), 1)
        self.assertEqual(scoped_findings[0]["severity"], "INFO")

    def test_ignores_deny_statement(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*"
            }]
        }

        findings = analyze_policy(policy)

        self.assertEqual(findings[0]["issue"],
                         "No configured risk rules triggered")

    def test_invalid_policy_structure(self):
        findings = analyze_policy([])

        self.assertEqual(findings[0]["issue"],
                         "Invalid policy structure")

    def test_detects_sensitive_iam_permission(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "iam:PassRole",
                "Resource": "arn:aws:iam::123456789012:role/example-role"
            }]
        }

        findings = analyze_policy(policy)
        issues = [finding["issue"] for finding in findings]

        self.assertIn("Sensitive IAM permission", issues)


if __name__ == "__main__":
    unittest.main(verbosity=2)
