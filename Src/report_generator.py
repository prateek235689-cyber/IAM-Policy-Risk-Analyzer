import json
from datetime import datetime, timezone
from pathlib import Path

from analyzer import analyze_file


def generate_report(policy_path, output_path):
    """Analyze an IAM policy and save findings as a JSON report."""
    policy_path = Path(policy_path)
    output_path = Path(output_path)

    findings = analyze_file(policy_path)

    high_count = sum(
        finding["severity"] == "HIGH" for finding in findings
    )
    medium_count = sum(
        finding["severity"] == "MEDIUM" for finding in findings
    )
    info_count = sum(
        finding["severity"] == "INFO" for finding in findings
    )

    report = {
        "report_title": "IAM Policy Risk Analysis Report",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "policy_file": policy_path.name,
        "summary": {
            "total_findings": len(findings),
            "high": high_count,
            "medium": medium_count,
            "info": info_count
        },
        "findings": findings,
        "disclaimer": (
            "This report uses educational, rule-based heuristics. "
            "It is not a complete AWS IAM security assessment, and "
            "the absence of findings does not prove a policy is secure."
        )
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    return report


if __name__ == "__main__":
    project_root = Path(__file__).resolve().parent.parent

    samples = [
        "broad_permissions_policy.json",
        "least_privilege_policy.json"
    ]

    for sample_name in samples:
        policy_path = project_root / "samples" / sample_name
        report_path = (
            project_root / "reports" /
            f"{policy_path.stem}_report.json"
        )

        report = generate_report(policy_path, report_path)

        print(f"\nReport generated: {report_path.name}")
        print(f"Total findings: {report['summary']['total_findings']}")
        print(f"HIGH: {report['summary']['high']}")
        print(f"MEDIUM: {report['summary']['medium']}")
        print(f"INFO: {report['summary']['info']}")
