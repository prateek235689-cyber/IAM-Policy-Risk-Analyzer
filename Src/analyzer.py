import json
from pathlib import Path


def analyze_policy(policy):
    """Analyze an IAM policy and return potential security findings."""
    findings = []

    if not isinstance(policy, dict):
        return [{
            "severity": "HIGH",
            "issue": "Invalid policy structure",
            "details": "The policy must be a JSON object.",
            "recommendation": "Provide a valid IAM policy document."
        }]

    statements = policy.get("Statement", [])

    if isinstance(statements, dict):
        statements = [statements]

    if not isinstance(statements, list):
        return [{
            "severity": "HIGH",
            "issue": "Invalid Statement structure",
            "details": "Statement must be an object or a list of objects.",
            "recommendation": "Correct the Statement structure and analyze again."
        }]

    for index, statement in enumerate(statements, start=1):
        if not isinstance(statement, dict):
            findings.append({
                "severity": "HIGH",
                "issue": "Invalid policy statement",
                "details": f"Statement {index} is not a JSON object.",
                "recommendation": "Review and correct this statement."
            })
            continue

        effect = statement.get("Effect")
        actions = statement.get("Action", [])
        resources = statement.get("Resource", [])

        if effect != "Allow":
            continue

        if isinstance(actions, str):
            actions = [actions]

        if isinstance(resources, str):
            resources = [resources]

        if not isinstance(actions, list) or not isinstance(resources, list):
            findings.append({
                "severity": "HIGH",
                "issue": "Invalid Action or Resource",
                "details": (
                    f"Statement {index} has an invalid Action "
                    "or Resource value."
                ),
                "recommendation": (
                    "Use a string or list of strings for Action and Resource."
                )
            })
            continue

        if any(
            not isinstance(item, str)
            for item in actions + resources
        ):
            findings.append({
                "severity": "HIGH",
                "issue": "Invalid Action or Resource entry",
                "details": (
                    f"Statement {index} contains a non-string entry."
                ),
                "recommendation": (
                    "Review all Action and Resource entries."
                )
            })
            continue

        # Check for broad action permissions.
        if "*" in actions:
            findings.append({
                "severity": "HIGH",
                "issue": "Wildcard action permission",
                "details": (
                    f"Statement {index} allows all actions "
                    "through Action: '*'."
                ),
                "recommendation": (
                    "Replace the wildcard with only the actions required."
                )
            })

        elif any("*" in action for action in actions):
            findings.append({
                "severity": "MEDIUM",
                "issue": "Wildcard in action name",
                "details": (
                    f"Statement {index} contains a wildcard "
                    "in an action pattern."
                ),
                "recommendation": (
                    "Review the action pattern and narrow permissions "
                    "where possible."
                )
            })

        # Check resource scope separately from action scope.
        if "*" in resources:
            findings.append({
                "severity": "HIGH",
                "issue": "Wildcard resource permission",
                "details": (
                    f"Statement {index} applies to all resources."
                ),
                "recommendation": (
                    "Restrict the resource scope to the required resource ARNs."
                )
            })

        elif any("*" in resource for resource in resources):
            findings.append({
                "severity": "INFO",
                "issue": "Scoped resource wildcard",
                "details": (
                    f"Statement {index} uses a wildcard within a resource "
                    "pattern. This may be appropriate for object-level access "
                    "but requires review."
                ),
                "recommendation": (
                    "Verify that the ARN scope matches the intended resources "
                    "and that the allowed actions are appropriate."
                )
            })

        # Flag selected sensitive IAM permissions.
        normalized_actions = [
            action.lower() for action in actions
        ]

        if any(
            action in ("iam:passrole", "iam:*")
            for action in normalized_actions
        ):
            findings.append({
                "severity": "HIGH",
                "issue": "Sensitive IAM permission",
                "details": (
                    f"Statement {index} includes IAM PassRole "
                    "or IAM wildcard access."
                ),
                "recommendation": (
                    "Review the required IAM actions and limit them "
                    "to specific roles and tasks."
                )
            })

    if not findings:
        findings.append({
            "severity": "INFO",
            "issue": "No configured risk rules triggered",
            "details": (
                "The analyzer did not detect any of its currently "
                "configured patterns."
            ),
            "recommendation": (
                "Continue reviewing the policy in context; this result "
                "does not prove it is secure."
            )
        })

    return findings


def analyze_file(file_path):
    """Load and analyze a policy file."""
    path = Path(file_path)

    try:
        with path.open("r", encoding="utf-8") as file:
            policy = json.load(file)

    except FileNotFoundError:
        return [{
            "severity": "HIGH",
            "issue": "Policy file not found",
            "details": f"Could not find: {path}",
            "recommendation": "Check the file path and try again."
        }]

    except json.JSONDecodeError as error:
        return [{
            "severity": "HIGH",
            "issue": "Invalid JSON",
            "details": f"JSON parsing failed: {error}",
            "recommendation": (
                "Correct the JSON syntax and analyze again."
            )
        }]

    except OSError as error:
        return [{
            "severity": "HIGH",
            "issue": "File access error",
            "details": str(error),
            "recommendation": (
                "Check file permissions and ensure the file is accessible."
            )
        }]

    return analyze_policy(policy)


if __name__ == "__main__":
    project_root = Path(__file__).resolve().parent.parent

    sample_files = [
        project_root / "samples" / "broad_permissions_policy.json",
        project_root / "samples" / "least_privilege_policy.json",
    ]

    for sample_file in sample_files:
        print("\n" + "=" * 65)
        print(f"Analyzing: {sample_file.name}")
        print("=" * 65)

        findings = analyze_file(sample_file)

        for finding in findings:
            print(f"[{finding['severity']}] {finding['issue']}")
            print(f"Details: {finding['details']}")
            print(
                f"Recommendation: {finding['recommendation']}"
            )
            print("-" * 65)
