# IAM Policy Risk Analyzer
A Python-based Cloud Security project that analyzes AWS IAM policy JSON documents to identify potentially risky permission patterns, generate structured security findings, and produce JSON analysis reports.

## Project Overview:
AWS Identity and Access Management (IAM) controls access to AWS resources. Overly broad permissions can increase the risk of unauthorized access and privilege misuse.
The **IAM Policy Risk Analyzer** is an educational, rule-based security tool designed to help identify selected IAM policy risks before policies are considered for use. It evaluates policy statements, reports configured risk patterns, and provides recommendations to encourage least-privilege access.
The project uses synthetic IAM policy examples and runs locally. It does not require deployment to AWS or access to a live AWS account.

## Objectives:
- Identify wildcard actions and broad resource permissions.
- Detect selected sensitive IAM permissions.
- Validate basic policy and statement structures.
- Generate security findings with severity levels and recommendations.
- Export analysis results as structured JSON reports.
- Test detection rules using automated unit tests.
- Demonstrate practical understanding of IAM security and least privilege.

## Key Features:
- **Policy analysis:** Reads and evaluates IAM policy JSON documents.
- **Wildcard detection:** Flags `Action: "*"` and `Resource: "*"`.
- **Permission pattern review:** Identifies wildcard patterns within action names and resource ARNs.
- **Sensitive permission detection:** Flags selected permissions such as `iam:PassRole` and `iam:*`.
- **Basic input validation:** Handles invalid policy structures, malformed JSON, missing files, and file access errors.
- **Severity-based findings:** Classifies configured findings as `HIGH`, `MEDIUM`, or `INFO`.
- **JSON report generation:** Produces reports containing timestamps, finding summaries, details, recommendations, and a disclaimer.
- **Automated testing:** Uses Python's `unittest` framework to verify key analyzer behaviors.

## Architecture:
```text
IAM Policy JSON
      |
      v
Policy Input and Validation
      |
      v
IAM Policy Analyzer
      |
      +--> Wildcard Action Checks
      |
      +--> Resource Scope Checks
      |
      +--> Sensitive IAM Permission Checks
      |
      +--> Policy Structure Validation
      |
      v
Security Findings
      |
      v
JSON Report Generator
      |
      +--> Summary of Findings
      |
      +--> Severity and Recommendations
      |
      v
Generated Reports in reports/
```

## Repository Structure:
```text
IAM-Policy-Risk-Analyzer/
|
|-- samples/
|   |-- broad_permissions_policy.json
|   |-- least_privilege_policy.json
|
|-- src/
|   |-- analyzer.py
|   |-- report_generator.py
|
|-- tests/
|   |-- test_analyzer.py
|
|-- reports/
|   |-- broad_permissions_policy_report.json
|   |-- least_privilege_policy_report.json
|
|-- evidence/
|   |-- 01-analyzer-execution.png
|   |-- 02-automated-tests.png
|   |-- 03-report-generation.png
|   |-- 04-generated-reports.png
|
|-- README.md
```

*The structure above describes the intended project layout. Keep filenames aligned with the files actually present in the repository.*

## Detection Rules:
| Detection rule | Severity | Purpose |
|---|---|---|
| Wildcard action (`Action: "*"`) | HIGH | Identifies permissions that allow all actions. |
| Wildcard resource (`Resource: "*"`) | HIGH | Identifies permissions that apply to all resources. |
| Wildcard within an action pattern | MEDIUM | Highlights action patterns that may grant broader access than intended. |
| Scoped resource wildcard | INFO | Flags resource patterns containing wildcards for contextual review. |
| Selected sensitive IAM permissions | HIGH | Flags `iam:PassRole` and `iam:*` for additional review. |
| Invalid policy structure | HIGH | Reports selected structural or input errors. |
| No configured rule matched | INFO | Indicates that the configured detection patterns did not trigger. |

Severity levels are the prototype's own rule-based classifications. They are not an official AWS risk score.

## Sample Scenarios:
### 1. Broad Permissions Policy
The synthetic broad-permissions example contains:

- `Effect: "Allow"`
- `Action: "*"`
- `Resource: "*"`

**Expected result:** The analyzer reports a high-severity wildcard action finding and a high-severity wildcard resource finding.
**Security recommendation:** Replace unrestricted permissions with only the actions and resources required for the intended task.

### 2. Least-Privilege Example:
The synthetic least-privilege example allows `s3:GetObject` against an example S3 bucket ARN.

**Expected result:** The analyzer reports an informational finding for the wildcard used within the object ARN pattern.
**Security recommendation:** Confirm that the bucket and object scope are appropriate for the intended use. An object-level wildcard can be legitimate and does not, by itself, mean the policy is overly permissive.

Both examples are for training and demonstration. They should not be treated as production policies.

## Technology Stack:
- **Language:** Python
- **Input format:** JSON
- **Testing:** Python `unittest`
- **Output format:** JSON security reports
- **Platform:** Local development environment
- **Cloud security domain:** AWS IAM, permissions review, and least-privilege principles

## How to Run

### Prerequisites:
- Python 3.10 or a compatible modern Python 3 version.
- The project files downloaded or cloned to your local computer.
- No third-party Python packages are required by the current implementation.

### Run the policy analyzer:
From the project root directory:
```bash
python src/analyzer.py
```
The analyzer processes the two sample policies and prints the configured findings in the terminal.

### Run the automated tests:
```bash
python -m unittest discover -s tests -v
```
The test suite checks wildcard detection, scoped resource wildcard handling, Deny statement behavior, invalid policy structures, and sensitive IAM permission detection.

### Generate JSON reports:
```bash
python src/report_generator.py
```
The report generator creates the following files in the `reports/` directory:
- `broad_permissions_policy_report.json`
- `least_privilege_policy_report.json`
Each report contains a UTC timestamp, finding counts, detailed findings, recommendations, and a limitations disclaimer.

## Testing and Validation:
The project was tested locally using the sample policy files.
- The broad-permissions example produced two high-severity findings.
- The least-privilege example produced one informational finding.
- Six automated unit tests passed during validation.
- JSON report generation completed successfully.
- Terminal output and report-generation evidence screenshots are included in the repository.

These results reflect the current sample inputs and configured rules; they are not a comprehensive assessment of AWS IAM security.

## Evidence and Screenshots:
The `evidence/` directory contains visual evidence of the local experiments, including:
1. Analyzer execution and findings.
2. Automated unit-test results.
3. JSON report generation.
4. Generated report files.
These screenshots help demonstrate that the project was executed and tested locally.

## Security Considerations and Limitations:
This project is an educational prototype, not a replacement for a full IAM security assessment.
- It uses static, rule-based checks rather than a complete AWS policy evaluation engine.
- It does not connect to AWS, retrieve live IAM policies, or monitor cloud activity.
- It does not implement AWS IAM policy simulation.
- It does not fully evaluate identity policies, resource policies, permission boundaries, service control policies, conditions, or cross-account access.
- A policy with no findings is not necessarily secure.
- Findings require contextual review before any permissions are changed.
The sample policies use placeholder resources and should not be attached to real AWS identities.

## Future Enhancements:
Potential improvements include:
- Add more detection rules for privilege escalation patterns and risky policy combinations.
- Expand unit tests for additional policy formats and edge cases.
- Add a human-readable HTML report.
- Add a command-line interface for analyzing a user-supplied policy file.
- Integrate AWS IAM Access Analyzer findings where appropriate.
- Add an optional web interface for uploading and reviewing policy JSON documents.
- Improve policy validation and contextual risk scoring.

## Skills Demonstrated:
- AWS IAM security fundamentals
- Least-privilege access control
- Python programming
- JSON parsing and validation
- Rule-based security analysis
- Security finding classification
- Automated unit testing
- Structured report generation
- Security documentation and evidence collection
- GitHub project organization

## Author:
**Prateek Gupta**
Cloud Security | AWS Security | IAM | Python

This project is part of my hands-on Cloud Security learning portfolio, focused on understanding cloud permissions, identifying selected security risks, and documenting reproducible security experiments.
