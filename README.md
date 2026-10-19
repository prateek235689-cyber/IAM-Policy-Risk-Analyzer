# IAM Policy Risk Analyzer:
A Python-based cloud security project that analyzes AWS IAM policy JSON documents, identifies potentially risky permissions, assigns risk levels, and recommends least-privilege improvements.

## Project Overview:
AWS Identity and Access Management (IAM) controls who can access AWS resources and which actions they can perform. Policies that grant broader permissions than necessary can increase security risk.
The IAM Policy Risk Analyzer is an educational security tool designed to inspect IAM policy documents and highlight configurations that deserve further review. It aims to help learners understand permission scope, wildcard usage, and least-privilege principles through repeatable local analysis.

## Objectives:
- Parse AWS IAM policy JSON documents.
- Identify potentially broad or risky permissions.
- Detect wildcard actions and resources.
- Assign risk levels using documented detection rules.
- Provide explanations and remediation recommendations.
- Generate structured findings and security reports.
- Validate the analyzer with automated tests.
- Document sample policies, test results, and limitations.

## Planned Features:
- **Policy validation:** Check the structure of policy JSON files.
- **Risk detection:** Flag selected broad permissions and wildcard patterns.
- **Risk classification:** Categorize findings by severity using explicit rules.
- **Remediation guidance:** Explain how permissions could be narrowed.
- **Report generation:** Export findings in a structured format.
- **Automated testing:** Test expected behavior with safe sample policies.

## Technology Stack:
- Python
- JSON
- AWS IAM policy concepts
- Python automated testing
- GitHub for source control and project documentation

## Project Workflow:
1. Load a sample IAM policy document.
2. Validate its JSON structure.
3. Inspect policy statements, actions, resources, and effects.
4. Apply the configured detection rules.
5. Produce findings with explanations and recommendations.
6. Generate a report and validate behavior using automated tests.

## Project Structure:
```text
IAM-Policy-Risk-Analyzer/
├── samples/
├── reports/
└── README.md
```
Additional source-code and test directories will be added as the implementation progresses.

## Security Scope:
This project is intended for local analysis of policy documents supplied by the user. It does not require deployment of AWS infrastructure.
A flagged permission is a potential risk indicator, not proof of an exploitable vulnerability. Findings must be interpreted in context, including the identity, resource, conditions, permission boundaries, and other applicable AWS controls.

## Development Status

**Current stage:** Initial repository and project documentation.
Detection logic, report generation, and automated tests will be implemented and documented in subsequent development milestones.

## Disclaimer:
This is an educational cloud security project. It does not replace AWS IAM policy validation, an organization's security review process, or a comprehensive assessment of effective permissions.
