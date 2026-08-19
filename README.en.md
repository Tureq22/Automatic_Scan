Automated Vulnerability Scanner for CI/CD

Português | English

Mostrar Imagem

An automated security gate for CI/CD pipelines. A Python orchestrator runs static code analysis (SAST, via Bandit), dependency analysis (SCA, via pip-audit and Trivy) and secret detection, consolidates the results into a unified JSON report, and fails the build when it finds vulnerabilities above the configured threshold — keeping insecure code out of the main branch.

Architecture
push / pull request
        │
        ▼
  GitHub Actions ──> security_scan.py
                          ├── Bandit     (SAST: insecure Python code patterns)
                          ├── pip-audit  (SCA: dependency CVEs, OSV database)
                          └── Trivy      (SCA + secrets + filesystem)
                               │
                               ▼
                      severity normalization
                               │
                               ▼
                     security_report.json
                               │
                 exit 0 (pass) │ exit 1 (block the merge)

The only contract between the script and the CI platform is the exit code, which makes the scanner portable to GitLab CI, Jenkins or any other platform without code changes.

Exit code	Meaning
0	No vulnerabilities above the threshold — build passes
1	Blocking vulnerabilities found — build fails
2	Tool execution error
Project structure
.
├── .github/workflows/security.yml   # GitHub Actions pipeline
├── scanner/security_scan.py         # Orchestrator (the core of the project)
├── requirements.txt                 # Application dependencies
├── .gitignore
└── README.md

The app/vulnerable_example.py file, containing intentional vulnerabilities, lives only in the demo/vulnerabilidades demonstration branch. The main branch is kept clean.

Usage
Installation
bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install bandit pip-audit

Trivy (optional locally, used in the pipeline):

bash
# Linux
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
# macOS
brew install trivy
# Windows
choco install trivy
Running
bash
python scanner/security_scan.py --path . --fail-on HIGH --report security_report.json
Argument	Default	Description
--path	.	Project directory to scan
--fail-on	HIGH	Minimum severity that fails the build: LOW, MEDIUM, HIGH, CRITICAL
--report	security_report.json	Output path for the JSON report
--skip	—	Tools to skip: bandit, pip-audit, trivy
Running tools individually

Useful for debugging: if a tool works on its own, the problem is in the orchestrator.

bash
bandit -r . -f json
pip-audit -r requirements.txt -f json --no-deps
trivy fs --format json --scanners vuln,secret .
Sample output

Running against the demonstration branch, with requests==2.19.1, flask==0.12.3 and vulnerable code:

============================================================
SECURITY SCAN SUMMARY
============================================================
 CRITICAL: 0
 HIGH: 29
 MEDIUM: 2
 LOW: 5
 Total: 36
 Failure threshold (--fail-on): HIGH
============================================================

Blocking vulnerabilities:
 [HIGH] (bandit) B602 - subprocess_popen_with_shell_equals_true -> ./app/vulnerable_example.py:23
 [HIGH] (bandit) B324 - hashlib -> ./app/vulnerable_example.py:28
 [HIGH] (pip-audit) PYSEC-2023-74 - requests 2.19.1 vulnerable -> requests
 ...

BUILD FAILED: 29 vulnerability(ies) >= HIGH found.

Every pip-audit finding includes a fix_versions field, pointing to the version that resolves the issue:

json
{
  "tool": "pip-audit",
  "type": "SCA",
  "severity": "HIGH",
  "id": "PYSEC-2023-74",
  "package": "requests",
  "installed_version": "2.19.1",
  "fix_versions": ["2.31.0"]
}
GitHub integration

The workflow runs on every push and pull_request targeting main, and can also be triggered manually from the Actions tab. The report is uploaded as an artifact with if: always(), so it stays available precisely when the build fails.

To turn the check into a real barrier to merging, enable branch protection under Settings → Branches → Add branch ruleset, marking the SAST + SCA Scan status check as required. Without it the workflow still runs and reports, but the merge button remains enabled.

Design decisions

pip-audit over Safety. It queries the OSV database and the PyPI Advisory Database, requires no API key, and is maintained by the PyPA. Safety now requires an account for full functionality.

Severity normalization. Each tool uses its own scale — Bandit works with LOW/MEDIUM/HIGH, Trivy adds CRITICAL and UNKNOWN, and pip-audit exposes no severity at all. The scanner maps everything onto a single scale before comparing against the threshold, treating CVEs without explicit severity as HIGH as a conservative default.

Exit code as the contract. The CI platform never has to understand the report format: 0 passes, 1 blocks. This decouples the scanner from the platform.

Graceful degradation. If a tool is not installed, the scanner warns and continues with the remaining ones rather than breaking the entire pipeline.

Possible extensions

SARIF output to integrate with GitHub's Security tab, automatic PR comments summarizing findings via actions/github-script, Semgrep for custom SAST rules, Gitleaks for dedicated secret scanning, and an equivalent .gitlab-ci.yml.

License

MIT