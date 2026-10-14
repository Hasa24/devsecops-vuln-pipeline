# DevSecOps Vulnerability Scanning Pipeline

A CI pipeline that scans a small Flask service three ways and turns the raw output
into one prioritized report with a pass/fail gate.

| Scan | Tool | Catches |
|---|---|---|
| Dependencies | pip-audit | Known CVEs/advisories in Python packages |
| Container image | Trivy | OS and library CVEs in the built image |
| IaC / config | Trivy config | Misconfigurations in Terraform and the Dockerfile |

`scripts/triage.py` then:
- merges and de-duplicates findings across scanners,
- ranks by severity, then by whether a fix exists,
- treats findings with no scanner severity (pip-audit) as HIGH so they cannot slip past the gate,
- supports `.vulnignore.json` suppressions that **must have a reason and an expiry**; expired or unjustified ignores stop applying and are listed in the report,
- exits non-zero if an actionable finding is at or above the threshold (default HIGH, fixable only).

The app, pinned requirements, Dockerfile and `infra/main.tf` are intentionally
vulnerable so the scanners have real findings. Nothing is deployed.

## Run locally
    pip install pytest pip-audit
    pytest -q
    pip-audit -r requirements.txt -f json -o pip-audit.json
    python scripts/triage.py --pip-audit pip-audit.json

## Tuning
- `--threshold CRITICAL` to block less, `--include-unfixable` to block more.
- `--unknown-as MEDIUM` once you have reviewed pip-audit findings and want less noise.

## Known limits
- pip-audit gives no severity, so severity for dependency findings is assumed, not measured.
- Reachability and business impact are not analyzed; the report is for a human to review.
