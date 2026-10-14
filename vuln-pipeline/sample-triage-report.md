# Security scan triage report

Findings with no scanner severity (pip-audit) are assumed HIGH until reviewed.

Gate: fail on **HIGH+** with a known fix. Result: **FAIL** (37 blocking finding(s)).

| Severity | Open findings |
|---|---|
| CRITICAL | 0 |
| HIGH | 37 |
| MEDIUM | 0 |
| LOW | 0 |
| UNKNOWN | 0 |

## Findings (highest priority first)

| Sev | ID | Package / target | Installed | Fix | Source |
|---|---|---|---|---|---|
| HIGH | PYSEC-2023-62 | flask | 2.0.1 | 2.2.5, 2.3.2 | pip-audit |
| HIGH | PYSEC-2026-2151 | flask | 2.0.1 | 3.1.3 | pip-audit |
| HIGH | PYSEC-2024-60 | idna | 2.10 | 3.7 | pip-audit |
| HIGH | PYSEC-2026-215 | idna | 2.10 | 3.15 | pip-audit |
| HIGH | PYSEC-2026-1471 | jinja2 | 3.0.1 | 3.1.6 | pip-audit |
| HIGH | PYSEC-2026-1472 | jinja2 | 3.0.1 | 3.1.5 | pip-audit |
| HIGH | PYSEC-2026-1473 | jinja2 | 3.0.1 | 3.1.3 | pip-audit |
| HIGH | PYSEC-2026-1474 | jinja2 | 3.0.1 | 3.1.4 | pip-audit |
| HIGH | PYSEC-2026-1475 | jinja2 | 3.0.1 | 3.1.5 | pip-audit |
| HIGH | PYSEC-2021-142 | pyyaml | 5.3.1 | 5.4 | pip-audit |
| HIGH | PYSEC-2023-74 | requests | 2.25.1 | 2.31.0 | pip-audit |
| HIGH | PYSEC-2026-1872 | requests | 2.25.1 | 2.32.4 | pip-audit |
| HIGH | PYSEC-2026-1873 | requests | 2.25.1 | 2.32.0 | pip-audit |
| HIGH | PYSEC-2026-2275 | requests | 2.25.1 | 2.33.0 | pip-audit |
| HIGH | PYSEC-2021-108 | urllib3 | 1.26.4 | 1.26.5 | pip-audit |
| HIGH | PYSEC-2023-192 | urllib3 | 1.26.4 | 1.26.17, 2.0.6 | pip-audit |
| HIGH | PYSEC-2023-212 | urllib3 | 1.26.4 | 1.26.18, 2.0.7 | pip-audit |
| HIGH | PYSEC-2026-141 | urllib3 | 1.26.4 | 2.7.0 | pip-audit |
| HIGH | PYSEC-2026-1994 | urllib3 | 1.26.4 | 2.6.0 | pip-audit |
| HIGH | PYSEC-2026-1995 | urllib3 | 1.26.4 | 1.26.19, 2.2.2 | pip-audit |
| HIGH | PYSEC-2026-1996 | urllib3 | 1.26.4 | 2.6.3 | pip-audit |
| HIGH | PYSEC-2026-1998 | urllib3 | 1.26.4 | 2.6.0 | pip-audit |
| HIGH | PYSEC-2026-1999 | urllib3 | 1.26.4 | 2.5.0 | pip-audit |
| HIGH | PYSEC-2026-4175 | urllib3 | 1.26.4 | 2.8.0 | pip-audit |
| HIGH | PYSEC-2026-4177 | urllib3 | 1.26.4 | 2.8.0 | pip-audit |
| HIGH | CVE-2026-102598 | werkzeug | 2.0.1 | 3.1.9 | pip-audit |
| HIGH | PYSEC-2022-203 | werkzeug | 2.0.1 | 2.1.1 | pip-audit |
| HIGH | PYSEC-2023-221 | werkzeug | 2.0.1 | 2.3.8, 3.0.1 | pip-audit |
| HIGH | PYSEC-2023-57 | werkzeug | 2.0.1 | 2.2.3 | pip-audit |
| HIGH | PYSEC-2023-58 | werkzeug | 2.0.1 | 2.2.3 | pip-audit |
| HIGH | PYSEC-2026-1860 | werkzeug | 2.0.1 | 3.0.6 | pip-audit |
| HIGH | PYSEC-2026-2043 | werkzeug | 2.0.1 | 3.0.3 | pip-audit |
| HIGH | PYSEC-2026-2044 | werkzeug | 2.0.1 | 3.1.5 | pip-audit |
| HIGH | PYSEC-2026-2045 | werkzeug | 2.0.1 | 3.0.6 | pip-audit |
| HIGH | PYSEC-2026-2046 | werkzeug | 2.0.1 | 3.1.4 | pip-audit |
| HIGH | PYSEC-2026-2320 | werkzeug | 2.0.1 | 3.1.6 | pip-audit |
| HIGH | PYSEC-2026-3417 | werkzeug | 2.0.1 | 3.0.6 | pip-audit |
