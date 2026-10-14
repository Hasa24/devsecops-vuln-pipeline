#!/usr/bin/env python3
"""Normalize pip-audit and Trivy JSON reports, triage them, and gate the build.

- Merges findings from dependency, container-image and IaC scans into one list.
- Suppresses findings listed in an ignore file, but only while the entry has a
  reason and has not expired (expired ignores are reported and stop suppressing).
- Ranks what is left by severity, then by whether a fix exists.
- Writes a Markdown report and exits non-zero if any actionable finding is at or
  above the severity threshold.
"""
import argparse
import json
import sys
from dataclasses import dataclass
from datetime import date
from pathlib import Path

SEVERITY_ORDER = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


@dataclass
class Finding:
    source: str          # pip-audit | trivy-image | trivy-config
    id: str
    package: str         # package name, or resource/target for IaC
    installed: str
    fixed: str           # empty if no fix known
    severity: str
    title: str


def load_json(path):
    return json.loads(Path(path).read_text())


def parse_pip_audit(data):
    findings = []
    deps = data.get("dependencies", data) if isinstance(data, dict) else data
    for dep in deps:
        for v in dep.get("vulns", []):
            findings.append(Finding(
                source="pip-audit",
                id=v["id"],
                package=dep["name"],
                installed=dep.get("version", ""),
                fixed=", ".join(v.get("fix_versions", [])),
                severity="UNKNOWN",  # pip-audit does not report severity
                title=(v.get("description") or "").strip().split("\n")[0][:120],
            ))
    return findings


def parse_trivy(data, source):
    findings = []
    for result in data.get("Results", []) or []:
        target = result.get("Target", "")
        for v in result.get("Vulnerabilities", []) or []:
            findings.append(Finding(
                source=source,
                id=v["VulnerabilityID"],
                package=v.get("PkgName", target),
                installed=v.get("InstalledVersion", ""),
                fixed=v.get("FixedVersion", "") or "",
                severity=v.get("Severity", "UNKNOWN").upper(),
                title=(v.get("Title") or "")[:120],
            ))
        for m in result.get("Misconfigurations", []) or []:
            findings.append(Finding(
                source="trivy-config",
                id=m.get("ID", ""),
                package=target,
                installed="",
                fixed=m.get("Resolution", "") or "",
                severity=m.get("Severity", "UNKNOWN").upper(),
                title=(m.get("Title") or "")[:120],
            ))
    return findings


def load_ignores(path, today):
    """Return (active_ids, expired_entries, invalid_entries)."""
    if not path or not Path(path).exists():
        return {}, [], []
    active, expired, invalid = {}, [], []
    for entry in load_json(path).get("ignores", []):
        if not entry.get("reason") or not entry.get("expires"):
            invalid.append(entry)            # an ignore must be justified and time-boxed
            continue
        if date.fromisoformat(entry["expires"]) < today:
            expired.append(entry)
        else:
            active[entry["id"]] = entry
    return active, expired, invalid


def rank_key(f):
    return (-SEVERITY_ORDER.get(f.severity, 0), 0 if f.fixed else 1, f.package, f.id)


def triage(findings, ignores):
    seen, unique = set(), []
    for f in findings:                       # de-duplicate across scanners
        key = (f.id, f.package, f.installed)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    kept = [f for f in unique if f.id not in ignores]
    suppressed = [f for f in unique if f.id in ignores]
    return sorted(kept, key=rank_key), suppressed


def gate_failures(kept, threshold, fixable_only):
    limit = SEVERITY_ORDER[threshold]
    out = []
    for f in kept:
        if SEVERITY_ORDER.get(f.severity, 0) < limit:
            continue
        if fixable_only and not f.fixed:
            continue
        out.append(f)
    return out


def render(kept, suppressed, expired, invalid, failures, threshold):
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in kept:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    lines = ["# Security scan triage report", ""]
    lines.append("Findings with no scanner severity (pip-audit) are assumed HIGH until reviewed.")
    lines.append("")
    lines.append(f"Gate: fail on **{threshold}+** with a known fix. "
                 f"Result: **{'FAIL' if failures else 'PASS'}** "
                 f"({len(failures)} blocking finding(s)).")
    lines += ["", "| Severity | Open findings |", "|---|---|"]
    for sev in sorted(counts, key=lambda s: -SEVERITY_ORDER[s]):
        lines.append(f"| {sev} | {counts[sev]} |")
    lines += ["", "## Findings (highest priority first)", "",
              "| Sev | ID | Package / target | Installed | Fix | Source |", "|---|---|---|---|---|---|"]
    for f in kept[:50]:
        lines.append(f"| {f.severity} | {f.id} | {f.package} | {f.installed} | {f.fixed or '-'} | {f.source} |")
    if len(kept) > 50:
        lines.append(f"\n_{len(kept) - 50} more not shown._")
    if suppressed:
        lines += ["", "## Suppressed by ignore file", ""]
        lines += [f"- {f.id} ({f.package})" for f in suppressed]
    if expired:
        lines += ["", "## Expired ignores (no longer suppressing)", ""]
        lines += [f"- {e['id']} expired {e['expires']}: {e.get('reason', '')}" for e in expired]
    if invalid:
        lines += ["", "## Invalid ignores (missing reason or expiry, not applied)", ""]
        lines += [f"- {e.get('id', '?')}" for e in invalid]
    return "\n".join(lines) + "\n"


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--pip-audit", help="pip-audit JSON report")
    p.add_argument("--trivy-image", help="Trivy JSON report for the container image")
    p.add_argument("--trivy-config", help="Trivy JSON report for IaC/config scan")
    p.add_argument("--ignore-file", default=".vulnignore.json")
    p.add_argument("--threshold", default="HIGH", choices=list(SEVERITY_ORDER))
    p.add_argument("--include-unfixable", action="store_true",
                   help="also block on findings that have no fix yet")
    p.add_argument("--unknown-as", default="HIGH", choices=list(SEVERITY_ORDER),
                   help="severity to assume when a scanner reports none (pip-audit does not)")
    p.add_argument("--report", default="triage-report.md")
    args = p.parse_args(argv)

    findings = []
    if args.pip_audit:
        findings += parse_pip_audit(load_json(args.pip_audit))
    if args.trivy_image:
        findings += parse_trivy(load_json(args.trivy_image), "trivy-image")
    if args.trivy_config:
        findings += parse_trivy(load_json(args.trivy_config), "trivy-config")

    for f in findings:                       # scanners without severity must not slip past the gate
        if f.severity == "UNKNOWN":
            f.severity = args.unknown_as
            f.title = "[severity assumed] " + f.title

    ignores, expired, invalid = load_ignores(args.ignore_file, date.today())
    kept, suppressed = triage(findings, ignores)
    failures = gate_failures(kept, args.threshold, fixable_only=not args.include_unfixable)

    Path(args.report).write_text(render(kept, suppressed, expired, invalid, failures, args.threshold))
    print(f"{len(findings)} findings, {len(kept)} open, {len(suppressed)} suppressed, "
          f"{len(failures)} blocking. Report: {args.report}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
