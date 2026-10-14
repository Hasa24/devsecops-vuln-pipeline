import json
import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import triage  # noqa: E402

FX = Path(__file__).parent / "fixtures"


def load_all():
    f = []
    f += triage.parse_pip_audit(triage.load_json(FX / "pip_audit.json"))
    f += triage.parse_trivy(triage.load_json(FX / "trivy_image.json"), "trivy-image")
    f += triage.parse_trivy(triage.load_json(FX / "trivy_config.json"), "trivy-config")
    return f


def test_parsers_find_everything():
    assert len(load_all()) == 6


def test_dedup_is_per_package_and_version():
    kept, _ = triage.triage(load_all(), {})
    # same CVE id on a different package is NOT a duplicate
    assert len(kept) == 6


def test_ranking_severity_then_fix():
    kept, _ = triage.triage(load_all(), {})
    assert kept[0].severity == "CRITICAL"
    highs = [f for f in kept if f.severity == "HIGH"]
    assert highs[0].id == "CVE-2024-0002"


def test_gate_ignores_unfixable_by_default():
    kept, _ = triage.triage(load_all(), {})
    blocking = triage.gate_failures(kept, "HIGH", fixable_only=True)
    assert {f.id for f in blocking} == {"CVE-2024-0001", "AVD-AWS-0107"}
    with_unfixable = triage.gate_failures(kept, "HIGH", fixable_only=False)
    assert "CVE-2024-0002" in {f.id for f in with_unfixable}


def test_ignore_needs_reason_and_unexpired(tmp_path):
    p = tmp_path / "ign.json"
    p.write_text(json.dumps({"ignores": [
        {"id": "A", "reason": "ok", "expires": "2999-01-01"},
        {"id": "B", "reason": "old", "expires": "2000-01-01"},
        {"id": "C", "expires": "2999-01-01"},
    ]}))
    active, expired, invalid = triage.load_ignores(p, date(2026, 10, 14))
    assert set(active) == {"A"}
    assert [e["id"] for e in expired] == ["B"]
    assert [e["id"] for e in invalid] == ["C"]


def test_suppressed_finding_does_not_block():
    ignores = {"CVE-2024-0001": {"id": "CVE-2024-0001"}, "AVD-AWS-0107": {"id": "AVD-AWS-0107"}}
    kept, suppressed = triage.triage(load_all(), ignores)
    assert not triage.gate_failures(kept, "HIGH", fixable_only=True)
    assert len(suppressed) == 3


def test_main_exit_codes(tmp_path):
    args = ["--pip-audit", str(FX / "pip_audit.json"),
            "--trivy-image", str(FX / "trivy_image.json"),
            "--trivy-config", str(FX / "trivy_config.json"),
            "--ignore-file", str(tmp_path / "none.json"),
            "--report", str(tmp_path / "r.md")]
    assert triage.main(args) == 1
    assert "FAIL" in (tmp_path / "r.md").read_text()


def test_unknown_severity_is_assumed_not_ignored(tmp_path):
    args = ["--pip-audit", str(FX / "pip_audit.json"),
            "--ignore-file", str(tmp_path / "none.json"),
            "--report", str(tmp_path / "r.md")]
    assert triage.main(args) == 1          # fixable pip-audit finding now blocks
    assert triage.main(args + ["--unknown-as", "LOW"]) == 0
