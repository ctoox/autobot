import pytest
from pathlib import Path
from src.security.baseline_checker import SecurityBaselineChecker


@pytest.fixture
def checker():
    return SecurityBaselineChecker({})


@pytest.fixture
def scan_results_with_issues(tmp_path):
    script = tmp_path / "insecure.py"
    script.write_text(
        """
password = "hardcoded_secret_123"
api_key = "sk-abc123def456"
"""
    )
    from src.scanner.code_scanner import ScanFile
    return [
        ScanFile(path=script, content=script.read_text(), file_type="unknown")
    ]


class TestSecurityBaselineChecker:
    def test_detect_hardcoded_credentials(self, checker, scan_results_with_issues):
        report = checker.check(Path("/tmp"), scan_results_with_issues)
        assert report["total_findings"] > 0
        assert report["severity_counts"]["critical"] > 0

    def test_clean_file_no_findings(self, checker, tmp_path):
        script = tmp_path / "clean.py"
        script.write_text(
            """
import os
password = os.environ.get("PASSWORD")
"""
        )
        from src.scanner.code_scanner import ScanFile
        results = [ScanFile(path=script, content=script.read_text(), file_type="unknown")]
        report = checker.check(tmp_path, results)
        assert report["severity_counts"]["critical"] == 0

    def test_compliance_score_calculation(self, checker):
        findings = [
            {"severity": "critical"},
            {"severity": "high"},
            {"severity": "medium"},
        ]
        score = checker._calc_compliance_score(findings, 10)
        assert 0 <= score <= 100

    def test_severity_counting(self, checker):
        findings = [
            {"severity": "critical"},
            {"severity": "critical"},
            {"severity": "high"},
            {"severity": "medium"},
        ]
        counts = checker._count_severity(findings)
        assert counts["critical"] == 2
        assert counts["high"] == 1
        assert counts["medium"] == 1
