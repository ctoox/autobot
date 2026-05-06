from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# 安全基线规则
BASELINE_RULES = [
    {
        "id": "SEC-001",
        "name": "no_hardcoded_credentials",
        "severity": "critical",
        "patterns": [
            r'password\s*=\s*["\'][^"\']+["\']',
            r'secret\s*=\s*["\'][^"\']+["\']',
            r'api_key\s*=\s*["\'][^"\']+["\']',
            r'token\s*=\s*["\'][^"\']+["\']',
        ],
        "description": "凭据必须通过环境变量或密钥管理服务获取",
    },
    {
        "id": "SEC-002",
        "name": "ssh_host_key_verification",
        "severity": "high",
        "patterns": [r"AutoAddPolicy", r"set_missing_host_key_policy\(.*AutoAdd"],
        "description": "SSH 连接必须验证主机密钥，禁止 AutoAddPolicy",
    },
    {
        "id": "SEC-003",
        "name": "input_validation",
        "severity": "high",
        "patterns": [r"os\.system\(", r"subprocess\.call\(\[.*shell.*\]"],
        "description": "禁止使用 os.system，必须使用 subprocess.run 并验证输入",
    },
    {
        "id": "SEC-004",
        "name": "acl_rule_management",
        "severity": "medium",
        "patterns": [r"deny.*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*"],
        "description": "ACL 封堵规则应通过动态模板管理，禁止硬编码",
    },
    {
        "id": "SEC-005",
        "name": "log_sanitization",
        "severity": "medium",
        "patterns": [r"logger.*password|logger.*secret|logger.*token"],
        "description": "日志中不得输出敏感信息",
    },
    {
        "id": "SEC-006",
        "name": "connection_timeout",
        "severity": "low",
        "patterns": [r"ConnectHandler\(.*\)"],
        "description": "SSH 连接必须设置超时参数",
    },
]


class SecurityBaselineChecker:
    """安全基线检查器

    根据运营商安全基线标准，检查运维脚本的安全性。
    """

    def __init__(self, config: dict[str, Any]):
        self.config = config
        self.rules = BASELINE_RULES
        self.custom_rules = config.get("custom_rules", [])

    def check(self, target_path: Path, scan_results: list) -> dict[str, Any]:
        """执行安全基线检查

        Args:
            target_path: 扫描目标目录
            scan_results: 代码扫描结果

        Returns:
            安全检查报告
        """
        findings = []
        files_checked = 0

        for scan_file in scan_results:
            files_checked += 1
            file_findings = self._check_file(scan_file)
            findings.extend(file_findings)

        issues_fixed = sum(1 for f in findings if f.get("auto_fixable"))
        severity_counts = self._count_severity(findings)

        report = {
            "files_checked": files_checked,
            "total_findings": len(findings),
            "issues_fixed": issues_fixed,
            "severity_counts": severity_counts,
            "findings": findings,
            "acl_externalized": not any(
                f["rule_id"] == "SEC-004" for f in findings
            ),
            "exception_coverage": self._calc_exception_coverage(scan_results),
            "compliance_score": self._calc_compliance_score(findings, files_checked),
        }

        logger.info(
            "Security check: %d files, %d findings, compliance: %.1f%%",
            files_checked,
            len(findings),
            report["compliance_score"],
        )
        return report

    def _check_file(self, scan_file) -> list[dict]:
        """检查单个文件的安全问题"""
        findings = []
        content = scan_file.content

        all_rules = self.rules + self.custom_rules

        for rule in all_rules:
            for pattern in rule["patterns"]:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    line_num = content[:match.start()].count("\n") + 1
                    findings.append({
                        "rule_id": rule["id"],
                        "rule_name": rule["name"],
                        "severity": rule["severity"],
                        "description": rule["description"],
                        "file_path": str(scan_file.path),
                        "line_number": line_num,
                        "auto_fixable": rule["severity"] in ("medium", "low"),
                    })

        return findings

    def _count_severity(self, findings: list[dict]) -> dict[str, int]:
        """统计各严重程度数量"""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for finding in findings:
            severity = finding.get("severity", "low")
            counts[severity] = counts.get(severity, 0) + 1
        return counts

    def _calc_exception_coverage(self, scan_results: list) -> float:
        """计算异常处理覆盖率"""
        if not scan_results:
            return 0.0
        covered = sum(
            1 for f in scan_results
            if "try" in f.content and "except" in f.content
        )
        return (covered / len(scan_results)) * 100

    def _calc_compliance_score(self, findings: list, files_count: int) -> float:
        """计算合规分数"""
        if files_count == 0:
            return 100.0

        severity_weights = {"critical": 10, "high": 5, "medium": 2, "low": 1}
        total_deductions = sum(
            severity_weights.get(f["severity"], 1) for f in findings
        )
        max_score = files_count * 10
        score = max(0, (max_score - total_deductions) / max_score * 100)
        return round(score, 1)
