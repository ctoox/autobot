from __future__ import annotations

import ast
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ScanFile:
    path: Path
    content: str
    file_type: str
    issues: list[dict] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)

# 识别的脚本类型及其特征
SCRIPT_PATTERNS = {
    "network_monitor": re.compile(
        r"netmiko|paramiko|ConnectHandler|ssh.*device|telnet", re.IGNORECASE
    ),
    "routing_mgmt": re.compile(
        r"bgp|ospf|static_route|route_map|vrf|prefix_list", re.IGNORECASE
    ),
    "security_block": re.compile(
        r"acl|block|deny|firewall|ip.*ban|blacklist|whitelist", re.IGNORECASE
    ),
    "host_check": re.compile(
        r"health.*check|cpu.*usage|disk.*usage|memor|巡检|巡检脚本",
        re.IGNORECASE,
    ),
    "telemetry": re.compile(
        r"telemetry|prometheus|metrics|pushgateway|/metrics", re.IGNORECASE
    ),
}


class CodeScanner:
    """运维脚本代码扫描器

    扫描目标目录下的 Python 运维脚本，识别脚本类型并提取基本信息。
    """

    def __init__(self, config: dict[str, Any]):
        self.config = config
        self.extensions = config.get("extensions", [".py"])
        self.exclude_dirs = set(
            config.get("exclude_dirs", [".git", "__pycache__", "venv", ".tox"])
        )
        self.max_file_size = config.get("max_file_size_mb", 10) * 1024 * 1024

    def scan(self, target_path: Path) -> list[ScanFile]:
        """扫描目录下的所有运维脚本

        Args:
            target_path: 目标扫描目录

        Returns:
            扫描结果列表
        """
        results = []
        for file_path in target_path.rglob("*"):
            if not self._should_scan(file_path):
                continue

            try:
                content = file_path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, PermissionError) as e:
                logger.warning("Skipping %s: %s", file_path, e)
                continue

            scan_file = ScanFile(
                path=file_path,
                content=content,
                file_type=self._classify_script(content),
            )
            scan_file.metrics = self._collect_metrics(scan_file)
            scan_file.issues = self._preliminary_issues(scan_file)
            results.append(scan_file)

        logger.info("Scanned %d files in %s", len(results), target_path)
        return results

    def _should_scan(self, file_path: Path) -> bool:
        if file_path.suffix not in self.extensions:
            return False
        if any(part in self.exclude_dirs for part in file_path.parts):
            return False
        if file_path.stat().st_size > self.max_file_size:
            return False
        return True

    def _classify_script(self, content: str) -> str:
        """根据内容特征分类脚本类型"""
        for script_type, pattern in SCRIPT_PATTERNS.items():
            if pattern.search(content):
                return script_type
        return "unknown"

    def _collect_metrics(self, scan_file: ScanFile) -> dict[str, Any]:
        """收集代码度量指标"""
        lines = scan_file.content.splitlines()
        metrics = {
            "total_lines": len(lines),
            "code_lines": sum(
                1 for l in lines if l.strip() and not l.strip().startswith("#")
            ),
            "comment_lines": sum(
                1 for l in lines if l.strip().startswith("#")
            ),
            "blank_lines": sum(1 for l in lines if not l.strip()),
            "file_size_bytes": scan_file.path.stat().st_size,
        }

        # AST 分析
        try:
            tree = ast.parse(scan_file.content)
            metrics["functions"] = sum(
                1 for node in ast.walk(tree)
                if isinstance(node, ast.FunctionDef)
            )
            metrics["classes"] = sum(
                1 for node in ast.walk(tree)
                if isinstance(node, ast.ClassDef)
            )
        except SyntaxError:
            metrics["functions"] = 0
            metrics["classes"] = 0

        return metrics

    def _preliminary_issues(self, scan_file: ScanFile) -> list[dict]:
        """初步扫描常见问题"""
        issues = []
        content = scan_file.content

        # 硬编码凭据检测
        cred_patterns = [
            (r'password\s*=\s*["\'][^"\']+["\']', "hardcoded_password"),
            (r'api_key\s*=\s*["\'][^"\']+["\']', "hardcoded_api_key"),
            (r'secret\s*=\s*["\'][^"\']+["\']', "hardcoded_secret"),
            (r'token\s*=\s*["\'][^"\']+["\']', "hardcoded_token"),
        ]
        for pattern, issue_type in cred_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                issues.append({
                    "type": "security",
                    "severity": "critical",
                    "rule": issue_type,
                    "message": f"Detected {issue_type}",
                })

        # 同步 SSH 调用 (应使用异步)
        if "ConnectHandler" in content and "async" not in content:
            issues.append({
                "type": "performance",
                "severity": "medium",
                "rule": "sync_ssh_connection",
                "message": "Synchronous SSH connection detected, consider async",
            })

        # 硬编码 IP 封堵规则
        if re.search(r"acl.*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", content, re.IGNORECASE):
            issues.append({
                "type": "maintainability",
                "severity": "medium",
                "rule": "hardcoded_acl_rules",
                "message": "Hardcoded ACL rules detected",
            })

        return issues
