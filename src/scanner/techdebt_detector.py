from __future__ import annotations

import ast
import logging
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class TechDebtItem:
    category: str
    severity: str
    description: str
    file_path: str
    line_number: int | None = None
    suggestion: str = ""


class TechDebtDetector:
    """技术债检测器

    检测运维脚本中的常见技术债模式:
    - 同步阻塞调用(Netmiko/Paramiko)
    - 缺少异常处理
    - 硬编码配置
    - 过时的 API 用法
    - 缺失日志记录
    - 资源泄漏风险
    """

    def __init__(self, config: dict[str, Any]):
        self.config = config

    def detect(self, scan_results) -> list[dict[str, Any]]:
        """执行技术债检测

        Args:
            scan_results: CodeScanner 的扫描结果

        Returns:
            技术债检测报告
        """
        report = []
        for scan_file in scan_results:
            file_debts = self._analyze_file(scan_file)
            if file_debts:
                report.append({
                    "file_path": str(scan_file.path),
                    "file_type": scan_file.file_type,
                    "debts": file_debts,
                })
        return report

    def _analyze_file(self, scan_file) -> list[dict]:
        debts = []
        content = scan_file.content

        debts.extend(self._check_sync_blocking(scan_file))
        debts.extend(self._check_exception_handling(scan_file))
        debts.extend(self._check_hardcoded_config(scan_file))
        debts.extend(self._check_logging(scan_file))
        debts.extend(self._check_resource_leak(scan_file))
        debts.extend(self._check_deprecated_api(scan_file))

        return debts

    def _check_sync_blocking(self, scan_file) -> list[dict]:
        """检测同步阻塞调用"""
        debts = []
        content = scan_file.content

        sync_patterns = [
            (r"\.send_command\(", "netmiko_send_command", "Use send_command_timing or async variant"),
            (r"\.exec_command\(", "paramiko_exec", "Use async exec_command"),
            (r"\.connect\(", "sync_connect", "Use async connection pool"),
            (r"time\.sleep\(", "time_sleep", "Use asyncio.sleep"),
            (r"requests\.(get|post)\(", "sync_http", "Use aiohttp for async HTTP"),
        ]

        import re
        for pattern, rule, suggestion in sync_patterns:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count("\n") + 1
                debts.append({
                    "category": "performance",
                    "severity": "medium",
                    "description": f"Sync blocking call: {rule}",
                    "file_path": str(scan_file.path),
                    "line_number": line_num,
                    "suggestion": suggestion,
                })

        return debts

    def _check_exception_handling(self, scan_file) -> list[dict]:
        """检测缺失异常处理"""
        debts = []
        try:
            tree = ast.parse(scan_file.content)
        except SyntaxError:
            return debts

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                has_try = any(
                    isinstance(child, ast.Try)
                    for child in ast.walk(node)
                )
                if not has_try and node.name not in ("__init__", "__str__", "__repr__"):
                    debts.append({
                        "category": "reliability",
                        "severity": "high",
                        "description": f"Function '{node.name}' lacks exception handling",
                        "file_path": str(scan_file.path),
                        "line_number": node.lineno,
                        "suggestion": "Add try/except with proper error logging",
                    })

        return debts

    def _check_hardcoded_config(self, scan_file) -> list[dict]:
        """检测硬编码配置"""
        debts = []
        content = scan_file.content

        config_patterns = [
            (r'(?<![\w])HOST\s*=\s*["\']', "hardcoded_host"),
            (r'(?<![\w])PORT\s*=\s*["\']?\d+["\']?', "hardcoded_port"),
            (r'(?<![\w])USERNAME\s*=\s*["\']', "hardcoded_username"),
            (r'(?<![\w])IP\s*=\s*["\']\d{1,3}\.', "hardcoded_ip"),
            (r'(?<![\w])SUBNET\s*=\s*["\']', "hardcoded_subnet"),
        ]

        import re
        for pattern, rule in config_patterns:
            if re.search(pattern, content):
                debts.append({
                    "category": "maintainability",
                    "severity": "medium",
                    "description": f"Hardcoded configuration: {rule}",
                    "file_path": str(scan_file.path),
                    "suggestion": "Externalize to config file or environment variables",
                })

        return debts

    def _check_logging(self, scan_file) -> list[dict]:
        """检测缺失日志记录"""
        debts = []
        content = scan_file.content

        if "import logging" not in content and "from logging" not in content:
            debts.append({
                "category": "observability",
                "severity": "low",
                "description": "No logging module imported",
                "file_path": str(scan_file.path),
                "suggestion": "Add structured logging for production scripts",
            })

        if "logger" not in content and "logging." not in content:
            debts.append({
                "category": "observability",
                "severity": "low",
                "description": "No logger instance found",
                "file_path": str(scan_file.path),
                "suggestion": "Initialize logger with appropriate level",
            })

        return debts

    def _check_resource_leak(self, scan_file) -> list[dict]:
        """检测资源泄漏风险"""
        debts = []
        try:
            tree = ast.parse(scan_file.content)
        except SyntaxError:
            return debts

        # 检测 open() 没有使用 with 语句
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id == "open":
                    if not isinstance(node.parent, ast.withitem) if hasattr(node, 'parent') else True:
                        debts.append({
                            "category": "reliability",
                            "severity": "medium",
                            "description": "File opened without context manager",
                            "file_path": str(scan_file.path),
                            "line_number": node.lineno,
                            "suggestion": "Use 'with open()' for automatic cleanup",
                        })

        return debts

    def _check_deprecated_api(self, scan_file) -> list[dict]:
        """检测过时的 API 用法"""
        debts = []
        content = scan_file.content

        deprecated = {
            "from netmiko import ConnectHandler;": "Use netmiko.ConnectionHandler or newer API",
            "paramiko.SSHClient().load_system_host_keys": "Use paramiko.AutoAddPolicy or known_hosts",
            "telnetlib": "Use netmiko or asyncssh instead of telnetlib",
            "optparse": "Use argparse instead of optparse",
        }

        for deprecated_api, suggestion in deprecated.items():
            if deprecated_api in content:
                debts.append({
                    "category": "maintainability",
                    "severity": "medium",
                    "description": f"Deprecated API: {deprecated_api[:50]}",
                    "file_path": str(scan_file.path),
                    "suggestion": suggestion,
                })

        return debts
