from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# 网络规范校验规则
SPEC_RULES = [
    {
        "id": "NET-001",
        "name": "telemetry_standard",
        "severity": "high",
        "description": "监控脚本应使用 Telemetry/Prometheus 标准指标采集",
        "check": "has_telemetry",
    },
    {
        "id": "NET-002",
        "name": "async_connection",
        "severity": "medium",
        "description": "网络设备连接应使用异步模式",
        "check": "uses_async",
    },
    {
        "id": "NET-003",
        "name": "structured_logging",
        "severity": "medium",
        "description": "日志输出应使用结构化格式(JSON)",
        "check": "has_structured_logging",
    },
    {
        "id": "NET-004",
        "name": "connection_pool",
        "severity": "medium",
        "description": "批量设备操作应使用连接池",
        "check": "uses_connection_pool",
    },
    {
        "id": "NET-005",
        "name": "config_versioning",
        "severity": "low",
        "description": "配置变更应有版本追踪",
        "check": "has_config_versioning",
    },
]


class NetworkSpecValidator:
    """网络规范校验器

    校验运维脚本是否符合最新核心网络规范。
    """

    def __init__(self, config: dict[str, Any]):
        self.config = config
        self.rules = SPEC_RULES

    def validate(self, scan_results: list) -> dict[str, Any]:
        """执行规范校验

        Args:
            scan_results: 代码扫描结果

        Returns:
            规范校验报告
        """
        violations = []
        compliant_files = 0
        total_files = len(scan_results)

        for scan_file in scan_results:
            file_violations = self._check_file(scan_file)
            if not file_violations:
                compliant_files += 1
            else:
                violations.extend(file_violations)

        compliance_rate = (
            (compliant_files / total_files * 100) if total_files > 0 else 100.0
        )

        report = {
            "total_files": total_files,
            "compliant_files": compliant_files,
            "compliance_rate": round(compliance_rate, 1),
            "violations": violations,
            "rule_summary": self._summarize_rules(violations),
        }

        logger.info(
            "Spec validation: %.1f%% compliant (%d/%d)",
            compliance_rate,
            compliant_files,
            total_files,
        )
        return report

    def _check_file(self, scan_file) -> list[dict]:
        """检查单个文件的规范符合性"""
        violations = []
        content = scan_file.content

        for rule in self.rules:
            check_fn = getattr(self, f"_check_{rule['check']}", None)
            if check_fn and not check_fn(content):
                violations.append({
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "severity": rule["severity"],
                    "description": rule["description"],
                    "file_path": str(scan_file.path),
                })

        return violations

    def _check_has_telemetry(self, content: str) -> bool:
        return (
            "prometheus" in content.lower()
            or "telemetry" in content.lower()
            or "metrics" in content.lower()
        )

    def _check_uses_async(self, content: str) -> bool:
        return "async " in content or "asyncio" in content or "aiohttp" in content

    def _check_has_structured_logging(self, content: str) -> bool:
        return "json" in content.lower() and ("logger" in content or "logging" in content)

    def _check_uses_connection_pool(self, content: str) -> bool:
        return (
            "pool" in content.lower()
            or "ConnectionPool" in content
            or "session" in content.lower()
        )

    def _check_has_config_versioning(self, content: str) -> bool:
        return (
            "version" in content.lower()
            or "git" in content.lower()
            or "backup" in content.lower()
        )

    def _summarize_rules(self, violations: list[dict]) -> dict[str, int]:
        """按规则汇总违规数量"""
        summary = {}
        for v in violations:
            rule_id = v["rule_id"]
            summary[rule_id] = summary.get(rule_id, 0) + 1
        return summary
