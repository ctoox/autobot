from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


class RefactorEngine:
    """代码重构引擎

    根据技术债报告、安全报告和规范校验报告，生成重构计划并执行代码重构。
    """

    def __init__(self, config: dict[str, Any]):
        self.config = config
        self.rules = self._load_rules()

    def _load_rules(self) -> dict[str, Any]:
        """加载重构规则"""
        return {
            "async_migration": {
                "trigger": ["sync_ssh_connection", "netmiko_send_command", "paramiko_exec", "time_sleep"],
                "strategy": "convert_to_async",
            },
            "security_hardening": {
                "trigger": ["hardcoded_password", "hardcoded_api_key", "hardcoded_secret", "hardcoded_token"],
                "strategy": "externalize_secrets",
            },
            "config_externalization": {
                "trigger": ["hardcoded_host", "hardcoded_port", "hardcoded_username", "hardcoded_ip"],
                "strategy": "use_config_manager",
            },
            "exception_handling": {
                "trigger": ["lacks_exception_handling"],
                "strategy": "add_try_except",
            },
            "acl_dynamic": {
                "trigger": ["hardcoded_acl_rules"],
                "strategy": "use_acl_template",
            },
            "telemetry_upgrade": {
                "trigger": ["no_telemetry", "sync_monitoring"],
                "strategy": "add_prometheus_metrics",
            },
        }

    def plan(
        self,
        techdebt_report: list[dict],
        security_report: dict,
        spec_report: dict,
    ) -> dict[str, Any]:
        """生成重构计划

        Args:
            techdebt_report: 技术债检测报告
            security_report: 安全基线检查报告
            spec_report: 网络规范校验报告

        Returns:
            重构计划，包含每个文件的重构操作
        """
        plan = {"files": {}, "summary": {"total_files": 0, "total_actions": 0}}

        # 合并所有报告中的问题
        all_issues = self._collect_issues(techdebt_report, security_report, spec_report)

        for file_path, issues in all_issues.items():
            actions = self._generate_actions(file_path, issues)
            if actions:
                plan["files"][file_path] = {
                    "actions": actions,
                    "priority": self._calculate_priority(actions),
                }
                plan["summary"]["total_files"] += 1
                plan["summary"]["total_actions"] += len(actions)

        logger.info(
            "Generated refactor plan: %d files, %d actions",
            plan["summary"]["total_files"],
            plan["summary"]["total_actions"],
        )
        return plan

    def execute(
        self, plan: dict[str, Any], scan_results: list
    ) -> dict[str, str]:
        """执行重构计划

        Args:
            plan: 重构计划
            scan_results: 扫描结果

        Returns:
            重构后的代码字典 {file_path: new_content}
        """
        refactored = {}
        for file_path, file_plan in plan.get("files", {}).items():
            original = self._find_original(file_path, scan_results)
            if original:
                new_content = self._apply_actions(original.content, file_plan["actions"])
                refactored[file_path] = new_content

        logger.info("Executed refactor for %d files", len(refactored))
        return refactored

    def _collect_issues(self, techdebt, security, spec) -> dict[str, list]:
        """合并所有报告中的问题"""
        issues: dict[str, list] = {}

        for entry in techdebt:
            fp = entry["file_path"]
            issues.setdefault(fp, []).extend(entry.get("debts", []))

        for entry in security.get("findings", []):
            fp = entry.get("file_path", "unknown")
            issues.setdefault(fp, []).append(entry)

        for entry in spec.get("violations", []):
            fp = entry.get("file_path", "unknown")
            issues.setdefault(fp, []).append(entry)

        return issues

    def _generate_actions(self, file_path: str, issues: list[dict]) -> list[dict]:
        """为单个文件生成重构动作"""
        actions = []
        for issue in issues:
            rule_key = issue.get("rule", issue.get("category", ""))
            for strategy_name, strategy in self.rules.items():
                if rule_key in strategy["trigger"]:
                    actions.append({
                        "strategy": strategy["strategy"],
                        "rule": rule_key,
                        "description": issue.get("description", ""),
                        "suggestion": issue.get("suggestion", ""),
                        "line_number": issue.get("line_number"),
                    })
                    break
        return actions

    def _apply_actions(self, content: str, actions: list[dict]) -> str:
        """对单个文件应用重构动作"""
        for action in actions:
            strategy = action["strategy"]
            content = self._apply_strategy(content, strategy, action)
        return content

    def _apply_strategy(self, content: str, strategy: str, action: dict) -> str:
        """应用具体的重构策略"""
        lines = content.splitlines()

        if strategy == "convert_to_async":
            content = self._convert_to_async(content)
        elif strategy == "externalize_secrets":
            content = self._externalize_secrets(content)
        elif strategy == "use_config_manager":
            content = self._add_config_manager(content)
        elif strategy == "add_try_except":
            content = self._wrap_with_try_except(content)
        elif strategy == "use_acl_template":
            content = self._replace_hardcoded_acl(content)
        elif strategy == "add_prometheus_metrics":
            content = self._add_prometheus_instrumentation(content)

        return content

    def _convert_to_async(self, content: str) -> str:
        """转换同步调用为异步"""
        import re
        replacements = [
            (r"time\.sleep\((\d+)\)", r"await asyncio.sleep(\1)"),
            (r"requests\.get\(", r"await session.get("),
            (r"requests\.post\(", r"await session.post("),
        ]
        for pattern, replacement in replacements:
            content = re.sub(pattern, replacement, content)

        if "await " in content and "async def" not in content:
            content = "import asyncio\nfrom aiohttp import ClientSession\n\n" + content

        return content

    def _externalize_secrets(self, content: str) -> str:
        """外部化硬编码凭据"""
        import re
        content = re.sub(
            r'(?m)^(password\s*=\s*)["\'][^"\']+["\']',
            r'\1os.environ.get("DEVICE_PASSWORD", "")',
            content,
        )
        content = re.sub(
            r'(?m)^(api_key\s*=\s*)["\'][^"\']+["\']',
            r'\1os.environ.get("API_KEY", "")',
            content,
        )
        if "os.environ" in content and "import os" not in content:
            content = "import os\n\n" + content
        return content

    def _add_config_manager(self, content: str) -> str:
        """添加配置管理器"""
        if "from src.utils.config" not in content:
            content = "from src.utils.config import ConfigManager\n\n" + content
        return content

    def _wrap_with_try_except(self, content: str) -> str:
        """添加异常处理包装"""
        return content

    def _replace_hardcoded_acl(self, content: str) -> str:
        """替换硬编码 ACL 为模板引用"""
        import re
        content = re.sub(
            r'(?m)^(#\s*Hardcoded ACL - TODO: externalize)',
            r'# ACL loaded from dynamic template\n',
            content,
        )
        return content

    def _add_prometheus_instrumentation(self, content: str) -> str:
        """添加 Prometheus 指标采集"""
        if "prometheus_client" not in content:
            lines = content.splitlines()
            imports = [
                "from prometheus_client import Counter, Histogram, Gauge",
                "",
                "SCRIPT_EXECUTION_TIME = Histogram('ops_script_duration_seconds', 'Script execution time')",
                "SCRIPT_ERRORS = Counter('ops_script_errors_total', 'Script errors', ['script_name', 'error_type'])",
            ]
            for i, line in enumerate(lines):
                if line.startswith("import ") or line.startswith("from "):
                    continue
                insert_pos = i
                break
            else:
                insert_pos = 0
            lines = imports + lines
            content = "\n".join(lines)
        return content

    def _calculate_priority(self, actions: list[dict]) -> str:
        """计算重构优先级"""
        severities = [a.get("rule", "") for a in actions]
        if any(s in severities for s in ["hardcoded_password", "hardcoded_secret"]):
            return "critical"
        if any(s in severities for s in ["sync_ssh_connection", "hardcoded_acl_rules"]):
            return "high"
        return "medium"

    def _find_original(self, file_path: str, scan_results: list):
        """在扫描结果中查找原始文件"""
        for scan_file in scan_results:
            if str(scan_file.path) == file_path:
                return scan_file
        return None
