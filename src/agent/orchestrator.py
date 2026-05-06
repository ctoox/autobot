from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

try:
    from openclaw import Agent, Tool
    HAS_OPENCLAW = True
except (ImportError, AttributeError):
    HAS_OPENCLAW = False
    Agent = Any
    Tool = Any

from src.scanner.code_scanner import CodeScanner
from src.scanner.techdebt_detector import TechDebtDetector
from src.refactor.engine import RefactorEngine
from src.refactor.pr_generator import PRGenerator
from src.security.baseline_checker import SecurityBaselineChecker
from src.network.spec_validator import NetworkSpecValidator
from src.testing.test_runner import TestRunner

logger = logging.getLogger(__name__)


class AgentOrchestrator:
    """OpenClaw 运维重构 Agent 核心调度器

    编排扫描、分析、重构、测试、PR 提交的完整流水线。
    """

    def __init__(self, config: dict[str, Any]):
        self.config = config
        self.scanner = CodeScanner(config.get("scanner", {}))
        self.techdebt_detector = TechDebtDetector(config.get("techdebt", {}))
        self.security_checker = SecurityBaselineChecker(
            config.get("security", {})
        )
        self.spec_validator = NetworkSpecValidator(config.get("network", {}))
        self.refactor_engine = RefactorEngine(config.get("refactor", {}))
        self.pr_generator = PRGenerator(config.get("pr", {}))
        self.test_runner = TestRunner(config.get("testing", {}))

    def run(self, target_path: str, repo_url: str) -> dict[str, Any]:
        """执行完整的重构流水线

        Args:
            target_path: 待扫描的脚本目录
            repo_url: 目标代码仓库 URL

        Returns:
            执行结果字典，包含扫描报告、重构统计、测试结果
        """
        target = Path(target_path)
        logger.info("Starting ops agent pipeline for %s", target)

        # Phase 1: 扫描与技术债检测
        scan_results = self.scanner.scan(target)
        techdebt_report = self.techdebt_detector.detect(scan_results)

        # Phase 2: 安全基线检查
        security_report = self.security_checker.check(target, scan_results)

        # Phase 3: 网络规范校验
        spec_report = self.spec_validator.validate(scan_results)

        # Phase 4: 代码重构
        refactor_plan = self.refactor_engine.plan(
            techdebt_report, security_report, spec_report
        )
        refactored_code = self.refactor_engine.execute(
            refactor_plan, scan_results
        )

        # Phase 5: 测试验证
        test_results = self.test_runner.run(refactored_code)

        # Phase 6: 生成 PR
        pr_result = self.pr_generator.generate(
            repo_url=repo_url,
            refactored_code=refactored_code,
            reports={
                "techdebt": techdebt_report,
                "security": security_report,
                "spec": spec_report,
                "test": test_results,
            },
        )

        return {
            "scan_results": scan_results,
            "techdebt_report": techdebt_report,
            "security_report": security_report,
            "spec_report": spec_report,
            "refactor_plan": refactor_plan,
            "test_results": test_results,
            "pr_result": pr_result,
        }

    def register_tools(self, agent: Agent) -> Agent:
        """注册 OpenClaw 工具到 Agent"""

        @agent.tool("scan_scripts")
        def scan_scripts(target: str) -> dict:
            return self.scanner.scan(Path(target))

        @agent.tool("detect_techdebt")
        def detect_techdebt(scan_report: dict) -> dict:
            return self.techdebt_detector.detect(scan_report)

        @agent.tool("check_security")
        def check_security(target: str, scan_report: dict) -> dict:
            return self.security_checker.check(Path(target), scan_report)

        @agent.tool("validate_specs")
        def validate_specs(scan_report: dict) -> dict:
            return self.spec_validator.validate(scan_report)

        @agent.tool("refactor_code")
        def refactor_code(reports: dict) -> dict:
            plan = self.refactor_engine.plan(
                reports["techdebt"], reports["security"], reports["spec"]
            )
            return self.refactor_engine.execute(plan, reports["scan_results"])

        @agent.tool("run_tests")
        def run_tests(refactored: dict) -> dict:
            return self.test_runner.run(refactored)

        @agent.tool("generate_pr")
        def generate_pr(repo_url: str, refactored: dict, reports: dict) -> dict:
            return self.pr_generator.generate(repo_url, refactored, reports)

        return agent
