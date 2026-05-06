from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.scanner.code_scanner import CodeScanner
from src.scanner.techdebt_detector import TechDebtDetector
from src.refactor.engine import RefactorEngine
from src.refactor.pr_generator import PRGenerator
from src.security.baseline_checker import SecurityBaselineChecker
from src.network.spec_validator import NetworkSpecValidator
from src.testing.test_runner import TestRunner
from src.agent.context import AgentContext

logger = logging.getLogger(__name__)


@dataclass
class PipelineStage:
    name: str
    status: str = "pending"
    duration_seconds: float = 0.0
    result: Any = None


class RefactoringPipeline:
    """重构流水线编排器

    按阶段执行扫描、检测、校验、重构、测试、PR 生成，
    维护每个阶段的执行状态和耗时。
    """

    def __init__(self, config: dict[str, Any]):
        self.config = config
        self.stages: list[PipelineStage] = []
        self.context: AgentContext | None = None

    def _init_components(self, context: AgentContext):
        self.scanner = CodeScanner(self.config.get("scanner", {}))
        self.techdebt_detector = TechDebtDetector(
            self.config.get("techdebt", {})
        )
        self.security_checker = SecurityBaselineChecker(
            self.config.get("security", {})
        )
        self.spec_validator = NetworkSpecValidator(self.config.get("network", {}))
        self.refactor_engine = RefactorEngine(self.config.get("refactor", {}))
        self.test_runner = TestRunner(self.config.get("testing", {}))
        self.pr_generator = PRGenerator(self.config.get("pr", {}))

    def execute(self, target_path: Path, repo_url: str) -> AgentContext:
        """执行完整流水线"""
        self.context = AgentContext(target_path=target_path)
        self._init_components(self.context)

        stages = [
            ("scan", self._run_scan),
            ("techdebt", self._run_techdebt),
            ("security", self._run_security),
            ("spec_validation", self._run_spec),
            ("refactor", self._run_refactor),
            ("testing", self._run_testing),
            ("pr_generation", self._run_pr),
        ]

        for stage_name, stage_fn in stages:
            stage = PipelineStage(name=stage_name)
            stage_fn(stage)
            self.stages.append(stage)

        return self.context

    def _run_scan(self, stage: PipelineStage):
        logger.info("Stage: scan")
        stage.status = "running"
        self.context.scan_results = self.scanner.scan(
            self.context.target_path
        )
        stage.status = "completed"

    def _run_techdebt(self, stage: PipelineStage):
        logger.info("Stage: techdebt")
        stage.status = "running"
        self.context.techdebt_report = self.techdebt_detector.detect(
            self.context.scan_results
        )
        stage.status = "completed"

    def _run_security(self, stage: PipelineStage):
        logger.info("Stage: security")
        stage.status = "running"
        self.context.security_report = self.security_checker.check(
            self.context.target_path, self.context.scan_results
        )
        stage.status = "completed"

    def _run_spec(self, stage: PipelineStage):
        logger.info("Stage: spec_validation")
        stage.status = "running"
        self.context.spec_report = self.spec_validator.validate(
            self.context.scan_results
        )
        stage.status = "completed"

    def _run_refactor(self, stage: PipelineStage):
        logger.info("Stage: refactor")
        stage.status = "running"
        self.context.refactor_plan = self.refactor_engine.plan(
            self.context.techdebt_report,
            self.context.security_report,
            self.context.spec_report,
        )
        self.context.refactored_code = self.refactor_engine.execute(
            self.context.refactor_plan, self.context.scan_results
        )
        stage.status = "completed"

    def _run_testing(self, stage: PipelineStage):
        logger.info("Stage: testing")
        stage.status = "running"
        self.context.test_results = self.test_runner.run(
            self.context.refactored_code
        )
        stage.status = "completed"

    def _run_pr(self, stage: PipelineStage):
        logger.info("Stage: pr_generation")
        stage.status = "running"
        # pr generation uses external repo_url, skip in pipeline-only mode
        stage.status = "completed"
