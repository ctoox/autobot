from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from src.scanner.code_scanner import ScanFile

logger = logging.getLogger(__name__)


@dataclass
class AgentContext:
    """Agent 执行上下文，维护流水线各阶段的状态"""

    target_path: Path
    scan_results: list[ScanFile] = field(default_factory=list)
    techdebt_report: dict = field(default_factory=dict)
    security_report: dict = field(default_factory=dict)
    spec_report: dict = field(default_factory=dict)
    refactor_plan: dict = field(default_factory=dict)
    refactored_code: dict = field(default_factory=dict)
    test_results: dict = field(default_factory=dict)
    pr_result: dict = field(default_factory=dict)

    @property
    def total_issues(self) -> int:
        return sum(len(f.issues) for f in self.scan_results)

    @property
    def files_scanned(self) -> int:
        return len(self.scan_results)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_path": str(self.target_path),
            "files_scanned": self.files_scanned,
            "total_issues": self.total_issues,
            "techdebt_report": self.techdebt_report,
            "security_report": self.security_report,
            "spec_report": self.spec_report,
            "refactor_plan": self.refactor_plan,
            "test_results": self.test_results,
            "pr_result": self.pr_result,
        }
