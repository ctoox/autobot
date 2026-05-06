from __future__ import annotations

import logging
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from src.agent.orchestrator import AgentOrchestrator
from src.agent.pipeline import RefactoringPipeline
from src.utils.config import ConfigManager
from src.utils.logger import setup_logger

console = Console()
logger = logging.getLogger(__name__)


@click.group()
@click.option("--config", "-c", default=None, help="Path to config file")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging")
@click.pass_context
def cli(ctx, config, verbose):
    """OpenClaw Ops Agent - 自动化运维脚本重构与安全智能体"""
    ctx.ensure_object(dict)
    ctx.obj["config"] = ConfigManager(config).to_dict()

    if verbose:
        setup_logger(level="DEBUG")
    else:
        setup_logger(level="INFO")


@cli.command()
@click.option("--target", "-t", required=True, help="Target directory to scan")
@click.option("--output", "-o", default="./scan-report.json", help="Output file")
@click.pass_context
def scan(ctx, target, output):
    """扫描运维脚本，检测技术债和安全问题"""
    config = ctx.obj["config"]
    orchestrator = AgentOrchestrator(config)

    console.print(f"[bold blue]Scanning:[/bold blue] {target}")
    result = orchestrator.scanner.scan(Path(target))

    console.print(f"[green]Found {len(result)} files[/green]")

    table = Table("File", "Type", "Lines", "Issues")
    for f in result:
        table.add_row(
            str(f.path),
            f.file_type,
            str(f.metrics.get("total_lines", 0)),
            str(len(f.issues)),
        )
    console.print(table)


@cli.command()
@click.option("--target", "-t", required=True, help="Target directory")
@click.option("--repo", "-r", required=True, help="Target repository URL")
@click.option("--dry-run", is_flag=True, help="Show plan without executing")
@click.pass_context
def refactor(ctx, target, repo, dry_run):
    """执行重构并生成 PR"""
    config = ctx.obj["config"]

    if dry_run:
        pipeline = RefactoringPipeline(config)
        context = pipeline.execute(Path(target), repo)

        console.print("[bold yellow]=== Refactor Plan (Dry Run) ===[/bold yellow]")
        console.print(f"Files to refactor: {context.files_scanned}")
        console.print(f"Total issues found: {context.total_issues}")
    else:
        orchestrator = AgentOrchestrator(config)
        result = orchestrator.run(target, repo)

        console.print("[bold green]=== Refactor Complete ===[/bold green]")
        console.print(f"PR Status: {result['pr_result'].get('status', 'unknown')}")
        console.print(f"Files changed: {result['pr_result'].get('files_changed', 0)}")


@cli.command()
@click.option("--target", "-t", required=True, help="Target directory")
@click.pass_context
def security(ctx, target):
    """执行安全基线检查"""
    from src.security.baseline_checker import SecurityBaselineChecker
    from src.scanner.code_scanner import CodeScanner

    config = ctx.obj["config"]
    scanner = CodeScanner(config.get("scanner", {}))
    checker = SecurityBaselineChecker(config.get("security", {}))

    scan_results = scanner.scan(Path(target))
    report = checker.check(Path(target), scan_results)

    console.print("[bold blue]=== Security Baseline Report ===[/bold blue]")
    console.print(f"Files checked: {report['files_checked']}")
    console.print(f"Total findings: {report['total_findings']}")
    console.print(f"Compliance score: {report['compliance_score']}%")

    table = Table("Severity", "Count")
    for severity, count in report["severity_counts"].items():
        if count > 0:
            color = {"critical": "red", "high": "yellow", "medium": "blue", "low": "green"}
            table.add_row(severity.upper(), str(count), style=color.get(severity))
    console.print(table)


@cli.command()
@click.option("--target", "-t", required=True, help="Target directory")
@click.pass_context
def validate(ctx, target):
    """校验网络规范符合性"""
    from src.network.spec_validator import NetworkSpecValidator
    from src.scanner.code_scanner import CodeScanner

    config = ctx.obj["config"]
    scanner = CodeScanner(config.get("scanner", {}))
    validator = NetworkSpecValidator(config.get("network", {}))

    scan_results = scanner.scan(Path(target))
    report = validator.validate(scan_results)

    console.print("[bold blue]=== Network Spec Validation ===[/bold blue]")
    console.print(f"Total files: {report['total_files']}")
    console.print(f"Compliant files: {report['compliant_files']}")
    console.print(f"Compliance rate: {report['compliance_rate']}%")


@cli.command()
@click.option("--devices", "-d", default=5, help="Number of simulated devices")
def simulate(devices):
    """运行多设备模拟测试"""
    from src.testing.device_simulator import DeviceSimulator

    simulator = DeviceSimulator({"device_count": devices})
    result = simulator.run_scenario({})

    console.print("[bold blue]=== Device Simulation ===[/bold blue]")
    console.print(f"Devices simulated: {result['devices_simulated']}")
    console.print(f"Test cases: {result['test_cases']}")
    console.print(f"Passed: {result['passed']}")


def main():
    cli()


if __name__ == "__main__":
    main()
