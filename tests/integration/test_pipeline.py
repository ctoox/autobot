import pytest
from pathlib import Path
from src.agent.orchestrator import AgentOrchestrator


@pytest.fixture
def config():
    return {
        "scanner": {"extensions": [".py"], "exclude_dirs": [".git", "__pycache__"]},
        "techdebt": {},
        "security": {},
        "network": {},
        "refactor": {},
        "testing": {"simulator": {"device_count": 3}},
        "pr": {"branch_prefix": "test/refactor", "auto_merge": False},
    }


@pytest.fixture
def sample_scripts(tmp_path):
    scripts = [
        ("monitor.py", """
from netmiko import ConnectHandler
import time

def check_device(ip):
    conn = ConnectHandler(device_type='cisco_ios', host=ip, username='admin', password='secret')
    output = conn.send_command("show version")
    time.sleep(2)
    return output
"""),
        ("block.py", """
import requests

def block_ip(ip, api_url):
    requests.post(f"{api_url}/block", json={"ip": ip})
"""),
    ]
    for name, content in scripts:
        (tmp_path / name).write_text(content)
    return tmp_path


class TestOrchestratorIntegration:
    def test_full_pipeline(self, config, sample_scripts):
        orchestrator = AgentOrchestrator(config)
        result = orchestrator.run(
            target_path=str(sample_scripts),
            repo_url="https://github.com/test-org/test-repo",
        )

        assert "scan_results" in result
        assert "techdebt_report" in result
        assert "security_report" in result
        assert "refactor_plan" in result
        assert "pr_result" in result
        assert result["pr_result"]["status"] == "generated"

    def test_scan_finds_files(self, config, sample_scripts):
        orchestrator = AgentOrchestrator(config)
        results = orchestrator.scanner.scan(sample_scripts)
        assert len(results) == 2

    def test_pr_generation(self, config, sample_scripts):
        orchestrator = AgentOrchestrator(config)
        scan_results = orchestrator.scanner.scan(sample_scripts)
        techdebt = orchestrator.techdebt_detector.detect(scan_results)
        security = orchestrator.security_checker.check(sample_scripts, scan_results)
        spec = orchestrator.spec_validator.validate(scan_results)

        refactor_plan = orchestrator.refactor_engine.plan(techdebt, security, spec)
        refactored = orchestrator.refactor_engine.execute(refactor_plan, scan_results)

        pr = orchestrator.pr_generator.generate(
            repo_url="https://github.com/test-org/test-repo",
            refactored_code=refactored,
            reports={"techdebt": techdebt, "security": security, "spec": spec, "test": {}},
        )

        assert pr["status"] == "generated"
        assert "refactor" in pr["branch_name"]
        assert pr["files_changed"] == len(refactored)
