import pytest
from pathlib import Path
from src.scanner.code_scanner import CodeScanner
from src.scanner.techdebt_detector import TechDebtDetector


@pytest.fixture
def scanner():
    return CodeScanner({"extensions": [".py"], "exclude_dirs": [".git", "__pycache__"]})


@pytest.fixture
def techdebt_detector():
    return TechDebtDetector({})


@pytest.fixture
def sample_script(tmp_path):
    script = tmp_path / "test_monitor.py"
    script.write_text(
        """
import time
from netmiko import ConnectHandler

password = "admin123"

def check_device(ip):
    conn = ConnectHandler(
        device_type='cisco_ios',
        host=ip,
        username='admin',
        password=password
    )
    output = conn.send_command("show version")
    time.sleep(5)
    return output
"""
    )
    return script


class TestCodeScanner:
    def test_scan_single_file(self, scanner, sample_script):
        results = scanner.scan(sample_script.parent)
        assert len(results) == 1
        assert results[0].file_type == "network_monitor"

    def test_scan_empty_dir(self, scanner, tmp_path):
        results = scanner.scan(tmp_path)
        assert len(results) == 0

    def test_scan_excludes_cache(self, scanner, tmp_path):
        cache_dir = tmp_path / "__pycache__"
        cache_dir.mkdir()
        (cache_dir / "test.pyc").write_text("data")
        results = scanner.scan(tmp_path)
        assert len(results) == 0

    def test_classify_routing_script(self, scanner, tmp_path):
        script = tmp_path / "bgp_config.py"
        script.write_text("bgp neighbor 10.0.0.1 remote-as 65001")
        results = scanner.scan(tmp_path)
        assert results[0].file_type == "routing_mgmt"

    def test_classify_security_script(self, scanner, tmp_path):
        script = tmp_path / "block_ip.py"
        script.write_text("acl deny 192.168.1.100 any")
        results = scanner.scan(tmp_path)
        assert results[0].file_type == "security_block"


class TestTechDebtDetector:
    def test_detect_sync_blocking(self, techdebt_detector, sample_script):
        from src.scanner.code_scanner import ScanFile
        results = [ScanFile(path=sample_script, content=sample_script.read_text(), file_type="test")]
        report = techdebt_detector.detect(results)
        assert len(report) > 0

    def test_detect_hardcoded_password(self, scanner, sample_script):
        results = scanner.scan(sample_script.parent)
        assert len(results) == 1
        has_password_issue = any(
            "password" in i.get("rule", "").lower() or "password" in i.get("message", "").lower()
            for i in results[0].issues
        )
        assert has_password_issue
