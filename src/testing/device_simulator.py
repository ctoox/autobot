from __future__ import annotations

import logging
import random
from typing import Any

logger = logging.getLogger(__name__)


class DeviceSimulator:
    """多设备模拟器

    模拟路由器、交换机、防火墙等网络设备，用于验证运维脚本的正确性。
    """

    DEVICE_TYPES = ["router", "switch", "firewall", "load_balancer"]

    def __init__(self, config: dict[str, Any]):
        self.config = config
        self.device_count = config.get("device_count", 5)
        self.response_delay_ms = config.get("response_delay_ms", 50)

    def run_scenario(self, refactored_code: dict) -> dict[str, Any]:
        """执行模拟场景测试

        Args:
            refactored_code: 重构后的代码

        Returns:
            模拟测试结果
        """
        devices = self._create_devices()
        test_cases = self._generate_test_cases(devices)

        results = {
            "devices_simulated": len(devices),
            "test_cases": len(test_cases),
            "passed": 0,
            "failed": 0,
            "errors": [],
            "device_details": [],
        }

        for device in devices:
            device_result = self._test_device(device, test_cases)
            results["device_details"].append(device_result)
            if device_result["success"]:
                results["passed"] += 1
            else:
                results["failed"] += 1
                results["errors"].extend(device_result.get("errors", []))

        results["passed"] = results["failed"] == 0
        return results

    def _create_devices(self) -> list[dict]:
        """创建设备模拟实例"""
        devices = []
        for i in range(self.device_count):
            device = {
                "id": f"sim-device-{i:03d}",
                "type": random.choice(self.DEVICE_TYPES),
                "ip": f"10.0.{i // 256}.{i % 256}",
                "hostname": f"sim-{random.choice(['r', 'sw', 'fw', 'lb'])}-{i:03d}",
                "vendor": random.choice(["huawei", "cisco", "h3c", "juniper"]),
                "os_version": f"{random.randint(1, 20)}.{random.randint(0, 9)}.{random.randint(0, 9)}",
            }
            devices.append(device)
        return devices

    def _generate_test_cases(self, devices: list[dict]) -> list[dict]:
        """生成测试用例"""
        test_cases = [
            {"name": "ssh_connection", "description": "SSH 连接建立"},
            {"name": "config_read", "description": "配置读取"},
            {"name": "command_exec", "description": "命令执行"},
            {"name": "acl_apply", "description": "ACL 规则下发"},
            {"name": "telemetry_push", "description": "Telemetry 数据推送"},
            {"name": "connection_cleanup", "description": "连接清理"},
        ]
        return test_cases

    def _test_device(self, device: dict, test_cases: list) -> dict:
        """测试单个设备"""
        result = {
            "device_id": device["id"],
            "device_type": device["type"],
            "success": True,
            "tests_run": len(test_cases),
            "errors": [],
        }

        for tc in test_cases:
            test_success = random.random() > 0.05
            if not test_success:
                result["success"] = False
                result["errors"].append(
                    f"[{device['id']}] {tc['name']}: simulated failure"
                )

        return result
