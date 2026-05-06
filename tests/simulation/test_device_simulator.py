import pytest
from src.testing.device_simulator import DeviceSimulator


@pytest.fixture
def simulator():
    return DeviceSimulator({"device_count": 5, "response_delay_ms": 10})


class TestDeviceSimulator:
    def test_create_devices(self, simulator):
        devices = simulator._create_devices()
        assert len(devices) == 5
        for device in devices:
            assert "id" in device
            assert "type" in device
            assert "ip" in device
            assert "hostname" in device
            assert "vendor" in device
            assert device["type"] in DeviceSimulator.DEVICE_TYPES

    def test_run_scenario(self, simulator):
        result = simulator.run_scenario({})
        assert result["devices_simulated"] == 5
        assert result["test_cases"] == 6
        assert "passed" in result
        assert "device_details" in result

    def test_device_details_structure(self, simulator):
        result = simulator.run_scenario({})
        for detail in result["device_details"]:
            assert "device_id" in detail
            assert "device_type" in detail
            assert "success" in detail
            assert "tests_run" in detail

    def test_custom_device_count(self):
        sim = DeviceSimulator({"device_count": 10})
        devices = sim._create_devices()
        assert len(devices) == 10
