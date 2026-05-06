from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml


class ConfigManager:
    """配置管理器

    管理运维脚本的配置，支持 YAML 配置文件和环境变量覆盖。
    """

    def __init__(self, config_path: str | None = None):
        self.config_path = config_path
        self._config: dict[str, Any] = {}
        self._load()

    def _load(self):
        """加载配置"""
        if self.config_path:
            path = Path(self.config_path)
            if path.exists():
                with open(path, encoding="utf-8") as f:
                    self._config = yaml.safe_load(f) or {}
        self._apply_env_overrides()

    def _apply_env_overrides(self):
        """应用环境变量覆盖"""
        env_mapping = {
            "DEVICE_PASSWORD": "device_password",
            "API_KEY": "api_key",
            "TELEMETRY_ENDPOINT": "telemetry.endpoint",
            "PROMETHEUS_PUSHGATEWAY": "prometheus.pushgateway",
        }
        for env_key, config_key in env_mapping.items():
            value = os.environ.get(env_key)
            if value:
                self._set_nested(config_key, value)

    def _set_nested(self, key: str, value: str):
        """设置嵌套配置"""
        keys = key.split(".")
        current = self._config
        for k in keys[:-1]:
            current = current.setdefault(k, {})
        current[keys[-1]] = value

    def get(self, key: str, default: Any = None) -> Any:
        """获取配置值"""
        keys = key.split(".")
        current = self._config
        for k in keys:
            if isinstance(current, dict):
                current = current.get(k)
            else:
                return default
            if current is None:
                return default
        return current

    def to_dict(self) -> dict[str, Any]:
        return dict(self._config)
