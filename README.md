# OpenClaw Ops Agent - 自动化运维脚本重构与安全智能体

基于 OpenClaw 构建的自动化代码库重构与安全运维 Agent，面向核心网络运维场景，自动扫描技术债、安全隐患和架构不一致问题，生成符合最新网络规范与安全基线的重构 PR。

## 功能特性

- **智能代码扫描**: 自动识别 Netmiko/Paramiko 交互逻辑中的性能瓶颈、异步优化缺失、安全封堵规则硬编码等问题
- **规范驱动重构**: 结合 Telemetry、Prometheus 和 ACL 动态下发规范，一键生成优化后的 Python 代码
- **自动化 PR 生成**: 自动生成可直接合并的 Pull Request，附带变更说明与影响评估
- **闭环测试验证**: 集成单元测试、集成测试及多设备模拟环境验证
- **安全合规扫描**: 内置安全基线检查，确保脚本符合企业安全标准
- **CI/CD 集成**: 自动运行多设备模拟测试和安全扫描流水线

## 覆盖场景

| 模块 | 说明 |
|------|------|
| 核心网络设备监控 | 路由器/交换机/防火墙状态监控脚本重构 |
| 路由管理 | BGP/OSPF/静态路由配置脚本优化 |
| 主机安全检测 | 资产巡检、漏洞扫描、合规检测脚本升级 |
| 网络安全封堵 | ACL 动态下发、IP 封堵/解封策略重构 |

## 项目结构

```
openclaw-ops-agent/
├── src/
│   ├── agent/          # Agent 核心调度与编排
│   ├── scanner/        # 代码扫描与技术债检测
│   ├── refactor/       # 重构引擎与代码生成
│   ├── security/       # 安全基线与合规检查
│   ├── network/        # 网络规范与协议适配
│   ├── testing/        # 测试框架与模拟器
│   └── utils/          # 工具函数与辅助模块
├── tests/
│   ├── unit/           # 单元测试
│   ├── integration/    # 集成测试
│   └── simulation/     # 多设备模拟测试
├── configs/            # 配置文件(规范/基线/模板)
├── .github/workflows/  # CI/CD 流水线
└── scripts/            # 辅助脚本
```

## 快速开始

### 环境要求

- Python 3.10+
- uv (推荐) 或 pip

### 使用 uv 启动 (推荐)

```bash
# 安装 uv (如果还没有安装)
# Windows: winget install --id=astral-sh.uv -e
# macOS/Linux: curl -LsSf https://astral.sh/uv/install.sh | sh

# 克隆项目后进入目录
cd openclaw-ops-agent

# 创建虚拟环境并安装依赖
uv sync

# 运行扫描
uv run ops-agent scan --target ./legacy-scripts --output ./scan-report

# 执行安全基线检查
uv run ops-agent security --target ./legacy-scripts

# 校验网络规范
uv run ops-agent validate --target ./legacy-scripts

# 运行多设备模拟
uv run ops-agent simulate --devices 10

# 运行测试
uv run pytest tests/ -v
```

### 使用 pip 安装

```bash
pip install -r requirements.txt

# 运行扫描
python -m src scan --target ./legacy-scripts
```

### 运行扫描

```bash
# 扫描指定目录下的运维脚本
python -m src.agent scan --target ./legacy-scripts --output ./scan-report

# 执行重构并生成 PR
python -m src.agent refactor --scan-report ./scan-report --repo my-org/ops-scripts

# 运行全套测试
python -m pytest tests/ -v --simulator=multi-device
```

## 配置说明

详见 `configs/` 目录下的配置文件:

- `network_specs.yaml` - 核心网络设备规范
- `security_baseline.yaml` - 安全基线配置
- `refactoring_rules.yaml` - 重构规则引擎配置
- `acl_templates.yaml` - ACL 动态下发模板

## 成效指标

| 指标 | 优化前 | 优化后 |
|------|--------|--------|
| 代码规范符合率 | 45% | 92% |
| 重构效率 | 基准 | +80% |
| 日均处理脚本数 | 手动 | 500+ |

## License

Internal Use Only
