# SingScan

SingScan 是一个面向授权渗透测试场景的自动化资产发现与信息收集系统。它把子域名枚举、存活探测、端口扫描、URL 爬取、目录爆破和漏洞验证串成一条可持续执行的扫描流程，并用 SQLite 保存资产状态，避免重复扫描。

## 核心能力

- 子域名收集：通过 `Subfinder` 枚举目标域名资产。
- 存活探测：通过 `Httpx` 判断存活站点并采集标题、技术栈、CDN、IP 等信息。
- 深度扫描：根据资产状态继续执行 `Nmap`、`URLFinder`、`FFUF`、`EHole`。
- 规则驱动验证：结合 `RuleEngine` 和 `ScanPlanner` 生成 `Nuclei` / `Afrog` 分组计划，只对高价值目标做聚焦验证。
- 状态持久化：扫描结果写入 `assets.db`，后续阶段基于数据库快照继续推进。

## 当前架构

```text
├── main.py                      # 程序入口
├── singscan/
│   ├── db_manager.py            # SQLite 持久化、schema 维护、结果回写
│   └── modules/
│       ├── scan_orchestrator.py # 串联完整扫描流程
│       ├── scan_planner.py      # 决定下一步扫什么
│       ├── target_file_writer.py# 把计划写成扫描器可消费的目标文件
│       ├── rule_engine.py       # 资产评分与动作建议
│       ├── ehole_result_mapper.py
│       └── *.py                 # 各扫描器 adapter
├── result/                      # 扫描结果目录
└── assets.db                    # SQLite 资产库
```

### 关键模块职责

- `singscan/modules/scan_orchestrator.py`：流程编排层，负责串联各阶段并协调 planner、adapter 与持久化层。
- `singscan/modules/scan_planner.py`：只负责根据资产快照生成下一阶段目标和 `Nuclei` / `Afrog` 分组计划。
- `singscan/modules/target_file_writer.py`：把 planner 产出的目标列表写成 txt 文件，供具体扫描器消费。
- `singscan/db_manager.py`：负责建表、schema 补齐、扫描结果入库、状态回写，以及给 planner / rule engine 提供读取接口。
- `singscan/modules/ehole_result_mapper.py`：处理 `EHole` 输出，提取子域名、归一化技术指纹，并合并技术栈信息。

## 扫描流程

1. `Subfinder` 收集子域名并写入数据库。
2. `Httpx` 探测存活目标并更新标题、IP、技术栈、CDN 等字段。
3. `EHole` 在存活目标上补充指纹信息，`RuleEngine` 完成第一轮资产评分。
4. `Nmap` 和 `URLFinder` 并发执行，继续补充端口和 URL 数据。
5. `RuleEngine` 再次评估资产，`ScanPlanner` 生成 `Nuclei` / `Afrog` 分组计划。
6. `Nuclei` 和 `Afrog` 对高优先级目标执行规则驱动的漏洞验证。

## 运行方式

### 方式 1：兼容入口

```bash
python main.py
```

当前根入口会执行 `main.py` 中写入的目标域名：`demo.com`。

## 运行前准备

- Python 3 环境可用。
- 外部扫描工具已经安装并能从当前代码调用成功：`Subfinder`、`Httpx`、`Nmap`、`URLFinder`、`FFUF`、`EHole`、`Nuclei`、`Afrog`。
- 扫描行为仅应在授权范围内执行。

## 输出与数据

- 数据库默认写入仓库根目录的 `assets.db`。
- 扫描结果默认输出到 `result/YYYYMMDD_<domain>/`。
- `singscan/modules/publi.py` 会把结果目录固定在仓库根目录，而不是 `singscan/` 包内部。

## **成果展示**

- ##### 一站式获取站点信息

![b841df9b5143f4a04dc75c7dc2eb1284](img\b841df9b5143f4a04dc75c7dc2eb1284.png)

![809a7c3642c15343c610dba2b6b5d18b](img\809a7c3642c15343c610dba2b6b5d18b.png)

##### 数据库将系统、中间件、ip、是否还有cnd、每个工具的使用状态等全部记录

![97e9cac05b694699984eb2d692c13e65](img\97e9cac05b694699984eb2d692c13e65.png![4](img\4.png)![5](img\5.png)![3](img\3.png)

![97e9cac05b694699984eb2d692c13e65](img\97e9cac05b694699984eb2d692c13e65.png)
