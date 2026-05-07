# PROJECT STATE

## 当前阶段

- 当前阶段：阶段3 collector
- 状态：已完成

## 已完成内容

- 完成阶段0环境检查。
- 完成阶段1项目初始化、本地 Git 仓库初始化和基础骨架搭建。
- 新增数据库模块：`repeater_nms/db/`，包含 `base`、`session`、`models`、`seeds`、`init_db`。
- 实现 13 张 `repeater_` 前缀表模型：
  - `repeater_users`
  - `repeater_devices`
  - `repeater_mib_nodes`
  - `repeater_mib_enums`
  - `repeater_snmp_metric_samples`
  - `repeater_device_latest_values`
  - `repeater_trap_events`
  - `repeater_alarm_rules`
  - `repeater_active_alarms`
  - `repeater_alarm_events`
  - `repeater_alarm_ack_logs`
  - `repeater_popup_notifications`
  - `repeater_operation_logs`
- 实现幂等初始化逻辑：
  - 只允许对 MySQL schema `zjq_admin` 执行初始化
  - 建表前先检查已存在的 `repeater_` 表
  - 重复执行不重复插入 MIB、枚举、告警规则种子
  - 初始 `admin` 用户仅在不存在时创建，密码从 `ADMIN_PASSWORD` 读取
- 导入内置种子数据：
  - MIB/OID 26 条
  - 枚举 22 条
  - 告警规则 35 条
- 提供两个初始化入口：
  - `flask --app wsgi init-db`
  - `python -m repeater_nms.db init-db`
- 实现 collector 核心链路：
  - `pysnmp` v2c GET 封装
  - RX10 Trap PDU 解析
  - 按 OID 后缀索引拆分多条告警
  - OID/MIB/枚举翻译
  - 告警归一化
  - MySQL 持久化
  - Redis 发布接口封装
  - collector 单实例锁
  - `pysnmp` Trap listener 封装
- 新增真实样本 fixture：
  - `tests/fixtures/rx10_almchg_tcpdump_sample.txt`
- 新增阶段3测试：
  - `tests/test_trap_parser.py`
- 阶段3自测通过：
  - `pytest tests/test_trap_parser.py tests/test_db_init.py`，共 `5 passed`
  - `python -m repeater_nms.collector parse-fixture --fixture tests/fixtures/rx10_almchg_tcpdump_sample.txt`
  - `PysnmpTrapListener` 本地绑定/启动/停止 smoke test
  - `python -m repeater_nms.collector poll-once` 零设备场景 smoke test

## 待办事项

- 进入阶段4，实现登录、设备管理、Trap 查询、SSE、告警中心与页面。
- 将 collector 发布的 `repeater_nms:trap_events` 接入 Flask SSE。
- 增加基于服务器的 Trap 联机验证和页面联调。

## 已知问题

- 阶段2和阶段3的数据库自测使用本地 SQLite 验证建表和幂等逻辑；服务器 MySQL 实际执行留到阶段5部署时完成。
- 远端 `80` 端口当前未监听，部署阶段需确认 Nginx 状态。
- 当前 Web 仍是最小骨架，尚未接入登录、设备管理和告警页面。
- 本地 agent 环境下，对 `172.31.3.239` 的实时 SNMP GET 烟测与命令行 `snmpget` 都出现过超时；该问题未影响离线 parser/collector 链路，需要在后续联调时以你的本机手工命令结果为准再次确认。

## 最近一次部署状态

- 尚未开始部署。

## 重要决策

- 采用 Flask app factory + 独立 collector 模块结构。
- 时间存储方案定为 UTC 入库，页面按 `Asia/Shanghai` 展示。
- 数据库初始化命令默认保护 `zjq_admin` 之外的 MySQL schema，避免误操作。
- 表结构已预留 Trap PDU 拆分、多告警归一化、活动告警去重和弹窗确认所需字段。
- Trap 解析失败时仍保留原始 PDU 记录，写入 `parse_status=failed` 和 `parse_error`。
- Trap 接收白名单优先来源于设备表中的 read community，并可用环境变量补充。
