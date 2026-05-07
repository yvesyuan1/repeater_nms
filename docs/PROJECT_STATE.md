# PROJECT STATE

## 当前阶段

- 当前阶段：阶段4 Flask API 和页面
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
- 实现阶段4 Web 能力：
  - 登录、退出
  - 用户管理
  - 设备管理、设备详情
  - MIB 节点展示
  - Trap 查询页面
  - SSE 实时流接口 `GET /api/events/stream`
  - 告警中心、活动告警确认
  - 弹窗通知 API 与页面右下角提示
  - 操作日志页面
- 新增 Web 侧测试：
  - `tests/test_web_app.py`
- 阶段4自测通过：
  - `pytest tests/test_web_app.py tests/test_trap_parser.py tests/test_db_init.py`，共 `8 passed`
  - 本地 Flask 启动 smoke test：
    - `GET /healthz` 返回 `200`
    - `GET /login` 返回 `200`
    - 登录页文本正常显示

## 待办事项

- 进入阶段5，生成 systemd、Nginx 和服务器部署步骤。
- 在服务器上创建 `.env`、venv、初始化数据库并启动服务。
- 在服务器侧验证 UDP 1162 Trap 监听与 Nginx SSE 代理。

## 已知问题

- 阶段2和阶段3的数据库自测使用本地 SQLite 验证建表和幂等逻辑；服务器 MySQL 实际执行留到阶段5部署时完成。
- 远端 `80` 端口当前未监听，部署阶段需确认 Nginx 状态。
- 本地 agent 环境下，对 `172.31.3.239` 的实时 SNMP GET 烟测与命令行 `snmpget` 都出现过超时；该问题未影响离线 parser/collector 链路，需要在后续联调时以你的本机手工命令结果为准再次确认。
- 当前 Web 已完成基础管理页面，但尚未做更细粒度权限矩阵和复杂前端交互。
- 若 Redis 不可用，SSE 接口会返回错误事件，页面会进入自动重连状态；服务器联调时需结合真实 Redis 验证。

## 最近一次部署状态

- 尚未开始部署。

## 重要决策

- 采用 Flask app factory + 独立 collector 模块结构。
- 时间存储方案定为 UTC 入库，页面按 `Asia/Shanghai` 展示。
- 数据库初始化命令默认保护 `zjq_admin` 之外的 MySQL schema，避免误操作。
- 表结构已预留 Trap PDU 拆分、多告警归一化、活动告警去重和弹窗确认所需字段。
- Trap 解析失败时仍保留原始 PDU 记录，写入 `parse_status=failed` 和 `parse_error`。
- Trap 接收白名单优先来源于设备表中的 read community，并可用环境变量补充。
- Web 侧采用请求级 SQLAlchemy session + Flask-Login，SSE 直接订阅 Redis pub/sub，前端用原生 `EventSource` 自动重连。
