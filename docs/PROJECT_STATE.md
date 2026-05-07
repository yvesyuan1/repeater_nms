# PROJECT STATE

## 当前阶段

- 当前阶段：阶段2 数据库模型和种子数据
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

## 待办事项

- 进入阶段3，实现 SNMP GET、Trap listener、OID 翻译、告警归一化和 Redis 发布。
- 增加真实 Trap 样本 fixture 与 parser 测试。
- 将数据库初始化逻辑接入后续部署脚本和服务器 `.env`。

## 已知问题

- 阶段2自测使用本地 SQLite 验证建表和幂等逻辑；服务器 MySQL 实际执行留到阶段5部署时完成。
- 远端 `80` 端口当前未监听，部署阶段需确认 Nginx 状态。
- 当前 Web 仍是最小骨架，尚未接入登录、设备管理和告警页面。

## 最近一次部署状态

- 尚未开始部署。

## 重要决策

- 采用 Flask app factory + 独立 collector 模块结构。
- 时间存储方案定为 UTC 入库，页面按 `Asia/Shanghai` 展示。
- 数据库初始化命令默认保护 `zjq_admin` 之外的 MySQL schema，避免误操作。
- 表结构已预留 Trap PDU 拆分、多告警归一化、活动告警去重和弹窗确认所需字段。
