# PROJECT STATE

## 当前阶段

- 当前阶段：阶段6
- 状态：已完成阶段6验收

## 已完成内容

- 阶段0：完成本地与服务器环境检查、风险梳理、TODO 和阶段计划
- 阶段1：完成项目初始化、基础文档、最小 Flask Web 和 collector 骨架
- 阶段2：完成数据库模型、初始化命令、幂等建表、MIB/枚举/告警规则种子数据、admin 初始化逻辑
- 阶段3：完成 SNMP GET、Trap 解析、RX10 多告警拆分、告警归一化、MySQL/Redis 写入、样本测试
- 阶段4：完成登录、设备管理、设备模板、Trap 页面、告警中心、SSE、操作日志和前端页面
- 阶段5：完成服务器部署、systemd、Nginx、MySQL 初始化、Redis 接入、真实设备联调
- 阶段6：完成验收、自测、README 收口、项目状态文档更新

## 阶段6验收结果

- Web 对外地址：`http://172.25.22.2:10099/login`
- `repeater-nms-web` 状态：`active`
- `repeater-nms-collector` 状态：`active`
- `nginx` 状态：`active`
- Gunicorn 监听：`127.0.0.1:5000`
- Collector 监听：`0.0.0.0:1162/udp`
- MySQL 监听：`127.0.0.1:3306`
- Redis 监听：`127.0.0.1:6379`
- Redis 连通：`PONG`
- 数据库表前缀检查：仅使用 `zjq_admin` 中 `repeater_` 前缀表
- 设备数量：`1`
- 最新 SNMP 状态数量：`8`
- Trap 事件数量：`547`
- 活动告警数量：`6`
- 告警事件数量：`229`
- 未确认弹窗数量：`0`
- 最近轮询状态：设备 `RX10-SERVER / 172.25.22.6` 为 `ok`
- Redis 最新快照 key：`repeater_nms:device:1:latest_poll`
- 已验证多条同 PDU 拆分入库，示例 `pdu_id`：
  - `e5e112d874648a62`，拆分 `14` 条
  - `cfa1c36f5fc67c90`，拆分 `14` 条
  - `084dbf03b16c5b49`，拆分 `14` 条
- Collector 日志已验证真实 Trap 进入解析链路，最近可见 `performance` Trap `split_count=14`

## 最近一次自测

- 本地测试命令：
  - `python -m pytest tests/test_web_app.py tests/test_trap_parser.py tests/test_db_init.py`
- 本地结果：`15 passed`
- 覆盖内容：
  - Web 主要页面访问
  - Trap 解析与多告警拆分
  - 告警规则与活动告警逻辑
  - 分页和过滤
  - 数据库初始化与种子数据

## 当前功能状态

- 已支持设备模板，不再写死 RX10
- 内置模板：`bohui_rx10 / 博汇 / RX10 / 中继器`
- 已支持按模板区分：
  - MIB 节点
  - 枚举翻译
  - 采集策略
  - Trap 解析归属
  - 告警规则
- 已支持首页设备运行总览
- 已支持 Trap 实时页、详情页、分页、多选过滤、Trap 类型过滤
- 已支持告警中心时间线展示、分页、筛选、确认
- 已支持 Redis pub/sub + SSE 实时推送

## 已知问题

- 当前仅完成单设备真实联调，多设备并发场景尚未做压力验证
- 设备模板已支持增删改查，但尚未实现模板复制和版本化
- 采集策略已支持枚举匹配和数值比较，但暂未提供更复杂的表达式规则
- Trap 详情页仍以 JSON 明细为主，后续可继续增强成更强的运维排障视图

## 最近一次部署状态

- 部署日期：`2026-05-08`
- 部署目录：`/home/jkxz/yves-admin`
- Web 访问：`http://172.25.22.2:10099`
- 服务器状态：运行中
- 真实轮询：运行中
- 真实 Trap：运行中

## 重要决策

- 单仓库、多进程：Web 与 collector 独立进程部署
- 时间方案：UTC 入库，页面按 `Asia/Shanghai` 展示
- Collector 单实例运行，避免重复监听 `1162/udp`
- Web 通过 Gunicorn + Nginx 提供服务，对外端口固定为 `10099`
- Trap 与告警主数据以 MySQL 为准，Redis 仅承担实时分发与缓存
- 只允许操作 `zjq_admin` 中 `repeater_` 前缀表

## 下一步建议

- 继续补充多设备实机联调
- 增强 Trap 详情页的运维可读性
- 为设备模板增加模板复制与版本管理
- 增加阶段性备份、恢复和回滚脚本
