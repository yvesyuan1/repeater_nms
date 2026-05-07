# PROJECT STATE

## 当前阶段

- 当前阶段：阶段5，本地试运行与结构优化
- 状态：本地 Web、数据库、采集轮询、Trap 展示链路可运行；服务器正式部署尚未开始

## 已完成内容

- 阶段0环境检查已完成
- 阶段1项目初始化已完成
- 阶段2数据库模型、初始化命令、种子数据已完成
- 阶段3collector、SNMP GET、Trap 解析、样本测试已完成
- 阶段4Web API、页面、SSE、告警中心已完成
- 阶段5本地试运行能力已完成
  - `flask --app wsgi init-db`
  - `flask --app wsgi seed-local-demo`
  - `scripts/run_local_trial.ps1`
  - 本地 SQLite 演示库：`local_trial.sqlite`
  - 本地演示设备：`172.25.22.6`
- 本轮已完成的结构优化
  - 新增设备模板能力，当前内置模板：`bohui_rx10 / 博汇 / RX10 / 中继器`
  - 设备表已关联 `device_profile_code`
  - MIB 节点、枚举、告警规则、Trap 事件已支持按设备模板区分
  - 新增采集策略表 `repeater_polling_strategies`
  - collector 轮询逻辑已改为优先按采集策略驱动
  - 首页已改为“设备运行总览”，直接展示所有设备实时状态
  - 设备详情页“最新 SNMP 状态”已补充分组、中文名、展示值、枚举解释、健康状态、失败信息
  - MIB 页面已改为“设备模板”视角，展示模板、采集策略、MIB、枚举、告警规则
  - 告警中心已改为统一告警列表，不再分“活动告警/历史告警”两个主区块
  - 设备模板页已补充完整配置能力，可对模板、采集策略、MIB 节点、枚举、告警规则执行增删改查
  - 首页总览已补充“查看详情”入口
  - Trap 列表与首页最近 Trap 已补充详情页入口
  - Trap 详情页已支持查看翻译结果、基础字段和原始 Trap JSON

## 待办事项

- 继续优化本地页面细节和数据解释
- 进入阶段5服务器部署
- 生成并验证 `systemd` 服务文件
- 生成并验证 `Nginx` 配置
- 在服务器创建 `venv`、落地 `.env`、初始化数据库并启动服务
- 服务器侧验证 UDP `1162` 监听、Redis、MySQL、SSE

## 已知问题

- 当前仍是本地试运行，尚未完成服务器部署和联调
- Trap 联机验证仍需在服务器侧完成
- `172.25.22.6` 的真实 SNMP 返回值会影响首页和详情页的展示内容，当前页面已按真实轮询结果展示
- 当前只对部分核心状态配置了默认正常判断；未配置判断规则的指标会显示“未知”
- 当前 `repeater_mib_nodes.oid/name` 与 `repeater_mib_enums.enum_name+code` 仍是全局唯一约束，不支持跨模板重复定义同名节点/枚举；如后续要彻底放开，需要单独做约束迁移

## 最近一次部署状态

- 本地试运行成功，Web 地址：`http://127.0.0.1:5000`
- 本地 `poll-once` 成功，当前按策略采集 `8` 个核心状态项
- 本地测试通过：
  - `pytest tests/test_web_app.py tests/test_trap_parser.py tests/test_db_init.py`
  - 结果：`9 passed`
- 服务器部署尚未开始

## 重要决策

- 采用单仓库、Web 与 collector 分进程结构
- 时间存储方案保持为 UTC 入库，页面按 `Asia/Shanghai` 展示
- 数据库初始化继续坚持只新增/补字段，不删表重建
- 设备模板能力采用最小可用抽象，避免为单一 `RX10` 写死主流程
- 采集策略已落库，后续新增设备型号时优先通过模板、MIB、策略、告警规则扩展
- Trap 解析失败时仍保留原始 PDU，并写入 `parse_status=failed` 与 `parse_error`
