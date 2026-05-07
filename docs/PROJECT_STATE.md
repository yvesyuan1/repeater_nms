# PROJECT STATE

## 当前阶段

- 当前阶段：阶段5，本地试运行中
- 状态：已完成本地试运行，尚未开始服务器部署

## 已完成内容

- 阶段0环境检查已完成
- 阶段1项目初始化已完成
- 阶段2数据库模型、初始化命令、种子数据已完成
- 阶段3collector、Trap 解析、样本测试已完成
- 阶段4Web API、页面、SSE、告警中心已完成
- 已补充本地试运行能力：
  - `flask --app wsgi seed-local-demo`
  - `scripts/run_local_trial.ps1`
  - 本地 SQLite 演示库 `local_trial.sqlite`
  - 预置设备 `172.25.22.6`
  - 预置 Trap / 活动告警 / 弹窗数据
- 已补充 `cryptography` 依赖，兼容 MySQL 8 认证插件

## 待办事项

- 进入阶段5服务器部署
- 生成并验证 systemd 服务文件
- 生成并验证 Nginx 配置
- 在服务器创建 venv、`.env`、初始化数据库并启动服务
- 服务器侧验证 UDP 1162 监听、Redis、MySQL、SSE

## 已知问题

- 当前只完成本地试运行，未做服务器联调
- Trap 联机验证仍需在服务器侧完成
- 设备 `172.25.22.6` 的真实 SNMP 联调需等待你的网络恢复后再次验证

## 最近一次部署状态

- 本地试运行成功，Web 已可访问
- 服务器部署尚未开始

## 重要决策

- 采用 Flask app factory + 独立 collector 模块结构
- 时间存储方案定为 UTC 入库，页面按 `Asia/Shanghai` 展示
- 数据库初始化命令默认保护 `zjq_admin` 之外的 MySQL schema
- Trap 解析失败时仍保留原始 PDU 记录，并写入 `parse_status=failed` 与 `parse_error`
- Web 侧采用 Flask-Login；SSE 直接订阅 Redis pub/sub；前端使用原生 `EventSource`
