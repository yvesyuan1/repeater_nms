# repeater-nms AGENTS

## 项目规则

- 项目业务名统一使用 `repeater-nms`
- Python 包名统一使用 `repeater_nms`
- Web 服务名统一使用 `repeater-nms-web`
- 采集服务名统一使用 `repeater-nms-collector`
- 页面标题统一使用 `中继器网管`
- MySQL schema 固定使用 `zjq_admin`
- 所有业务表必须使用 `repeater_` 前缀
- Redis channel 前缀固定使用 `repeater_nms`
- 服务器部署目录固定为 `/home/jkxz/yves-admin`

## 架构约束

- 单仓库，多进程服务
- Web 进程负责 Flask API、模板页面、登录鉴权、SSE 输出
- Collector 进程负责 SNMP GET 轮询、Trap 监听、OID 翻译、告警归一化、MySQL/Redis 写入
- Trap 监听和轮询逻辑禁止运行在 Flask Web 进程内
- Gunicorn 可以多进程运行 Web，collector 必须保持单实例
- Trap 实时展示必须使用 SSE/EventSource，不允许定时刷新冒充实时
- 时间统一按 UTC 入库，前端默认按 `Asia/Shanghai` 展示

## 禁止事项

- 不要把数据库密码、SNMP community、管理员密码写入 Git 或提交到仓库
- 仓库只保留 `.env.example`，真实 `.env` 只放服务器部署目录
- 不要执行 `drop database`、`truncate table`、删除非本项目表、覆盖 Nginx 主配置
- 不要修改 `zjq_admin` 中非 `repeater_` 前缀的任何表
- 不要在日志中明文输出数据库密码、SNMP read/write community、管理员密码
- 不要假设服务器可以稳定访问外网下载依赖，优先本地生成文件后再部署

## 常用命令

- 创建虚拟环境：`python -m venv .venv`
- 安装依赖：`.venv\Scripts\python -m pip install -r requirements-dev.txt`
- 启动开发 Web：`.venv\Scripts\python -m flask --app wsgi run --debug`
- 启动 collector：`.venv\Scripts\python -m repeater_nms.collector`
- 初始化数据库：`.venv\Scripts\python -m flask --app wsgi init-db`
- 独立入口初始化数据库：`.venv\Scripts\python -m repeater_nms.db init-db`
- 初始化本地演示数据：`.venv\Scripts\python -m flask --app wsgi seed-local-demo`
- 本地试运行脚本：`powershell -ExecutionPolicy Bypass -File .\scripts\run_local_trial.ps1`
- 解析 Trap fixture：`.venv\Scripts\python -m repeater_nms.collector parse-fixture --fixture tests/fixtures/rx10_almchg_tcpdump_sample.txt`
- 执行一次轮询：`.venv\Scripts\python -m repeater_nms.collector poll-once`
- 运行测试：`.venv\Scripts\python -m pytest`
- 查看远端服务：`ssh WYJ-2 'systemctl status repeater-nms-web repeater-nms-collector --no-pager'`

## 数据库和部署注意事项

- 初始化脚本必须可重复执行，种子数据不能重复插入
- 活动告警去重键固定为 `device_id + alarm_obj + alarm_id`
- Trap 事件必须支持同一 PDU 拆分为多条告警，并保留共同 `pdu_id`
- 设备匹配必须优先使用 Trap UDP 源 IP，不得使用源端口匹配
- 远端部署优先流程为：本地准备代码与依赖清单，再通过 SSH/SCP/rsync 同步到服务器
- Nginx 仅允许新增 `/etc/nginx/sites-available/repeater-nms`，不得覆盖 `/etc/nginx/nginx.conf`
