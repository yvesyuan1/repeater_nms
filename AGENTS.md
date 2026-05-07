# repeater-nms AGENTS

## 项目规则

- 项目业务名称统一使用 `repeater-nms`。
- Python 包名统一使用 `repeater_nms`。
- Web 服务名统一使用 `repeater-nms-web`。
- 采集服务名统一使用 `repeater-nms-collector`。
- 页面标题统一使用 `中继器网管`。
- 服务器部署目录固定为 `/home/jkxz/yves-admin`。
- 数据库固定使用已有 schema `zjq_admin`，禁止创建新数据库。
- Redis channel 前缀固定使用 `repeater_nms`。

## 架构约束

- 采用单仓库、多进程服务结构。
- Web 进程负责 Flask API、模板页面、登录鉴权、SSE 输出。
- Collector 进程负责 SNMP GET 轮询、Trap 监听、OID 翻译、告警归一化、MySQL/Redis 写入。
- Trap 监听与轮询逻辑禁止运行在 Flask Web 进程内。
- Gunicorn 可以多进程运行 Web，但 collector 必须保持单实例。
- Trap 实时展示必须使用 SSE/EventSource，禁止用定时刷新冒充实时。
- 数据库存储时间统一采用 UTC，前端和页面默认按 `Asia/Shanghai` 展示。

## 禁止事项

- 禁止把数据库密码、SNMP community、管理员密码写入 Git 或提交到仓库。
- 禁止提交真实 `.env` 文件，仓库只保留 `.env.example`。
- 禁止执行 `drop database`、`truncate table`、删除非本项目表、覆盖 Nginx 主配置。
- 禁止修改 `zjq_admin` 中非 `repeater_` 前缀的任何表。
- 禁止在日志中明文输出数据库密码、SNMP read/write community、管理员密码。
- 禁止假设服务器可稳定访问外网安装依赖，优先本地生成文件后再部署。

## 常用命令

- 初始化本地依赖：`python -m venv .venv`
- 安装依赖：`.venv\Scripts\python -m pip install -r requirements.txt`
- 启动开发 Web：`.venv\Scripts\python -m flask --app wsgi run --debug`
- 启动 collector 骨架：`.venv\Scripts\python -m repeater_nms.collector`
- 初始化数据库：`.venv\Scripts\python -m flask --app wsgi init-db`
- 初始化数据库（独立入口）：`.venv\Scripts\python -m repeater_nms.db init-db`
- 运行测试：`.venv\Scripts\python -m pytest`
- 查看远端服务：`ssh WYJ-2 'systemctl status repeater-nms-web repeater-nms-collector --no-pager'`

## 数据库和部署注意事项

- 所有表名必须使用 `repeater_` 前缀。
- 初始化脚本必须可重复执行，且种子数据不可重复插入。
- 活动告警去重键固定为 `device_id + alarm_obj + alarm_id`。
- Trap 事件必须支持同一个 PDU 拆分为多条告警，并保留共同的 `pdu_id`。
- 设备匹配必须优先使用 Trap UDP 源 IP，不得用源端口匹配。
- 服务器部署优先流程为：本地准备代码与依赖清单，再通过 SSH/SCP/rsync 同步到远端。
- Nginx 仅允许新增 `/etc/nginx/sites-available/repeater-nms`，不得覆盖 `/etc/nginx/nginx.conf`。
