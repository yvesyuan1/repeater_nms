# repeater-nms 部署说明

## 本地开发方式

- 本地目录：`F:\codeXSpace\repeater_nms`
- 推荐使用 Python 3.12 虚拟环境。
- 使用 `.env.example` 复制生成本地临时 `.env`，仅用于本地调试，不提交 Git。
- 开发期 Web 运行在 `127.0.0.1:5000`。
- collector 开发期可先跑骨架和离线解析测试，不依赖真实设备。

## 服务器部署方式

- 服务器通过 `ssh WYJ-2` 访问。
- 部署目录固定为 `/home/jkxz/yves-admin`。
- 优先在本地准备项目文件，再通过 `scp` 或 `rsync` 同步到远端。
- 远端真实 `.env` 只放在 `/home/jkxz/yves-admin/.env`。
- 远端 Python 运行在独立 `venv` 中。

## systemd

计划提供两个服务：

- `repeater-nms-web.service`
- `repeater-nms-collector.service`

原则：

- Web 服务通过 Gunicorn 监听 `127.0.0.1:5000`。
- collector 必须保持单实例，监听 `0.0.0.0:1162/udp`。
- collector 进程会从设备表加载已启用设备的 read community 作为 Trap 接收白名单，也可通过 `SNMP_TRAP_COMMUNITIES` 追加。
- 服务文件放在 `/etc/systemd/system/`，修改后执行 `systemctl daemon-reload`。

## Nginx

- 新增站点配置文件 `/etc/nginx/sites-available/repeater-nms`。
- 仅新增站点，不覆盖 `/etc/nginx/nginx.conf`。
- 反向代理到 `127.0.0.1:5000`。
- `/api/events/stream` 必须关闭 buffering，并配置长超时以支持 SSE。
- 变更后先执行 `nginx -t`，成功后再 `systemctl reload nginx`。

## MySQL

- 使用已有 schema：`zjq_admin`。
- 用户：`my_analyzer`。
- 真实密码仅通过环境变量 `DB_PASSWORD` 注入。
- 只允许创建和维护 `repeater_` 前缀表。
- 数据库存储时间统一采用 UTC，前端展示转换为 `Asia/Shanghai`。
- 阶段2初始化命令：
  - `python -m flask --app wsgi init-db`
  - `python -m repeater_nms.db init-db`
- 初始化命令会校验目标库名；非 `zjq_admin` 的 MySQL schema 会直接拒绝执行。

## Redis

- 默认地址：`redis://127.0.0.1:6379/0`
- SSE 与 collector 实时事件 channel：`repeater_nms:trap_events`
- 可扩展缓存键前缀：`repeater_nms:*`
- collector 会缓存每台设备最近一次轮询状态，供后续 Web 页面直接读取。

## Trap 端口说明

- collector 监听 `0.0.0.0:1162/udp`
- 设备侧示例配置目标：`172.25.22.2/1162`
- 样本中设备源端口可能是 `162`，不得据此匹配设备
- 1162 不是低端口，collector 不要求 root 或 `CAP_NET_BIND_SERVICE`
