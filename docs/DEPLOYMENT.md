# repeater-nms 部署说明

## 本地开发方式

- 本地目录：`F:\codeXSpace\repeater_nms`
- 推荐 Python 3.12 虚拟环境
- 开发 Web：
  - `python -m flask --app wsgi run --debug`
- 启动 collector：
  - `python -m repeater_nms.collector`
- 初始化数据库：
  - `python -m flask --app wsgi init-db`
- 运行测试：
  - `python -m pytest`

## 本地试运行方式

- 试运行脚本：
  - `powershell -ExecutionPolicy Bypass -File .\scripts\run_local_trial.ps1`
- 本地试运行默认使用 SQLite
- 默认地址：
  - `http://127.0.0.1:5000`

## 服务器部署方式

- 服务器别名：`WYJ-2`
- 部署目录：`/home/jkxz/yves-admin`
- 同步方式：优先在本地准备代码，再通过 `scp` 或等价方式同步
- 生产环境真实 `.env` 只允许放在：
  - `/home/jkxz/yves-admin/.env`

推荐顺序：

1. 同步代码到 `/home/jkxz/yves-admin`
2. 创建虚拟环境并安装依赖
3. 写入服务器 `.env`
4. 初始化数据库
5. 安装 systemd 服务文件
6. 安装 Nginx 站点配置
7. 执行 `nginx -t`
8. 启动并检查 Web、collector、Nginx

## 当前服务器试运行结果

- 服务器访问地址：
  - `http://172.25.22.2:10099`
- Gunicorn：
  - `127.0.0.1:5000`
- Collector：
  - `0.0.0.0:1162/udp`
- Redis：
  - `127.0.0.1:6379`
- MySQL：
  - `127.0.0.1:3306`

## systemd

已生成并使用以下服务文件：

- `deploy/systemd/repeater-nms-web.service`
- `deploy/systemd/repeater-nms-collector.service`

安装位置：

- `/etc/systemd/system/repeater-nms-web.service`
- `/etc/systemd/system/repeater-nms-collector.service`

常用命令：

- `sudo systemctl daemon-reload`
- `sudo systemctl enable --now repeater-nms-web repeater-nms-collector`
- `sudo systemctl status repeater-nms-web repeater-nms-collector --no-pager`
- `journalctl -u repeater-nms-web -n 100 --no-pager`
- `journalctl -u repeater-nms-collector -n 100 --no-pager`

## Nginx

站点配置文件：

- `deploy/nginx/repeater-nms.conf`

服务器安装路径：

- `/etc/nginx/sites-available/repeater-nms`

启用方式：

- 建立到 `/etc/nginx/sites-enabled/repeater-nms` 的软链接

要求：

- 不覆盖 `/etc/nginx/nginx.conf`
- 反代到 `127.0.0.1:5000`
- 对 `/api/events/stream` 关闭 buffering
- 变更后先执行：
  - `sudo nginx -t`
- 测试成功后再执行：
  - `sudo systemctl reload nginx`

当前对外端口：

- `10099/tcp`

## MySQL

- schema：`zjq_admin`
- 用户：`my_analyzer`
- 只允许创建和维护 `repeater_` 前缀表
- 初始化命令：
  - `python -m flask --app wsgi init-db`

注意事项：

- 不新建数据库
- 不修改 `zjq_admin` 中非 `repeater_` 前缀表
- 如果密码包含 `@` 等特殊字符，`DATABASE_URL` 中必须做 URL 编码
- 时间统一按 UTC 入库，前端按 `Asia/Shanghai` 展示

## Redis

- 地址：`redis://127.0.0.1:6379/0`
- 实时事件通道：
  - `repeater_nms:trap_events`

用途：

- SSE 实时事件发布
- 最新状态缓存
- 实时 Trap 缓存

## Trap 端口说明

- Collector 监听：
  - `0.0.0.0:1162/udp`
- 设备源端口可能是 `162/udp`
- 设备匹配必须优先使用源 IP，不得使用源端口
- 单条 Trap 解析失败不得导致 collector 退出

## 服务器验收检查

- `ss -lntp | grep 10099`
- `ss -lntp | grep 5000`
- `ss -lunp | grep 1162`
- `redis-cli ping`
- `curl -I http://127.0.0.1:10099/login`
- `journalctl -u repeater-nms-collector -n 100 --no-pager`
- `mysql -h127.0.0.1 -u<user> -p -e "select count(*) from zjq_admin.repeater_trap_events;"`
