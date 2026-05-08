# PROJECT STATE

## 当前阶段

- 当前阶段：阶段5
- 状态：服务器部署与联调已完成，待进入阶段6验收

## 已完成内容

- 阶段0环境检查已完成
- 阶段1项目初始化已完成
- 阶段2数据库模型、初始化命令、种子数据已完成
- 阶段3collector、SNMP GET、Trap 解析、样本测试已完成
- 阶段4Web API、页面、SSE、告警中心已完成
- 阶段5服务器部署已完成

## 本阶段完成结果

- 已将项目部署到 `/home/jkxz/yves-admin`
- 已在服务器创建 Python 虚拟环境并安装依赖
- 已在服务器落地真实 `.env`
- 已完成 MySQL `zjq_admin` 初始化与种子数据导入
- 已创建并启用 `repeater-nms-web.service`
- 已创建并启用 `repeater-nms-collector.service`
- 已创建并启用 Nginx 站点 `/etc/nginx/sites-available/repeater-nms`
- Web 通过 Gunicorn 监听 `127.0.0.1:5000`
- Nginx 已对外监听 `10099`
- collector 已监听 `0.0.0.0:1162/udp`
- Redis 已接入服务器本机服务
- 已在服务器录入设备 `172.25.22.6`
- 服务器轮询已成功，单次轮询返回 `1` 台设备、`8` 个核心状态项
- 已验证真实 Trap 从 `172.25.22.6` 到达服务器 `1162/udp`
- 已验证真实 Trap 成功写入 `zjq_admin.repeater_trap_events`
- 已验证本机访问 `http://172.25.22.2:10099/login` 返回 `200`

## 待办事项

- 进入阶段6验收
- 验证 SSE 页面实时推送是否可在浏览器侧稳定接收
- 验证更多真实 Trap 样本的拆分、翻译、活动告警和弹窗逻辑
- 验证告警中心、设备总览、Trap 详情页在服务器环境下的展示完整性
- 补充服务器部署后的操作手册和回滚步骤

## 已知问题

- 服务器当前已完成单条真实 `almchg` Trap 入库验证，但仍需继续观察多条同 PDU Trap 的线上表现
- 采集与 Trap 已联通，后续仍需按阶段6补做完整验收清单
- 当前设备模板、MIB、枚举、告警规则已可配置，但复杂模板复制和版本化仍未实现

## 最近一次部署状态

- 部署时间：2026-05-08
- 部署目录：`/home/jkxz/yves-admin`
- 对外访问地址：`http://172.25.22.2:10099`
- Web 服务状态：运行中
- Collector 服务状态：运行中
- Nginx 状态：运行中
- MySQL 初始化：成功
- Redis 连通性：成功
- Trap 监听：成功
- 真实 Trap 入库：成功

## 重要决策

- 保持单仓库、Web 与 collector 分进程部署
- 保持 UTC 入库，前端按 `Asia/Shanghai` 展示
- Web 仅监听 `127.0.0.1:5000`，由 Nginx 暴露 `10099`
- collector 独立监听 `0.0.0.0:1162/udp`
- 服务器外网不稳定，继续采用“本地生成代码与配置，再同步到服务器”的部署方式
- 数据库仅操作 `zjq_admin` 中的 `repeater_` 前缀表
