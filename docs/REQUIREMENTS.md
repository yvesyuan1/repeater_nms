# repeater-nms 第一版需求

## 需求说明

`repeater-nms` 用于 10G IPVB 中继器 RX10 的网管开发。第一版目标覆盖设备管理、SNMP GET 采集、SNMP Trap 实时接收展示、告警管理、基础 Web 页面和部署能力。

## 第一版范围

- 用户登录、退出、用户管理
- 设备管理
- RX10 内置 MIB/OID 展示
- SNMP v2c GET 轮询 APS/DFP 核心状态
- SNMP v2 Trap 接收、保存、翻译、拆分、归一化
- Trap 实时页面，基于 SSE 展示最近 100 条事件
- 活动告警、历史告警、确认、备注、弹窗通知
- MySQL 持久化与 Redis 实时分发
- Nginx、Gunicorn、systemd 部署
- 初始化脚本，包括建表、MIB/枚举/告警规则种子、初始 admin 用户

## 暂不实现内容

- SNMP SET 控制倒换
- 前端倒换操作
- 复杂驾驶舱
- 完整 MIB 编译器
- 多租户
- 企业微信、短信、钉钉通知
- 复杂权限矩阵
- 自动配置下发

## 非功能要求

- Trap 监听与轮询进程必须与 Web 进程分离
- collector 必须容忍单个 Trap 或单个 OID 失败，不得整体崩溃
- 所有敏感配置通过环境变量注入
- 真实 Trap 样本解析必须有离线测试，不依赖真实设备在线
