# RX10 MIB 与 Trap 映射

## 根 OID

- 企业根：`1.3.6.1.4.1.42669`
- Trap 根：`1.3.6.1.4.1.42669.1`
- APS 根：`1.3.6.1.4.1.42669.2`
- DFP 根：`1.3.6.1.4.1.42669.3`

## Trap 通知

| 名称 | 完整 OID | 含义 |
| --- | --- | --- |
| almchg | `1.3.6.1.4.1.42669.1.1.0.1` | 告警变更通知 |
| performance | `1.3.6.1.4.1.42669.1.1.0.5` | 性能数据上报通知 |

## almchgTable 字段

| 字段 | OID 前缀 | 含义 |
| --- | --- | --- |
| almChgIdx | `1.3.6.1.4.1.42669.1.2.1.1.1` | 索引，格式 `ifindex.almid` |
| almChgObj | `1.3.6.1.4.1.42669.1.2.1.1.2` | 告警对象 |
| almChgAid | `1.3.6.1.4.1.42669.1.2.1.1.3` | 告警 ID |
| almChgLvl | `1.3.6.1.4.1.42669.1.2.1.1.4` | 告警级别 |
| almChgTime | `1.3.6.1.4.1.42669.1.2.1.1.5` | 设备上报告警时间原始值 |
| almChgStat | `1.3.6.1.4.1.42669.1.2.1.1.6` | 告警状态 |
| almChgObjDesc | `1.3.6.1.4.1.42669.1.2.1.1.7` | 告警对象描述 |

## performanceTable 字段

| 字段 | OID 前缀 | 含义 |
| --- | --- | --- |
| perIdx | `1.3.6.1.4.1.42669.1.2.5.1.1` | 索引，格式 `time.ordinal` |
| perDesc | `1.3.6.1.4.1.42669.1.2.5.1.2` | 性能字符串 `objid,perid,val,flag,nms,vneid` |

## 其他节点

| 名称 | OID | 权限 | 含义 |
| --- | --- | --- | --- |
| almGetall | `1.3.6.1.4.1.42669.1.2.200` | read-only | 手动触发设备重新上报当前所有告警 |

## APS 节点

| 名称 | OID | 权限 | 含义 |
| --- | --- | --- | --- |
| apsEn | `1.3.6.1.4.1.42669.2.1` | read-write | APS 使能 |
| apsWorkPort | `1.3.6.1.4.1.42669.2.2` | read-only | 当前 APS 工作口 |
| apsPrtPort | `1.3.6.1.4.1.42669.2.3` | read-only | 当前 APS 保护口 |
| apsRevertive | `1.3.6.1.4.1.42669.2.4` | read-write | 恢复模式 |
| apsWtrTime | `1.3.6.1.4.1.42669.2.5` | read-write | WTR 时间 |
| apsHoldoffTime | `1.3.6.1.4.1.42669.2.6` | read-write | 保护倒换延迟 |
| apsBwsvThrd | `1.3.6.1.4.1.42669.2.7` | read-write | 带宽保护倒换阈值 |
| apsSwCmd | `1.3.6.1.4.1.42669.2.8` | read-write | 倒换命令，第一版只展示 |
| apsActive | `1.3.6.1.4.1.42669.2.9` | read-only | 当前活跃侧 |
| apsStat | `1.3.6.1.4.1.42669.2.10` | read-only | APS 状态机状态 |

## DFP 节点

| 名称 | OID | 权限 | 含义 |
| --- | --- | --- | --- |
| dfpEn | `1.3.6.1.4.1.42669.3.1` | read-write | DFP 使能 |
| dfpPeer | `1.3.6.1.4.1.42669.3.2` | read-only | DFP 对端 IPv4 地址 |
| dfpSwCmd | `1.3.6.1.4.1.42669.3.3` | read-write | 倒换命令，第一版只展示 |
| dfpActive | `1.3.6.1.4.1.42669.3.4` | read-only | 当前 DFP 活跃侧 |

## 枚举说明

### EALARMLVL

- `0` = `cleared`
- `1` = `indeterminate`
- `2` = `warning`
- `3` = `minor`
- `4` = `major`
- `5` = `critical`

### EALARMSTAT

- `42` = `change`
- `43` = `report`
- `45` = `close`

### EAPSSTATE

- `0` = `normal`
- `1` = `holdW`
- `2` = `holdP`
- `3` = `protectW`
- `4` = `protectP`
- `5` = `wtrW`
- `6` = `wtrP`
- `7` = `forceW`
- `8` = `forceP`
- `15` = `disable`

### EDFPCMD

- `0` = `normal`
- `1` = `self`
- `2` = `peer`

## 告警规则

### Critical

- Power1_Fail
- Power2_Fail
- HighTemp
- LowTemp
- PKG_FAIL
- LOS
- LsrOffline
- HighSysMem
- HighRootfs
- HighAppdisk
- PKG_NOTREADY

### Major

- FAN1_FAIL
- FAN2_FAIL
- FAN3_FAIL
- FAN4_FAIL

### Warning

- LB_15L
- LB_24L
- LB_15H
- LB_24H
- LT_15L
- LT_24L
- LT_15H
- LT_24H
- IOP_15L
- IOP_24L
- IOP_15H
- IOP_24H
- OOP_15L
- OOP_24L
- OOP_15H
- OOP_24H
- RAM_15H
- RAM_24H
- CPU_15H
- CPU_24H

## 性能项说明

- `LB`：激光器偏置电流
- `LT`：激光器温度
- `IOP`：激光器输入光功率
- `OOP`：激光器输出光功率
- `RAM`：内存利用率
- `CPU`：CPU 利用率

## 真实 Trap 样本解析规则

- 服务器监听 `0.0.0.0:1162/udp`。
- 设备匹配优先使用 Trap UDP 源 IP。
- `1.3.6.1.6.3.1.1.4.1.0` 表示 Trap 类型字段，`almchg` 对应 `1.3.6.1.4.1.42669.1.1.0.1`。
- `1.3.6.1.2.1.1.3.0` 保存为 `sysUpTime`。
- `almchg` Trap 必须按 OID 后缀 `<index1>.<index2>` 分组。
- 同一个 Trap PDU 可能拆分出多条独立告警事件，所有拆分事件保留相同 `pdu_id`。
- `received_at` 作为默认排序和主显示时间。
- `almChgTime` 原样保存为 `device_alarm_time_raw`，不在第一版强转成人类时间。

