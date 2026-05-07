from __future__ import annotations


ROOT_OID = "1.3.6.1.4.1.42669"
SYS_UPTIME_OID = "1.3.6.1.2.1.1.3.0"
SNMP_TRAP_OID_FIELD = "1.3.6.1.6.3.1.1.4.1.0"

ALMCHG_TRAP_OID = "1.3.6.1.4.1.42669.1.1.0.1"
PERFORMANCE_TRAP_OID = "1.3.6.1.4.1.42669.1.1.0.5"

ALMCHG_TABLE_PREFIX = "1.3.6.1.4.1.42669.1.2.1.1"
PERFORMANCE_TABLE_PREFIX = "1.3.6.1.4.1.42669.1.2.5.1"

ALMCHG_FIELDS = {
    "1": "alarm_index_raw",
    "2": "alarm_obj",
    "3": "alarm_id",
    "4": "severity_code",
    "5": "device_alarm_time_raw",
    "6": "status_code",
    "7": "alarm_obj_desc",
}

PERFORMANCE_FIELDS = {
    "1": "performance_index",
    "2": "performance_desc",
}

ACTIVE_ALARM_SEVERITIES = {"indeterminate", "warning", "minor", "major", "critical"}
ACTIVE_ALARM_STATUSES = {"report", "change"}
POPUP_SEVERITIES = {"major", "critical"}
POPUP_STATUSES = {"report", "change"}

