from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Index, Integer, Numeric, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from repeater_nms.db.base import Base, TimestampMixin, utc_now


class User(TimestampMixin, Base):
    __tablename__ = "repeater_users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(32), default="admin", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Device(TimestampMixin, Base):
    __tablename__ = "repeater_devices"
    __table_args__ = (
        UniqueConstraint("name", name="uq_repeater_devices_name"),
        UniqueConstraint("ip", name="uq_repeater_devices_ip"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    ip: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    snmp_port: Mapped[int] = mapped_column(Integer, default=161, nullable=False)
    trap_port: Mapped[int] = mapped_column(Integer, default=1162, nullable=False)
    snmp_version: Mapped[str] = mapped_column(String(16), default="v2c", nullable=False)
    read_community: Mapped[str] = mapped_column(String(255), nullable=False)
    write_community: Mapped[str | None] = mapped_column(String(255))
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    notes: Mapped[str | None] = mapped_column(Text)
    last_online_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_polled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_poll_status: Mapped[str | None] = mapped_column(String(32))
    last_poll_message: Mapped[str | None] = mapped_column(String(255))


class MibNode(TimestampMixin, Base):
    __tablename__ = "repeater_mib_nodes"
    __table_args__ = (
        UniqueConstraint("oid", name="uq_repeater_mib_nodes_oid"),
        UniqueConstraint("name", name="uq_repeater_mib_nodes_name"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    oid: Mapped[str] = mapped_column(String(255), nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    category: Mapped[str] = mapped_column(String(32), nullable=False)
    access: Mapped[str] = mapped_column(String(32), nullable=False)
    data_type: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    enum_name: Mapped[str | None] = mapped_column(String(64))
    is_pollable: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_trap_field: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_set_reserved: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    scalar_suffix_zero: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class MibEnum(TimestampMixin, Base):
    __tablename__ = "repeater_mib_enums"
    __table_args__ = (UniqueConstraint("enum_name", "code", name="uq_repeater_mib_enums_name_code"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    enum_name: Mapped[str] = mapped_column(String(64), nullable=False)
    code: Mapped[int] = mapped_column(Integer, nullable=False)
    label: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[str] = mapped_column(String(255), nullable=False)


class SnmpMetricSample(Base):
    __tablename__ = "repeater_snmp_metric_samples"
    __table_args__ = (
        Index("ix_repeater_snmp_metric_samples_device_collected", "device_id", "collected_at"),
        Index("ix_repeater_snmp_metric_samples_created_at", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int | None] = mapped_column(ForeignKey("repeater_devices.id"), index=True)
    mib_node_id: Mapped[int | None] = mapped_column(ForeignKey("repeater_mib_nodes.id"))
    oid: Mapped[str] = mapped_column(String(255), nullable=False)
    oid_name: Mapped[str | None] = mapped_column(String(128))
    metric_key: Mapped[str | None] = mapped_column(String(128))
    value_raw: Mapped[str | None] = mapped_column(Text)
    value_text: Mapped[str | None] = mapped_column(Text)
    value_num: Mapped[Decimal | None] = mapped_column(Numeric(20, 6))
    value_json: Mapped[dict[str, Any] | list[Any] | None] = mapped_column(JSON)
    poll_status: Mapped[str] = mapped_column(String(32), default="ok", nullable=False)
    error_message: Mapped[str | None] = mapped_column(String(255))
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class DeviceLatestValue(Base):
    __tablename__ = "repeater_device_latest_values"
    __table_args__ = (
        UniqueConstraint("device_id", "oid", name="uq_repeater_device_latest_values_device_oid"),
        Index("ix_repeater_device_latest_values_created_at", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("repeater_devices.id"), index=True, nullable=False)
    mib_node_id: Mapped[int | None] = mapped_column(ForeignKey("repeater_mib_nodes.id"))
    oid: Mapped[str] = mapped_column(String(255), nullable=False)
    oid_name: Mapped[str | None] = mapped_column(String(128))
    value_raw: Mapped[str | None] = mapped_column(Text)
    value_text: Mapped[str | None] = mapped_column(Text)
    value_num: Mapped[Decimal | None] = mapped_column(Numeric(20, 6))
    value_json: Mapped[dict[str, Any] | list[Any] | None] = mapped_column(JSON)
    poll_status: Mapped[str] = mapped_column(String(32), default="ok", nullable=False)
    error_message: Mapped[str | None] = mapped_column(String(255))
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        nullable=False,
    )


class TrapEvent(Base):
    __tablename__ = "repeater_trap_events"
    __table_args__ = (
        Index("ix_repeater_trap_events_device_received", "device_id", "received_at"),
        Index("ix_repeater_trap_events_severity_status", "severity", "status"),
        Index("ix_repeater_trap_events_alarm", "alarm_id", "alarm_obj"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int | None] = mapped_column(ForeignKey("repeater_devices.id"), index=True)
    pdu_id: Mapped[str | None] = mapped_column(String(64), index=True)
    packet_id: Mapped[str | None] = mapped_column(String(64))
    source_ip: Mapped[str] = mapped_column(String(64), nullable=False)
    source_port: Mapped[int | None] = mapped_column(Integer)
    local_ip: Mapped[str | None] = mapped_column(String(64))
    local_port: Mapped[int | None] = mapped_column(Integer)
    snmp_version: Mapped[str | None] = mapped_column(String(16))
    community_masked: Mapped[str | None] = mapped_column(String(64))
    trap_oid: Mapped[str | None] = mapped_column(String(255))
    trap_name: Mapped[str | None] = mapped_column(String(128))
    trap_type: Mapped[str | None] = mapped_column(String(64))
    sys_uptime: Mapped[str | None] = mapped_column(String(128))
    alarm_index: Mapped[str | None] = mapped_column(String(64))
    alarm_obj: Mapped[str | None] = mapped_column(String(128), index=True)
    alarm_id: Mapped[str | None] = mapped_column(String(128), index=True)
    severity_code: Mapped[int | None] = mapped_column(Integer)
    severity: Mapped[str | None] = mapped_column(String(32), index=True)
    status_code: Mapped[int | None] = mapped_column(Integer)
    status: Mapped[str | None] = mapped_column(String(32), index=True)
    device_alarm_time_raw: Mapped[str | None] = mapped_column(String(255))
    alarm_obj_desc: Mapped[str | None] = mapped_column(Text)
    is_active_alarm: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    should_popup: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    parse_status: Mapped[str] = mapped_column(String(32), default="parsed", nullable=False)
    parse_error: Mapped[str | None] = mapped_column(Text)
    raw_summary: Mapped[str | None] = mapped_column(Text)
    raw_json: Mapped[dict[str, Any] | list[Any] | None] = mapped_column(JSON)
    translated_json: Mapped[dict[str, Any] | list[Any] | None] = mapped_column(JSON)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True, nullable=False)


class AlarmRule(TimestampMixin, Base):
    __tablename__ = "repeater_alarm_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    alarm_id: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    default_severity: Mapped[str] = mapped_column(String(32), nullable=False)
    should_create_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    should_popup: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    category: Mapped[str | None] = mapped_column(String(64))
    description: Mapped[str] = mapped_column(String(255), nullable=False)


class ActiveAlarm(Base):
    __tablename__ = "repeater_active_alarms"
    __table_args__ = (
        UniqueConstraint("dedupe_key", name="uq_repeater_active_alarms_dedupe_key"),
        Index("ix_repeater_active_alarms_state", "severity", "status", "is_open"),
        Index("ix_repeater_active_alarms_created_at", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int | None] = mapped_column(ForeignKey("repeater_devices.id"), index=True)
    dedupe_key: Mapped[str] = mapped_column(String(255), nullable=False)
    alarm_obj: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    alarm_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    severity_code: Mapped[int | None] = mapped_column(Integer)
    severity: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_trap_event_id: Mapped[int | None] = mapped_column(ForeignKey("repeater_trap_events.id"))
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    is_open: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_acknowledged: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    acknowledged_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("repeater_users.id"))
    notes: Mapped[str | None] = mapped_column(Text)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        nullable=False,
    )


class AlarmEvent(Base):
    __tablename__ = "repeater_alarm_events"
    __table_args__ = (
        Index("ix_repeater_alarm_events_device_occurred", "device_id", "occurred_at"),
        Index("ix_repeater_alarm_events_alarm", "alarm_id", "alarm_obj"),
        Index("ix_repeater_alarm_events_created_at", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    active_alarm_id: Mapped[int | None] = mapped_column(ForeignKey("repeater_active_alarms.id"), index=True)
    trap_event_id: Mapped[int | None] = mapped_column(ForeignKey("repeater_trap_events.id"), index=True)
    device_id: Mapped[int | None] = mapped_column(ForeignKey("repeater_devices.id"), index=True)
    alarm_obj: Mapped[str | None] = mapped_column(String(128), index=True)
    alarm_id: Mapped[str | None] = mapped_column(String(128), index=True)
    severity_code: Mapped[int | None] = mapped_column(Integer)
    severity: Mapped[str | None] = mapped_column(String(32), index=True)
    status_code: Mapped[int | None] = mapped_column(Integer)
    status: Mapped[str | None] = mapped_column(String(32), index=True)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    message: Mapped[str | None] = mapped_column(String(255))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class AlarmAckLog(Base):
    __tablename__ = "repeater_alarm_ack_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    active_alarm_id: Mapped[int] = mapped_column(ForeignKey("repeater_active_alarms.id"), index=True, nullable=False)
    alarm_event_id: Mapped[int | None] = mapped_column(ForeignKey("repeater_alarm_events.id"), index=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("repeater_users.id"), index=True)
    ack_note: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True, nullable=False)


class PopupNotification(Base):
    __tablename__ = "repeater_popup_notifications"
    __table_args__ = (
        UniqueConstraint("popup_key", name="uq_repeater_popup_notifications_popup_key"),
        Index("ix_repeater_popup_notifications_state", "status", "severity"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    popup_key: Mapped[str] = mapped_column(String(128), nullable=False)
    trap_event_id: Mapped[int | None] = mapped_column(ForeignKey("repeater_trap_events.id"), index=True)
    active_alarm_id: Mapped[int | None] = mapped_column(ForeignKey("repeater_active_alarms.id"), index=True)
    device_id: Mapped[int | None] = mapped_column(ForeignKey("repeater_devices.id"), index=True)
    severity: Mapped[str | None] = mapped_column(String(32), index=True)
    alarm_obj: Mapped[str | None] = mapped_column(String(128), index=True)
    alarm_id: Mapped[str | None] = mapped_column(String(128), index=True)
    status: Mapped[str] = mapped_column(String(32), default="pending", nullable=False)
    is_acknowledged: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    acknowledged_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("repeater_users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        index=True,
        nullable=False,
    )


class OperationLog(Base):
    __tablename__ = "repeater_operation_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("repeater_users.id"), index=True)
    username_snapshot: Mapped[str | None] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    target_type: Mapped[str | None] = mapped_column(String(64))
    target_id: Mapped[str | None] = mapped_column(String(64))
    source_ip: Mapped[str | None] = mapped_column(String(64))
    details_json: Mapped[dict[str, Any] | list[Any] | None] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True, nullable=False)
