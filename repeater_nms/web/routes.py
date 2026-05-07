from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any

from flask import Blueprint, Response, current_app, flash, jsonify, redirect, render_template, request, stream_with_context, url_for
from flask_login import current_user, login_required, login_user, logout_user
from sqlalchemy import and_, func, or_, select
from werkzeug.security import check_password_hash, generate_password_hash

from repeater_nms.db.models import ActiveAlarm, AlarmEvent, Device, DeviceLatestValue, MibNode, OperationLog, PopupNotification, TrapEvent, User
from repeater_nms.web.db import get_db_session
from repeater_nms.web.extensions import login_manager
from repeater_nms.web.security import role_required
from repeater_nms.web.utils import log_operation, redis_client_from_app


web_bp = Blueprint("web", __name__)


@login_manager.user_loader
def load_user(user_id: str) -> User | None:
    session = get_db_session()
    return session.get(User, int(user_id))


def _base_context(**extra):
    return {
        "page_title": current_app.config["PAGE_TITLE"],
        "app_name": current_app.config["APP_NAME"],
        **extra,
    }


def _query_recent_traps(limit: int = 100):
    session = get_db_session()
    return session.execute(
        select(TrapEvent).order_by(TrapEvent.received_at.desc(), TrapEvent.id.desc()).limit(limit)
    ).scalars().all()


def _query_pending_popups(limit: int = 20):
    session = get_db_session()
    return session.execute(
        select(PopupNotification)
        .where(PopupNotification.is_acknowledged.is_(False), PopupNotification.status == "pending")
        .order_by(PopupNotification.created_at.desc())
        .limit(limit)
    ).scalars().all()


def _popup_to_dict(item: PopupNotification) -> dict[str, Any]:
    return {
        "id": item.id,
        "popup_key": item.popup_key,
        "severity": item.severity,
        "alarm_obj": item.alarm_obj,
        "alarm_id": item.alarm_id,
        "status": item.status,
        "created_at": item.created_at.astimezone(timezone.utc).isoformat() if item.created_at else None,
    }


@web_bp.get("/")
def root():
    if current_user.is_authenticated:
        return redirect(url_for("web.dashboard"))
    return redirect(url_for("web.login"))


@web_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("web.dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        session = get_db_session()
        user = session.execute(select(User).where(User.username == username)).scalar_one_or_none()
        if user is None or not user.is_active or not check_password_hash(user.password_hash, password):
            flash("用户名或密码错误。", "error")
        else:
            login_user(user, remember=False)
            user.last_login_at = datetime.now(timezone.utc)
            log_operation(
                session,
                user_id=user.id,
                username_snapshot=user.username,
                action="login",
                target_type="user",
                target_id=str(user.id),
            )
            session.commit()
            return redirect(url_for("web.dashboard"))

    return render_template("login.html", **_base_context(page_name="登录"))


@web_bp.post("/logout")
@login_required
def logout():
    session = get_db_session()
    log_operation(
        session,
        user_id=current_user.id,
        username_snapshot=current_user.username,
        action="logout",
        target_type="user",
        target_id=str(current_user.id),
    )
    session.commit()
    logout_user()
    flash("已退出登录。", "success")
    return redirect(url_for("web.login"))


@web_bp.get("/dashboard")
@login_required
def dashboard():
    session = get_db_session()
    device_total = session.scalar(select(func.count()).select_from(Device)) or 0
    enabled_devices = session.scalar(select(func.count()).select_from(Device).where(Device.is_enabled.is_(True))) or 0
    active_alarm_total = session.scalar(select(func.count()).select_from(ActiveAlarm).where(ActiveAlarm.is_open.is_(True))) or 0
    recent_traps = session.execute(
        select(TrapEvent).order_by(TrapEvent.received_at.desc(), TrapEvent.id.desc()).limit(10)
    ).scalars().all()
    recent_devices = session.execute(
        select(Device).order_by(Device.updated_at.desc(), Device.id.desc()).limit(10)
    ).scalars().all()
    return render_template(
        "dashboard.html",
        **_base_context(
            page_name="总览",
            device_total=device_total,
            enabled_devices=enabled_devices,
            active_alarm_total=active_alarm_total,
            recent_traps=recent_traps,
            recent_devices=recent_devices,
        ),
    )


@web_bp.route("/users", methods=["GET", "POST"])
@login_required
@role_required("admin")
def users():
    session = get_db_session()
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "viewer")
        is_active = request.form.get("is_active") == "on"
        if not username or not password:
            flash("用户名和密码不能为空。", "error")
        elif session.execute(select(User).where(User.username == username)).scalar_one_or_none():
            flash("用户名已存在。", "error")
        else:
            user = User(
                username=username,
                password_hash=generate_password_hash(password),
                role=role,
                is_active=is_active,
            )
            session.add(user)
            session.flush()
            log_operation(
                session,
                user_id=current_user.id,
                username_snapshot=current_user.username,
                action="create_user",
                target_type="user",
                target_id=str(user.id),
                details_json={"username": username, "role": role, "is_active": is_active},
            )
            session.commit()
            flash("用户已创建。", "success")
            return redirect(url_for("web.users"))

    users_list = session.execute(select(User).order_by(User.id.asc())).scalars().all()
    return render_template("users.html", **_base_context(page_name="用户管理", users=users_list))


@web_bp.post("/users/<int:user_id>/toggle")
@login_required
@role_required("admin")
def toggle_user(user_id: int):
    session = get_db_session()
    user = session.get(User, user_id)
    if user is None:
        flash("用户不存在。", "error")
        return redirect(url_for("web.users"))
    user.is_active = not user.is_active
    log_operation(
        session,
        user_id=current_user.id,
        username_snapshot=current_user.username,
        action="toggle_user",
        target_type="user",
        target_id=str(user.id),
        details_json={"is_active": user.is_active},
    )
    session.commit()
    flash("用户状态已更新。", "success")
    return redirect(url_for("web.users"))


@web_bp.route("/devices", methods=["GET", "POST"])
@login_required
def devices():
    session = get_db_session()
    if request.method == "POST":
        if current_user.role not in {"admin", "operator"}:
            return Response(status=403)
        name = request.form.get("name", "").strip()
        ip = request.form.get("ip", "").strip()
        read_community = request.form.get("read_community", "").strip()
        write_community = request.form.get("write_community", "").strip() or None
        if not name or not ip or not read_community:
            flash("设备名称、IP 和 read community 不能为空。", "error")
        else:
            device = Device(
                name=name,
                ip=ip,
                snmp_port=int(request.form.get("snmp_port", "161") or 161),
                trap_port=int(request.form.get("trap_port", "1162") or 1162),
                snmp_version=request.form.get("snmp_version", "v2c"),
                read_community=read_community,
                write_community=write_community,
                is_enabled=request.form.get("is_enabled") == "on",
                notes=request.form.get("notes", "").strip() or None,
            )
            session.add(device)
            session.flush()
            log_operation(
                session,
                user_id=current_user.id,
                username_snapshot=current_user.username,
                action="create_device",
                target_type="device",
                target_id=str(device.id),
                details_json={
                    "name": device.name,
                    "ip": device.ip,
                    "snmp_port": device.snmp_port,
                    "trap_port": device.trap_port,
                    "read_community_masked": "***",
                    "write_community_masked": "***" if write_community else None,
                },
            )
            session.commit()
            flash("设备已创建。", "success")
            return redirect(url_for("web.devices"))

    device_rows = session.execute(select(Device).order_by(Device.id.desc())).scalars().all()
    return render_template("devices.html", **_base_context(page_name="设备管理", devices=device_rows))


@web_bp.get("/devices/<int:device_id>")
@login_required
def device_detail(device_id: int):
    session = get_db_session()
    device = session.get(Device, device_id)
    if device is None:
        return Response("device not found", status=404)
    latest_values = session.execute(
        select(DeviceLatestValue).where(DeviceLatestValue.device_id == device.id).order_by(DeviceLatestValue.oid.asc())
    ).scalars().all()
    recent_traps = session.execute(
        select(TrapEvent).where(TrapEvent.device_id == device.id).order_by(TrapEvent.received_at.desc()).limit(10)
    ).scalars().all()
    active_alarms = session.execute(
        select(ActiveAlarm).where(ActiveAlarm.device_id == device.id, ActiveAlarm.is_open.is_(True)).order_by(ActiveAlarm.last_seen_at.desc())
    ).scalars().all()
    return render_template(
        "device_detail.html",
        **_base_context(
            page_name=f"设备详情 - {device.name}",
            device=device,
            latest_values=latest_values,
            recent_traps=recent_traps,
            active_alarms=active_alarms,
        ),
    )


@web_bp.route("/devices/<int:device_id>/edit", methods=["GET", "POST"])
@login_required
@role_required("admin", "operator")
def edit_device(device_id: int):
    session = get_db_session()
    device = session.get(Device, device_id)
    if device is None:
        return Response("device not found", status=404)
    if request.method == "POST":
        device.name = request.form.get("name", device.name).strip() or device.name
        device.ip = request.form.get("ip", device.ip).strip() or device.ip
        device.snmp_port = int(request.form.get("snmp_port", str(device.snmp_port)) or device.snmp_port)
        device.trap_port = int(request.form.get("trap_port", str(device.trap_port)) or device.trap_port)
        device.snmp_version = request.form.get("snmp_version", device.snmp_version)
        if read_community := request.form.get("read_community", "").strip():
            device.read_community = read_community
        if "write_community" in request.form:
            write_community = request.form.get("write_community", "").strip()
            if write_community:
                device.write_community = write_community
        device.is_enabled = request.form.get("is_enabled") == "on"
        device.notes = request.form.get("notes", "").strip() or None
        log_operation(
            session,
            user_id=current_user.id,
            username_snapshot=current_user.username,
            action="edit_device",
            target_type="device",
            target_id=str(device.id),
            details_json={
                "name": device.name,
                "ip": device.ip,
                "snmp_port": device.snmp_port,
                "trap_port": device.trap_port,
                "read_community_masked": "***",
                "write_community_masked": "***" if device.write_community else None,
            },
        )
        session.commit()
        flash("设备已更新。", "success")
        return redirect(url_for("web.device_detail", device_id=device.id))
    return render_template("device_form.html", **_base_context(page_name=f"编辑设备 - {device.name}", device=device))


@web_bp.post("/devices/<int:device_id>/toggle")
@login_required
@role_required("admin", "operator")
def toggle_device(device_id: int):
    session = get_db_session()
    device = session.get(Device, device_id)
    if device is None:
        flash("设备不存在。", "error")
        return redirect(url_for("web.devices"))
    device.is_enabled = not device.is_enabled
    log_operation(
        session,
        user_id=current_user.id,
        username_snapshot=current_user.username,
        action="toggle_device",
        target_type="device",
        target_id=str(device.id),
        details_json={"is_enabled": device.is_enabled},
    )
    session.commit()
    flash("设备启停状态已更新。", "success")
    return redirect(url_for("web.devices"))


@web_bp.get("/mib-nodes")
@login_required
def mib_nodes():
    session = get_db_session()
    rows = session.execute(select(MibNode).order_by(MibNode.oid.asc())).scalars().all()
    return render_template("mib_nodes.html", **_base_context(page_name="MIB 节点", nodes=rows))


@web_bp.get("/traps")
@login_required
def traps():
    session = get_db_session()
    severity = request.args.get("severity", "").strip()
    device_id = request.args.get("device_id", "").strip()
    stmt = select(TrapEvent).order_by(TrapEvent.received_at.desc(), TrapEvent.id.desc()).limit(100)
    if severity:
        stmt = stmt.where(TrapEvent.severity == severity)
    if device_id:
        stmt = stmt.where(TrapEvent.device_id == int(device_id))
    trap_rows = session.execute(stmt).scalars().all()
    devices = session.execute(select(Device).order_by(Device.name.asc())).scalars().all()
    return render_template(
        "traps.html",
        **_base_context(page_name="Trap 实时页面", traps=trap_rows, devices=devices, filter_severity=severity, filter_device_id=device_id),
    )


@web_bp.get("/alarms")
@login_required
def alarms():
    session = get_db_session()
    active_alarms = session.execute(
        select(ActiveAlarm).order_by(ActiveAlarm.last_seen_at.desc(), ActiveAlarm.id.desc())
    ).scalars().all()
    history = session.execute(
        select(AlarmEvent).order_by(AlarmEvent.occurred_at.desc(), AlarmEvent.id.desc()).limit(200)
    ).scalars().all()
    return render_template("alarms.html", **_base_context(page_name="告警中心", active_alarms=active_alarms, alarm_history=history))


@web_bp.post("/alarms/<int:alarm_id>/ack")
@login_required
@role_required("admin", "operator")
def ack_alarm(alarm_id: int):
    session = get_db_session()
    alarm = session.get(ActiveAlarm, alarm_id)
    if alarm is None:
        flash("活动告警不存在。", "error")
        return redirect(url_for("web.alarms"))
    alarm.is_acknowledged = True
    alarm.acknowledged_at = datetime.now(timezone.utc)
    alarm.acknowledged_by_user_id = current_user.id
    note = request.form.get("note", "").strip() or None
    if note:
        alarm.notes = note
    log_operation(
        session,
        user_id=current_user.id,
        username_snapshot=current_user.username,
        action="ack_alarm",
        target_type="active_alarm",
        target_id=str(alarm.id),
        details_json={"note": note},
    )
    session.commit()
    flash("活动告警已确认。", "success")
    return redirect(url_for("web.alarms"))


@web_bp.get("/logs")
@login_required
def logs():
    session = get_db_session()
    rows = session.execute(
        select(OperationLog).order_by(OperationLog.created_at.desc(), OperationLog.id.desc()).limit(200)
    ).scalars().all()
    return render_template("logs.html", **_base_context(page_name="操作日志", logs=rows))


@web_bp.get("/api/trap-events")
@login_required
def api_trap_events():
    session = get_db_session()
    severity = request.args.get("severity", "").strip()
    device_id = request.args.get("device_id", "").strip()
    stmt = select(TrapEvent).order_by(TrapEvent.received_at.desc(), TrapEvent.id.desc()).limit(100)
    if severity:
        stmt = stmt.where(TrapEvent.severity == severity)
    if device_id:
        stmt = stmt.where(TrapEvent.device_id == int(device_id))
    rows = session.execute(stmt).scalars().all()
    return jsonify(
        [
            {
                "id": item.id,
                "pdu_id": item.pdu_id,
                "received_at": item.received_at.astimezone(timezone.utc).isoformat(),
                "source_ip": item.source_ip,
                "device_id": item.device_id,
                "trap_type": item.trap_type,
                "trap_name": item.trap_name,
                "alarm_obj": item.alarm_obj,
                "alarm_id": item.alarm_id,
                "severity": item.severity,
                "status": item.status,
                "device_alarm_time_raw": item.device_alarm_time_raw,
                "raw_summary": item.raw_summary,
            }
            for item in rows
        ]
    )


@web_bp.get("/api/popup-notifications")
@login_required
def api_popup_notifications():
    return jsonify([_popup_to_dict(item) for item in _query_pending_popups()])


@web_bp.post("/api/popup-notifications/<int:popup_id>/ack")
@login_required
@role_required("admin", "operator")
def api_ack_popup(popup_id: int):
    session = get_db_session()
    popup = session.get(PopupNotification, popup_id)
    if popup is None:
        return jsonify({"ok": False, "error": "not_found"}), 404
    popup.is_acknowledged = True
    popup.acknowledged_at = datetime.now(timezone.utc)
    popup.acknowledged_by_user_id = current_user.id
    popup.status = "acknowledged"
    log_operation(
        session,
        user_id=current_user.id,
        username_snapshot=current_user.username,
        action="ack_popup",
        target_type="popup_notification",
        target_id=str(popup.id),
    )
    session.commit()
    return jsonify({"ok": True})


@web_bp.get("/api/events/stream")
@login_required
def event_stream():
    heartbeat_seconds = current_app.config["SSE_HEARTBEAT_SECONDS"]

    @stream_with_context
    def generate():
        yield "retry: 3000\n\n"
        pubsub = None
        try:
            publisher = redis_client_from_app(current_app)
            pubsub = publisher.redis.pubsub(ignore_subscribe_messages=True)
            pubsub.subscribe(publisher.trap_channel)
            last_heartbeat = time.monotonic()
            while True:
                message = pubsub.get_message(timeout=1.0)
                now = time.monotonic()
                if message and message.get("type") == "message":
                    payload = message["data"]
                    yield f"event: trap_event\ndata: {payload}\n\n"
                    last_heartbeat = now
                elif now - last_heartbeat >= heartbeat_seconds:
                    yield "event: heartbeat\ndata: {}\n\n"
                    last_heartbeat = now
        except Exception as exc:
            error_payload = json.dumps({"message": str(exc)}, ensure_ascii=False)
            yield f"event: error\ndata: {error_payload}\n\n"
        finally:
            if pubsub is not None:
                pubsub.close()

    return Response(generate(), mimetype="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@web_bp.get("/healthz")
def healthz():
    return {"status": "ok", "service": "repeater-nms-web"}
