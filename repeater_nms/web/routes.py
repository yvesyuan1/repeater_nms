from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any

from flask import (
    Blueprint,
    Response,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session as flask_session,
    stream_with_context,
    url_for,
)
from flask_login import current_user, login_required, login_user, logout_user
from sqlalchemy import func, or_, select
from werkzeug.security import check_password_hash, generate_password_hash

from repeater_nms.db.models import (
    ActiveAlarm,
    AlarmAckLog,
    AlarmEvent,
    Device,
    DeviceLatestValue,
    MibNode,
    OperationLog,
    PopupNotification,
    TrapEvent,
    User,
)
from repeater_nms.web.db import get_db_session
from repeater_nms.web.extensions import login_manager
from repeater_nms.web.security import role_required
from repeater_nms.web.utils import (
    build_captcha_svg,
    build_trap_summary,
    device_name_label,
    format_dt,
    generate_captcha_code,
    log_operation,
    parse_local_datetime,
    redis_client_from_app,
    role_description,
    role_label,
    severity_label,
    status_label,
    trap_name_label,
    trap_type_label,
)


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


def _device_map(session) -> dict[int, str]:
    return {item.id: item.name for item in session.execute(select(Device)).scalars().all()}


def _device_name(device_id: int | None, device_names: dict[int, str]) -> str:
    if device_id is None:
        return "未知设备"
    return device_names.get(device_id, f"设备#{device_id}")


def _refresh_captcha() -> None:
    flask_session["captcha_code"] = generate_captcha_code(current_app.config["CAPTCHA_LENGTH"])


def _captcha_ok(user_input: str) -> bool:
    expect = str(flask_session.get("captcha_code", "")).strip().upper()
    actual = str(user_input or "").strip().upper()
    return bool(expect and actual and expect == actual)


def _trap_payload(item: TrapEvent, device_name: str) -> dict[str, Any]:
    summary_zh = build_trap_summary(
        device_name=device_name,
        trap_name=item.trap_name,
        trap_type=item.trap_type,
        alarm_obj=item.alarm_obj,
        alarm_id=item.alarm_id,
        severity=item.severity,
        status=item.status,
        raw_summary=item.raw_summary,
    )
    return {
        "id": item.id,
        "pdu_id": item.pdu_id,
        "received_at": format_dt(item.received_at),
        "received_at_iso": item.received_at.astimezone(timezone.utc).isoformat() if item.received_at else None,
        "source_ip": item.source_ip,
        "device_id": item.device_id,
        "device_name": device_name,
        "trap_type": item.trap_type,
        "trap_type_label": trap_type_label(item.trap_type),
        "trap_name": item.trap_name,
        "trap_name_label": trap_name_label(item.trap_name),
        "alarm_obj": item.alarm_obj,
        "alarm_id": item.alarm_id,
        "severity": item.severity,
        "severity_label": severity_label(item.severity),
        "status": item.status,
        "status_label": status_label(item.status),
        "device_alarm_time_raw": item.device_alarm_time_raw,
        "raw_summary": item.raw_summary,
        "summary_zh": summary_zh,
        "translated_json": item.translated_json,
    }


@web_bp.get("/captcha.svg")
def captcha_svg():
    _refresh_captcha()
    svg = build_captcha_svg(flask_session["captcha_code"])
    return Response(svg, mimetype="image/svg+xml", headers={"Cache-Control": "no-store"})


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
        captcha = request.form.get("captcha", "")
        session = get_db_session()

        if not _captcha_ok(captcha):
            flash("验证码错误，请重新输入。", "error")
            _refresh_captcha()
            return render_template("login.html", **_base_context(page_name="登录"))

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

        _refresh_captcha()

    if request.method == "GET":
        _refresh_captcha()
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
    active_alarm_total = session.scalar(
        select(func.count()).select_from(ActiveAlarm).where(ActiveAlarm.is_open.is_(True))
    ) or 0
    recent_traps = session.execute(
        select(TrapEvent).order_by(TrapEvent.received_at.desc(), TrapEvent.id.desc()).limit(10)
    ).scalars().all()
    recent_devices = session.execute(
        select(Device).order_by(Device.updated_at.desc(), Device.id.desc()).limit(10)
    ).scalars().all()
    device_names = _device_map(session)
    trap_views = [_trap_payload(item, _device_name(item.device_id, device_names)) for item in recent_traps]
    return render_template(
        "dashboard.html",
        **_base_context(
            page_name="总览",
            device_total=device_total,
            enabled_devices=enabled_devices,
            active_alarm_total=active_alarm_total,
            recent_traps=trap_views,
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
    return render_template(
        "users.html",
        **_base_context(
            page_name="用户管理",
            users=users_list,
            role_descriptions=[
                {"role": "admin", "label": role_label("admin"), "description": role_description("admin")},
                {"role": "operator", "label": role_label("operator"), "description": role_description("operator")},
                {"role": "viewer", "label": role_label("viewer"), "description": role_description("viewer")},
            ],
        ),
    )


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
            flash("设备名称、IP 和读团体字不能为空。", "error")
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
    return render_template(
        "devices.html",
        **_base_context(
            page_name="设备管理",
            devices=device_rows,
            collector_hint="采集状态由独立采集服务写入。当前本地试运行如果只启动了页面服务，需要额外执行采集服务或 poll-once 才会出现采集结果。",
        ),
    )


@web_bp.get("/devices/<int:device_id>")
@login_required
def device_detail(device_id: int):
    session = get_db_session()
    device = session.get(Device, device_id)
    if device is None:
        return Response("device not found", status=404)
    latest_values = session.execute(
        select(DeviceLatestValue)
        .where(DeviceLatestValue.device_id == device.id)
        .order_by(DeviceLatestValue.oid.asc())
    ).scalars().all()
    recent_traps = session.execute(
        select(TrapEvent)
        .where(TrapEvent.device_id == device.id)
        .order_by(TrapEvent.received_at.desc(), TrapEvent.id.desc())
        .limit(10)
    ).scalars().all()
    active_alarms = session.execute(
        select(ActiveAlarm)
        .where(ActiveAlarm.device_id == device.id, ActiveAlarm.is_open.is_(True))
        .order_by(ActiveAlarm.last_seen_at.desc())
    ).scalars().all()
    trap_views = [_trap_payload(item, device.name) for item in recent_traps]
    return render_template(
        "device_detail.html",
        **_base_context(
            page_name=f"设备详情 - {device.name}",
            device=device,
            latest_values=latest_values,
            recent_traps=trap_views,
            active_alarms=active_alarms,
            collector_hint="如果这里还是空白，通常不是页面问题，而是当前还没有独立采集服务轮询并写入数据。",
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
    keyword = request.args.get("keyword", "").strip()
    stmt = select(TrapEvent)
    if severity:
        stmt = stmt.where(TrapEvent.severity == severity)
    if device_id:
        stmt = stmt.where(TrapEvent.device_id == int(device_id))
    if keyword:
        stmt = stmt.where(
            or_(
                TrapEvent.alarm_obj.ilike(f"%{keyword}%"),
                TrapEvent.alarm_id.ilike(f"%{keyword}%"),
                TrapEvent.source_ip.ilike(f"%{keyword}%"),
                TrapEvent.pdu_id.ilike(f"%{keyword}%"),
                TrapEvent.raw_summary.ilike(f"%{keyword}%"),
            )
        )
    stmt = stmt.order_by(TrapEvent.received_at.desc(), TrapEvent.id.desc()).limit(100)
    trap_rows = session.execute(stmt).scalars().all()
    devices = session.execute(select(Device).order_by(Device.name.asc())).scalars().all()
    device_names = _device_map(session)
    trap_views = [_trap_payload(item, _device_name(item.device_id, device_names)) for item in trap_rows]
    return render_template(
        "traps.html",
        **_base_context(
            page_name="Trap 实时页面",
            traps=trap_views,
            devices=devices,
            filter_severity=severity,
            filter_device_id=device_id,
            filter_keyword=keyword,
        ),
    )


@web_bp.get("/alarms")
@login_required
def alarms():
    session = get_db_session()
    device_id = request.args.get("device_id", "").strip()
    severity = request.args.get("severity", "").strip()
    ack_state = request.args.get("ack_state", "").strip()
    open_state = request.args.get("open_state", "open").strip() or "open"
    history_status = request.args.get("history_status", "").strip()
    keyword = request.args.get("keyword", "").strip()
    start_at = request.args.get("start_at", "").strip()
    end_at = request.args.get("end_at", "").strip()

    active_stmt = select(ActiveAlarm)
    if device_id:
        active_stmt = active_stmt.where(ActiveAlarm.device_id == int(device_id))
    if severity:
        active_stmt = active_stmt.where(ActiveAlarm.severity == severity)
    if ack_state == "ack":
        active_stmt = active_stmt.where(ActiveAlarm.is_acknowledged.is_(True))
    elif ack_state == "unack":
        active_stmt = active_stmt.where(ActiveAlarm.is_acknowledged.is_(False))
    if open_state == "open":
        active_stmt = active_stmt.where(ActiveAlarm.is_open.is_(True))
    elif open_state == "closed":
        active_stmt = active_stmt.where(ActiveAlarm.is_open.is_(False))
    if keyword:
        active_stmt = active_stmt.where(
            or_(
                ActiveAlarm.alarm_obj.ilike(f"%{keyword}%"),
                ActiveAlarm.alarm_id.ilike(f"%{keyword}%"),
                ActiveAlarm.notes.ilike(f"%{keyword}%"),
            )
        )
    active_stmt = active_stmt.order_by(ActiveAlarm.is_open.desc(), ActiveAlarm.last_seen_at.desc(), ActiveAlarm.id.desc())

    history_stmt = select(AlarmEvent)
    if device_id:
        history_stmt = history_stmt.where(AlarmEvent.device_id == int(device_id))
    if severity:
        history_stmt = history_stmt.where(AlarmEvent.severity == severity)
    if history_status:
        history_stmt = history_stmt.where(AlarmEvent.status == history_status)
    if keyword:
        history_stmt = history_stmt.where(
            or_(
                AlarmEvent.alarm_obj.ilike(f"%{keyword}%"),
                AlarmEvent.alarm_id.ilike(f"%{keyword}%"),
                AlarmEvent.message.ilike(f"%{keyword}%"),
            )
        )
    start_dt = parse_local_datetime(start_at)
    end_dt = parse_local_datetime(end_at, end_of_day=True)
    if start_dt is not None:
        history_stmt = history_stmt.where(AlarmEvent.occurred_at >= start_dt)
    if end_dt is not None:
        history_stmt = history_stmt.where(AlarmEvent.occurred_at < end_dt)
    history_stmt = history_stmt.order_by(AlarmEvent.occurred_at.desc(), AlarmEvent.id.desc()).limit(300)

    active_alarms = session.execute(active_stmt).scalars().all()
    history = session.execute(history_stmt).scalars().all()
    devices = session.execute(select(Device).order_by(Device.name.asc())).scalars().all()
    device_names = _device_map(session)
    return render_template(
        "alarms.html",
        **_base_context(
            page_name="告警中心",
            active_alarms=active_alarms,
            alarm_history=history,
            devices=devices,
            device_names=device_names,
            filters={
                "device_id": device_id,
                "severity": severity,
                "ack_state": ack_state,
                "open_state": open_state,
                "history_status": history_status,
                "keyword": keyword,
                "start_at": start_at,
                "end_at": end_at,
            },
        ),
    )


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
    session.add(
        AlarmAckLog(
            active_alarm_id=alarm.id,
            user_id=current_user.id,
            ack_note=note,
        )
    )
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
    flash("活动告警已确认。确认并不等于关闭，只有收到 close/cleared 后才会离开活动告警。", "success")
    return redirect(request.referrer or url_for("web.alarms"))


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
    keyword = request.args.get("keyword", "").strip()
    stmt = select(TrapEvent)
    if severity:
        stmt = stmt.where(TrapEvent.severity == severity)
    if device_id:
        stmt = stmt.where(TrapEvent.device_id == int(device_id))
    if keyword:
        stmt = stmt.where(
            or_(
                TrapEvent.alarm_obj.ilike(f"%{keyword}%"),
                TrapEvent.alarm_id.ilike(f"%{keyword}%"),
                TrapEvent.source_ip.ilike(f"%{keyword}%"),
                TrapEvent.pdu_id.ilike(f"%{keyword}%"),
                TrapEvent.raw_summary.ilike(f"%{keyword}%"),
            )
        )
    rows = session.execute(stmt.order_by(TrapEvent.received_at.desc(), TrapEvent.id.desc()).limit(100)).scalars().all()
    device_names = _device_map(session)
    return jsonify([_trap_payload(item, _device_name(item.device_id, device_names)) for item in rows])


@web_bp.get("/api/popup-notifications")
@login_required
def api_popup_notifications():
    session = get_db_session()
    device_names = _device_map(session)
    items = session.execute(
        select(PopupNotification)
        .where(PopupNotification.is_acknowledged.is_(False), PopupNotification.status == "pending")
        .order_by(PopupNotification.created_at.desc())
        .limit(20)
    ).scalars().all()
    return jsonify(
        [
            {
                "id": item.id,
                "popup_key": item.popup_key,
                "severity": item.severity,
                "severity_label": severity_label(item.severity),
                "alarm_obj": item.alarm_obj,
                "alarm_id": item.alarm_id,
                "status": item.status,
                "status_label": status_label(item.status),
                "device_name": _device_name(item.device_id, device_names),
                "created_at": item.created_at.astimezone(timezone.utc).isoformat() if item.created_at else None,
            }
            for item in items
        ]
    )


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
                    yield 'event: heartbeat\ndata: {"message":"heartbeat"}\n\n'
                    last_heartbeat = now
        except Exception as exc:
            error_payload = json.dumps({"message": f"实时事件通道异常：{exc}"}, ensure_ascii=False)
            yield f"event: error\ndata: {error_payload}\n\n"
        finally:
            if pubsub is not None:
                pubsub.close()

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@web_bp.get("/healthz")
def healthz():
    return {"status": "ok", "service": "repeater-nms-web"}
