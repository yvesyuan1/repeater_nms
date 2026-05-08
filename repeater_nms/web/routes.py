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
from sqlalchemy.exc import IntegrityError
from werkzeug.security import check_password_hash, generate_password_hash

from repeater_nms.db.models import (
    ActiveAlarm,
    AlarmAckLog,
    AlarmEvent,
    AlarmRule,
    Device,
    DeviceLatestValue,
    DeviceProfile,
    MibEnum,
    MibNode,
    OperationLog,
    PollingStrategy,
    PopupNotification,
    TrapEvent,
    User,
)
from repeater_nms.db.seed_data import DEFAULT_PROFILE_CODE
from repeater_nms.web.db import get_db_session
from repeater_nms.web.extensions import login_manager
from repeater_nms.web.security import role_required
from repeater_nms.web.utils import (
    build_captcha_svg,
    build_trap_summary,
    compute_device_overview_status,
    format_dt,
    generate_captcha_code,
    health_label,
    highest_severity,
    log_operation,
    overview_status_label,
    parse_local_datetime,
    profile_title,
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


def _refresh_captcha() -> None:
    flask_session["captcha_code"] = generate_captcha_code(current_app.config["CAPTCHA_LENGTH"])


def _captcha_ok(user_input: str) -> bool:
    expect = str(flask_session.get("captcha_code", "")).strip().upper()
    actual = str(user_input or "").strip().upper()
    return bool(expect and actual and expect == actual)


def _device_map(session) -> dict[int, Device]:
    return {item.id: item for item in session.execute(select(Device)).scalars().all()}


def _profile_map(session) -> dict[str, DeviceProfile]:
    return {item.profile_code: item for item in session.execute(select(DeviceProfile)).scalars().all()}


def _metric_text(value: Any) -> str:
    if value is None:
        return "-"
    text = str(value).strip()
    if not text or text.lower() in {"null", "none", "nan"}:
        return "-"
    return text


def _metric_value(row: DeviceLatestValue | None, *, prefer_enum: bool = False) -> str:
    if row is None:
        return "-"
    candidates = []
    if prefer_enum:
        candidates.extend([row.enum_text, row.display_value, row.value_text, row.value_raw])
    else:
        candidates.extend([row.display_value, row.enum_text, row.value_text, row.value_raw])
    for item in candidates:
        text = _metric_text(item)
        if text != "-":
            return text
    return "-"


def _bool_form(name: str) -> bool:
    return request.form.get(name) == "on"


def _split_expected_values(text: str | None) -> list[str]:
    raw = (text or "").replace("，", ",")
    return [item.strip() for item in raw.split(",") if item.strip()]


def _json_pretty(value: Any) -> str:
    if value is None:
        return "-"
    try:
        return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)
    except Exception:
        return str(value)


def _int_form(name: str, default: int, *, minimum: int | None = None) -> int:
    raw = request.form.get(name, "").strip()
    try:
        value = int(raw or default)
    except Exception:
        value = default
    if minimum is not None:
        value = max(minimum, value)
    return value


def _redirect_profile_page(profile_code: str | None = None, **query):
    params = {key: value for key, value in query.items() if value not in (None, "", False)}
    if profile_code:
        params["profile_code"] = profile_code
    if params:
        return redirect(url_for("web.mib_nodes", **params))
    return redirect(url_for("web.mib_nodes"))


def _strategy_from_form(strategy: PollingStrategy, *, mib_node: MibNode | None = None) -> None:
    strategy.poll_interval_seconds = _int_form("poll_interval_seconds", strategy.poll_interval_seconds or 60, minimum=5)
    strategy.display_order = _int_form("display_order", strategy.display_order or 100, minimum=1)
    strategy.is_enabled = _bool_form("is_enabled")
    strategy.save_history = _bool_form("save_history")
    strategy.show_in_overview = _bool_form("show_in_overview")
    strategy.show_in_device_card = _bool_form("show_in_device_card")
    strategy.judge_type = request.form.get("judge_type", "").strip() or None
    expected_value_text = request.form.get("expected_value_text", "").strip()
    strategy.expected_value_text = expected_value_text or None
    strategy.expected_values_json = _split_expected_values(expected_value_text) if expected_value_text else None
    strategy.health_on_mismatch = request.form.get("health_on_mismatch", "").strip() or None
    strategy.notes = request.form.get("notes", "").strip() or None
    if mib_node is not None:
        strategy.mib_node_id = mib_node.id
        strategy.oid = mib_node.oid
        strategy.node_name = mib_node.name
        strategy.node_name_zh = mib_node.name_zh
        strategy.category = mib_node.category
    else:
        strategy.mib_node_id = None
        strategy.oid = request.form.get("oid", strategy.oid).strip() or strategy.oid
        strategy.node_name = request.form.get("node_name", strategy.node_name).strip() or strategy.node_name
        strategy.node_name_zh = request.form.get("node_name_zh", strategy.node_name_zh or "").strip() or None
        strategy.category = request.form.get("category", strategy.category or "").strip() or None


def _mib_node_from_form(node: MibNode) -> None:
    node.oid = request.form.get("oid", node.oid).strip() or node.oid
    node.name = request.form.get("name", node.name).strip() or node.name
    node.name_zh = request.form.get("name_zh", node.name_zh or "").strip() or None
    node.category = request.form.get("category", node.category).strip() or node.category
    node.category_zh = request.form.get("category_zh", node.category_zh or "").strip() or None
    node.access = request.form.get("access", node.access).strip() or node.access
    node.data_type = request.form.get("data_type", node.data_type).strip() or node.data_type
    node.description = request.form.get("description", node.description).strip() or node.description
    node.enum_name = request.form.get("enum_name", node.enum_name or "").strip() or None
    node.unit = request.form.get("unit", node.unit or "").strip() or None
    node.overview_order = _int_form("overview_order", node.overview_order or 100, minimum=0)
    node.is_pollable = _bool_form("is_pollable")
    node.is_trap_field = _bool_form("is_trap_field")
    node.is_set_reserved = _bool_form("is_set_reserved")
    node.scalar_suffix_zero = _bool_form("scalar_suffix_zero")


def _alarm_rule_from_form(rule: AlarmRule) -> None:
    rule.alarm_id = request.form.get("alarm_id", rule.alarm_id).strip() or rule.alarm_id
    rule.default_severity = request.form.get("default_severity", rule.default_severity).strip() or rule.default_severity
    rule.should_create_active = _bool_form("should_create_active")
    rule.should_popup = _bool_form("should_popup")
    rule.category = request.form.get("category", rule.category or "").strip() or None
    rule.description = request.form.get("description", rule.description).strip() or rule.description


def _trap_payload(item: TrapEvent, device: Device | None, profile: DeviceProfile | None) -> dict[str, Any]:
    device_name = device.name if device else "未知设备"
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
        "profile_title": profile_title(profile.vendor if profile else None, profile.model if profile else None),
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
        "detail_url": url_for("web.trap_detail", trap_id=item.id),
    }


def _collect_device_overviews(session) -> list[dict[str, Any]]:
    devices = session.execute(select(Device).order_by(Device.name.asc())).scalars().all()
    profiles = _profile_map(session)
    strategies = session.execute(select(PollingStrategy).where(PollingStrategy.is_enabled.is_(True))).scalars().all()
    active_alarms = session.execute(select(ActiveAlarm)).scalars().all()
    latest_values = session.execute(select(DeviceLatestValue)).scalars().all()
    recent_traps = session.execute(select(TrapEvent).order_by(TrapEvent.received_at.desc(), TrapEvent.id.desc())).scalars().all()

    active_by_device: dict[int, list[ActiveAlarm]] = {}
    for item in active_alarms:
        if item.device_id is None:
            continue
        active_by_device.setdefault(item.device_id, []).append(item)

    strategy_names_by_profile: dict[str, set[str]] = {}
    for item in strategies:
        strategy_names_by_profile.setdefault(item.profile_code, set()).add(item.node_name)

    latest_by_device: dict[int, dict[str, DeviceLatestValue]] = {}
    for item in latest_values:
        profile_code = item.profile_code or DEFAULT_PROFILE_CODE
        strategy_names = strategy_names_by_profile.get(profile_code)
        metric_key = item.oid_name or item.oid
        if strategy_names and item.oid_name and item.oid_name not in strategy_names:
            continue
        latest_by_device.setdefault(item.device_id, {})[metric_key] = item

    recent_trap_by_device: dict[int, TrapEvent] = {}
    for item in recent_traps:
        if item.device_id is None:
            continue
        recent_trap_by_device.setdefault(item.device_id, item)

    overviews: list[dict[str, Any]] = []
    for device in devices:
        profile = profiles.get(device.device_profile_code)
        current_alarms = [item for item in active_by_device.get(device.id, []) if item.is_open]
        highest_alarm = highest_severity([item.severity for item in current_alarms if item.severity])
        latest_rows = latest_by_device.get(device.id, {})
        health_statuses = [row.health_status for row in latest_rows.values() if row.health_status]
        overview_status = compute_device_overview_status(
            last_poll_status=device.last_poll_status,
            highest_alarm_severity=highest_alarm,
            health_statuses=health_statuses,
        )
        aps_active = latest_rows.get("apsActive")
        aps_stat = latest_rows.get("apsStat")
        dfp_active = latest_rows.get("dfpActive")
        overviews.append(
            {
                "device": device,
                "profile": profile,
                "profile_title": profile_title(profile.vendor if profile else None, profile.model if profile else None),
                "vendor": None if profile is None else profile.vendor,
                "model": None if profile is None else profile.model,
                "active_alarm_count": len(current_alarms),
                "highest_alarm_severity": highest_alarm,
                "highest_alarm_label": severity_label(highest_alarm),
                "recent_trap_at": None if device.id not in recent_trap_by_device else format_dt(recent_trap_by_device[device.id].received_at),
                "recent_poll_at": format_dt(device.last_polled_at),
                "recent_error": "-" if device.last_poll_status == "ok" else _metric_text(device.last_poll_message),
                "aps_active": _metric_value(aps_active),
                "aps_active_health": None if aps_active is None else aps_active.health_status,
                "aps_stat": _metric_value(aps_stat, prefer_enum=True),
                "aps_stat_text": None if aps_stat is None else _metric_text(aps_stat.enum_text or aps_stat.health_reason),
                "dfp_active": _metric_value(dfp_active),
                "dfp_active_health": None if dfp_active is None else dfp_active.health_status,
                "overview_status": overview_status,
                "overview_status_label": overview_status_label(overview_status),
            }
        )
    return overviews


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
    overviews = _collect_device_overviews(session)
    trap_rows = session.execute(select(TrapEvent).order_by(TrapEvent.received_at.desc(), TrapEvent.id.desc()).limit(10)).scalars().all()
    devices = _device_map(session)
    profiles = _profile_map(session)
    traps = [_trap_payload(item, devices.get(item.device_id) if item.device_id else None, profiles.get(item.profile_code or DEFAULT_PROFILE_CODE)) for item in trap_rows]
    return render_template(
        "dashboard.html",
        **_base_context(
            page_name="设备运行总览",
            device_total=len(overviews),
            online_devices=sum(1 for item in overviews if item["device"].is_enabled),
            active_alarm_total=sum(item["active_alarm_count"] for item in overviews),
            device_overviews=overviews,
            recent_traps=traps,
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
    profiles = session.execute(select(DeviceProfile).order_by(DeviceProfile.vendor.asc(), DeviceProfile.model.asc())).scalars().all()
    if request.method == "POST":
        if current_user.role not in {"admin", "operator"}:
            return Response(status=403)
        name = request.form.get("name", "").strip()
        ip = request.form.get("ip", "").strip()
        read_community = request.form.get("read_community", "").strip()
        write_community = request.form.get("write_community", "").strip() or None
        profile_code = request.form.get("device_profile_code", DEFAULT_PROFILE_CODE).strip() or DEFAULT_PROFILE_CODE
        if not name or not ip or not read_community:
            flash("设备名称、IP 和读团体字不能为空。", "error")
        else:
            device = Device(
                name=name,
                ip=ip,
                device_profile_code=profile_code,
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
                details_json={"name": device.name, "ip": device.ip, "device_profile_code": profile_code},
            )
            session.commit()
            flash("设备已创建。", "success")
            return redirect(url_for("web.devices"))

    device_rows = session.execute(select(Device).order_by(Device.id.desc())).scalars().all()
    profile_map = _profile_map(session)
    return render_template(
        "devices.html",
        **_base_context(page_name="设备管理", devices=device_rows, profiles=profiles, profile_map=profile_map),
    )


@web_bp.get("/devices/<int:device_id>")
@login_required
def device_detail(device_id: int):
    session = get_db_session()
    device = session.get(Device, device_id)
    if device is None:
        return Response("device not found", status=404)
    profile = session.execute(select(DeviceProfile).where(DeviceProfile.profile_code == device.device_profile_code)).scalar_one_or_none()
    strategies = session.execute(
        select(PollingStrategy)
        .where(PollingStrategy.profile_code == device.device_profile_code, PollingStrategy.is_enabled.is_(True))
        .order_by(PollingStrategy.display_order.asc(), PollingStrategy.id.asc())
    ).scalars().all()
    latest_values_all = session.execute(
        select(DeviceLatestValue)
        .where(DeviceLatestValue.device_id == device.id)
        .order_by(DeviceLatestValue.category.asc(), DeviceLatestValue.oid_name.asc())
    ).scalars().all()
    strategy_map = {item.node_name: item for item in strategies}
    strategy_rows: list[tuple[int, int, DeviceLatestValue]] = []
    extra_rows: list[tuple[str, str, DeviceLatestValue]] = []
    for row in latest_values_all:
        if row.oid_name in strategy_map:
            strategy_rows.append((strategy_map[row.oid_name].display_order, row.id, row))
        elif row.category or row.oid_name_zh:
            extra_rows.append((row.category or "zzz", row.oid_name or row.oid, row))
    latest_values = [item for _, _, item in sorted(strategy_rows, key=lambda value: (value[0], value[1]))]
    latest_values.extend(item for _, _, item in sorted(extra_rows, key=lambda value: (value[0], value[1])))
    recent_traps = session.execute(
        select(TrapEvent).where(TrapEvent.device_id == device.id).order_by(TrapEvent.received_at.desc()).limit(10)
    ).scalars().all()
    active_alarms = session.execute(
        select(ActiveAlarm).where(ActiveAlarm.device_id == device.id, ActiveAlarm.is_open.is_(True)).order_by(ActiveAlarm.last_seen_at.desc())
    ).scalars().all()
    trap_views = [_trap_payload(item, device, profile) for item in recent_traps]
    return render_template(
        "device_detail.html",
        **_base_context(
            page_name=f"设备详情 - {device.name}",
            device=device,
            profile=profile,
            latest_values=latest_values,
            recent_traps=trap_views,
            active_alarms=active_alarms,
        ),
    )


@web_bp.route("/devices/<int:device_id>/edit", methods=["GET", "POST"])
@login_required
@role_required("admin", "operator")
def edit_device(device_id: int):
    session = get_db_session()
    device = session.get(Device, device_id)
    profiles = session.execute(select(DeviceProfile).order_by(DeviceProfile.vendor.asc(), DeviceProfile.model.asc())).scalars().all()
    if device is None:
        return Response("device not found", status=404)
    if request.method == "POST":
        device.name = request.form.get("name", device.name).strip() or device.name
        device.ip = request.form.get("ip", device.ip).strip() or device.ip
        device.device_profile_code = request.form.get("device_profile_code", device.device_profile_code).strip() or device.device_profile_code
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
            details_json={"name": device.name, "ip": device.ip, "device_profile_code": device.device_profile_code},
        )
        session.commit()
        flash("设备已更新。", "success")
        return redirect(url_for("web.device_detail", device_id=device.id))
    return render_template("device_form.html", **_base_context(page_name=f"编辑设备 - {device.name}", device=device, profiles=profiles))


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
    profiles = session.execute(select(DeviceProfile).order_by(DeviceProfile.vendor.asc(), DeviceProfile.model.asc())).scalars().all()
    selected_code = request.args.get("profile_code", "").strip() or (profiles[0].profile_code if profiles else DEFAULT_PROFILE_CODE)
    active_tab = request.args.get("tab", "").strip() or "profile"
    create_mode = request.args.get("mode", "").strip() == "create"
    selected_profile = next((item for item in profiles if item.profile_code == selected_code), None)
    nodes = session.execute(
        select(MibNode)
        .where(MibNode.profile_code == selected_code)
        .order_by(MibNode.category.asc(), MibNode.overview_order.asc(), MibNode.oid.asc())
    ).scalars().all()
    strategies = session.execute(
        select(PollingStrategy).where(PollingStrategy.profile_code == selected_code).order_by(PollingStrategy.display_order.asc(), PollingStrategy.id.asc())
    ).scalars().all()
    enums = session.execute(
        select(MibEnum).where(MibEnum.profile_code == selected_code).order_by(MibEnum.enum_name.asc(), MibEnum.code.asc())
    ).scalars().all()
    alarm_rules = session.execute(
        select(AlarmRule).where(AlarmRule.profile_code == selected_code).order_by(AlarmRule.category.asc(), AlarmRule.alarm_id.asc())
    ).scalars().all()
    selected_strategy_id = request.args.get("strategy_id", type=int)
    selected_node_id = request.args.get("node_id", type=int)
    selected_enum_id = request.args.get("enum_id", type=int)
    selected_rule_id = request.args.get("rule_id", type=int)
    selected_strategy = next((item for item in strategies if item.id == selected_strategy_id), strategies[0] if strategies else None)
    selected_node = next((item for item in nodes if item.id == selected_node_id), nodes[0] if nodes else None)
    selected_enum = next((item for item in enums if item.id == selected_enum_id), enums[0] if enums else None)
    selected_rule = next((item for item in alarm_rules if item.id == selected_rule_id), alarm_rules[0] if alarm_rules else None)
    return render_template(
        "mib_nodes.html",
        **_base_context(
            page_name="设备模板",
            profiles=profiles,
            selected_profile=selected_profile,
            active_tab=active_tab,
            create_mode=create_mode,
            nodes=nodes,
            strategies=strategies,
            enums=enums,
            alarm_rules=alarm_rules,
            selected_strategy=selected_strategy,
            selected_node=selected_node,
            selected_enum=selected_enum,
            selected_rule=selected_rule,
            judge_type_options=[
                ("", "不做判断"),
                ("enum_equals", "枚举值匹配"),
                ("value_equals", "原始值匹配"),
            ],
            health_options=[
                ("", "未知"),
                ("warning", "警告"),
                ("major", "主要"),
                ("critical", "紧急"),
            ],
            severity_options=[
                ("warning", "警告"),
                ("minor", "次要"),
                ("major", "主要"),
                ("critical", "紧急"),
                ("indeterminate", "不确定"),
                ("cleared", "清除"),
            ],
            can_manage_templates=current_user.role == "admin",
        ),
    )


@web_bp.post("/mib-nodes/profiles")
@login_required
@role_required("admin")
def create_mib_profile():
    session = get_db_session()
    profile_code = request.form.get("profile_code", "").strip()
    vendor = request.form.get("vendor", "").strip()
    model = request.form.get("model", "").strip()
    category = request.form.get("category", "").strip() or "中继器"
    parser_key = request.form.get("parser_key", "").strip() or DEFAULT_PROFILE_CODE
    description = request.form.get("description", "").strip() or None

    if not profile_code or not vendor or not model:
        flash("模板编码、厂家和型号不能为空。", "error")
        return redirect(url_for("web.mib_nodes"))
    if session.execute(select(DeviceProfile).where(DeviceProfile.profile_code == profile_code)).scalar_one_or_none():
        flash("模板编码已存在。", "error")
        return redirect(url_for("web.mib_nodes", profile_code=profile_code))

    profile = DeviceProfile(
        profile_code=profile_code,
        vendor=vendor,
        model=model,
        category=category,
        parser_key=parser_key,
        description=description,
        is_builtin=False,
    )
    session.add(profile)
    session.flush()
    log_operation(
        session,
        user_id=current_user.id,
        username_snapshot=current_user.username,
        action="create_device_profile",
        target_type="device_profile",
        target_id=str(profile.id),
        details_json={"profile_code": profile.profile_code, "vendor": vendor, "model": model},
    )
    session.commit()
    flash("设备模板已创建。", "success")
    return _redirect_profile_page(profile.profile_code, tab="profile")


@web_bp.post("/mib-nodes/profiles/<profile_code>")
@login_required
@role_required("admin")
def update_mib_profile(profile_code: str):
    session = get_db_session()
    profile = session.execute(select(DeviceProfile).where(DeviceProfile.profile_code == profile_code)).scalar_one_or_none()
    if profile is None:
        flash("设备模板不存在。", "error")
        return redirect(url_for("web.mib_nodes"))

    profile.vendor = request.form.get("vendor", profile.vendor).strip() or profile.vendor
    profile.model = request.form.get("model", profile.model).strip() or profile.model
    profile.category = request.form.get("category", profile.category).strip() or profile.category
    profile.parser_key = request.form.get("parser_key", profile.parser_key).strip() or profile.parser_key
    profile.description = request.form.get("description", "").strip() or None
    log_operation(
        session,
        user_id=current_user.id,
        username_snapshot=current_user.username,
        action="update_device_profile",
        target_type="device_profile",
        target_id=str(profile.id),
        details_json={"profile_code": profile.profile_code},
    )
    session.commit()
    flash("设备模板配置已更新。", "success")
    return _redirect_profile_page(profile.profile_code, tab="profile")


@web_bp.post("/mib-nodes/profiles/<profile_code>/delete")
@login_required
@role_required("admin")
def delete_mib_profile(profile_code: str):
    session = get_db_session()
    profile = session.execute(select(DeviceProfile).where(DeviceProfile.profile_code == profile_code)).scalar_one_or_none()
    if profile is None:
        flash("设备模板不存在。", "error")
        return _redirect_profile_page(tab="profile")
    if profile.is_builtin:
        flash("内置设备模板不允许删除。", "error")
        return _redirect_profile_page(profile.profile_code, tab="profile")
    if session.execute(select(Device.id).where(Device.device_profile_code == profile_code).limit(1)).scalar_one_or_none() is not None:
        flash("仍有设备使用该模板，不能删除。", "error")
        return _redirect_profile_page(profile.profile_code, tab="profile")
    if session.execute(select(TrapEvent.id).where(TrapEvent.profile_code == profile_code).limit(1)).scalar_one_or_none() is not None:
        flash("该模板已有 Trap 历史记录，不能删除。", "error")
        return _redirect_profile_page(profile.profile_code, tab="profile")

    session.query(PollingStrategy).filter(PollingStrategy.profile_code == profile_code).delete()
    session.query(AlarmRule).filter(AlarmRule.profile_code == profile_code).delete()
    session.query(MibEnum).filter(MibEnum.profile_code == profile_code).delete()
    session.query(MibNode).filter(MibNode.profile_code == profile_code).delete()
    log_operation(
        session,
        user_id=current_user.id,
        username_snapshot=current_user.username,
        action="delete_device_profile",
        target_type="device_profile",
        target_id=str(profile.id),
        details_json={"profile_code": profile.profile_code},
    )
    session.delete(profile)
    session.commit()
    flash("设备模板已删除。", "success")
    return _redirect_profile_page(tab="profile")


@web_bp.post("/mib-nodes/strategies")
@login_required
@role_required("admin")
def create_polling_strategy():
    session = get_db_session()
    profile_code = request.form.get("profile_code", "").strip()
    profile = session.execute(select(DeviceProfile).where(DeviceProfile.profile_code == profile_code)).scalar_one_or_none()
    if profile is None:
        flash("设备模板不存在。", "error")
        return _redirect_profile_page(tab="strategies")

    mib_node_id_raw = request.form.get("mib_node_id", "").strip()
    mib_node = None
    if mib_node_id_raw:
        mib_node = session.get(MibNode, int(mib_node_id_raw))
        if mib_node is None or mib_node.profile_code != profile_code:
            flash("采集项关联的 MIB 节点不存在。", "error")
            return _redirect_profile_page(profile_code, tab="strategies", mode="create")

    strategy = PollingStrategy(
        profile_code=profile_code,
        oid=request.form.get("oid", "").strip() or (mib_node.oid if mib_node else ""),
        node_name=request.form.get("node_name", "").strip() or (mib_node.name if mib_node else ""),
        node_name_zh=request.form.get("node_name_zh", "").strip() or (mib_node.name_zh if mib_node else None),
        category=request.form.get("category", "").strip() or (mib_node.category if mib_node else None),
        poll_interval_seconds=60,
        is_enabled=True,
        save_history=True,
        show_in_overview=False,
        show_in_device_card=False,
        display_order=100,
    )
    _strategy_from_form(strategy, mib_node=mib_node)
    if not strategy.oid or not strategy.node_name:
        flash("采集策略必须填写节点名和 OID。", "error")
        return _redirect_profile_page(profile_code, tab="strategies", mode="create")

    session.add(strategy)
    try:
        session.flush()
    except IntegrityError:
        session.rollback()
        flash("同一模板下节点名重复，无法创建采集策略。", "error")
        return _redirect_profile_page(profile_code, tab="strategies", mode="create")
    log_operation(
        session,
        user_id=current_user.id,
        username_snapshot=current_user.username,
        action="create_polling_strategy",
        target_type="polling_strategy",
        target_id=str(strategy.id),
        details_json={"profile_code": strategy.profile_code, "node_name": strategy.node_name},
    )
    session.commit()
    flash("采集策略已创建。", "success")
    return _redirect_profile_page(profile_code, tab="strategies", strategy_id=strategy.id)


@web_bp.post("/mib-nodes/strategies/<int:strategy_id>")
@login_required
@role_required("admin")
def update_polling_strategy(strategy_id: int):
    session = get_db_session()
    strategy = session.get(PollingStrategy, strategy_id)
    if strategy is None:
        flash("采集策略不存在。", "error")
        return _redirect_profile_page(tab="strategies")

    mib_node_id_raw = request.form.get("mib_node_id", "").strip()
    mib_node = None
    if mib_node_id_raw:
        mib_node = session.get(MibNode, int(mib_node_id_raw))
        if mib_node is None or mib_node.profile_code != strategy.profile_code:
            flash("采集项关联的 MIB 节点不存在。", "error")
            return _redirect_profile_page(strategy.profile_code, tab="strategies", strategy_id=strategy.id)

    _strategy_from_form(strategy, mib_node=mib_node)
    log_operation(
        session,
        user_id=current_user.id,
        username_snapshot=current_user.username,
        action="update_polling_strategy",
        target_type="polling_strategy",
        target_id=str(strategy.id),
        details_json={"profile_code": strategy.profile_code, "node_name": strategy.node_name},
    )
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        flash("同一模板下节点名重复，无法保存采集策略。", "error")
        return _redirect_profile_page(strategy.profile_code, tab="strategies", strategy_id=strategy.id)
    flash("采集策略已更新。", "success")
    return _redirect_profile_page(strategy.profile_code, tab="strategies", strategy_id=strategy.id)


@web_bp.post("/mib-nodes/strategies/<int:strategy_id>/delete")
@login_required
@role_required("admin")
def delete_polling_strategy(strategy_id: int):
    session = get_db_session()
    strategy = session.get(PollingStrategy, strategy_id)
    if strategy is None:
        flash("采集策略不存在。", "error")
        return _redirect_profile_page(tab="strategies")
    profile_code = strategy.profile_code
    log_operation(
        session,
        user_id=current_user.id,
        username_snapshot=current_user.username,
        action="delete_polling_strategy",
        target_type="polling_strategy",
        target_id=str(strategy.id),
        details_json={"profile_code": strategy.profile_code, "node_name": strategy.node_name},
    )
    session.delete(strategy)
    session.commit()
    flash("采集策略已删除。", "success")
    return _redirect_profile_page(profile_code, tab="strategies")


@web_bp.post("/mib-nodes/nodes")
@login_required
@role_required("admin")
def create_mib_node():
    session = get_db_session()
    profile_code = request.form.get("profile_code", "").strip()
    profile = session.execute(select(DeviceProfile).where(DeviceProfile.profile_code == profile_code)).scalar_one_or_none()
    if profile is None:
        flash("设备模板不存在。", "error")
        return _redirect_profile_page(tab="nodes")

    node = MibNode(
        profile_code=profile_code,
        oid=request.form.get("oid", "").strip(),
        name=request.form.get("name", "").strip(),
        category=request.form.get("category", "").strip() or "system",
        access=request.form.get("access", "").strip() or "read-only",
        data_type=request.form.get("data_type", "").strip() or "String",
        description=request.form.get("description", "").strip() or "未填写说明",
    )
    _mib_node_from_form(node)
    if not node.oid or not node.name:
        flash("MIB 节点必须填写 OID 和节点名。", "error")
        return _redirect_profile_page(profile_code, tab="nodes", mode="create")

    session.add(node)
    try:
        session.flush()
    except IntegrityError:
        session.rollback()
        flash("OID 或节点名已存在，当前库暂不支持跨模板重复。", "error")
        return _redirect_profile_page(profile_code, tab="nodes", mode="create")
    log_operation(
        session,
        user_id=current_user.id,
        username_snapshot=current_user.username,
        action="create_mib_node",
        target_type="mib_node",
        target_id=str(node.id),
        details_json={"profile_code": node.profile_code, "name": node.name, "oid": node.oid},
    )
    session.commit()
    flash("MIB 节点已创建。", "success")
    return _redirect_profile_page(profile_code, tab="nodes", node_id=node.id)


@web_bp.post("/mib-nodes/nodes/<int:node_id>")
@login_required
@role_required("admin")
def update_mib_node(node_id: int):
    session = get_db_session()
    node = session.get(MibNode, node_id)
    if node is None:
        flash("MIB 节点不存在。", "error")
        return _redirect_profile_page(tab="nodes")

    _mib_node_from_form(node)
    try:
        session.flush()
    except IntegrityError:
        session.rollback()
        flash("OID 或节点名已存在，当前库暂不支持跨模板重复。", "error")
        return _redirect_profile_page(node.profile_code, tab="nodes", node_id=node.id)
    log_operation(
        session,
        user_id=current_user.id,
        username_snapshot=current_user.username,
        action="update_mib_node",
        target_type="mib_node",
        target_id=str(node.id),
        details_json={"profile_code": node.profile_code, "name": node.name, "oid": node.oid},
    )
    session.commit()
    flash("MIB 节点已更新。", "success")
    return _redirect_profile_page(node.profile_code, tab="nodes", node_id=node.id)


@web_bp.post("/mib-nodes/nodes/<int:node_id>/delete")
@login_required
@role_required("admin")
def delete_mib_node(node_id: int):
    session = get_db_session()
    node = session.get(MibNode, node_id)
    if node is None:
        flash("MIB 节点不存在。", "error")
        return _redirect_profile_page(tab="nodes")
    profile_code = node.profile_code
    if session.execute(select(PollingStrategy.id).where(PollingStrategy.mib_node_id == node.id).limit(1)).scalar_one_or_none() is not None:
        flash("该 MIB 节点仍被采集策略引用，不能删除。", "error")
        return _redirect_profile_page(profile_code, tab="nodes", node_id=node.id)
    log_operation(
        session,
        user_id=current_user.id,
        username_snapshot=current_user.username,
        action="delete_mib_node",
        target_type="mib_node",
        target_id=str(node.id),
        details_json={"profile_code": node.profile_code, "name": node.name, "oid": node.oid},
    )
    session.delete(node)
    session.commit()
    flash("MIB 节点已删除。", "success")
    return _redirect_profile_page(profile_code, tab="nodes")


@web_bp.post("/mib-nodes/enums")
@login_required
@role_required("admin")
def create_mib_enum():
    session = get_db_session()
    profile_code = request.form.get("profile_code", "").strip()
    if session.execute(select(DeviceProfile.id).where(DeviceProfile.profile_code == profile_code)).scalar_one_or_none() is None:
        flash("设备模板不存在。", "error")
        return _redirect_profile_page(tab="enums")

    enum_name = request.form.get("enum_name", "").strip()
    label = request.form.get("label", "").strip()
    description = request.form.get("description", "").strip()
    code = _int_form("code", 0)
    if not enum_name or not label or not description:
        flash("枚举名称、值标签和说明不能为空。", "error")
        return _redirect_profile_page(profile_code, tab="enums", mode="create")

    enum_item = MibEnum(
        profile_code=profile_code,
        enum_name=enum_name,
        code=code,
        label=label,
        description=description,
    )
    session.add(enum_item)
    try:
        session.flush()
    except IntegrityError:
        session.rollback()
        flash("同名枚举值已存在，当前库暂不支持跨模板重复。", "error")
        return _redirect_profile_page(profile_code, tab="enums", mode="create")
    log_operation(
        session,
        user_id=current_user.id,
        username_snapshot=current_user.username,
        action="create_mib_enum",
        target_type="mib_enum",
        target_id=str(enum_item.id),
        details_json={"profile_code": enum_item.profile_code, "enum_name": enum_item.enum_name, "code": enum_item.code},
    )
    session.commit()
    flash("枚举已创建。", "success")
    return _redirect_profile_page(profile_code, tab="enums", enum_id=enum_item.id)


@web_bp.post("/mib-nodes/enums/<int:enum_id>")
@login_required
@role_required("admin")
def update_mib_enum(enum_id: int):
    session = get_db_session()
    enum_item = session.get(MibEnum, enum_id)
    if enum_item is None:
        flash("枚举不存在。", "error")
        return _redirect_profile_page(tab="enums")

    enum_item.enum_name = request.form.get("enum_name", enum_item.enum_name).strip() or enum_item.enum_name
    enum_item.code = _int_form("code", enum_item.code)
    enum_item.label = request.form.get("label", enum_item.label).strip() or enum_item.label
    enum_item.description = request.form.get("description", enum_item.description).strip() or enum_item.description
    try:
        session.flush()
    except IntegrityError:
        session.rollback()
        flash("同名枚举值已存在，当前库暂不支持跨模板重复。", "error")
        return _redirect_profile_page(enum_item.profile_code, tab="enums", enum_id=enum_item.id)
    log_operation(
        session,
        user_id=current_user.id,
        username_snapshot=current_user.username,
        action="update_mib_enum",
        target_type="mib_enum",
        target_id=str(enum_item.id),
        details_json={"profile_code": enum_item.profile_code, "enum_name": enum_item.enum_name, "code": enum_item.code},
    )
    session.commit()
    flash("枚举已更新。", "success")
    return _redirect_profile_page(enum_item.profile_code, tab="enums", enum_id=enum_item.id)


@web_bp.post("/mib-nodes/enums/<int:enum_id>/delete")
@login_required
@role_required("admin")
def delete_mib_enum(enum_id: int):
    session = get_db_session()
    enum_item = session.get(MibEnum, enum_id)
    if enum_item is None:
        flash("枚举不存在。", "error")
        return _redirect_profile_page(tab="enums")
    profile_code = enum_item.profile_code
    log_operation(
        session,
        user_id=current_user.id,
        username_snapshot=current_user.username,
        action="delete_mib_enum",
        target_type="mib_enum",
        target_id=str(enum_item.id),
        details_json={"profile_code": enum_item.profile_code, "enum_name": enum_item.enum_name, "code": enum_item.code},
    )
    session.delete(enum_item)
    session.commit()
    flash("枚举已删除。", "success")
    return _redirect_profile_page(profile_code, tab="enums")


@web_bp.post("/mib-nodes/alarm-rules")
@login_required
@role_required("admin")
def create_alarm_rule():
    session = get_db_session()
    profile_code = request.form.get("profile_code", "").strip()
    if session.execute(select(DeviceProfile.id).where(DeviceProfile.profile_code == profile_code)).scalar_one_or_none() is None:
        flash("设备模板不存在。", "error")
        return _redirect_profile_page(tab="rules")

    rule = AlarmRule(
        profile_code=profile_code,
        alarm_id=request.form.get("alarm_id", "").strip(),
        default_severity=request.form.get("default_severity", "").strip() or "warning",
        should_create_active=True,
        should_popup=False,
        description=request.form.get("description", "").strip() or "未填写告警说明",
    )
    _alarm_rule_from_form(rule)
    if not rule.alarm_id:
        flash("告警 ID 不能为空。", "error")
        return _redirect_profile_page(profile_code, tab="rules", mode="create")
    session.add(rule)
    session.flush()
    log_operation(
        session,
        user_id=current_user.id,
        username_snapshot=current_user.username,
        action="create_alarm_rule",
        target_type="alarm_rule",
        target_id=str(rule.id),
        details_json={"profile_code": rule.profile_code, "alarm_id": rule.alarm_id},
    )
    session.commit()
    flash("告警规则已创建。", "success")
    return _redirect_profile_page(profile_code, tab="rules", rule_id=rule.id)


@web_bp.post("/mib-nodes/alarm-rules/<int:rule_id>")
@login_required
@role_required("admin")
def update_alarm_rule(rule_id: int):
    session = get_db_session()
    rule = session.get(AlarmRule, rule_id)
    if rule is None:
        flash("告警规则不存在。", "error")
        return _redirect_profile_page(tab="rules")
    _alarm_rule_from_form(rule)
    log_operation(
        session,
        user_id=current_user.id,
        username_snapshot=current_user.username,
        action="update_alarm_rule",
        target_type="alarm_rule",
        target_id=str(rule.id),
        details_json={"profile_code": rule.profile_code, "alarm_id": rule.alarm_id},
    )
    session.commit()
    flash("告警规则已更新。", "success")
    return _redirect_profile_page(rule.profile_code, tab="rules", rule_id=rule.id)


@web_bp.post("/mib-nodes/alarm-rules/<int:rule_id>/delete")
@login_required
@role_required("admin")
def delete_alarm_rule(rule_id: int):
    session = get_db_session()
    rule = session.get(AlarmRule, rule_id)
    if rule is None:
        flash("告警规则不存在。", "error")
        return _redirect_profile_page(tab="rules")
    profile_code = rule.profile_code
    log_operation(
        session,
        user_id=current_user.id,
        username_snapshot=current_user.username,
        action="delete_alarm_rule",
        target_type="alarm_rule",
        target_id=str(rule.id),
        details_json={"profile_code": rule.profile_code, "alarm_id": rule.alarm_id},
    )
    session.delete(rule)
    session.commit()
    flash("告警规则已删除。", "success")
    return _redirect_profile_page(profile_code, tab="rules")


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
    trap_rows = session.execute(stmt.order_by(TrapEvent.received_at.desc(), TrapEvent.id.desc()).limit(100)).scalars().all()
    devices = _device_map(session)
    profiles = _profile_map(session)
    trap_views = [
        _trap_payload(item, devices.get(item.device_id) if item.device_id else None, profiles.get(item.profile_code or DEFAULT_PROFILE_CODE))
        for item in trap_rows
    ]
    return render_template(
        "traps.html",
        **_base_context(
            page_name="Trap 实时页面",
            traps=trap_views,
            devices=list(devices.values()),
            filter_severity=severity,
            filter_device_id=device_id,
            filter_keyword=keyword,
        ),
    )


@web_bp.get("/traps/<int:trap_id>")
@login_required
def trap_detail(trap_id: int):
    session = get_db_session()
    trap = session.get(TrapEvent, trap_id)
    if trap is None:
        return Response("trap not found", status=404)
    device = session.get(Device, trap.device_id) if trap.device_id else None
    profile = session.execute(select(DeviceProfile).where(DeviceProfile.profile_code == (trap.profile_code or DEFAULT_PROFILE_CODE))).scalar_one_or_none()
    payload = _trap_payload(trap, device, profile)
    raw_varbinds = []
    if isinstance(trap.raw_json, dict):
        maybe_varbinds = trap.raw_json.get("varbinds")
        if isinstance(maybe_varbinds, list):
            raw_varbinds = maybe_varbinds
    return render_template(
        "trap_detail.html",
        **_base_context(
            page_name=f"Trap 详情 - {trap.id}",
            trap=trap,
            payload=payload,
            device=device,
            profile=profile,
            raw_json_pretty=_json_pretty(trap.raw_json),
            translated_json_pretty=_json_pretty(trap.translated_json),
            raw_varbinds=raw_varbinds,
        ),
    )


@web_bp.get("/alarms")
@login_required
def alarms():
    session = get_db_session()
    device_id = request.args.get("device_id", "").strip()
    severity = request.args.get("severity", "").strip()
    ack_state = request.args.get("ack_state", "").strip()
    open_state = request.args.get("open_state", "").strip()
    history_status = request.args.get("history_status", "").strip()
    keyword = request.args.get("keyword", "").strip()
    start_at = request.args.get("start_at", "").strip()
    end_at = request.args.get("end_at", "").strip()

    events = session.execute(select(AlarmEvent).order_by(AlarmEvent.occurred_at.desc(), AlarmEvent.id.desc()).limit(500)).scalars().all()
    active_map = {item.id: item for item in session.execute(select(ActiveAlarm)).scalars().all()}
    devices = session.execute(select(Device).order_by(Device.name.asc())).scalars().all()
    device_names = {item.id: item.name for item in devices}

    start_dt = parse_local_datetime(start_at)
    end_dt = parse_local_datetime(end_at, end_of_day=True)
    rows: list[dict[str, Any]] = []
    for item in events:
        active_alarm = active_map.get(item.active_alarm_id) if item.active_alarm_id else None
        row = {
            "event": item,
            "active_alarm": active_alarm,
            "device_name": device_names.get(item.device_id, "未知设备"),
            "severity_label": severity_label(item.severity),
            "status_label": status_label(item.status),
            "active_state_label": "活动中" if active_alarm and active_alarm.is_open else "已关闭",
            "ack_state_label": "已确认" if active_alarm and active_alarm.is_acknowledged else "未确认",
        }
        if device_id and str(item.device_id or "") != device_id:
            continue
        if severity and item.severity != severity:
            continue
        if history_status and item.status != history_status:
            continue
        if ack_state == "ack" and not (active_alarm and active_alarm.is_acknowledged):
            continue
        if ack_state == "unack" and active_alarm and active_alarm.is_acknowledged:
            continue
        if open_state == "open" and not (active_alarm and active_alarm.is_open):
            continue
        if open_state == "closed" and active_alarm and active_alarm.is_open:
            continue
        if start_dt and item.occurred_at < start_dt:
            continue
        if end_dt and item.occurred_at >= end_dt:
            continue
        if keyword:
            haystack = " ".join(
                filter(
                    None,
                    [
                        item.alarm_obj,
                        item.alarm_id,
                        item.message,
                        None if active_alarm is None else active_alarm.notes,
                    ],
                )
            ).lower()
            if keyword.lower() not in haystack:
                continue
        rows.append(row)

    active_count = sum(1 for item in active_map.values() if item.is_open)
    unacked_count = sum(1 for item in active_map.values() if item.is_open and not item.is_acknowledged)
    return render_template(
        "alarms.html",
        **_base_context(
            page_name="告警中心",
            alarm_rows=rows,
            devices=devices,
            active_count=active_count,
            unacked_count=unacked_count,
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
    session.add(AlarmAckLog(active_alarm_id=alarm.id, user_id=current_user.id, ack_note=note))
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
    flash("告警已确认。", "success")
    return redirect(request.referrer or url_for("web.alarms"))


@web_bp.get("/logs")
@login_required
def logs():
    session = get_db_session()
    rows = session.execute(select(OperationLog).order_by(OperationLog.created_at.desc(), OperationLog.id.desc()).limit(200)).scalars().all()
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
    devices = _device_map(session)
    profiles = _profile_map(session)
    return jsonify(
        [
            _trap_payload(item, devices.get(item.device_id) if item.device_id else None, profiles.get(item.profile_code or DEFAULT_PROFILE_CODE))
            for item in rows
        ]
    )


@web_bp.get("/api/popup-notifications")
@login_required
def api_popup_notifications():
    session = get_db_session()
    device_names = {item.id: item.name for item in session.execute(select(Device)).scalars().all()}
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
                "device_name": device_names.get(item.device_id, "未知设备"),
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

    return Response(generate(), mimetype="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@web_bp.get("/healthz")
def healthz():
    return {"status": "ok", "service": "repeater-nms-web"}
