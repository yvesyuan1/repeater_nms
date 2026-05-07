from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from flask import request
from sqlalchemy.orm import Session

from repeater_nms.collector.publisher import RedisEventPublisher
from repeater_nms.db.models import OperationLog


def format_dt(value: datetime | None) -> str:
    if value is None:
        return "-"
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    local_value = value.astimezone()
    return local_value.strftime("%Y-%m-%d %H:%M:%S")


def mask_secret(value: str | None) -> str:
    if not value:
        return "-"
    if len(value) <= 2:
        return "*" * len(value)
    return f"{value[0]}{'*' * (len(value) - 2)}{value[-1]}"


def log_operation(
    session: Session,
    *,
    user_id: int | None,
    username_snapshot: str | None,
    action: str,
    target_type: str | None = None,
    target_id: str | None = None,
    details_json: dict[str, Any] | list[Any] | None = None,
) -> None:
    session.add(
        OperationLog(
            user_id=user_id,
            username_snapshot=username_snapshot,
            action=action,
            target_type=target_type,
            target_id=target_id,
            source_ip=request.headers.get("X-Forwarded-For", request.remote_addr),
            details_json=details_json,
        )
    )


def redis_client_from_app(app) -> RedisEventPublisher:
    return RedisEventPublisher(app.config["REDIS_URL"], app.config["REDIS_CHANNEL_PREFIX"])
