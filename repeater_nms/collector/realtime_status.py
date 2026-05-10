from __future__ import annotations

import json
import logging
import socket
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable

import redis
from sqlalchemy import select

from repeater_nms.db.models import Device
from repeater_nms.db.session import session_scope


LOGGER = logging.getLogger("repeater_nms.collector.realtime_status")

LATEST_TTL_SECONDS = 30
NORMAL_WINDOW_SECONDS = 5
HISTORY_MAX_ITEMS = 300
HISTORY_SAMPLE_SECONDS = 1.0


def _json_default(value: Any) -> str:
    return str(value)


def _to_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _to_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _parse_report_time(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return datetime.now(timezone.utc).isoformat()
    return text


def _rate_limited(logger: logging.Logger, key: str, message: str, *args: Any, interval: float = 60.0) -> None:
    now = time.monotonic()
    state = getattr(logger, "_repeater_realtime_rate_limit", {})
    last_at = state.get(key, 0.0)
    if now - last_at >= interval:
        logger.warning(message, *args)
        state[key] = now
        setattr(logger, "_repeater_realtime_rate_limit", state)


class RealtimeStatusProcessor:
    def __init__(
        self,
        database_url: str,
        redis_url: str,
        *,
        redis_client: redis.Redis | None = None,
    ) -> None:
        self.database_url = database_url
        self.redis = redis_client or redis.Redis.from_url(redis_url, decode_responses=True)

    @staticmethod
    def latest_key(device_id: int) -> str:
        return f"realtime:device:{device_id}:latest"

    @staticmethod
    def history_key(device_id: int) -> str:
        return f"realtime:device:{device_id}:history"

    @staticmethod
    def sample_marker_key(device_id: int) -> str:
        return f"realtime:device:{device_id}:history:last_sample_at"

    def process_datagram(self, data: bytes, *, source: tuple[str, int] | None = None) -> bool:
        try:
            text = data.decode("utf-8").strip()
        except UnicodeDecodeError:
            LOGGER.warning("realtime status json decode failed source=%s", source)
            return False
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            LOGGER.warning("realtime status json parse failed source=%s error=%s raw=%s", source, exc, text[:300])
            return False
        return self.process_payload(payload, raw_text=text, source=source)

    def process_payload(
        self,
        payload: dict[str, Any],
        *,
        raw_text: str | None = None,
        source: tuple[str, int] | None = None,
    ) -> bool:
        valid, reason = self._validate_payload(payload)
        if not valid:
            LOGGER.warning("realtime status field validation failed source=%s reason=%s payload=%s", source, reason, payload)
            return False

        device = self._single_device()
        if device is None:
            return False

        interfaces = self._normalize_interfaces(payload["interfaces"])
        report_ts = _parse_report_time(payload.get("ts"))
        received_at = datetime.now(timezone.utc)
        normalized = {
            "device_id": device["id"],
            "device_name": device["name"],
            "device_ip": device["ip"],
            "ts": report_ts,
            "received_at": received_at.isoformat(),
            "interfaces": interfaces,
            "raw_data": payload,
            "raw_text": raw_text or json.dumps(payload, ensure_ascii=False, default=_json_default),
        }
        try:
            self.redis.setex(
                self.latest_key(device["id"]),
                LATEST_TTL_SECONDS,
                json.dumps(normalized, ensure_ascii=False, default=_json_default),
            )
            self._append_history_sample(device["id"], report_ts, received_at, interfaces)
        except redis.RedisError as exc:
            LOGGER.warning("realtime status redis write failed device_id=%s error=%s", device["id"], exc)
            return False
        return True

    def _single_device(self) -> dict[str, Any] | None:
        with session_scope(self.database_url) as session:
            devices = session.execute(select(Device).order_by(Device.id.asc()).limit(2)).scalars().all()
        if not devices:
            _rate_limited(LOGGER, "no_device", "realtime status dropped: device table has no device")
            return None
        if len(devices) > 1:
            _rate_limited(
                LOGGER,
                "multi_device",
                "当前实时状态接收逻辑仅支持单设备，请确认设备表中是否只存在一台设备。",
            )
        device = devices[0]
        return {"id": device.id, "name": device.name, "ip": device.ip}

    @staticmethod
    def _validate_payload(payload: Any) -> tuple[bool, str]:
        if not isinstance(payload, dict):
            return False, "payload must be object"
        if "ts" not in payload:
            return False, "missing ts"
        interfaces = payload.get("interfaces")
        if not isinstance(interfaces, list):
            return False, "interfaces must be list"
        for index, item in enumerate(interfaces):
            if not isinstance(item, dict):
                return False, f"interfaces[{index}] must be object"
            for field in ["name", "bandwidth_mbps", "bandwidth_str", "packets_per_sec", "programs"]:
                if field not in item:
                    return False, f"missing interfaces[{index}].{field}"
        return True, "ok"

    @staticmethod
    def _normalize_interfaces(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        normalized = []
        for item in rows:
            normalized.append(
                {
                    "name": str(item.get("name") or "").strip(),
                    "bandwidth_mbps": _to_float(item.get("bandwidth_mbps")),
                    "bandwidth_str": str(item.get("bandwidth_str") or "").strip(),
                    "packets_per_sec": _to_int(item.get("packets_per_sec")),
                    "programs": _to_int(item.get("programs")),
                }
            )
        return normalized

    def _append_history_sample(
        self,
        device_id: int,
        report_ts: str,
        received_at: datetime,
        interfaces: list[dict[str, Any]],
    ) -> None:
        marker_key = self.sample_marker_key(device_id)
        now_seconds = time.time()
        last_sample = self.redis.get(marker_key)
        if last_sample is not None:
            try:
                if now_seconds - float(last_sample) < HISTORY_SAMPLE_SECONDS:
                    return
            except ValueError:
                pass
        by_name = {item["name"]: item for item in interfaces}

        def metric(interface_name: str, field: str) -> Any:
            return (by_name.get(interface_name) or {}).get(field)

        sample = {
            "ts": report_ts,
            "received_at": received_at.isoformat(),
            "ens7f0": {
                "bandwidth_mbps": metric("ens7f0", "bandwidth_mbps"),
                "programs": metric("ens7f0", "programs"),
                "packets_per_sec": metric("ens7f0", "packets_per_sec"),
            },
            "ens7f1": {
                "bandwidth_mbps": metric("ens7f1", "bandwidth_mbps"),
                "programs": metric("ens7f1", "programs"),
                "packets_per_sec": metric("ens7f1", "packets_per_sec"),
            },
        }
        pipe = self.redis.pipeline()
        pipe.rpush(self.history_key(device_id), json.dumps(sample, ensure_ascii=False, default=_json_default))
        pipe.ltrim(self.history_key(device_id), -HISTORY_MAX_ITEMS, -1)
        pipe.setex(marker_key, LATEST_TTL_SECONDS, str(now_seconds))
        pipe.execute()


class UdpRealtimeStatusListener:
    def __init__(
        self,
        bind_host: str,
        bind_port: int,
        handler: Callable[..., bool],
    ) -> None:
        self.bind_host = bind_host
        self.bind_port = bind_port
        self.handler = handler
        self.thread: threading.Thread | None = None
        self.socket: socket.socket | None = None
        self._running = threading.Event()

    def start(self) -> None:
        self._running.set()
        self.thread = threading.Thread(target=self._run, name="repeater-nms-realtime-status-listener", daemon=True)
        self.thread.start()
        LOGGER.info("realtime status udp listener started bind=%s:%s", self.bind_host, self.bind_port)

    def stop(self) -> None:
        self._running.clear()
        if self.socket is not None:
            try:
                self.socket.close()
            except OSError:
                pass
        if self.thread is not None:
            self.thread.join(timeout=5)

    def _run(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket = sock
        try:
            sock.settimeout(1.0)
            sock.bind((self.bind_host, self.bind_port))
            while self._running.is_set():
                try:
                    data, address = sock.recvfrom(65535)
                except socket.timeout:
                    continue
                except OSError:
                    if self._running.is_set():
                        LOGGER.exception("realtime status udp listener socket error")
                    break
                try:
                    self.handler(data, source=address)
                except Exception:
                    LOGGER.exception("realtime status datagram handler failed source=%s", address)
        except Exception:
            LOGGER.exception("realtime status udp listener crashed")
        finally:
            try:
                sock.close()
            except OSError:
                pass
