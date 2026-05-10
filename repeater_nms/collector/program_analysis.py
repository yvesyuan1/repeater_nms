from __future__ import annotations

import json
import logging
import re
import socket
import threading
import time
from datetime import datetime, timezone
from typing import Any

import redis
from sqlalchemy import select

from repeater_nms.db.models import Device
from repeater_nms.db.session import session_scope


LOGGER = logging.getLogger("repeater_nms.collector.program_analysis")

PROGRAM_TTL_SECONDS = 60
BATCH_TTL_SECONDS = 60
PORT_STALE_SECONDS = 10
PROGRAM_STALE_SECONDS = 30
INTERFACE_BY_PORT = {2001: "ens7f0", 2002: "ens7f1"}
TRAILING_COMMA_RE = re.compile(r",(\s*[}\]])")
MISSING_FIELD_COMMA_RE = re.compile(r'([0-9"\]}])(\s*\n\s*")(?=[^"\n]+":)')
MISSING_OBJECT_COMMA_RE = re.compile(r"(})(\s*\n\s*{)")


def _json_default(value: Any) -> str:
    return str(value)


def _to_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _to_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _rate_limited(logger: logging.Logger, key: str, message: str, *args: Any, interval: float = 60.0) -> None:
    now = time.monotonic()
    state = getattr(logger, "_repeater_program_rate_limit", {})
    last_at = state.get(key, 0.0)
    if now - last_at >= interval:
        logger.warning(message, *args)
        state[key] = now
        setattr(logger, "_repeater_program_rate_limit", state)


class ProgramAnalysisProcessor:
    def __init__(self, database_url: str, redis_url: str, *, redis_client: redis.Redis | None = None) -> None:
        self.database_url = database_url
        self.redis = redis_client or redis.Redis.from_url(redis_url, decode_responses=True)

    @staticmethod
    def programs_key(device_id: int, interface_name: str) -> str:
        return f"program:device:{device_id}:{interface_name}:programs"

    @staticmethod
    def batch_key(device_id: int, interface_name: str) -> str:
        return f"program:device:{device_id}:{interface_name}:batch"

    def process_datagram(self, data: bytes, *, interface_name: str, source: tuple[str, int] | None = None) -> bool:
        try:
            text = data.decode("utf-8").strip()
        except UnicodeDecodeError:
            LOGGER.warning("program analysis json decode failed interface=%s source=%s", interface_name, source)
            return False
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            compatible_text = self._compatible_json_text(text)
            if compatible_text == text:
                LOGGER.warning("program analysis json parse failed interface=%s source=%s error=%s raw=%s", interface_name, source, exc, text[:300])
                return False
            try:
                payload = json.loads(compatible_text)
                LOGGER.debug("program analysis json parsed after compatibility cleanup interface=%s source=%s", interface_name, source)
            except json.JSONDecodeError as compatible_exc:
                LOGGER.warning("program analysis json parse failed interface=%s source=%s error=%s raw=%s", interface_name, source, compatible_exc, text[:300])
                return False
        return self.process_payload(payload, interface_name=interface_name, raw_text=text, source=source)

    @staticmethod
    def _compatible_json_text(text: str) -> str:
        cleaned = TRAILING_COMMA_RE.sub(r"\1", text)
        cleaned = MISSING_FIELD_COMMA_RE.sub(r"\1,\2", cleaned)
        cleaned = MISSING_OBJECT_COMMA_RE.sub(r"\1,\2", cleaned)
        cleaned = TRAILING_COMMA_RE.sub(r"\1", cleaned)
        return cleaned

    def process_payload(
        self,
        payload: dict[str, Any],
        *,
        interface_name: str,
        raw_text: str | None = None,
        source: tuple[str, int] | None = None,
    ) -> bool:
        valid, reason = self._validate_payload(payload)
        if not valid:
            LOGGER.warning("program analysis field validation failed interface=%s source=%s reason=%s payload=%s", interface_name, source, reason, payload)
            return False
        device = self._single_device()
        if device is None:
            return False

        batch = payload["batch"]
        received_at = datetime.now(timezone.utc).isoformat()
        programs = [
            self._normalize_program(item, interface_name=interface_name, received_at=received_at)
            for item in payload["programs"]
            if isinstance(item, dict)
        ]
        batch_payload = {
            "interface": interface_name,
            "last_update_time": received_at,
            "total": _to_int(batch.get("total")) or 0,
            "last_batch_start": _to_int(batch.get("start")),
            "last_batch_end": _to_int(batch.get("end")),
            "last_duration": _to_float(batch.get("duration")),
            "received_count": len(programs),
            "data_status": "normal",
            "batch_device": batch.get("device"),
            "raw_data": payload,
            "raw_text": raw_text or json.dumps(payload, ensure_ascii=False, default=_json_default),
        }
        try:
            pipe = self.redis.pipeline()
            for item in programs:
                pipe.hset(
                    self.programs_key(device["id"], interface_name),
                    str(item["no"]),
                    json.dumps(item, ensure_ascii=False, default=_json_default),
                )
            pipe.expire(self.programs_key(device["id"], interface_name), PROGRAM_TTL_SECONDS)
            pipe.setex(
                self.batch_key(device["id"], interface_name),
                BATCH_TTL_SECONDS,
                json.dumps(batch_payload, ensure_ascii=False, default=_json_default),
            )
            pipe.execute()
        except redis.RedisError as exc:
            LOGGER.warning("program analysis redis write failed device_id=%s interface=%s error=%s", device["id"], interface_name, exc)
            return False
        return True

    def _single_device(self) -> dict[str, Any] | None:
        with session_scope(self.database_url) as session:
            devices = session.execute(select(Device).order_by(Device.id.asc()).limit(2)).scalars().all()
        if not devices:
            _rate_limited(LOGGER, "no_device", "program analysis dropped: device table has no device")
            return None
        if len(devices) > 1:
            _rate_limited(
                LOGGER,
                "multi_device",
                "当前节目频道分析接收逻辑仅支持单设备，请确认设备表中是否只存在一台设备。",
            )
        device = devices[0]
        return {"id": device.id, "name": device.name, "ip": device.ip}

    @staticmethod
    def _validate_payload(payload: Any) -> tuple[bool, str]:
        if not isinstance(payload, dict):
            return False, "payload must be object"
        batch = payload.get("batch")
        if not isinstance(batch, dict):
            return False, "missing batch"
        for field in ["start", "end", "total", "duration", "device"]:
            if field not in batch:
                return False, f"missing batch.{field}"
        programs = payload.get("programs")
        if not isinstance(programs, list):
            return False, "missing programs"
        for index, item in enumerate(programs):
            if not isinstance(item, dict):
                return False, f"programs[{index}] must be object"
            for field in ["no", "stream", "total_bw", "status", "l1", "l2", "l3"]:
                if field not in item:
                    return False, f"missing programs[{index}].{field}"
        return True, "ok"

    @staticmethod
    def _normalize_program(item: dict[str, Any], *, interface_name: str, received_at: str) -> dict[str, Any]:
        stream = str(item.get("stream") or "").strip()
        multicast_address, udp_port = stream, None
        if ":" in stream:
            multicast_address, port_text = stream.rsplit(":", 1)
            udp_port = _to_int(port_text)
        status = str(item.get("status") or "").strip() or "unknown"
        video_bw = _to_int(item.get("video_bw"))
        audio_bw = _to_int(item.get("audio_bw"))
        return {
            "interface": interface_name,
            "no": _to_int(item.get("no")) or 0,
            "stream": stream,
            "multicast_address": multicast_address,
            "udp_port": udp_port,
            "status": status,
            "total_bw": _to_int(item.get("total_bw")) or 0,
            "video_bw": video_bw,
            "audio_bw": audio_bw,
            "video_codec": str(item.get("video_codec") or "").strip(),
            "audio_codec": str(item.get("audio_codec") or "").strip(),
            "l1": _to_int(item.get("l1")) or 0,
            "l2": _to_int(item.get("l2")) or 0,
            "l3": _to_int(item.get("l3")) or 0,
            "no_video": not video_bw,
            "no_audio": not audio_bw,
            "last_update_time": received_at,
            "raw_data": item,
        }


class UdpProgramAnalysisListener:
    def __init__(self, bind_host: str, bind_port: int, interface_name: str, processor: ProgramAnalysisProcessor) -> None:
        self.bind_host = bind_host
        self.bind_port = bind_port
        self.interface_name = interface_name
        self.processor = processor
        self.thread: threading.Thread | None = None
        self.socket: socket.socket | None = None
        self._running = threading.Event()

    def start(self) -> None:
        self._running.set()
        self.thread = threading.Thread(
            target=self._run,
            name=f"repeater-nms-program-analysis-{self.interface_name}",
            daemon=True,
        )
        self.thread.start()
        LOGGER.info("program analysis udp listener started bind=%s:%s interface=%s", self.bind_host, self.bind_port, self.interface_name)

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
                        LOGGER.exception("program analysis udp listener socket error interface=%s", self.interface_name)
                    break
                try:
                    self.processor.process_datagram(data, interface_name=self.interface_name, source=address)
                except Exception:
                    LOGGER.exception("program analysis datagram handler failed interface=%s source=%s", self.interface_name, address)
        except Exception:
            LOGGER.exception("program analysis udp listener crashed interface=%s", self.interface_name)
        finally:
            try:
                sock.close()
            except OSError:
                pass
