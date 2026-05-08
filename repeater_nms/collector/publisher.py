from __future__ import annotations

import json
import logging
from typing import Any

import redis

from repeater_nms.collector.schemas import PublishedTrapEvent


LOGGER = logging.getLogger("repeater_nms.collector.publisher")


def _json_default(value: Any) -> str:
    return str(value)


class EventPublisher:
    def publish_trap_event(self, event: PublishedTrapEvent) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def cache_device_snapshot(self, device_id: int, payload: dict[str, Any]) -> None:  # pragma: no cover - interface
        raise NotImplementedError


class RedisEventPublisher(EventPublisher):
    def __init__(self, redis_url: str, channel_prefix: str) -> None:
        self.redis = redis.Redis.from_url(redis_url, decode_responses=True)
        self.channel_prefix = channel_prefix
        self._redis_available = True

    @property
    def trap_channel(self) -> str:
        return f"{self.channel_prefix}:trap_events"

    def publish_trap_event(self, event: PublishedTrapEvent) -> None:
        if not self._redis_available:
            return
        try:
            self.redis.publish(
                self.trap_channel,
                json.dumps(event.to_dict(), ensure_ascii=False, default=_json_default),
            )
        except redis.RedisError as exc:
            self._redis_available = False
            LOGGER.warning("redis publish skipped after connection failure: %s", exc)

    def cache_device_snapshot(self, device_id: int, payload: dict[str, Any]) -> None:
        if not self._redis_available:
            return
        try:
            self.redis.set(
                f"{self.channel_prefix}:device:{device_id}:latest_poll",
                json.dumps(payload, ensure_ascii=False, default=_json_default),
            )
        except redis.RedisError as exc:
            self._redis_available = False
            LOGGER.warning("redis cache skipped after connection failure: %s", exc)


class InMemoryEventPublisher(EventPublisher):
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []
        self.snapshots: dict[int, dict[str, Any]] = {}

    def publish_trap_event(self, event: PublishedTrapEvent) -> None:
        self.events.append(event.to_dict())

    def cache_device_snapshot(self, device_id: int, payload: dict[str, Any]) -> None:
        self.snapshots[device_id] = payload
