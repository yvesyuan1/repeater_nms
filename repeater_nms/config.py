from __future__ import annotations

import os

from repeater_nms.env import load_environment


load_environment()


class Config:
    APP_NAME = "repeater-nms"
    PAGE_TITLE = "中继器网管"
    TESTING = os.getenv("TESTING", "0") == "1"
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key")
    DATABASE_URL = os.getenv(
        "DATABASE_URL",
        "mysql+pymysql://my_analyzer:change-me@127.0.0.1:3306/zjq_admin?charset=utf8mb4",
    )
    REDIS_URL = os.getenv("REDIS_URL", "redis://127.0.0.1:6379/0")
    REDIS_CHANNEL_PREFIX = os.getenv("REDIS_CHANNEL_PREFIX", "repeater_nms")
    APP_HOST = os.getenv("APP_HOST", "127.0.0.1")
    APP_PORT = int(os.getenv("APP_PORT", "5000"))
    TIMEZONE = os.getenv("TIMEZONE", "Asia/Shanghai")
    ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
    SSE_HEARTBEAT_SECONDS = int(os.getenv("SSE_HEARTBEAT_SECONDS", "15"))
    SESSION_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_HTTPONLY = True
