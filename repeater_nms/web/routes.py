from __future__ import annotations

from flask import Blueprint, current_app, render_template


web_bp = Blueprint("web", __name__)


@web_bp.get("/")
def index():
    return render_template(
        "index.html",
        page_title=current_app.config["PAGE_TITLE"],
        app_name=current_app.config["APP_NAME"],
    )


@web_bp.get("/healthz")
def healthz():
    return {"status": "ok", "service": "repeater-nms-web"}

