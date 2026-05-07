from __future__ import annotations

from flask import Flask

from repeater_nms.config import Config
from repeater_nms.web.cli import register_cli
from repeater_nms.web.db import close_db_session
from repeater_nms.web.extensions import login_manager
from repeater_nms.web.utils import (
    mask_secret,
    poll_status_description,
    poll_status_label,
    role_description,
    role_label,
    severity_label,
    status_label,
    trap_name_label,
    trap_type_label,
    format_dt,
)


def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config.from_object(Config)
    login_manager.init_app(app)

    from repeater_nms.web.routes import web_bp

    app.register_blueprint(web_bp)
    register_cli(app)
    app.teardown_appcontext(close_db_session)

    @app.context_processor
    def inject_globals():
        return {
            "channel_prefix": app.config["REDIS_CHANNEL_PREFIX"],
        }

    app.jinja_env.filters["dt"] = format_dt
    app.jinja_env.filters["masked"] = mask_secret
    app.jinja_env.filters["role_label"] = role_label
    app.jinja_env.filters["role_desc"] = role_description
    app.jinja_env.filters["severity_label"] = severity_label
    app.jinja_env.filters["status_label"] = status_label
    app.jinja_env.filters["poll_status_label"] = poll_status_label
    app.jinja_env.filters["poll_status_desc"] = poll_status_description
    app.jinja_env.filters["trap_name_label"] = trap_name_label
    app.jinja_env.filters["trap_type_label"] = trap_type_label
    return app
