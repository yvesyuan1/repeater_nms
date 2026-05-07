from __future__ import annotations

from flask import Flask

from repeater_nms.config import Config
from repeater_nms.web.db import close_db_session
from repeater_nms.web.extensions import login_manager
from repeater_nms.web.cli import register_cli


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

    app.jinja_env.filters["dt"] = lambda value: __import__("repeater_nms.web.utils", fromlist=["format_dt"]).format_dt(value)
    app.jinja_env.filters["masked"] = lambda value: __import__("repeater_nms.web.utils", fromlist=["mask_secret"]).mask_secret(value)
    return app
