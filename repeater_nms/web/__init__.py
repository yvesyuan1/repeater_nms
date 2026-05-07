from __future__ import annotations

from flask import Flask

from repeater_nms.config import Config
from repeater_nms.web.cli import register_cli


def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config.from_object(Config)

    from repeater_nms.web.routes import web_bp

    app.register_blueprint(web_bp)
    register_cli(app)
    return app
