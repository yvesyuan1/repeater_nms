from __future__ import annotations

from flask_login import LoginManager


login_manager = LoginManager()
login_manager.login_view = "web.login"
login_manager.login_message = "请先登录。"
