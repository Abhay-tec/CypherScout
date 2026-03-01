import os
from datetime import timedelta

from authlib.integrations.flask_client import OAuth
from flask import Flask

from .config import Config
from .db import init_database
from .ml import neural_engine

oauth = OAuth()


def create_app(config_class: type[Config] = Config) -> Flask:
    app = Flask(
        __name__,
        template_folder="../templates",
        static_folder="../templates/static",
        static_url_path="/static",
    )
    app.config.from_object(config_class)
    app.permanent_session_lifetime = timedelta(days=app.config["SESSION_DAYS"])

    if app.config["ALLOW_INSECURE_OAUTH"]:
        os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

    oauth.init_app(app)
    oauth.register(
        name="google",
        client_id=app.config["GOOGLE_CLIENT_ID"],
        client_secret=app.config["GOOGLE_CLIENT_SECRET"],
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"},
        authorize_params={"prompt": "select_account"},
    )

    from .routes.api import api_bp
    from .routes.web import web_bp

    app.register_blueprint(web_bp)
    app.register_blueprint(api_bp)

    init_database(app)
    neural_engine.train_from_db(app.config["DATABASE_PATH"])

    return app
