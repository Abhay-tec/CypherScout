import os
import threading
from datetime import timedelta
from pathlib import Path
import json

from authlib.integrations.flask_client import OAuth
from flask import Flask, jsonify, request, session

from .config import Config
from .db import get_db, init_database
from .ml import neural_engine
from .services.governance import find_governed_app_from_url, get_effective_trust_level
from .services.notifications import push_notification
from .services.notify import send_security_alert
from .services.trusted_apps import normalize_link_key

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

    # On Vercel, persist DB in the writable /tmp mount; copy seed file if bundled.
    db_path = Path(app.config["DATABASE_PATH"])
    if str(db_path).startswith("/tmp"):
        bundled_db = Path(app.root_path).parent / "cypher.db"
        if bundled_db.exists() and not db_path.exists():
            db_path.write_bytes(bundled_db.read_bytes())

    init_database(app)

    def _shadow_metadata_payload() -> dict:
        bundle_path = Path(app.root_path) / "data" / "shadow_bundle.json"
        try:
            payload = json.loads(bundle_path.read_text(encoding="utf-8"))
        except Exception:
            payload = {}
        payload["hardware_mask"] = {
            "battery": "100%",
            "location": "Cypher-Shield-Vault",
            "os": "Hidden-OS",
            "ip": "0.0.0.0",
        }
        return payload

    @app.before_request
    def _shadow_mode_interceptor():
        email = session.get("user_email")
        if not email or request.method == "OPTIONS":
            return None

        candidate = (request.args.get("url") or request.args.get("target") or request.referrer or "").strip()
        if not candidate:
            return None
        host = normalize_link_key(candidate)
        if not host:
            return None

        scan_text = " ".join(
            [
                request.path or "",
                request.query_string.decode("utf-8", errors="ignore"),
                (request.referrer or ""),
                " ".join((request.values or {}).keys()),
            ]
        ).lower()
        indicators = ("battery", "geolocation", "location", "hardware", "os", "fingerprint", "metadata", "device")
        if not any(token in scan_text for token in indicators):
            return None

        conn = get_db()
        governed_app = find_governed_app_from_url(conn, candidate)
        is_blocked_app = bool(governed_app and get_effective_trust_level(conn, email, governed_app["app_key"]) == "BLOCK")
        is_privacy_net = host == "privacy.net" or host.endswith(".privacy.net")
        if not (is_privacy_net or is_blocked_app):
            return None

        target_name = "privacy.net" if is_privacy_net else governed_app["display_name"]
        alert = f"Security Shield Active: Blocked {target_name} from hardware scanning. Fake data injected."
        push_notification(conn, email, "Security Shield Active", alert, "danger")
        conn.commit()
        send_security_alert(
            app,
            email=email,
            title="Action Required: Hardware Scan Blocked",
            details=f"{alert}<br>Host: {host}",
        )
        return jsonify(
            {
                "status": "shadow_intercepted",
                "shadow_mode": True,
                "source": target_name,
                "alert": alert,
                "shadow_bundle": _shadow_metadata_payload(),
            }
        )

    def _bootstrap_neural_training():
        try:
            neural_engine.train_from_db(app.config["DATABASE_PATH"])
        except Exception:
            pass

    threading.Thread(target=_bootstrap_neural_training, daemon=True).start()

    return app
