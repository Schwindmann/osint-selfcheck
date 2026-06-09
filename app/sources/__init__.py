from flask import Flask
from dotenv import load_dotenv
import os
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

csrf = CSRFProtect()
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)


def create_app():
    """
    App-Fabrik: erstellt und konfiguriert die Flask-App.
    """
    load_dotenv()

    app = Flask(__name__,
                static_folder='static',
                template_folder='templates')

    # ── Konfiguration ──────────────────────────────────────
    app.config['SECRET_KEY'] = os.getenv(
        'SECRET_KEY',
        'dev-fallback-key'
    )
    app.config['DATABASE'] = 'osint.db'
    app.config['BASE_URL'] = os.getenv(
        'BASE_URL',
        'http://localhost:5000'
    )
    app.config['WTF_CSRF_TIME_LIMIT'] = 3600

    # ── Extensions aktivieren ──────────────────────────────
    csrf.init_app(app)
    limiter.init_app(app)

    # ── Datenbank initialisieren ───────────────────────────
    from app.models import init_db
    init_db(app)

    # ── Routen registrieren ────────────────────────────────
    from app.routes import main
    app.register_blueprint(main)

    # ── Scheduler starten ──────────────────────────────────
    # Räumt alte Sessions automatisch alle 30 Minuten auf
    from app.scheduler import start_scheduler
    start_scheduler(app)

    return app