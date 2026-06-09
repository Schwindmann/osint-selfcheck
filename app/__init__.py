from flask import Flask
from dotenv import load_dotenv
import os
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Diese zwei Objekte werden global erstellt
# damit routes.py sie importieren kann
csrf = CSRFProtect()
limiter = Limiter(
    key_func=get_remote_address,  # Rate Limit pro IP-Adresse
    default_limits=["200 per day", "50 per hour"]
)


def create_app():
    """
    App-Fabrik: erstellt und konfiguriert die Flask-App.

    Warum Fabrik-Pattern?
    So kann man später einfach verschiedene Konfigurationen
    erstellen — z.B. eine Test-Konfiguration mit eigener DB.
    """
    # .env Datei laden bevor wir irgendwas lesen
    load_dotenv()

    # Flask-App erstellen
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
    # CSRF-Token 1 Stunde gültig
    app.config['WTF_CSRF_TIME_LIMIT'] = 3600

    # ── Extensions aktivieren ──────────────────────────────
    csrf.init_app(app)    # CSRF-Schutz an App binden
    limiter.init_app(app) # Rate Limiting an App binden

    # ── Datenbank initialisieren ───────────────────────────
    # Tabellen erstellen falls sie noch nicht existieren
    from app.models import init_db
    init_db(app)

    # ── Routen registrieren ────────────────────────────────
    from app.routes import main
    app.register_blueprint(main)

    return app