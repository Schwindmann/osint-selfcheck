import sqlite3
from datetime import datetime, timedelta
from flask import g, current_app


def get_db():
    """
    Datenbankverbindung für den aktuellen Request holen.

    Flask's g-Objekt lebt nur während eines einzelnen
    HTTP-Requests. So öffnen wir maximal eine Verbindung
    pro Request statt für jeden Aufruf eine neue.
    """
    if 'db' not in g:
        g.db = sqlite3.connect(
            current_app.config['DATABASE']
        )
        # row_factory: Ergebnisse als Dictionary
        # Vorher: row[0], row[1]
        # Nachher: row['email'], row['token']
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(e=None):
    """
    Verbindung am Ende jedes Requests schließen.
    Wird automatisch von Flask aufgerufen.
    """
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db(app):
    """
    Tabellen erstellen falls sie noch nicht existieren.
    Wird einmal beim App-Start aufgerufen.
    CREATE TABLE IF NOT EXISTS = sicher, kann mehrfach
    aufgerufen werden ohne Fehler.
    """
    conn = sqlite3.connect(app.config['DATABASE'])
    cursor = conn.cursor()

    # ── Tabelle 1: scan_sessions ───────────────────────────
    # Eine Session = ein Scan-Vorgang
    # Status-Werte:
    # 'pending'  → nicht alle E-Mails bestätigt
    # 'ready'    → alle bestätigt, Scan kann starten
    # 'scanning' → Scan läuft gerade
    # 'done'     → Scan fertig, Report liegt vor
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_sessions (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT UNIQUE NOT NULL,
            status     TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # ── Tabelle 2: emails ──────────────────────────────────
    # Eine Session kann mehrere E-Mails haben.
    # Jede E-Mail bekommt einen eigenen Token.
    # verified: 0 = nicht bestätigt, 1 = bestätigt
    # expires_at: Token läuft nach 24 Stunden ab
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS emails (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            email      TEXT NOT NULL,
            token      TEXT UNIQUE NOT NULL,
            verified   INTEGER DEFAULT 0,
            expires_at TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # ── Tabelle 3: usernames ───────────────────────────────
    # Usernames brauchen keine Verifikation
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS usernames (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            username   TEXT NOT NULL
        )
    ''')

    conn.commit()
    conn.close()

    # Flask sagen: close_db nach jedem Request aufrufen
    app.teardown_appcontext(close_db)


def cleanup_expired_sessions(app):
    """
    Alte Sessions löschen — Zero Retention Prinzip.
    Alles älter als 1 Stunde wird komplett gelöscht.
    Wird in Block 4 automatisch per Scheduler aufgerufen.
    """
    conn = sqlite3.connect(app.config['DATABASE'])
    cursor = conn.cursor()

    # Sessions löschen die älter als 1 Stunde sind
    cursor.execute('''
        DELETE FROM scan_sessions
        WHERE created_at < datetime('now', '-1 hour')
    ''')

    # Verwaiste E-Mails löschen
    cursor.execute('''
        DELETE FROM emails
        WHERE session_id NOT IN (
            SELECT session_id FROM scan_sessions
        )
    ''')

    # Verwaiste Usernames löschen
    cursor.execute('''
        DELETE FROM usernames
        WHERE session_id NOT IN (
            SELECT session_id FROM scan_sessions
        )
    ''')

    conn.commit()
    conn.close()