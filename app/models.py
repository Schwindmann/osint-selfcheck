import sqlite3
from datetime import datetime, timedelta
from flask import g, current_app


def get_db():
    """
    Datenbankverbindung für den aktuellen Request holen.
    Flask's g-Objekt lebt nur während eines einzelnen
    HTTP-Requests.
    """
    if 'db' not in g:
        g.db = sqlite3.connect(
            current_app.config['DATABASE']
        )
        # Ergebnisse als Dictionary statt Tuple
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(e=None):
    """Verbindung am Ende jedes Requests schließen."""
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db(app):
    """
    Tabellen erstellen falls nicht vorhanden.
    Wird beim App-Start aufgerufen.
    """
    conn = sqlite3.connect(app.config['DATABASE'])
    cursor = conn.cursor()

    # ── Tabelle 1: scan_sessions ───────────────────────────
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_sessions (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT UNIQUE NOT NULL,
            status     TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # ── Tabelle 2: emails ──────────────────────────────────
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
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS usernames (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            username   TEXT NOT NULL
        )
    ''')

    # ── Tabelle 4: scan_results ────────────────────────────
    # Hier landen alle Rohdaten von den APIs.
    # source:   woher kommt der Fund (hibp, emailrep, usw.)
    # category: was für ein Fund (leak, profile, reputation)
    # data:     die eigentlichen Daten als JSON-String
    # target:   für welche E-Mail oder Username gilt das
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_results (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            source     TEXT NOT NULL,
            category   TEXT NOT NULL,
            target     TEXT NOT NULL,
            data       TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    conn.commit()
    conn.close()

    app.teardown_appcontext(close_db)


def save_result(session_id, source, category, target, data):
    """
    Einen Scan-Treffer in der Datenbank speichern.

    session_id: zu welchem Scan gehört das
    source:     z.B. 'hibp', 'emailrep', 'sherlock'
    category:   z.B. 'leak', 'profile', 'reputation'
    target:     die E-Mail oder der Username
    data:       JSON-String mit den Rohdaten
    """
    db = get_db()
    db.execute(
        '''INSERT INTO scan_results
           (session_id, source, category, target, data)
           VALUES (?, ?, ?, ?, ?)''',
        (session_id, source, category, target, data)
    )
    db.commit()


def get_results(session_id):
    """
    Alle Ergebnisse einer Session laden.
    Gibt eine Liste von Rows zurück.
    """
    db = get_db()
    return db.execute(
        '''SELECT source, category, target, data, created_at
           FROM scan_results
           WHERE session_id = ?
           ORDER BY created_at ASC''',
        (session_id,)
    ).fetchall()


def cleanup_expired_sessions(app):
    """
    Alte Sessions + alle zugehörigen Daten löschen.
    Zero Retention: alles älter als 1 Stunde wird gelöscht.
    """
    conn = sqlite3.connect(app.config['DATABASE'])
    cursor = conn.cursor()

    cursor.execute('''
        DELETE FROM scan_sessions
        WHERE created_at < datetime('now', '-1 hour')
    ''')

    # Alle verwaisten Daten mitlöschen
    for table in ['emails', 'usernames', 'scan_results']:
        cursor.execute(
            'DELETE FROM ' + table + ' WHERE session_id NOT IN '
            '(SELECT session_id FROM scan_sessions)'
        )

    conn.commit()
    conn.close()