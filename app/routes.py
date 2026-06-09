from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    jsonify
)
import secrets
import os
from datetime import datetime, timedelta

from app.models import get_db
from app.validators import validate_form_input
from app.verifier import generate_token, send_verification_email
from app import limiter
import json
main = Blueprint('main', __name__)


def is_valid_session_id(session_id):
    """
    Session-ID auf gültige Zeichen prüfen.
    Verhindert seltsame Eingaben in der URL.
    """
    return (
        session_id and
        len(session_id) <= 50 and
        session_id.replace('-', '').replace('_', '').isalnum()
    )


@main.route('/', methods=['GET', 'POST'])
@limiter.limit("5 per minute;20 per hour")
def index():
    """
    Startseite — Eingabeformular.
    GET:  Formular anzeigen
    POST: Formulardaten verarbeiten
    """
    if request.method == 'POST':

        raw_emails = request.form.getlist('emails[]')
        raw_usernames = request.form.getlist('usernames[]')

        ok, clean_emails, clean_usernames, error = validate_form_input(
            raw_emails,
            raw_usernames
        )

        if not ok:
            return render_template(
                'index.html',
                error=error,
                prev_emails=raw_emails,
                prev_usernames=raw_usernames
            )

        session_id = secrets.token_urlsafe(16)
        db = get_db()

        db.execute(
            'INSERT INTO scan_sessions (session_id, status) VALUES (?, ?)',
            (session_id, 'pending')
        )

        for username in clean_usernames:
            db.execute(
                'INSERT INTO usernames (session_id, username) VALUES (?, ?)',
                (session_id, username)
            )

        base_url = os.getenv('BASE_URL','https://web-production-34b5d.up.railway.app')
        mail_errors = []

        for email in clean_emails:
            token = generate_token()
            expires_at = datetime.now() + timedelta(hours=24)
            db.execute(
                '''INSERT INTO emails
                   (session_id, email, token, verified, expires_at)
                   VALUES (?, ?, ?, 0, ?)''',
                (session_id, email, token, expires_at.isoformat())
            )
            sent = send_verification_email(email, token, base_url)
            if not sent:
                mail_errors.append(email)

        db.commit()
        session['scan_session_id'] = session_id

        if mail_errors:
            flash(
                f'Links für {", ".join(mail_errors)} '
                f'konnten nicht gesendet werden. '
                f'Schau ins Terminal.',
                'warning'
            )

        return redirect(
            url_for('main.pending', session_id=session_id)
        )

    return render_template('index.html')


@main.route('/pending/<session_id>')
def pending(session_id):
    """Warteseite — zeigt welche E-Mails bestätigt wurden."""
    if not is_valid_session_id(session_id):
        return redirect(url_for('main.index'))

    db = get_db()
    scan = db.execute(
        'SELECT status FROM scan_sessions WHERE session_id = ?',
        (session_id,)
    ).fetchone()

    if not scan:
        return render_template(
            'error.html',
            message='Session nicht gefunden oder abgelaufen.'
        )

    if scan['status'] == 'ready':
        return redirect(
            url_for('main.ready', session_id=session_id)
        )

    emails = db.execute(
        'SELECT email, verified, expires_at FROM emails WHERE session_id = ?',
        (session_id,)
    ).fetchall()

    total = len(emails)
    verified_count = sum(1 for e in emails if e['verified'])

    return render_template(
        'pending.html',
        emails=emails,
        total=total,
        verified=verified_count,
        session_id=session_id
    )


@main.route('/verify/<token>')
def verify(token):
    """Bestätigungslink verarbeiten."""
    if len(token) > 100 or not token.replace(
        '-', '').replace('_', '').isalnum():
        return render_template(
            'error.html',
            message='Ungültiger Link.'
        )

    db = get_db()
    email_row = db.execute(
        'SELECT * FROM emails WHERE token = ?',
        (token,)
    ).fetchone()

    if not email_row:
        return render_template(
            'error.html',
            message='Ungültiger oder bereits verwendeter Link.'
        )

    expires_at = datetime.fromisoformat(email_row['expires_at'])
    if datetime.now() > expires_at:
        return render_template(
            'error.html',
            message='Dieser Link ist abgelaufen. '
                    'Bitte starte einen neuen Scan.'
        )

    if email_row['verified']:
        return redirect(
            url_for('main.pending', session_id=email_row['session_id'])
        )

    db.execute(
        'UPDATE emails SET verified = 1 WHERE token = ?',
        (token,)
    )
    db.commit()

    session_id = email_row['session_id']
    alle_emails = db.execute(
        'SELECT verified FROM emails WHERE session_id = ?',
        (session_id,)
    ).fetchall()

    alle_bestaetigt = all(e['verified'] for e in alle_emails)

    if alle_bestaetigt:
        db.execute(
            'UPDATE scan_sessions SET status = ? WHERE session_id = ?',
            ('ready', session_id)
        )
        db.commit()
        return redirect(url_for('main.ready', session_id=session_id))

    return redirect(url_for('main.pending', session_id=session_id))


@main.route('/ready/<session_id>')
def ready(session_id):
    """Alle E-Mails bestätigt — Scan kann starten."""
    if not is_valid_session_id(session_id):
        return redirect(url_for('main.index'))

    db = get_db()
    scan = db.execute(
        'SELECT status FROM scan_sessions WHERE session_id = ?',
        (session_id,)
    ).fetchone()

    if not scan or scan['status'] != 'ready':
        return redirect(url_for('main.index'))

    emails = db.execute(
        'SELECT email FROM emails WHERE session_id = ?',
        (session_id,)
    ).fetchall()

    usernames = db.execute(
        'SELECT username FROM usernames WHERE session_id = ?',
        (session_id,)
    ).fetchall()

    return render_template(
        'ready.html',
        emails=[e['email'] for e in emails],
        usernames=[u['username'] for u in usernames],
        session_id=session_id
    )


@main.route('/scan/<session_id>')
def scan(session_id):
    """
    Scan starten.
    Lädt die Scanning-Seite und startet den Scan im Hintergrund.
    """
    if not is_valid_session_id(session_id):
        return redirect(url_for('main.index'))

    db = get_db()
    scan_row = db.execute(
        'SELECT status FROM scan_sessions WHERE session_id = ?',
        (session_id,)
    ).fetchone()

    # Nur starten wenn Status 'ready' ist
    if not scan_row or scan_row['status'] != 'ready':
        return redirect(url_for('main.index'))

    # E-Mails und Usernames für den Scan laden
    emails = db.execute(
        'SELECT email FROM emails WHERE session_id = ?',
        (session_id,)
    ).fetchall()

    usernames = db.execute(
        'SELECT username FROM usernames WHERE session_id = ?',
        (session_id,)
    ).fetchall()

    email_list = [e['email'] for e in emails]
    username_list = [u['username'] for u in usernames]

    # Scan im Hintergrund starten
    from app.pipeline.orchestrator import start_scan_thread
    from flask import current_app
    start_scan_thread(
        session_id,
        email_list,
        username_list,
        current_app._get_current_object()
        # _get_current_object() gibt die echte App-Instanz
        # nicht den Proxy — wichtig für Threads
    )

    # Sofort zur Ladeseite weiterleiten
    return render_template(
        'scanning.html',
        session_id=session_id
    )


@main.route('/scan-status/<session_id>')
def scan_status(session_id):
    """
    Gibt den aktuellen Scan-Status als JSON zurück.
    Wird von der Ladeseite alle 3 Sekunden abgefragt.

    Antwort:
    { "status": "scanning" }  → noch nicht fertig
    { "status": "done" }      → fertig, weiterleiten
    { "status": "error" }     → Fehler aufgetreten
    """
    if not is_valid_session_id(session_id):
        return jsonify({'status': 'error'})

    db = get_db()
    scan_row = db.execute(
        'SELECT status FROM scan_sessions WHERE session_id = ?',
        (session_id,)
    ).fetchone()

    if not scan_row:
        return jsonify({'status': 'error'})

    return jsonify({'status': scan_row['status']})

@main.route('/report/<session_id>')
def report(session_id):
    """
    Report anzeigen.
    Nutzt jetzt den Processor für Bewertung und Scoring.
    """
    if not is_valid_session_id(session_id):
        return redirect(url_for('main.index'))

    db = get_db()
    scan_row = db.execute(
        'SELECT status FROM scan_sessions WHERE session_id = ?',
        (session_id,)
    ).fetchone()

    if not scan_row or scan_row['status'] != 'done':
        return render_template(
            'error.html',
            message='Report nicht gefunden oder '
                    'Scan noch nicht fertig.'
        )

    # Rohdaten aus DB laden
    raw_results = db.execute(
        '''SELECT source, category, target, data
           FROM scan_results
           WHERE session_id = ?
           ORDER BY source, target''',
        (session_id,)
    ).fetchall()

    # Processor — bewertet und strukturiert die Rohdaten
    from app.pipeline.processor import process_results
    processed = process_results(raw_results)

    return render_template(
        'report.html',
        session_id=session_id,
        findings=processed['findings'],
        summary=processed['summary'],
        todos=processed['todos']
    )


# ── Fehlerseiten ───────────────────────────────────────────

@main.app_errorhandler(404)
def not_found(e):
    return render_template(
        'error.html',
        message='Diese Seite existiert nicht.'
    ), 404


@main.app_errorhandler(429)
def rate_limit_exceeded(e):
    return render_template(
        'error.html',
        message='Zu viele Anfragen. Bitte warte einen Moment.'
    ), 429