from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash
)
import secrets
import os
from datetime import datetime, timedelta

from app.models import get_db
from app.validators import validate_form_input
from app.verifier import generate_token, send_verification_email
from app import limiter

# Blueprint = Gruppe zusammengehöriger Routen
main = Blueprint('main', __name__)


def is_valid_session_id(session_id):
    """
    Session-ID auf gültige Zeichen prüfen.
    Verhindert seltsame Eingaben in der URL.
    Erlaubt: Buchstaben, Zahlen, Bindestrich, Unterstrich
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

        # Formulardaten lesen
        # getlist() holt alle Felder mit demselben Namen
        # nötig weil wir mehrere emails[] haben
        raw_emails = request.form.getlist('emails[]')
        raw_usernames = request.form.getlist('usernames[]')

        # Validierung — prüft Format, Duplikate, Limits
        ok, clean_emails, clean_usernames, error = validate_form_input(
            raw_emails,
            raw_usernames
        )

        if not ok:
            # Fehler anzeigen + Formular mit alten Werten füllen
            # damit User nicht alles neu tippen muss
            return render_template(
                'index.html',
                error=error,
                prev_emails=raw_emails,
                prev_usernames=raw_usernames
            )

        # Einzigartige Session-ID für diesen Scan
        session_id = secrets.token_urlsafe(16)

        db = get_db()

        # Session in DB speichern
        db.execute(
            'INSERT INTO scan_sessions (session_id, status) VALUES (?, ?)',
            (session_id, 'pending')
            # ? Platzhalter = Schutz vor SQL Injection
        )

        # Usernames speichern
        for username in clean_usernames:
            db.execute(
                'INSERT INTO usernames (session_id, username) VALUES (?, ?)',
                (session_id, username)
            )

        # E-Mails speichern + Bestätigungslinks senden
        base_url = os.getenv('BASE_URL', 'http://localhost:5000')
        mail_errors = []

        for email in clean_emails:
            token = generate_token()
            # Token läuft in 24 Stunden ab
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

        # Session-ID im Browser-Cookie merken
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
    """
    Zeigt welche E-Mails schon bestätigt wurden.
    Aktualisiert sich automatisch alle 10 Sekunden.
    """
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

    # Wenn schon alles bestätigt: direkt weiterleiten
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
    """
    Wird aufgerufen wenn User auf Bestätigungslink klickt.
    Token prüfen → E-Mail als bestätigt markieren →
    schauen ob alle bestätigt sind → weiterleiten.
    """
    # Token-Format prüfen
    if len(token) > 100 or not token.replace('-', '').replace('_', '').isalnum():
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

    # Token abgelaufen?
    expires_at = datetime.fromisoformat(email_row['expires_at'])
    if datetime.now() > expires_at:
        return render_template(
            'error.html',
            message='Dieser Link ist abgelaufen. '
                    'Bitte starte einen neuen Scan.'
        )

    # Schon bestätigt? Einfach weiterleiten
    if email_row['verified']:
        return redirect(
            url_for('main.pending', session_id=email_row['session_id'])
        )

    # Als bestätigt markieren
    db.execute(
        'UPDATE emails SET verified = 1 WHERE token = ?',
        (token,)
    )
    db.commit()

    session_id = email_row['session_id']

    # Prüfen ob ALLE E-Mails bestätigt sind
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
    """
    Alle E-Mails bestätigt — Scan kann starten.
    Zeigt Zusammenfassung der eingegebenen Daten.
    """
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