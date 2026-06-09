import secrets
import os
import smtplib
from email.mime.text import MIMEText


def generate_token():
    """
    Kryptografisch sicheren Token generieren.
    secrets ist sicherer als random.
    Beispiel: 'xK9mP2nR8vL4qW7tY3uZ5aB1'
    """
    return secrets.token_urlsafe(32)


def send_verification_email(to_email, token, base_url):
    """
    Bestätigungslink senden.

    Entwicklungsmodus (SMTP leer):
    → Link erscheint nur im Terminal

    Produktionsmodus (SMTP konfiguriert):
    → Echte Mail wird versendet
    """
    # Vollständigen Link zusammenbauen
    verify_url = base_url + "/verify/" + token

    # Immer ins Terminal ausgeben
    print("\n" + "=" * 55)
    print("  BESTAETIGUNGSLINK")
    print("  Fuer: " + to_email)
    print("  -> " + verify_url)
    print("=" * 55 + "\n")

    # SMTP aus .env lesen
    smtp_host = os.getenv('SMTP_HOST', '').strip()
    smtp_user = os.getenv('SMTP_USER', '').strip()
    smtp_pass = os.getenv('SMTP_PASS', '').strip()

    # Wenn SMTP nicht konfiguriert: nur Terminal
    if not (smtp_host and smtp_user and smtp_pass):
        return True

    # Plain-Text Mail senden
    try:
        body = (
            "Hallo,\n\n"
            "bitte bestatige deine E-Mail-Adresse:\n\n"
            + verify_url + "\n\n"
            "Dieser Link ist 24 Stunden gueltig.\n"
            "Wenn du keinen Scan angefordert hast, "
            "ignoriere diese Mail.\n"
        )

        msg = MIMEText(body, 'plain', 'utf-8')
        msg['From'] = smtp_user
        msg['To'] = to_email
        msg['Subject'] = 'Bestatige deine E-Mail - OSINT SelfCheck'

        smtp_port = int(os.getenv('SMTP_PORT', 465))
        with smtplib.SMTP_SSL(smtp_host, smtp_port) as server:
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)

        print("Mail gesendet an " + to_email)
        return True

    except Exception as e:
        print("Mail-Fehler fuer " + to_email + ": " + str(e))
        return False