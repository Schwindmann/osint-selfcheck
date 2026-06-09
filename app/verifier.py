import secrets
import os


def generate_token():
    """Sicheren Token generieren."""
    return secrets.token_urlsafe(32)


def send_verification_email(to_email, token, base_url):
    """
    Bestätigungslink senden via SendGrid HTTP API.
    Nutzt Port 443 (HTTPS) statt SMTP Port 587.
    """
    verify_url = base_url + "/verify/" + token

    # Immer ins Terminal ausgeben
    print("\n" + "=" * 55)
    print("  BESTAETIGUNGSLINK")
    print("  Fuer: " + to_email)
    print("  -> " + verify_url)
    print("=" * 55 + "\n")

    api_key = os.getenv('SMTP_PASS', '').strip()
    from_email = os.getenv('SMTP_FROM', '').strip()

    if not api_key or not from_email:
        print("SendGrid nicht konfiguriert — nur Terminal")
        return True

    try:
        import sendgrid
        from sendgrid.helpers.mail import Mail

        sg = sendgrid.SendGridAPIClient(api_key=api_key)

        message = Mail(
            from_email=from_email,
            to_emails=to_email,
            subject='Bestätige deine E-Mail — OSINT SelfCheck',
            plain_text_content=(
                "Hallo,\n\n"
                "bitte bestätige deine E-Mail-Adresse:\n\n"
                + verify_url + "\n\n"
                "Dieser Link ist 24 Stunden gültig.\n"
                "Wenn du keinen Scan angefordert hast, "
                "ignoriere diese Mail.\n"
            )
        )

        response = sg.send(message)
        print("Mail gesendet an " + to_email +
              " (Status: " + str(response.status_code) + ")")
        return True

    except Exception as e:
        print("Mail-Fehler fuer " + to_email + ": " + str(e))
        return False