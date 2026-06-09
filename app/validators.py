import re
from email_validator import validate_email as _validate_email
from email_validator import EmailNotValidError


def validate_email(email):
    """
    E-Mail-Adresse validieren.
    Gibt zurück:
    - (True, bereinigte_email) wenn gültig
    - (False, fehlermeldung)   wenn ungültig
    """
    try:
        # check_deliverability=False = kein DNS-Lookup
        # würde die App sonst verlangsamen
        valid = _validate_email(email, check_deliverability=False)
        # normalized = E-Mail in Kleinbuchstaben, bereinigt
        return True, valid.normalized
    except EmailNotValidError as e:
        return False, str(e)


def validate_username(username):
    """
    Username validieren.
    Erlaubt: Buchstaben, Zahlen, Bindestrich, Unterstrich, Punkt
    Verboten: Leerzeichen, Sonderzeichen, zu lang
    """
    if len(username) < 1:
        return False, 'Username darf nicht leer sein.'

    if len(username) > 50:
        return False, 'Username darf maximal 50 Zeichen haben.'

    # \w = Buchstaben + Zahlen + Unterstrich
    # .-  = Punkt und Bindestrich auch erlaubt
    pattern = r'^[\w.\-]+$'
    if not re.match(pattern, username, re.UNICODE):
        return False, f'"{username}" enthält ungültige Zeichen.'

    return True, username.strip()


def validate_form_input(emails, usernames):
    """
    Komplettes Formular validieren.
    Gibt zurück:
    - (True,  emails, usernames, None)         alles ok
    - (False, [],     [],        fehlermeldung) Fehler
    """
    # ── E-Mails prüfen ─────────────────────────────────────
    if not emails:
        return False, [], [], 'Bitte mindestens eine E-Mail eingeben.'

    if len(emails) > 5:
        return False, [], [], 'Maximal 5 E-Mail-Adressen erlaubt.'

    clean_emails = []
    for email in emails:
        ok, result = validate_email(email)
        if not ok:
            return False, [], [], f'Ungültige E-Mail "{email}": {result}'
        if result in clean_emails:
            return False, [], [], f'E-Mail "{result}" wurde mehrfach eingegeben.'
        clean_emails.append(result)

    # ── Usernames prüfen ───────────────────────────────────
    if len(usernames) > 10:
        return False, [], [], 'Maximal 10 Usernames erlaubt.'

    clean_usernames = []
    for username in usernames:
        if not username.strip():
            continue  # leere Felder überspringen
        ok, result = validate_username(username)
        if not ok:
            return False, [], [], result
        if result not in clean_usernames:
            clean_usernames.append(result)

    return True, clean_emails, clean_usernames, None