import whois
import json


def check_domain(domain):
    """
    WHOIS-Informationen für eine Domain abfragen.

    Kostenlos, kein API-Key nötig.
    Funktioniert für .com, .de, .net, .org und viele mehr.

    Gibt zurück:
    - Dictionary mit Domain-Infos
    - None bei Fehler oder unbekannter Domain

    Beispiel-Rückgabe:
    {
        'domain': 'example.com',
        'registrar': 'GoDaddy',
        'creation_date': '1995-08-14',
        'expiration_date': '2024-08-13',
        'name_servers': ['ns1.example.com'],
        'status': 'active'
    }
    """
    # Domain bereinigen
    # Nutzer gibt vielleicht "https://example.com" ein
    domain = domain.strip().lower()
    domain = domain.replace('https://', '')
    domain = domain.replace('http://', '')
    domain = domain.replace('www.', '')

    # Nur die Domain selbst ohne Pfad
    # "example.com/about" → "example.com"
    if '/' in domain:
        domain = domain.split('/')[0]

    print(f"[WHOIS] Prüfe Domain: {domain}")

    try:
        w = whois.whois(domain)

        # Datum sicher als String konvertieren
        # whois gibt manchmal datetime, manchmal Liste zurück
        def safe_date(value):
            if value is None:
                return ''
            if isinstance(value, list):
                value = value[0]
            try:
                return str(value)[:10]  # Nur Datum, keine Uhrzeit
            except Exception:
                return str(value)

        # Nameserver bereinigen
        nameservers = w.name_servers or []
        if isinstance(nameservers, str):
            nameservers = [nameservers]
        # Duplikate entfernen und Kleinbuchstaben
        nameservers = list(set(
            ns.lower() for ns in nameservers if ns
        ))

        result = {
            'domain': domain,
            'registrar': w.registrar or 'Unbekannt',
            'creation_date': safe_date(w.creation_date),
            'expiration_date': safe_date(w.expiration_date),
            'updated_date': safe_date(w.updated_date),
            'name_servers': nameservers[:5],  # Max 5
            'status': str(w.status[0])[:50] if w.status else 'unknown'
        }

        print(f"[WHOIS] {domain}: Registrar = {result['registrar']}")
        return result

    except whois.parser.PywhoisError:
        print(f"[WHOIS] Domain nicht gefunden: {domain}")
        return None

    except Exception as e:
        print(f"[WHOIS] Fehler für {domain}: {e}")
        return None


def extract_domain_from_email(email):
    """
    Domain aus einer E-Mail-Adresse extrahieren.

    'user@example.com' → 'example.com'

    Nützlich wenn wir die Domain einer E-Mail prüfen wollen.
    """
    try:
        return email.split('@')[1].strip().lower()
    except Exception:
        return None