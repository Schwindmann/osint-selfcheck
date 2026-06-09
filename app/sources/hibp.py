import requests
import os
import time


def check_email(email):
    """
    E-Mail bei Have I Been Pwned prüfen.

    Gibt zurück:
    - Liste von Leaks wenn gefunden
    - Leere Liste wenn keine Leaks
    - None wenn API-Key fehlt oder Fehler

    Beispiel-Rückgabe:
    [
        {
            'name': 'LinkedIn',
            'date': '2021-06-22',
            'data_classes': ['Email addresses', 'Passwords'],
            'description': 'In 2021...',
            'is_verified': True
        },
        ...
    ]
    """
    api_key = os.getenv('HIBP_API_KEY', '').strip()

    # Kein API-Key → überspringen aber kein Absturz
    if not api_key:
        print("[HIBP] Kein API-Key konfiguriert — übersprungen")
        return []

    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"

    headers = {
        # API-Key im Header mitschicken
        'hibp-api-key': api_key,
        # Pflichtfeld laut HIBP-Dokumentation
        'user-agent': 'OSINT-SelfCheck/1.0'
    }

    params = {
        # Nur Leak-Namen holen wäre kürzer,
        # aber wir wollen alle Details
        'truncateResponse': 'false'
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            params=params,
            # Nach 10 Sekunden abbrechen
            timeout=10
        )

        # 200 = Leaks gefunden
        if response.status_code == 200:
            breaches = response.json()
            print(f"[HIBP] {email}: {len(breaches)} Leak(s) gefunden")

            # Nur die Felder die wir brauchen
            clean = []
            for breach in breaches:
                clean.append({
                    'name': breach.get('Name', ''),
                    'date': breach.get('BreachDate', ''),
                    'data_classes': breach.get('DataClasses', []),
                    'description': breach.get('Description', ''),
                    'is_verified': breach.get('IsVerified', False),
                    'is_sensitive': breach.get('IsSensitive', False)
                })
            return clean

        # 404 = keine Leaks gefunden (das ist gut!)
        elif response.status_code == 404:
            print(f"[HIBP] {email}: Keine Leaks gefunden")
            return []

        # 401 = API-Key ungültig
        elif response.status_code == 401:
            print("[HIBP] Fehler: API-Key ungültig")
            return []

        # 429 = zu viele Anfragen
        elif response.status_code == 429:
            print("[HIBP] Rate Limit erreicht — kurz warten")
            # 2 Sekunden warten und nochmal versuchen
            time.sleep(2)
            return check_email(email)

        else:
            print(f"[HIBP] Unerwarteter Status: {response.status_code}")
            return []

    except requests.exceptions.Timeout:
        print(f"[HIBP] Timeout für {email}")
        return []

    except requests.exceptions.ConnectionError:
        print(f"[HIBP] Keine Verbindung möglich")
        return []

    except Exception as e:
        print(f"[HIBP] Fehler: {e}")
        return []