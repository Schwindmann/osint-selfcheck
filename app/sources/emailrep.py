import requests
import os


def check_email(email):
    """
    E-Mail-Reputation bei EmailRep.io prüfen.

    Kostenlos nutzbar, API-Key optional aber empfohlen.
    Holen unter: https://emailrep.io/key

    Gibt zurück:
    - Dictionary mit Reputationsdaten
    - None bei Fehler

    Beispiel-Rückgabe:
    {
        'email': 'test@gmail.com',
        'reputation': 'high',
        'suspicious': False,
        'references': 23,
        'details': {
            'blacklisted': False,
            'malicious_activity': False,
            'spam': False,
            'data_breach': True,
            'first_seen': '2015-01-01',
            'last_seen': '2024-12-01',
            'profiles': ['twitter', 'linkedin']
        }
    }
    """
    url = f"https://emailrep.io/{email}"

    # API-Key aus .env — optional
    api_key = os.getenv('EMAILREP_API_KEY', '').strip()

    headers = {
        'User-Agent': 'OSINT-SelfCheck/1.0'
    }

    # Key nur mitsenden wenn vorhanden
    if api_key:
        headers['Key'] = api_key

    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=10
        )

        # 200 = Daten gefunden
        if response.status_code == 200:
            data = response.json()
            print(f"[EmailRep] {email}: Reputation = "
                  f"{data.get('reputation', 'unknown')}")

            # Nur relevante Felder zurückgeben
            details = data.get('details', {})
            return {
                'email': email,
                'reputation': data.get('reputation', 'unknown'),
                'suspicious': data.get('suspicious', False),
                'references': data.get('references', 0),
                'blacklisted': details.get('blacklisted', False),
                'malicious_activity': details.get(
                    'malicious_activity', False
                ),
                'spam': details.get('spam', False),
                'data_breach': details.get('data_breach', False),
                'first_seen': details.get('first_seen', ''),
                'last_seen': details.get('last_seen', ''),
                'profiles': details.get('profiles', [])
            }

        # 400 = ungültige E-Mail
        elif response.status_code == 400:
            print(f"[EmailRep] Ungültige E-Mail: {email}")
            return None

        # 429 = Rate Limit
        elif response.status_code == 429:
            print("[EmailRep] Rate Limit erreicht")
            return None

        else:
            print(f"[EmailRep] Status: {response.status_code}")
            return None

    except requests.exceptions.Timeout:
        print(f"[EmailRep] Timeout für {email}")
        return None

    except requests.exceptions.ConnectionError:
        print("[EmailRep] Keine Verbindung möglich")
        return None

    except Exception as e:
        print(f"[EmailRep] Fehler: {e}")
        return None