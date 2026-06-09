import subprocess
import sys
import json
import re


def check_username(username):
    """
    Username auf 300+ Plattformen prüfen via Sherlock.

    Sherlock läuft als separater Prozess — wir starten es
    wie einen Terminal-Befehl und lesen den Output aus.

    Gibt zurück:
    - Liste von gefundenen Profilen
    - Leere Liste wenn nichts gefunden

    Beispiel-Rückgabe:
    [
        {
            'platform': 'GitHub',
            'url': 'https://github.com/username',
            'status': 'found'
        },
        ...
    ]
    """
    print(f"[Sherlock] Suche nach Username: {username}")

    results = []

    try:
        # Sherlock als Subprocess starten
        # sys.executable = der Python-Pfad der aktuell läuft
        # --print-found = nur gefundene Profile ausgeben
        # --no-color    = keine Farb-Codes im Output
        # --timeout 10  = max 10 Sekunden pro Plattform
        process = subprocess.run(
            [
                'sherlock',
                username,
                '--print-found',
                '--no-color',
                '--timeout', '10'
            ],
            capture_output=True,  # stdout + stderr abfangen
            text=True,            # Output als Text (nicht bytes)
            timeout=120           # Gesamtzeit max 2 Minuten
        )

        # Output Zeile für Zeile durchgehen
        for line in process.stdout.splitlines():
            line = line.strip()

            # Sherlock gibt gefundene Profile so aus:
            # [+] GitHub: https://github.com/username
            if line.startswith('[+]'):
                # Platform und URL aus der Zeile extrahieren
                # Beispiel: "[+] GitHub: https://github.com/test"
                # Nach "[+] " kommt "GitHub: https://..."
                content = line[4:]  # "[+] " entfernen

                if ': ' in content:
                    parts = content.split(': ', 1)
                    platform = parts[0].strip()
                    url = parts[1].strip()

                    # Nur echte URLs aufnehmen
                    if url.startswith('http'):
                        results.append({
                            'platform': platform,
                            'url': url,
                            'status': 'found'
                        })

        print(f"[Sherlock] {username}: "
              f"{len(results)} Profil(e) gefunden")
        return results

    except subprocess.TimeoutExpired:
        print(f"[Sherlock] Timeout für {username}")
        return results  # Teilergebnisse zurückgeben

    except FileNotFoundError:
        print("[Sherlock] Nicht installiert — pip install sherlock-project")
        return []

    except Exception as e:
        print(f"[Sherlock] Fehler: {e}")
        return []


def check_multiple_usernames(usernames):
    """
    Mehrere Usernames nacheinander prüfen.

    Gibt ein Dictionary zurück:
    {
        'username1': [liste von profilen],
        'username2': [liste von profilen],
        ...
    }
    """
    all_results = {}

    for username in usernames:
        if username.strip():
            results = check_username(username.strip())
            all_results[username] = results

    return all_results