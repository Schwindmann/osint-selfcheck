# OSINT SelfCheck

Prüfe deinen eigenen digitalen Fußabdruck —
kostenlos, sicher, ohne Account.

## Was es macht

- Prüft deine E-Mail-Adressen auf bekannte Datenlecks
- Sucht deine Usernames auf 300+ Plattformen
- Bewertet die Reputation deiner E-Mail-Adressen
- Erstellt einen übersichtlichen Report mit To-do-Liste

## Datenschutz

- Jede E-Mail wird per Bestätigungslink verifiziert
- Alle Daten werden 1 Stunde nach dem Scan automatisch gelöscht
- Zero Retention by Design

## Tech Stack

- Python 3.13 + Flask
- SQLite
- Have I Been Pwned API
- EmailRep.io API
- Sherlock (Username-Check)
- WHOIS/DNS

## Lokale Installation

```bash
# Repository klonen
git clone https://github.com/DEIN-NAME/osint-selfcheck.git
cd osint-selfcheck

# Virtuelle Umgebung
python -m venv venv
venv\Scripts\activate  # Windows
source venv/bin/activate  # Mac/Linux

# Libraries installieren
pip install -r requirements.txt

# Konfiguration
cp .env.example .env
# .env mit eigenen Werten füllen

# App starten
python run.py
```

## Umgebungsvariablen

| Variable | Beschreibung | Pflicht |
|---|---|---|
| SECRET_KEY | Geheimer Flask-Key | Ja |
| BASE_URL | App-URL | Ja |
| HIBP_API_KEY | Have I Been Pwned Key | Nein |
| EMAILREP_API_KEY | EmailRep.io Key | Nein |

## Ethik & Rechtliches

Dieses Tool ist ausschließlich für den
Self-Check eigener Daten gedacht.
Die Nutzung für fremde Daten ist untersagt.

## Lizenz

MIT License