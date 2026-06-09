import json
import threading
from app.sources import hibp, emailrep, username_check, whois_check
from app.models import save_result, get_db
from flask import current_app


def run_scan(session_id, emails, usernames, app):
    """
    Kompletten Scan für eine Session durchführen.

    Läuft in einem separaten Thread damit der Browser
    nicht wartet — der User sieht eine Ladeseite während
    der Scan im Hintergrund läuft.

    session_id: eindeutige ID der Session
    emails:     Liste von E-Mail-Adressen
    usernames:  Liste von Usernames
    app:        Flask-App-Instanz (für App-Kontext)
    """
    # App-Kontext im Thread öffnen
    # Threads haben keinen automatischen Flask-Kontext
    # ohne das würde get_db() und current_app nicht funktionieren
    with app.app_context():
        try:
            print(f"\n[Scan] Starte Scan für Session: {session_id}")
            print(f"[Scan] E-Mails: {emails}")
            print(f"[Scan] Usernames: {usernames}")

            # Status auf 'scanning' setzen
            _update_status(session_id, 'scanning')

            # ── Schritt 1: E-Mails scannen ─────────────────
            for email in emails:
                print(f"\n[Scan] Verarbeite E-Mail: {email}")

                # Have I Been Pwned
                print(f"[Scan] → HIBP...")
                hibp_results = hibp.check_email(email)
                if hibp_results:
                    save_result(
                        session_id=session_id,
                        source='hibp',
                        category='leak',
                        target=email,
                        data=json.dumps(hibp_results)
                    )

                # EmailRep
                print(f"[Scan] → EmailRep...")
                emailrep_result = emailrep.check_email(email)
                if emailrep_result:
                    save_result(
                        session_id=session_id,
                        source='emailrep',
                        category='reputation',
                        target=email,
                        data=json.dumps(emailrep_result)
                    )

                # WHOIS für die Domain der E-Mail
                domain = whois_check.extract_domain_from_email(email)
                if domain:
                    # Bekannte Provider überspringen
                    # (gmail.com, outlook.com etc. sind uninteressant)
                    skip_domains = [
                        'gmail.com', 'googlemail.com',
                        'outlook.com', 'hotmail.com',
                        'yahoo.com', 'web.de', 'gmx.de',
                        'gmx.net', 'icloud.com', 'me.com'
                    ]
                    if domain not in skip_domains:
                        print(f"[Scan] → WHOIS für {domain}...")
                        whois_result = whois_check.check_domain(domain)
                        if whois_result:
                            save_result(
                                session_id=session_id,
                                source='whois',
                                category='domain',
                                target=domain,
                                data=json.dumps(whois_result)
                            )

            # ── Schritt 2: Usernames scannen ───────────────
            if usernames:
                print(f"\n[Scan] Verarbeite {len(usernames)} Username(s)...")
                all_username_results = \
                    username_check.check_multiple_usernames(usernames)

                for username, profiles in all_username_results.items():
                    if profiles:
                        save_result(
                            session_id=session_id,
                            source='sherlock',
                            category='profile',
                            target=username,
                            data=json.dumps(profiles)
                        )

            # ── Scan abgeschlossen ─────────────────────────
            _update_status(session_id, 'done')
            print(f"\n[Scan] ✓ Scan abgeschlossen: {session_id}")

        except Exception as e:
            print(f"\n[Scan] ✗ Fehler: {e}")
            # Bei Fehler: Status auf 'error' setzen
            _update_status(session_id, 'error')


def start_scan_thread(session_id, emails, usernames, app):
    """
    Scan in einem separaten Thread starten.

    Warum Thread?
    Sherlock braucht 20-60 Sekunden.
    Ohne Thread würde der Browser solange warten
    und dann einen Timeout-Fehler zeigen.

    Mit Thread:
    → Browser bekommt sofort die Ladeseite
    → Scan läuft im Hintergrund
    → Ladeseite fragt alle 3 Sekunden nach ob fertig
    """
    thread = threading.Thread(
        target=run_scan,
        args=(session_id, emails, usernames, app),
        # daemon=True = Thread stirbt wenn App beendet wird
        daemon=True
    )
    thread.start()
    print(f"[Scan] Thread gestartet für: {session_id}")
    return thread


def _update_status(session_id, status):
    """
    Session-Status in der Datenbank aktualisieren.
    Interner Hilfsfunktion — nur innerhalb dieses Moduls.
    """
    db = get_db()
    db.execute(
        'UPDATE scan_sessions SET status = ? WHERE session_id = ?',
        (status, session_id)
    )
    db.commit()
    print(f"[Scan] Status → {status}")