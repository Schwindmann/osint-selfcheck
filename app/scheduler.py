import threading
import time
import sqlite3


def cleanup_job(app):
    """
    Hintergrund-Job: löscht alte Sessions alle 30 Minuten.

    Warum 30 Minuten?
    Sessions laufen nach 1 Stunde ab.
    Alle 30 Minuten aufräumen bedeutet:
    maximal 90 Minuten bleiben Daten gespeichert.
    Das ist akzeptabel für Zero Retention.
    """
    while True:
        # 30 Minuten warten
        time.sleep(30 * 60)

        try:
            with app.app_context():
                conn = sqlite3.connect(
                    app.config['DATABASE']
                )
                cursor = conn.cursor()

                # Sessions löschen die älter als 1 Stunde
                cursor.execute('''
                    DELETE FROM scan_sessions
                    WHERE created_at < datetime('now', '-1 hour')
                ''')

                deleted = cursor.rowcount

                # Verwaiste Daten mitlöschen
                for table in [
                    'emails',
                    'usernames',
                    'scan_results'
                ]:
                    cursor.execute(
                        'DELETE FROM ' + table +
                        ' WHERE session_id NOT IN '
                        '(SELECT session_id FROM scan_sessions)'
                    )

                conn.commit()
                conn.close()

                if deleted > 0:
                    print(
                        f"[Scheduler] {deleted} alte "
                        f"Session(s) gelöscht"
                    )
                else:
                    print("[Scheduler] Nichts zu löschen")

        except Exception as e:
            print(f"[Scheduler] Fehler: {e}")


def start_scheduler(app):
    """
    Scheduler in separatem Thread starten.
    Startet beim App-Start automatisch.
    daemon=True = stirbt wenn App beendet wird.
    """
    thread = threading.Thread(
        target=cleanup_job,
        args=(app,),
        daemon=True
    )
    thread.start()
    print("[Scheduler] Gestartet — räumt alle 30min auf")
    return thread