import json


# ── Schweregrade ───────────────────────────────────────────
# 4 = Kritisch  (sofort handeln)
# 3 = Hoch      (bald handeln)
# 2 = Mittel    (im Blick behalten)
# 1 = Info      (zur Kenntnis nehmen)

SEVERITY_CRITICAL = 4
SEVERITY_HIGH     = 3
SEVERITY_MEDIUM   = 2
SEVERITY_INFO     = 1

SEVERITY_LABELS = {
    4: 'Kritisch',
    3: 'Hoch',
    2: 'Mittel',
    1: 'Info'
}

SEVERITY_COLORS = {
    4: 'red',
    3: 'orange',
    2: 'yellow',
    1: 'blue'
}

# Datenkategorien die besonders kritisch sind
CRITICAL_DATA_CLASSES = [
    'Passwords',
    'Credit cards',
    'Bank account numbers',
    'Social security numbers',
    'Private messages',
    'Auth tokens'
]

HIGH_DATA_CLASSES = [
    'Email addresses',
    'Usernames',
    'Phone numbers',
    'Physical addresses',
    'Dates of birth',
    'Government issued IDs'
]


def process_results(raw_results):
    """
    Rohdaten aus der Datenbank verarbeiten und bewerten.

    raw_results: Liste von DB-Rows aus scan_results
    Gibt zurück: Dictionary mit bewerteten Ergebnissen
    """
    findings = []

    for row in raw_results:
        data = json.loads(row['data'])

        if row['source'] == 'hibp':
            findings.extend(
                _process_hibp(row['target'], data)
            )
        elif row['source'] == 'emailrep':
            findings.extend(
                _process_emailrep(row['target'], data)
            )
        elif row['source'] == 'sherlock':
            findings.extend(
                _process_sherlock(row['target'], data)
            )
        elif row['source'] == 'whois':
            findings.extend(
                _process_whois(row['target'], data)
            )

    # Nach Schweregrad sortieren (kritischste zuerst)
    findings.sort(key=lambda x: x['severity'], reverse=True)

    # Zusammenfassung erstellen
    summary = _build_summary(findings)

    # To-do-Liste erstellen
    todos = _build_todos(findings)

    return {
        'findings': findings,
        'summary': summary,
        'todos': todos
    }


def _process_hibp(email, breaches):
    """
    HIBP Leak-Daten bewerten.
    Jeder Leak bekommt einen eigenen Fund-Eintrag.
    """
    results = []

    for breach in breaches:
        data_classes = breach.get('data_classes', [])

        # Schweregrad bestimmen
        severity = SEVERITY_MEDIUM  # Standard

        for dc in data_classes:
            if dc in CRITICAL_DATA_CLASSES:
                severity = SEVERITY_CRITICAL
                break
            elif dc in HIGH_DATA_CLASSES:
                severity = SEVERITY_HIGH

        # Empfehlung generieren
        recommendation = _hibp_recommendation(
            breach.get('name', ''),
            data_classes,
            severity
        )

        results.append({
            'type': 'leak',
            'source': 'hibp',
            'target': email,
            'title': f"Datenleck: {breach.get('name', 'Unbekannt')}",
            'severity': severity,
            'severity_label': SEVERITY_LABELS[severity],
            'severity_color': SEVERITY_COLORS[severity],
            'details': {
                'name': breach.get('name', ''),
                'date': breach.get('date', '')[:4]
                        if breach.get('date') else '',
                'data_classes': data_classes,
                'is_verified': breach.get('is_verified', False)
            },
            'recommendation': recommendation
        })

    return results


def _hibp_recommendation(name, data_classes, severity):
    """Passende Empfehlung für einen HIBP-Leak generieren."""
    if severity == SEVERITY_CRITICAL:
        return (
            f"Ändere sofort dein Passwort bei {name} "
            f"und überall wo du dasselbe Passwort nutzt. "
            f"Aktiviere Zwei-Faktor-Authentifizierung."
        )
    elif severity == SEVERITY_HIGH:
        return (
            f"Prüfe dein Konto bei {name} auf verdächtige "
            f"Aktivitäten. Ändere dein Passwort als "
            f"Vorsichtsmaßnahme."
        )
    else:
        return (
            f"Deine E-Mail war in einem Leak bei {name}. "
            f"Sei vorsichtig bei Phishing-Mails die "
            f"diese Adresse verwenden."
        )


def _process_emailrep(email, data):
    """EmailRep Reputationsdaten bewerten."""
    results = []

    # Verdächtige E-Mail
    if data.get('suspicious'):
        results.append({
            'type': 'reputation',
            'source': 'emailrep',
            'target': email,
            'title': 'Verdächtige E-Mail-Adresse',
            'severity': SEVERITY_HIGH,
            'severity_label': SEVERITY_LABELS[SEVERITY_HIGH],
            'severity_color': SEVERITY_COLORS[SEVERITY_HIGH],
            'details': {
                'reputation': data.get('reputation', ''),
                'references': data.get('references', 0)
            },
            'recommendation': (
                'Diese E-Mail-Adresse wurde als verdächtig '
                'eingestuft. Prüfe ob sie kompromittiert wurde '
                'und erwäge eine neue Adresse zu verwenden.'
            )
        })

    # Blacklist
    if data.get('blacklisted'):
        results.append({
            'type': 'reputation',
            'source': 'emailrep',
            'target': email,
            'title': 'E-Mail auf Blacklist',
            'severity': SEVERITY_HIGH,
            'severity_label': SEVERITY_LABELS[SEVERITY_HIGH],
            'severity_color': SEVERITY_COLORS[SEVERITY_HIGH],
            'details': {
                'reputation': data.get('reputation', '')
            },
            'recommendation': (
                'Diese E-Mail-Adresse steht auf einer Blacklist. '
                'Das kann E-Mail-Zustellung beeinträchtigen. '
                'Kontaktiere deinen E-Mail-Anbieter.'
            )
        })

    # Spam-Aktivität
    if data.get('spam'):
        results.append({
            'type': 'reputation',
            'source': 'emailrep',
            'target': email,
            'title': 'Spam-Aktivität erkannt',
            'severity': SEVERITY_MEDIUM,
            'severity_label': SEVERITY_LABELS[SEVERITY_MEDIUM],
            'severity_color': SEVERITY_COLORS[SEVERITY_MEDIUM],
            'details': {},
            'recommendation': (
                'Von dieser Adresse wurde Spam versendet. '
                'Prüfe ob dein E-Mail-Konto kompromittiert '
                'wurde und ändere dein Passwort.'
            )
        })

    # Datenleck bekannt
    if data.get('data_breach') and not data.get('suspicious'):
        results.append({
            'type': 'reputation',
            'source': 'emailrep',
            'target': email,
            'title': 'E-Mail in Datenlecks bekannt',
            'severity': SEVERITY_MEDIUM,
            'severity_label': SEVERITY_LABELS[SEVERITY_MEDIUM],
            'severity_color': SEVERITY_COLORS[SEVERITY_MEDIUM],
            'details': {
                'first_seen': data.get('first_seen', ''),
                'last_seen': data.get('last_seen', ''),
                'profiles': data.get('profiles', [])
            },
            'recommendation': (
                'Diese E-Mail wurde in bekannten Datenlecks '
                'gefunden. Nutze Have I Been Pwned für Details.'
            )
        })

    # Wenn alles ok ist: positiver Fund
    if not results:
        results.append({
            'type': 'reputation',
            'source': 'emailrep',
            'target': email,
            'title': 'E-Mail Reputation unauffällig',
            'severity': SEVERITY_INFO,
            'severity_label': SEVERITY_LABELS[SEVERITY_INFO],
            'severity_color': SEVERITY_COLORS[SEVERITY_INFO],
            'details': {
                'reputation': data.get('reputation', 'unknown'),
                'profiles': data.get('profiles', [])
            },
            'recommendation': (
                'Keine auffälligen Aktivitäten gefunden.'
            )
        })

    return results


def _process_sherlock(username, profiles):
    """Sherlock Profil-Daten bewerten."""
    if not profiles:
        return []

    # Plattformen kategorisieren
    sensitive_platforms = [
        'facebook', 'instagram', 'twitter', 'linkedin',
        'tiktok', 'snapchat', 'telegram', 'discord'
    ]

    found_sensitive = [
        p for p in profiles
        if any(s in p['platform'].lower()
               for s in sensitive_platforms)
    ]

    severity = (
        SEVERITY_MEDIUM
        if found_sensitive
        else SEVERITY_INFO
    )

    return [{
        'type': 'profile',
        'source': 'sherlock',
        'target': username,
        'title': (
            f"Username '{username}' auf "
            f"{len(profiles)} Plattform(en) gefunden"
        ),
        'severity': severity,
        'severity_label': SEVERITY_LABELS[severity],
        'severity_color': SEVERITY_COLORS[severity],
        'details': {
            'profiles': profiles,
            'count': len(profiles),
            'sensitive_count': len(found_sensitive)
        },
        'recommendation': (
            f"Dein Username ist auf {len(profiles)} "
            f"Plattformen öffentlich sichtbar. "
            f"Prüfe ob alle Profile noch gewollt sind "
            f"und stelle nicht benötigte auf privat."
        )
    }]


def _process_whois(domain, data):
    """WHOIS Domain-Daten bewerten."""
    return [{
        'type': 'domain',
        'source': 'whois',
        'target': domain,
        'title': f"Domain-Info: {domain}",
        'severity': SEVERITY_INFO,
        'severity_label': SEVERITY_LABELS[SEVERITY_INFO],
        'severity_color': SEVERITY_COLORS[SEVERITY_INFO],
        'details': data,
        'recommendation': (
            'Domain-Informationen sind öffentlich '
            'im WHOIS-Register einsehbar.'
        )
    }]


def _build_summary(findings):
    """Zusammenfassung aller Funde erstellen."""
    counts = {4: 0, 3: 0, 2: 0, 1: 0}
    for f in findings:
        counts[f['severity']] += 1

    # Gesamtstatus bestimmen
    if counts[4] > 0:
        status = 'critical'
        status_text = 'Sofortiger Handlungsbedarf'
        status_color = 'red'
    elif counts[3] > 0:
        status = 'warning'
        status_text = 'Handlungsbedarf'
        status_color = 'orange'
    elif counts[2] > 0:
        status = 'medium'
        status_text = 'Im Blick behalten'
        status_color = 'yellow'
    else:
        status = 'good'
        status_text = 'Alles unauffällig'
        status_color = 'green'

    return {
        'total': len(findings),
        'critical': counts[4],
        'high': counts[3],
        'medium': counts[2],
        'info': counts[1],
        'status': status,
        'status_text': status_text,
        'status_color': status_color
    }


def _build_todos(findings):
    """
    To-do-Liste aus kritischen und hohen Funden erstellen.
    Nur Funde mit Handlungsbedarf kommen rein.
    """
    todos = []

    for f in findings:
        if f['severity'] >= SEVERITY_HIGH:
            todos.append({
                'title': f['title'],
                'recommendation': f['recommendation'],
                'severity': f['severity'],
                'severity_color': f['severity_color'],
                'done': False
            })

    return todos