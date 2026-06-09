/**
 * form.js — Formular-Interaktionen
 *
 * Zuständig für:
 * - Felder dynamisch hinzufügen und entfernen
 * - Echtzeit-Validierung während der User tippt
 * - Loading-State beim Absenden
 * - Screenreader-Ankündigungen
 */


// ── Felder hinzufügen ───────────────────────────────────

/**
 * Neues Eingabefeld in einen Container einfügen.
 *
 * @param {string} containerId  ID des Container-Divs
 * @param {string} inputType    'email' oder 'text'
 * @param {string} inputName    'emails[]' oder 'usernames[]'
 * @param {string} placeholder  Platzhalter-Text
 * @param {string} label        Label für Screenreader
 */
function addField(containerId, inputType, inputName,
                  placeholder, label) {

    const container = document.getElementById(containerId);

    // Anzahl vorhandener Felder für eindeutige IDs
    const fieldCount = container
        .querySelectorAll('.input-row').length;
    const fieldId = `${inputName.replace('[]', '')}-${fieldCount}`;

    // Neues Feld erstellen
    const div = document.createElement('div');
    div.className = 'input-row';

    div.innerHTML = `
        <label for="${fieldId}" class="sr-only">
            ${label} ${fieldCount + 1}
        </label>
        <input
            type="${inputType}"
            id="${fieldId}"
            name="${inputName}"
            placeholder="${placeholder}"
            class="input"
            aria-label="${label} ${fieldCount + 1}"
            autocomplete="off"
            autocorrect="off"
            autocapitalize="off"
            spellcheck="false"
        >
        <button
            type="button"
            class="btn-remove"
            onclick="removeField(this)"
            aria-label="${label} ${fieldCount + 1} entfernen"
            title="Feld entfernen"
        >✕</button>
    `;

    container.appendChild(div);

    // Fokus direkt auf neues Feld
    const newInput = div.querySelector('input');
    newInput.focus();

    // Echtzeit-Validierung für E-Mail-Felder
    if (inputType === 'email') {
        newInput.addEventListener('input', validateEmailField);
    }

    // Screenreader informieren
    announceToScreenreader(`${label} Feld hinzugefügt`);
}


/**
 * Feld entfernen.
 * @param {HTMLElement} button Der angeklickte Entfernen-Button
 */
function removeField(button) {
    const row = button.parentElement;
    const label = button.getAttribute('aria-label');
    row.remove();
    announceToScreenreader(`${label} entfernt`);
}


// Shortcut-Funktionen für die HTML onclick-Attribute
function addEmail() {
    addField(
        'email-container',
        'email',
        'emails[]',
        'weitere@email.de',
        'E-Mail-Adresse'
    );
}

function addUsername() {
    addField(
        'username-container',
        'text',
        'usernames[]',
        'weitererUsername',
        'Username'
    );
}


// ── Echtzeit-Validierung ────────────────────────────────

/**
 * E-Mail-Format live prüfen während der User tippt.
 * Zeigt grünen oder roten Rahmen als visuelles Feedback.
 * Die echte Validierung macht der Server — das hier ist nur UX.
 */
function validateEmailField(event) {
    const input = event.target;
    const value = input.value.trim();

    // Leer = neutral, kein Feedback
    if (value === '') {
        input.classList.remove('valid', 'invalid');
        return;
    }

    const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if (emailPattern.test(value)) {
        input.classList.add('valid');
        input.classList.remove('invalid');
        input.setAttribute('aria-invalid', 'false');
    } else {
        input.classList.add('invalid');
        input.classList.remove('valid');
        input.setAttribute('aria-invalid', 'true');
    }
}


// ── Loading-State beim Absenden ─────────────────────────

/**
 * Beim Absenden Button deaktivieren und Spinner zeigen.
 * Verhindert doppeltes Absenden.
 */
function handleSubmit() {
    const btn = document.getElementById('submit-btn');

    // Prüfen ob mindestens eine E-Mail eingegeben wurde
    const emailInputs = document.querySelectorAll(
        'input[name="emails[]"]'
    );
    let hasEmail = false;
    emailInputs.forEach(input => {
        if (input.value.trim() !== '') hasEmail = true;
    });

    if (!hasEmail) return;

    // Button deaktivieren
    btn.disabled = true;
    btn.innerHTML = `
        <span aria-hidden="true">⏳</span>
        <span>Wird verarbeitet...</span>
    `;
    btn.setAttribute('aria-busy', 'true');
}


// ── Screenreader-Ankündigungen ──────────────────────────

/**
 * Text für Screenreader ankündigen.
 * Schreibt in die aria-live Region im base.html.
 * @param {string} message Anzuküdigender Text
 */
function announceToScreenreader(message) {
    const announcer = document.getElementById('sr-announcer');
    if (!announcer) return;

    // Kurze Pause damit Screenreader die Änderung erkennt
    announcer.textContent = '';
    setTimeout(() => {
        announcer.textContent = message;
    }, 50);
}


// ── Initialisierung beim Seitenladen ───────────────────

document.addEventListener('DOMContentLoaded', function () {

    // Echtzeit-Validierung für initiale E-Mail-Felder
    document.querySelectorAll('input[type="email"]')
        .forEach(input => {
            input.addEventListener('input', validateEmailField);
        });

    // Submit-Handler ans Formular binden
    const form = document.getElementById('scan-form');
    if (form) {
        form.addEventListener('submit', handleSubmit);
    }

    // Countdown auf der Pending-Seite
    const countdown = document.getElementById(
        'refresh-countdown'
    );
    if (countdown) {
        let seconds = 10;
        setInterval(() => {
            seconds--;
            if (seconds <= 0) seconds = 10;
            countdown.textContent = seconds;
        }, 1000);
    }
});