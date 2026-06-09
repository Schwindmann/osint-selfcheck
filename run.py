from app import create_app

# App-Instanz erstellen
app = create_app()

if __name__ == '__main__':
    # debug=True = App startet automatisch neu bei Code-Änderungen
    # Nur für Entwicklung — niemals in Produktion!
    app.run(debug=True)