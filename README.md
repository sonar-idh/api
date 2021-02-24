# SoNAR API

## Installation

Erst username, password und URL der Graphdatenbank in  `flask-api/.env`  konfigurieren. 

Dann folgendes ausführen:

```
cd flask-api
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
export FLASK_APP=app.py
flask run
```
weitere Details s. bei [neo4j-movies-template](https://github.com/neo4j-examples/neo4j-movies-template).

## Funktionen
- Entitäten nach Label, Id, Label+Id finden
- Relationen nach Label, Id, Label+Id des Ausgangs- und/oder des Zielknotens finden
- Entitäten oder Relationen nach Namen suchen (Volltextsuche)
- Personennetzwerke suchen
- Statistik ausgeben
- Daten nach Id exportieren

Ausgaben s. in [Swagger-Dokumentation](LINK)
## Swagger-Dokumentation
## Jupyter-Beispiel
