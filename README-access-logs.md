# 123-bibel.de Access-Log-Analyzer

Python-Skript zur Analyse von Heroku Access-Logs für `123-bibel.de`. Extrahiert HTTP-Requests, bestimmt Geolocation und identifiziert VPN- sowie Mobile-Netze.

## Features

- **HTTP-Request Extraktion** aus Heroku Router Logs  
- **IP-Geolocation** mit bekannten Ranges  
- **VPN-Erkennung** (Mullvad, Linode, etc.)  
- **Mobile-Netz-Erkennung** (basierend auf ASN)  
- **Bot/Crawler-Identifikation** (Google, Microsoft, etc.)  
- **CSV-Export** für Tabellenkalkulationen  
- **HTML-Report** mit schöner Visualisierung  

## Installation

```bash
# Keine externen Abhängigkeiten notwendig - Standard-Python-Libraries reichen aus
python3 --version  # Benötigt Python 3.7+
```

## Verwendung

### Basis-Verwendung

```bash
# Analysiere alle .gz-Dateien im aktuellen Verzeichnis
python3 analyze_access_logs.py

# Oder mit spezifischem Log-Verzeichnis
python3 analyze_access_logs.py -d /path/to/logs
```

### Mit Export-Optionen

```bash
# CSV und HTML exportieren
python3 analyze_access_logs.py --csv access_logs.csv --html access_logs.html

# Nur CSV
python3 analyze_access_logs.py --csv output.csv

# Nur HTML
python3 analyze_access_logs.py --html report.html

# Verbose-Modus
python3 analyze_access_logs.py -v
```

## Output

Das Skript gibt folgende Informationen aus:

### Console-Output
```
ZUSAMMENFASSUNG
==================================================
Gesamt Requests:      21
Einzigartige IPs:     14
VPN-Verbindungen:     2
Mobile-Netze:         0 (Basis ASN-Lookup, unzuverlässig)
Bots/Crawler:         7

Länder (ohne Bots):
   USA: 5
   Deutschland: 1
   Schweden: 2
```

### Detaillierte Tabelle
```
DETAILLIERTE ZUGRIFF-LISTE
Datum/Zeit                IP                Land           Provider              VPN    Mobile  Bot    Status  Path
2026-07-03 07:32:55       144.172.89.63     USA            DigitalOcean                       -      404     /.git/config
2026-07-03 22:00:39       199.244.88.220    Schweden       Mullvad VPN           ✓             -      200     /
```

### CSV-Datei
```csv
Datum,Uhrzeit,IP-Adresse,Land,Stadt,Provider,ASN,VPN,Mobile,Bot,Methode,Pfad,Status,Bytes
2026-07-03,07:32:55,144.172.89.63,USA,N/A,DigitalOcean,AS14061,NEIN,NEIN,NEIN,GET,/.git/config,404,22
2026-07-03,22:00:39,199.244.88.220,Schweden,Stockholm,Mullvad VPN,AS201280,JA,NEIN,NEIN,GET,/,200,9604
```

### HTML-Report
Moderner, interaktiver HTML-Report mit:
- Dashboard mit Statistiken
- Geografische Verteilung
- Detaillierte Tabelle mit Farbmarkierungen
- Responsive Design

## Datenquellen

### Bekannte IP-Ranges
Das Skript enthält eine vordefinierte Liste mit über 14 bekannten IPs:

| IP-Range | Provider | Typ |
|----------|----------|-----|
| 144.172.x | DigitalOcean | Cloud |
| 66.249.69.x | Google | Googlebot |
| 199.244.88.x | Mullvad VPN | VPN |
| 104.210.x | Microsoft Azure | Cloud/Bot |
| 47.128.x | AWS | Cloud |
| 62.60.x | Hetzner Online | Cloud |

### IP-Ranges erweitern

Bearbeite die Klasse `IPGeolocation` im Skript:

```python
KNOWN_IPS = {
    '123.45.67.89': {
        'provider': 'Mein Provider',
        'country': 'Deutschland',
        'city': 'Berlin',
        'asn': 'AS12345',
        'vpn': False,
        'bot': False,
    },
    # Weitere IPs...
}
```

Oder erweitere die VPN/Mobile-Ranges:

```python
VPN_RANGES = [
    ('199.244.87.0', '199.244.88.255', 'Mullvad VPN'),
    ('123.0.0.0', '123.255.255.255', 'Mein VPN'),
]

MOBILE_RANGES = [
    ('188.0.0.0', '188.255.255.255', 'Deutsche Telekom'),
    ('100.0.0.0', '100.255.255.255', 'Mein Mobile Provider'),
]
```

## Wichtige Hinweise

**Mobile-Netz-Erkennung**
- Basiert auf ASN-Lookups (Autonomous System Number)
- **Nicht 100% zuverlässig** - Cloud-Provider können sich überschneiden
- Für genaue Mobile-Detection brauchst du externe GeoIP-Datenbanken (MaxMind, IP2Location)

**Heroku Router Logs**
- Extrahiert nur `heroku/router` Logs mit `fwd=` Feld (echte Client-IP)
- App-Logs und System-Logs werden ignoriert
- User-Agent nicht im Standard-Format enthalten → kein Browser-Fingerprinting möglich

**Zuverlässig erkannt**
- VPN-Verbindungen (wenn bekannte IP-Ranges)
- Bot/Crawler (Google, Microsoft, etc.)
- Geolocation für bekannte Hosting-Provider

## Python-API

Für programmtische Verwendung:

```python
from analyze_access_logs import AccessLogAnalyzer, IPGeolocation

# Analyzer initialisieren
analyzer = AccessLogAnalyzer('/path/to/logs')

# Alle Logs analysieren
total = analyzer.analyze_all_logs()

# Zusammenfassung
analyzer.print_summary()

# Detaillierte Tabelle
analyzer.print_detailed_table()

# Exporte
analyzer.export_csv('output.csv')
analyzer.export_html('report.html')

# Auf Requests zugreifen
for request in analyzer.requests:
    print(f"{request['client_ip']} - {request['country']} - VPN: {request['vpn']}")

# IP-Infos manuell abrufen
geo = IPGeolocation.get_info('199.244.88.220')
print(f"Provider: {geo['provider']}, VPN: {geo['vpn']}")
```

## Struktur der Requests

Jeder `request` ist ein Dictionary mit folgenden Feldern:

```python
{
    'timestamp': '2026-07-03T07:32:55.453628+00:00',
    'date': '2026-07-03',
    'time': '07:32:55',
    'client_ip': '144.172.89.63',
    'method': 'GET',
    'path': '/.git/config',
    'status': '404',
    'bytes': 22,
    'provider': 'DigitalOcean',
    'country': 'USA',
    'city': 'N/A',
    'asn': 'AS14061',
    'vpn': False,
    'mobile': False,
    'bot': False,
}
```

## Troubleshooting

### Keine Requests gefunden?
```bash
# Prüfe, ob gzip-Dateien im Verzeichnis sind
ls -la *.gz

# Prüfe Inhalt der gzip-Dateien
gunzip -c 2026-07-03-07_json.gz | head -20
```

### Fehler beim Lesen der Dateien?
```bash
# Stelle sicher, dass die Dateien gzip-komprimiert sind
file 2026-07-03-07_json.gz  # Sollte: gzip compressed data

# Versuche, manuell zu dekomprimieren
gunzip -t 2026-07-03-07_json.gz  # Testet Integrität
```

## Autor

Stephan Epp, Senior Software Developer  
GitHub: https://github.com/hjstephan86
