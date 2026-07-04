#!/bin/bash
# Beispiele zur Verwendung von analyze_access_logs.py

echo "🔍 123-bibel.de Access-Log Analyzer - Beispiele"
echo "================================================"

# Beispiel 1: Basis-Analyse im aktuellen Verzeichnis
echo ""
echo "Beispiel 1: Basis-Analyse"
echo "  $ python3 analyze_access_logs.py"
echo ""

# Beispiel 2: Mit spezifischem Log-Verzeichnis
echo "Beispiel 2: Spezifisches Verzeichnis"
echo "  $ python3 analyze_access_logs.py -d /path/to/logs"
echo ""

# Beispiel 3: CSV exportieren
echo "Beispiel 3: CSV exportieren"
echo "  $ python3 analyze_access_logs.py --csv access_logs.csv"
echo ""

# Beispiel 4: HTML-Report generieren
echo "Beispiel 4: HTML-Report"
echo "  $ python3 analyze_access_logs.py --html report.html"
echo ""

# Beispiel 5: CSV und HTML zusammen
echo "Beispiel 5: CSV und HTML zusammen"
echo "  $ python3 analyze_access_logs.py --csv out.csv --html report.html"
echo ""

# Beispiel 6: Verbose-Modus
echo "Beispiel 6: Verbose-Modus (mehr Details)"
echo "  $ python3 analyze_access_logs.py -v"
echo ""

# Beispiel 7: Alles zusammen mit Custom-Pfaden
echo "Beispiel 7: Alles zusammen"
echo "  $ python3 analyze_access_logs.py -d ./logs --csv results.csv --html report.html -v"
echo ""

echo "================================================"
echo "ℹ️  Hilfe anzeigen:"
echo "  $ python3 analyze_access_logs.py --help"
echo ""

# Optional: Einen echten Run ausführen, wenn das Skript existiert
if [ -f "analyze_access_logs.py" ]; then
    echo "✅ Skript gefunden: analyze_access_logs.py"
    echo ""
    echo "Starten Sie die Analyse mit:"
    echo "  python3 analyze_access_logs.py"
else
    echo "⚠️  Skript nicht gefunden. Stellen Sie sicher, dass analyze_access_logs.py im Verzeichnis ist."
fi
