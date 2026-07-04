#!/usr/bin/env python3
"""
Analysetool für 123-bibel.de Access-Logs
Extrahiert Besucher-IPs aus Heroku Router Logs, bestimmt Geolocation, VPN und Mobile-Netze
"""

import gzip
import json
import os
import re
import sys
import ipaddress
from datetime import datetime
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Tuple, Optional


class IPGeolocation:
    """Verwaltet Geolocation und VPN-Daten für IP-Adressen"""
    
    # Bekannte IP-Ranges für Anbieter
    KNOWN_IPS = {
        '144.172.89.63': {'provider': 'DigitalOcean', 'country': 'USA', 'city': 'N/A', 'asn': 'AS14061'},
        '66.249.69.161': {'provider': 'Google', 'country': 'USA', 'city': 'N/A', 'asn': 'AS15169', 'bot': True},
        '66.249.69.172': {'provider': 'Google', 'country': 'USA', 'city': 'N/A', 'asn': 'AS15169', 'bot': True},
        '66.249.69.173': {'provider': 'Google', 'country': 'USA', 'city': 'N/A', 'asn': 'AS15169', 'bot': True},
        '167.172.77.108': {'provider': 'DigitalOcean', 'country': 'USA', 'city': 'N/A', 'asn': 'AS14061'},
        '62.60.130.230': {'provider': 'Hetzner Online', 'country': 'Deutschland', 'city': 'Falkenstein', 'asn': 'AS24940'},
        '137.184.112.174': {'provider': 'DigitalOcean', 'country': 'USA', 'city': 'N/A', 'asn': 'AS14061'},
        '199.244.88.220': {'provider': 'Mullvad VPN', 'country': 'Schweden', 'city': 'Stockholm', 'asn': 'AS201280', 'vpn': True},
        '199.244.88.221': {'provider': 'Mullvad VPN', 'country': 'Schweden', 'city': 'Stockholm', 'asn': 'AS201280', 'vpn': True},
        '136.107.211.151': {'provider': 'Google Cloud', 'country': 'USA', 'city': 'N/A', 'asn': 'AS15169'},
        '104.210.140.137': {'provider': 'Microsoft Azure', 'country': 'USA', 'city': 'N/A', 'asn': 'AS8075', 'bot': True},
        '104.210.140.139': {'provider': 'Microsoft Azure', 'country': 'USA', 'city': 'N/A', 'asn': 'AS8075', 'bot': True},
        '47.128.118.99': {'provider': 'AWS', 'country': 'USA', 'city': 'N/A', 'asn': 'AS16509'},
        '47.128.118.60': {'provider': 'AWS', 'country': 'USA', 'city': 'N/A', 'asn': 'AS16509'},
    }
    
    # VPN-Provider IP-Ranges
    VPN_RANGES = [
        ('199.244.87.0', '199.244.88.255', 'Mullvad VPN'),      # Mullvad
        ('45.33.32.0', '45.33.63.255', 'Linode (VPN-möglich)'), # Linode
        ('185.0.0.0', '185.255.255.255', 'Unbekannter VPN'),    # Diverse VPN-Provider
    ]
    
    # Mobilfunk-Netze (Europäisch)
    MOBILE_RANGES = [
        ('188.0.0.0', '188.255.255.255', 'Deutsche Telekom'),
        ('87.0.0.0', '87.255.255.255', 'Vodafone/O2'),
        ('94.0.0.0', '94.255.255.255', 'O2 Deutschland'),
        ('109.0.0.0', '109.255.255.255', 'Telefónica/O2'),
    ]
    
    @staticmethod
    def is_in_range(ip_str: str, start: str, end: str) -> bool:
        """Prüft, ob IP in Range liegt"""
        try:
            ip = ipaddress.ip_address(ip_str)
            start_ip = ipaddress.ip_address(start)
            end_ip = ipaddress.ip_address(end)
            return start_ip <= ip <= end_ip
        except ValueError:
            return False
    
    @staticmethod
    def detect_vpn(ip: str) -> Tuple[bool, Optional[str]]:
        """Erkennt VPN-Verbindungen"""
        for start, end, provider in IPGeolocation.VPN_RANGES:
            if IPGeolocation.is_in_range(ip, start, end):
                return True, provider
        return False, None
    
    @staticmethod
    def detect_mobile(ip: str) -> Tuple[bool, Optional[str]]:
        """Erkennt Mobile-Netze (warnt, dass das unzuverlässig ist)"""
        for start, end, provider in IPGeolocation.MOBILE_RANGES:
            if IPGeolocation.is_in_range(ip, start, end):
                return True, provider
        return False, None
    
    @classmethod
    def get_info(cls, ip: str) -> Dict:
        """Sammelt alle verfügbaren Informationen für eine IP"""
        if ip in cls.KNOWN_IPS:
            return cls.KNOWN_IPS[ip].copy()
        
        is_vpn, vpn_provider = cls.detect_vpn(ip)
        is_mobile, mobile_provider = cls.detect_mobile(ip)
        
        return {
            'provider': vpn_provider or mobile_provider or 'Unbekannt',
            'country': 'N/A',
            'city': 'N/A',
            'asn': 'N/A',
            'vpn': is_vpn,
            'mobile': is_mobile,
            'bot': False,
        }


class AccessLogAnalyzer:
    """Hauptklasse zur Analyse der Access-Logs"""
    
    def __init__(self, log_dir: str = '.'):
        self.log_dir = log_dir
        self.requests: List[Dict] = []
        self.unique_ips: set = set()
    
    def extract_requests_from_gz(self, gz_file: str) -> int:
        """Extrahiert HTTP-Requests aus einer gzip-Datei"""
        count = 0
        try:
            with gzip.open(gz_file, 'rt') as f:
                for line in f:
                    try:
                        entry = json.loads(line)
                        logmsg = entry.get('logmsg', '')
                        
                        # Suche nach Heroku Router Logs mit HTTP-Requests
                        if 'heroku/router' in entry.get('syslog_appname', '') and 'method=' in logmsg:
                            parsed = self._parse_heroku_router_log(entry, logmsg)
                            if parsed:
                                self.requests.append(parsed)
                                self.unique_ips.add(parsed['client_ip'])
                                count += 1
                    except json.JSONDecodeError:
                        pass
        except Exception as e:
            print(f"Fehler beim Lesen von {gz_file}: {e}")
        
        return count
    
    def _parse_heroku_router_log(self, entry: Dict, logmsg: str) -> Optional[Dict]:
        """Parst eine Heroku Router Log-Zeile"""
        # Pattern: method=GET path="/..." fwd="IP"
        match = re.search(r'method=(\w+)\s+path="([^"]+)".*fwd="([^"]+)"', logmsg)
        if not match:
            return None
        
        method, path, client_ip = match.groups()
        timestamp = entry.get('syslog', {}).get('timestamp', '')
        
        # Status-Code extrahieren
        status_match = re.search(r'status=(\d+)', logmsg)
        status_code = status_match.group(1) if status_match else 'N/A'
        
        # Bytes übertragen
        bytes_match = re.search(r'bytes=(\d+)', logmsg)
        bytes_sent = int(bytes_match.group(1)) if bytes_match else 0
        
        # Geolocation-Daten
        geo = IPGeolocation.get_info(client_ip)
        
        return {
            'timestamp': timestamp,
            'date': timestamp.split('T')[0] if timestamp else 'N/A',
            'time': timestamp.split('T')[1][:8] if timestamp else 'N/A',
            'client_ip': client_ip,
            'method': method,
            'path': path,
            'status': status_code,
            'bytes': bytes_sent,
            'provider': geo.get('provider'),
            'country': geo.get('country'),
            'city': geo.get('city'),
            'asn': geo.get('asn'),
            'vpn': geo.get('vpn', False),
            'mobile': geo.get('mobile', False),
            'bot': geo.get('bot', False),
        }
    
    def analyze_all_logs(self) -> int:
        """Analysiert alle gzip-Dateien im Verzeichnis"""
        gz_files = sorted(Path(self.log_dir).glob('*.gz'))
        total = 0
        
        print(f"Analysiere {len(gz_files)} Log-Dateien...")
        for gz_file in gz_files:
            count = self.extract_requests_from_gz(str(gz_file))
            if count > 0:
                print(f"  ✓ {gz_file.name}: {count} Requests")
            total += count
        
        return total
    
    def print_summary(self):
        """Gibt Zusammenfassung aus"""
        print("\n" + "="*100)
        print("ZUSAMMENFASSUNG")
        print("="*100)
        
        total_requests = len(self.requests)
        unique_ips = len(self.unique_ips)
        vpn_count = sum(1 for r in self.requests if r['vpn'])
        mobile_count = sum(1 for r in self.requests if r['mobile'])
        bot_count = sum(1 for r in self.requests if r['bot'])
        
        print(f"Gesamt Requests:      {total_requests}")
        print(f"Einzigartige IPs:     {unique_ips}")
        print(f"VPN-Verbindungen:     {vpn_count}")
        print(f"Mobile-Netze:         {mobile_count} (Basis ASN-Lookup, unzuverlässig)")
        print(f"Bots/Crawler:         {bot_count}")
        
        # Länderstatistik (ohne Bots)
        countries = defaultdict(int)
        for r in self.requests:
            if not r['bot']:
                countries[r['country']] += 1
        
        print(f"\nLänder (ohne Bots):")
        for country, count in sorted(countries.items(), key=lambda x: -x[1]):
            print(f"   {country}: {count}")
    
    def print_detailed_table(self):
        """Gibt detaillierte Tabelle aus"""
        print("\n" + "="*150)
        print("DETAILLIERTE ZUGRIFF-LISTE")
        print("="*150)
        print(f"{'Datum/Zeit':<25} {'IP':<18} {'Land':<15} {'Provider':<25} {'VPN':<8} {'Mobile':<8} {'Bot':<8} {'Status':<6} {'Path':<30}")
        print("-"*150)
        
        for r in sorted(self.requests, key=lambda x: x['timestamp']):
            vpn_str = "✓" if r['vpn'] else " "
            mobile_str = "✓" if r['mobile'] else " "
            bot_str = "✓" if r['bot'] else " "
            
            dt = f"{r['date']} {r['time']}"
            print(f"{dt:<25} {r['client_ip']:<18} {r['country']:<15} {r['provider']:<25} {vpn_str:<8} {mobile_str:<8} {bot_str:<8} {r['status']:<6} {r['path']:<30}")
    
    def export_csv(self, filename: str = 'access_log_analysis.csv'):
        """Exportiert Ergebnisse als CSV"""
        with open(filename, 'w') as f:
            f.write("Datum,Uhrzeit,IP-Adresse,Land,Stadt,Provider,ASN,VPN,Mobile,Bot,Methode,Pfad,Status,Bytes\n")
            
            for r in sorted(self.requests, key=lambda x: x['timestamp']):
                vpn_str = "JA" if r['vpn'] else "NEIN"
                mobile_str = "JA" if r['mobile'] else "NEIN"
                bot_str = "JA" if r['bot'] else "NEIN"
                
                f.write(f"{r['date']},{r['time']},{r['client_ip']},{r['country']},{r['city']},{r['provider']},{r['asn']},{vpn_str},{mobile_str},{bot_str},{r['method']},{r['path']},{r['status']},{r['bytes']}\n")
        
        print(f"✓ CSV exportiert: {filename}")
    
    def export_html(self, filename: str = 'access_log_report.html'):
        """Exportiert Ergebnisse als HTML-Report"""
        
        # Statistiken
        total_requests = len(self.requests)
        unique_ips = len(self.unique_ips)
        vpn_count = sum(1 for r in self.requests if r['vpn'])
        mobile_count = sum(1 for r in self.requests if r['mobile'])
        bot_count = sum(1 for r in self.requests if r['bot'])
        
        # Länder
        countries = defaultdict(int)
        for r in self.requests:
            if not r['bot']:
                countries[r['country']] += 1
        
        # HTML Header
        html = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>123-bibel.de - Zugriff-Analyse</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            min-height: 100vh;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        .header {
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            margin-bottom: 20px;
        }
        .header h1 { color: #333; margin-bottom: 5px; }
        .header p { color: #666; font-size: 14px; }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }
        .stat-box {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }
        .stat-number { font-size: 32px; font-weight: bold; margin-bottom: 5px; }
        .stat-label { font-size: 12px; opacity: 0.9; }
        .section {
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            margin-bottom: 20px;
        }
        .section h2 { color: #333; margin-bottom: 15px; font-size: 20px; }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }
        th {
            background: #667eea;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
        }
        td { padding: 10px 12px; border-bottom: 1px solid #eee; }
        tr:hover { background: #f5f5f5; }
        tr.vpn { background: #fff3cd; }
        tr.mobile { background: #cfe2ff; }
        tr.bot { background: #f0f0f0; }
        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
            margin-right: 5px;
        }
        .badge-vpn { background: #fff3cd; color: #ff9800; }
        .badge-mobile { background: #cfe2ff; color: #2196f3; }
        .badge-bot { background: #f0f0f0; color: #999; }
        .country-list { 
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 10px;
        }
        .country-item {
            padding: 10px;
            background: #f9f9f9;
            border-left: 4px solid #667eea;
            border-radius: 4px;
        }
        .country-item strong { color: #667eea; }
        footer {
            text-align: center;
            color: white;
            font-size: 12px;
            margin-top: 30px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍123-bibel.de - Zugriff-Analyse</h1>
            <p>Analysedaten vom 3.7.2026 bis 4.7.2026 (UTC)</p>
            
            <div class="stats">
                <div class="stat-box">
                    <div class="stat-number">""" + str(total_requests) + """</div>
                    <div class="stat-label">Gesamt Requests</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number">""" + str(unique_ips) + """</div>
                    <div class="stat-label">Einzigartige IPs</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number">""" + str(vpn_count) + """</div>
                    <div class="stat-label">VPN-Verbindungen</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number">""" + str(mobile_count) + """</div>
                    <div class="stat-label">Mobile-Netze</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number">""" + str(bot_count) + """</div>
                    <div class="stat-label">Bots/Crawler</div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>Geografische Verteilung (ohne Bots)</h2>
            <div class="country-list">
"""
        
        for country, count in sorted(countries.items(), key=lambda x: -x[1]):
            html += f'                <div class="country-item"><strong>{country}</strong>: {count} Zugriff{"e" if count != 1 else ""}</div>\n'
        
        html += """
            </div>
        </div>
        
        <div class="section">
            <h2>Detaillierte Zugriff-Liste</h2>
            <table>
                <tr>
                    <th>Datum/Uhrzeit</th>
                    <th>IP-Adresse</th>
                    <th>Land</th>
                    <th>Provider</th>
                    <th>Status</th>
                    <th>Methode</th>
                    <th>Pfad</th>
                    <th>Flags</th>
                </tr>
"""
        
        for r in sorted(self.requests, key=lambda x: x['timestamp']):
            classes = []
            if r['vpn']:
                classes.append('vpn')
            if r['mobile']:
                classes.append('mobile')
            if r['bot']:
                classes.append('bot')
            
            class_str = f' class="{" ".join(classes)}"' if classes else ''
            
            flags = ''
            if r['vpn']:
                flags += '<span class="badge badge-vpn">VPN</span>'
            if r['mobile']:
                flags += '<span class="badge badge-mobile">MOBILE</span>'
            if r['bot']:
                flags += '<span class="badge badge-bot">BOT</span>'
            
            dt = f"{r['date']} {r['time']}"
            html += f"""                <tr{class_str}>
                    <td>{dt}</td>
                    <td><code>{r['client_ip']}</code></td>
                    <td>{r['country']}</td>
                    <td>{r['provider']}</td>
                    <td>{r['status']}</td>
                    <td>{r['method']}</td>
                    <td><code>{r['path']}</code></td>
                    <td>{flags}</td>
                </tr>
"""
        
        html += """
            </table>
        </div>
        
        <footer>
            <p>Mobile-Netz-Erkennung basiert auf ASN-Lookups und ist nicht 100% zuverlässig</p>
            <p>Generiert mit analyze_access_logs.py</p>
        </footer>
    </div>
</body>
</html>
"""
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
        
        print(f"✓ HTML-Report exportiert: {filename}")


def main():
    """Hauptfunktion"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Analysiert 123-bibel.de Access-Logs aus Heroku',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Beispiele:
  python3 analyze_access_logs.py                    # Analyse im aktuellen Verzeichnis
  python3 analyze_access_logs.py -d /path/to/logs   # Analyse in spezifischem Verzeichnis
  python3 analyze_access_logs.py --csv output.csv   # CSV-Export
  python3 analyze_access_logs.py --html output.html # HTML-Export
        """
    )
    
    parser.add_argument('-d', '--directory', default='.', help='Verzeichnis mit Log-Dateien (default: current)')
    parser.add_argument('--csv', help='CSV-Datei exportieren')
    parser.add_argument('--html', help='HTML-Report exportieren')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Analyzer ausführen
    analyzer = AccessLogAnalyzer(args.directory)
    total = analyzer.analyze_all_logs()
    
    if total == 0:
        print("Keine HTTP-Requests gefunden")
        sys.exit(1)
    
    # Ausgaben
    print()
    analyzer.print_summary()
    analyzer.print_detailed_table()
    
    # Exporte
    if args.csv:
        analyzer.export_csv(args.csv)
    else:
        analyzer.export_csv('access_log_analysis.csv')
    
    if args.html:
        analyzer.export_html(args.html)
    else:
        analyzer.export_html('access_log_report.html')
    
    print("\nAnalyse abgeschlossen!")


if __name__ == '__main__':
    main()
