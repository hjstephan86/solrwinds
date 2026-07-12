# Solarwinds - Log Analysis Tool

Professional tool for log analysis of Solarwinds log archives

## Modules

### Access-Logs Analysis

Professional Python-based analysis of Heroku Router logs with geolocation, VPN detection, and bot identification for https://www.123-bibel.de.

**Features:**
- HTTP request extraction from gzip-compressed logs
- IP geolocation with 14+ known hosting providers
- VPN detection (Mullvad, Linode, etc.)
- Bot/Crawler identification (Google, Microsoft, AWS)
- CSV & HTML exports

**Quick Start:**
```bash
python analyze-access-logs.py -d logs\ --csv access-log-analysis.csv --html access-log-analysis.html
```

**Requirements:**
- Python 3.7+
- No external dependencies (only Standard Library)

---

## Tools Overview

| Tool | Purpose | Status |
|------|---------|--------|
| `analyze-access-logs.py` | Heroku log analysis | Production-ready |

## Technology Stack

- **Language:** Python 3.7+
- **Standard Libraries:** gzip, json, re, argparse, pathlib, collections
- **Zero external dependencies** - completely self-contained

## Getting Started

1. **Clone the repository:**
   ```bash
   git clone https://github.com/hjstephan86/solrwnds.git
   cd solrwnds
   ```

2. **Analyze logs:**
   ```bash
   python3 analyze-access-logs.py -d logs
   ```

## Requirements

- **Python 3.7+** (no virtual environment needed)
- **Linux/macOS/Windows** (all platforms supported)
- **No external packages** required

## Author

**Stephan Epp** - Senior Software Developer

- GitHub: https://github.com/hjstephan86
- Email: hjstephan86@gmail.com
- Portfolio: https://github.com/hjstephan86/science (220+ research papers)

## Other Projects

- **Pyble**: FastAPI-based Bible Study App: https://github.com/hjstephan86/pyble
- **Subgraph-SAT-Solver**: C++ 17-Implementierung des SAT-Solvers: https://github.com/hjstephan86/subgraph-sat-solver
- **Science**: 220+ academic papers on graph theory, cryptography, embedded systems, etc.: https://github.com/hjstephan86/science

## Quick Links

- Repository: https://github.com/hjstephan86/solrwnds
- License: https://github.com/hjstephan86/solrwnds/blob/main/LICENSE
- Issues: https://github.com/hjstephan86/solrwnds/issues
