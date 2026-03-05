#!/usr/bin/env python
"""Entry point for CVE Scraper service - Run from project root."""
import sys
from pathlib import Path

# Agregar el servicio al path
service_dir = Path(__file__).parent / "services" / "cve-scraper"
sys.path.insert(0, str(service_dir))

# Importar y ejecutar
from scheduler import main

if __name__ == "__main__":
    main()
