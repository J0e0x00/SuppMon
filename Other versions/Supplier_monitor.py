import os
import json
import logging
import sqlite3
import argparse
from datetime import datetime, date
from pathlib import Path
import pandas as pd
import yaml
from dotenv import load_dotenv
import shodan
import requests
from deepdiff import DeepDiff
from rapidfuzz import fuzz
import jinja2

# Setup
load_dotenv()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[logging.FileHandler("monitor.log"), logging.StreamHandler()])

CONFIG = yaml.safe_load(open("config.yaml")) if Path("config.yaml").exists() else {}
DATA_DIR = Path(CONFIG.get("data_dir", "data"))
DATA_DIR.mkdir(exist_ok=True)
REPORTS_DIR = Path(CONFIG.get("report_dir", "reports"))
REPORTS_DIR.mkdir(exist_ok=True)

SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
LEAKIX_API_KEY = os.getenv("LEAKIX_API_KEY")
RANSOMWARE_API_KEY = os.getenv("RANSOMWARE_LIVE_API_KEY")

shodan_api = shodan.Shodan(SHODAN_API_KEY) if SHODAN_API_KEY else None

def load_suppliers(csv_path=CONFIG.get("suppliers_csv", "suppliers.csv")):
    return pd.read_csv(csv_path).to_dict('records')

def get_today_str():
    return date.today().isoformat()

# ====================== Data Collection ======================

def shodan_lookup(ip_or_host):
    if not shodan_api:
        return {"error": "No Shodan API key"}
    try:
        if ip_or_host.replace('.', '').isdigit():  # rough IP check
            host = shodan_api.host(ip_or_host)
        else:
            # Resolve domain via Shodan or fallback
            results = shodan_api.search(f"hostname:{ip_or_host}")
            if results['matches']:
                host = shodan_api.host(results['matches'][0]['ip_str'])
            else:
                return {"error": "No Shodan data"}
        # Extract tech
        tech = []
        for item in host.get('data', []):
            if 'product' in item or 'http' in item:
                tech.append(item.get('product') or item.get('http', {}).get('server'))
        return {
            "ip": host.get('ip_str'),
            "hostnames": host.get('hostnames', []),
            "ports": sorted(list(set([p['port'] for p in host.get('data', [])]))),
            "org": host.get('org'),
            "asn": host.get('asn'),
            "country": host.get('country_name'),
            "tech": [t for t in tech if t],
            "last_scan": host.get('last_update'),
            "vulns": list(host.get('vulns', {}).keys()) if 'vulns' in host else []
        }
    except Exception as e:
        logging.error(f"Shodan error for {ip_or_host}: {e}")
        return {"error": str(e)}

def leakix_lookup(ip_or_host):
    if not LEAKIX_API_KEY:
        return {"error": "No LeakIX key"}
    try:
        headers = {"api-key": LEAKIX_API_KEY, "Accept": "application/json"}
        url = f"https://leakix.net/host/{ip_or_host}" if ip_or_host.replace('.', '').isdigit() else f"https://leakix.net/domain/{ip_or_host}"
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            return {
                "services": data.get("services", []),
                "leaks": data.get("leaks", []),
                "plugins": [p.get("name") for p in data.get("plugins", [])]
            }
        return {"error": f"HTTP {resp.status_code}"}
    except Exception as e:
        logging.error(f"LeakIX error: {e}")
        return {"error": str(e)}

def check_ransomware_live(supplier_name, domain):
    if not RANSOMWARE_API_KEY:
        return {"error": "No Ransomware.live key"}
    try:
        # Example endpoint - adjust based on actual docs (search victims)
        resp = requests.get(
            f"https://api-pro.ransomware.live/v2/victim/search?q={supplier_name}",
            headers={"Authorization": f"Bearer {RANSOMWARE_API_KEY}"},
            timeout=10
        )
        if resp.status_code == 200:
            results = resp.json()
            # Filter relevant hits
            hits = [v for v in results if fuzz.partial_ratio(supplier_name.lower(), v.get("victim", "").lower()) > 85 or
                    (domain and domain in v.get("victim", ""))]
            return {"hits": hits, "new_victims": len(hits)}
        return {"error": f"HTTP {resp.status_code}"}
    except Exception as e:
        logging.error(f"Ransomware.live error: {e}")
        return {"error": str(e)}

# ====================== Storage & Change Detection ======================

def init_db():
    conn = sqlite3.connect(DATA_DIR / "scans.db")
    conn.execute("""CREATE TABLE IF NOT EXISTS scans (
        date TEXT, supplier_name TEXT, data JSON, PRIMARY KEY(date, supplier_name)
    )""")
    conn.commit()
    return conn

def save_scan(supplier, scan_data, scan_date=None):
    if not scan_date:
        scan_date = get_today_str()
    conn = init_db()
    conn.execute("INSERT OR REPLACE INTO scans VALUES (?, ?, ?)",
                 (scan_date, supplier['supplier_name'], json.dumps(scan_data)))
    conn.commit()

def load_previous_scan(supplier_name, days_ago=1):
    conn = init_db()
    prev_date = (datetime.now().date() - pd.Timedelta(days=days_ago)).isoformat()
    row = conn.execute("SELECT data FROM scans WHERE date=? AND supplier_name=?",
                       (prev_date, supplier_name)).fetchone()
    return json.loads(row[0]) if row else None

def compute_changes(current, previous):
    if not previous:
        return [{"type": "First_Scan", "severity": "Low", "description": "Initial baseline established"}]

    changes = []
    diff = DeepDiff(previous, current, ignore_order=True, verbose_level=2)

    # Port changes
    if 'ports' in current and 'ports' in previous:
        new_ports = set(current['ports']) - set(previous.get('ports', []))
        if new_ports:
            for p in new_ports:
                severity = "Critical" if p in CONFIG.get("high_risk_ports", []) else "High"
                changes.append({"type": "New_Port", "severity": severity,
                                "description": f"New port {p} exposed"})

    # Tech changes
    if 'tech' in current:
        new_tech = set(current['tech']) - set(previous.get('tech', []))
        if new_tech:
            changes.append({"type": "New_Technology", "severity": "Medium",
                            "description": f"New tech detected: {list(new_tech)}"})

    # Ransomware / Dark Web
    if current.get('ransomware_signals', {}).get('new_victims', 0) > 0:
        changes.append({"type": "Ransomware_Leak", "severity": "Critical",
                        "description": "Supplier mentioned on ransomware leak site"})

    return changes

# ====================== Main Scan & Report ======================

def scan_supplier(supplier):
    domain = supplier.get('domain')
    ip = supplier.get('ip')

    shodan_data = shodan_lookup(ip or domain)
    leakix_data = leakix_lookup(ip or domain)
    ransomware_data = check_ransomware_live(supplier['supplier_name'], domain)

    scan_data = {
        "timestamp": datetime.now().isoformat(),
        "supplier": supplier,
        "shodan": shodan_data,
        "leakix": leakix_data,
        "ransomware_signals": ransomware_data,
        "dark_web_leaks": ransomware_data,  # unified for now
        "tech_stack": shodan_data.get("tech", []) + leakix_data.get("plugins", [])
    }

    previous = load_previous_scan(supplier['supplier_name'])
    changes = compute_changes(scan_data, previous)

    scan_data["changes"] = changes
    scan_data["has_critical_changes"] = any(c["severity"] in ["Critical", "High"] for c in changes)

    save_scan(supplier, scan_data)
    return scan_data

def generate_daily_report(scans):
    today = get_today_str()
    template = """
# Supplier Attack Surface Report - {{ today }}

## Executive Summary
- Total suppliers: {{ suppliers|length }}
- Suppliers with critical changes: {{ critical_count }}
- Ransomware / Leak alerts: {{ ransomware_count }}

## Critical Alerts
{% for s in critical %}
**{{ s.supplier.supplier_name }}** ({{ s.supplier.criticality }})
- Changes: {{ s.changes|length }}
- Key issues: {{ s.changes[:3]|map(attribute='description')|join(', ') }}
{% endfor %}

## Full Details
{% for s in scans %}
### {{ s.supplier.supplier_name }}
Tech: {{ s.tech_stack }}
Changes: {{ s.changes }}
{% endfor %}
"""
    env = jinja2.Environment()
    t = env.from_string(template)
    critical = [s for s in scans if s.get("has_critical_changes")]
    report = t.render(
        today=today,
        suppliers=scans,
        critical_count=len(critical),
        ransomware_count=sum(1 for s in scans if s.get("ransomware_signals", {}).get("new_victims", 0) > 0),
        critical=critical,
        scans=scans
    )

    report_path = REPORTS_DIR / f"report_{today}.md"
    report_path.write_text(report)
    logging.info(f"Report generated: {report_path}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    suppliers = load_suppliers()
    results = []

    for supplier in suppliers:
        logging.info(f"Scanning {supplier['supplier_name']}...")
        try:
            data = scan_supplier(supplier)
            results.append(data)
        except Exception as e:
            logging.error(f"Failed to scan {supplier['supplier_name']}: {e}")

    generate_daily_report(results)
    logging.info("Daily supplier monitoring completed.")

if __name__ == "__main__":
    main()