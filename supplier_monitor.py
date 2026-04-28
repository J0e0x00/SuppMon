#!/usr/bin/env python3
"""
Supplier Attack Surface Monitor
================================
Continuously monitors the external attack surface and cyber risk of suppliers/vendors.

Usage:
    python supplier_monitor.py                    # Run full scan
    python supplier_monitor.py --supplier acme    # Scan single supplier
    python supplier_monitor.py --date 2024-01-15  # Use specific date label
    python supplier_monitor.py --force            # Force rescan (ignore cache)
    python supplier_monitor.py --report-only      # Generate report from latest data

Setup:
    pip install -r requirements.txt
    cp .env.example .env && nano .env  # Add your API keys
    mkdir -p data logs

CRON (daily at 06:00):
    0 6 * * * /path/to/venv/bin/python /path/to/supplier_monitor.py >> /path/to/logs/cron.log 2>&1
"""

import argparse
import json
import logging
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, date
from logging.handlers import RotatingFileHandler
from pathlib import Path

import pandas as pd
from dotenv import load_dotenv

# Local modules
from modules.collectors import (
    collect_shodan_data,
    collect_leakix_data,
    collect_virustotal_data,
    collect_abuseipdb_data,
    collect_whois_data,
    collect_crtsh_data,
    collect_dns_data,
    collect_ransomware_mentions,
    resolve_domain_to_ip,
)
from modules.analysis import detect_changes, calculate_risk_score, flag_issues
from modules.reporting import generate_html_report, generate_markdown_report
from modules.storage import (
    load_previous_scan,
    save_scan_results,
    save_latest_snapshot,
    load_config,
)
from modules.notifications import send_notifications

# ─── Logging Setup ────────────────────────────────────────────────────────────

def setup_logging(log_dir: str = "logs") -> logging.Logger:
    """Configure rotating file + console logging."""
    Path(log_dir).mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("supplier_monitor")
    logger.setLevel(logging.DEBUG)

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Rotating file handler: 10MB per file, keep 7 backups
    fh = RotatingFileHandler(
        os.path.join(log_dir, "supplier_monitor.log"),
        maxBytes=10 * 1024 * 1024,
        backupCount=7,
    )
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)

    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger


# ─── Supplier Loading ──────────────────────────────────────────────────────────

def load_suppliers(csv_path: str, filter_name: str = None) -> list[dict]:
    """
    Load supplier list from CSV.

    Required columns: supplier_name, domain
    Optional columns: ip, criticality, notes

    Args:
        csv_path: Path to suppliers.csv
        filter_name: If set, only return suppliers matching this name (case-insensitive)

    Returns:
        List of supplier dicts
    """
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Suppliers CSV not found: {csv_path}")

    df = pd.read_csv(csv_path)

    # Validate required columns
    required = {"supplier_name", "domain"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"suppliers.csv missing required columns: {missing}")

    # Normalize
    df["supplier_name"] = df["supplier_name"].str.strip()
    df["domain"] = df["domain"].str.strip().str.lower()
    df["ip"] = df.get("ip", pd.Series(dtype=str)).fillna("").str.strip()
    df["criticality"] = df.get("criticality", pd.Series(dtype=str)).fillna("Medium").str.strip()
    df["notes"] = df.get("notes", pd.Series(dtype=str)).fillna("").str.strip()

    suppliers = df.to_dict(orient="records")

    if filter_name:
        suppliers = [s for s in suppliers if filter_name.lower() in s["supplier_name"].lower()]
        if not suppliers:
            raise ValueError(f"No suppliers found matching: {filter_name}")

    return suppliers


# ─── Single Supplier Scan ─────────────────────────────────────────────────────

def scan_supplier(supplier: dict, config: dict, force: bool = False) -> dict:
    """
    Run all data collection for a single supplier.

    Collects data from: Shodan, LeakIX, VirusTotal, AbuseIPDB,
    WHOIS, crt.sh, DNS, ransomware feeds.

    Args:
        supplier: Dict with supplier_name, domain, ip, criticality, notes
        config: Configuration dict (API keys, settings)
        force: If True, skip cache checks

    Returns:
        Dict with all collected data and metadata
    """
    logger = logging.getLogger("supplier_monitor")
    name = supplier["supplier_name"]
    domain = supplier["domain"]
    today = date.today().isoformat()

    logger.info(f"[{name}] Starting scan for domain: {domain}")

    result = {
        "supplier_name": name,
        "domain": domain,
        "criticality": supplier.get("criticality", "Medium"),
        "notes": supplier.get("notes", ""),
        "scan_timestamp": datetime.utcnow().isoformat() + "Z",
        "scan_date": today,
        "ip_addresses": [],
        "shodan_data": {},
        "leakix_data": {},
        "virustotal_data": {},
        "abuseipdb_data": {},
        "whois_data": {},
        "crtsh_data": {},
        "dns_data": {},
        "ransomware_data": {},
        "flags": [],
        "risk_score": 0,
        "errors": [],
    }

    # ── Step 1: Resolve IPs ───────────────────────────────────────────────────
    known_ip = supplier.get("ip", "").strip()
    resolved_ips = []

    try:
        resolved_ips = resolve_domain_to_ip(domain)
        logger.info(f"[{name}] Resolved {domain} → {resolved_ips}")
    except Exception as e:
        logger.warning(f"[{name}] DNS resolution failed: {e}")
        result["errors"].append({"source": "dns_resolve", "error": str(e)})

    # Merge known IP with resolved IPs, deduplicate
    all_ips = list(dict.fromkeys(
        ([known_ip] if known_ip else []) + resolved_ips
    ))
    result["ip_addresses"] = all_ips
    primary_ip = all_ips[0] if all_ips else None

    # ── Step 2: Shodan ────────────────────────────────────────────────────────
    if config.get("shodan_api_key") and primary_ip:
        try:
            result["shodan_data"] = collect_shodan_data(
                primary_ip, domain, config["shodan_api_key"]
            )
            logger.info(f"[{name}] Shodan: {len(result['shodan_data'].get('ports', []))} ports found")
        except Exception as e:
            logger.error(f"[{name}] Shodan failed: {e}")
            result["errors"].append({"source": "shodan", "error": str(e)})

    # ── Step 3: LeakIX ───────────────────────────────────────────────────────
    if config.get("leakix_api_key"):
        try:
            result["leakix_data"] = collect_leakix_data(
                domain, primary_ip, config["leakix_api_key"]
            )
            leak_count = len(result["leakix_data"].get("leaks", []))
            logger.info(f"[{name}] LeakIX: {leak_count} leaks/issues found")
        except Exception as e:
            logger.error(f"[{name}] LeakIX failed: {e}")
            result["errors"].append({"source": "leakix", "error": str(e)})

    # ── Step 4: VirusTotal ───────────────────────────────────────────────────
    if config.get("virustotal_api_key"):
        try:
            result["virustotal_data"] = collect_virustotal_data(
                domain, primary_ip, config["virustotal_api_key"]
            )
            vt = result["virustotal_data"]
            logger.info(
                f"[{name}] VirusTotal: {vt.get('malicious_count', 0)} malicious detections"
            )
        except Exception as e:
            logger.error(f"[{name}] VirusTotal failed: {e}")
            result["errors"].append({"source": "virustotal", "error": str(e)})

    # ── Step 5: AbuseIPDB ────────────────────────────────────────────────────
    if config.get("abuseipdb_api_key") and primary_ip:
        try:
            result["abuseipdb_data"] = collect_abuseipdb_data(
                primary_ip, config["abuseipdb_api_key"]
            )
            abuse_score = result["abuseipdb_data"].get("abuse_confidence_score", 0)
            logger.info(f"[{name}] AbuseIPDB: confidence score {abuse_score}")
        except Exception as e:
            logger.error(f"[{name}] AbuseIPDB failed: {e}")
            result["errors"].append({"source": "abuseipdb", "error": str(e)})

    # ── Step 6: WHOIS ─────────────────────────────────────────────────────────
    try:
        result["whois_data"] = collect_whois_data(domain)
        expiry = result["whois_data"].get("expiration_date", "unknown")
        logger.info(f"[{name}] WHOIS: domain expires {expiry}")
    except Exception as e:
        logger.warning(f"[{name}] WHOIS failed: {e}")
        result["errors"].append({"source": "whois", "error": str(e)})

    # ── Step 7: Certificate Transparency (crt.sh) ────────────────────────────
    try:
        result["crtsh_data"] = collect_crtsh_data(domain)
        cert_count = len(result["crtsh_data"].get("certificates", []))
        logger.info(f"[{name}] crt.sh: {cert_count} certificates found")
    except Exception as e:
        logger.warning(f"[{name}] crt.sh failed: {e}")
        result["errors"].append({"source": "crtsh", "error": str(e)})

    # ── Step 8: DNS Records ───────────────────────────────────────────────────
    try:
        result["dns_data"] = collect_dns_data(domain)
        logger.info(f"[{name}] DNS: records collected")
    except Exception as e:
        logger.warning(f"[{name}] DNS collection failed: {e}")
        result["errors"].append({"source": "dns", "error": str(e)})

    # ── Step 9: Ransomware / Breach Mentions ─────────────────────────────────
    keywords = config.get("ransomware_keywords", [])
    try:
        result["ransomware_data"] = collect_ransomware_mentions(
            name, domain, keywords, config
        )
        mentions = result["ransomware_data"].get("mention_count", 0)
        logger.info(f"[{name}] Ransomware feeds: {mentions} mentions found")
    except Exception as e:
        logger.warning(f"[{name}] Ransomware check failed: {e}")
        result["errors"].append({"source": "ransomware", "error": str(e)})

    # ── Step 10: Flag Issues ──────────────────────────────────────────────────
    result["flags"] = flag_issues(result, config)

    # ── Step 11: Risk Score ───────────────────────────────────────────────────
    result["risk_score"] = calculate_risk_score(result)
    logger.info(f"[{name}] Risk score: {result['risk_score']}/100")

    return result


# ─── Main Orchestration ───────────────────────────────────────────────────────

def run_scan(args: argparse.Namespace, config: dict, logger: logging.Logger) -> list[dict]:
    """
    Orchestrate the full scan across all suppliers.

    Args:
        args: CLI arguments
        config: Loaded configuration
        logger: Logger instance

    Returns:
        List of scan results for all suppliers
    """
    suppliers_csv = config.get("suppliers_csv", "suppliers.csv")
    suppliers = load_suppliers(suppliers_csv, filter_name=args.supplier)
    logger.info(f"Loaded {len(suppliers)} suppliers from {suppliers_csv}")

    # Load previous scan for change detection
    previous_scan = load_previous_scan(config.get("data_dir", "data"))
    previous_by_name = {s["supplier_name"]: s for s in (previous_scan or [])}

    results = []
    max_workers = config.get("max_parallel_workers", 3)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_supplier = {
            executor.submit(scan_supplier, supplier, config, args.force): supplier
            for supplier in suppliers
        }

        for future in as_completed(future_to_supplier):
            supplier = future_to_supplier[future]
            name = supplier["supplier_name"]
            try:
                result = future.result()

                # Change detection
                if name in previous_by_name:
                    prev = previous_by_name[name]
                    changes = detect_changes(prev, result)
                    result["changes_from_previous"] = changes
                    logger.info(
                        f"[{name}] {len(changes)} changes detected vs previous scan"
                    )
                else:
                    result["changes_from_previous"] = []
                    logger.info(f"[{name}] No previous scan found — first run baseline")

                results.append(result)

            except Exception as e:
                logger.error(f"[{name}] Scan failed entirely: {e}", exc_info=True)
                results.append({
                    "supplier_name": name,
                    "domain": supplier.get("domain", ""),
                    "scan_timestamp": datetime.utcnow().isoformat() + "Z",
                    "error": str(e),
                    "risk_score": -1,
                    "flags": [],
                })

            # Brief pause between suppliers to respect global rate limits
            time.sleep(config.get("inter_supplier_delay_seconds", 2))

    return results


# ─── Entry Point ──────────────────────────────────────────────────────────────

def main():
    load_dotenv()

    parser = argparse.ArgumentParser(
        description="Supplier Attack Surface Monitor — Daily cyber risk scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--supplier", help="Scan only this supplier (partial name match)")
    parser.add_argument("--date", help="Override scan date label (YYYY-MM-DD)")
    parser.add_argument("--force", action="store_true", help="Force rescan, ignore cache")
    parser.add_argument("--report-only", action="store_true", help="Generate report from existing data")
    parser.add_argument("--config", default="config.yaml", help="Path to config file")
    parser.add_argument("--output-format", choices=["html", "markdown", "both"], default="both")
    args = parser.parse_args()

    # Override date label if provided
    if args.date:
        try:
            datetime.strptime(args.date, "%Y-%m-%d")
        except ValueError:
            print(f"ERROR: --date must be YYYY-MM-DD format, got: {args.date}")
            sys.exit(1)

    config = load_config(args.config)
    logger = setup_logging(config.get("log_dir", "logs"))

    logger.info("=" * 60)
    logger.info("Supplier Attack Surface Monitor — Starting")
    logger.info(f"Scan date: {args.date or date.today().isoformat()}")
    logger.info("=" * 60)

    data_dir = config.get("data_dir", "data")
    Path(data_dir).mkdir(parents=True, exist_ok=True)

    if args.report_only:
        logger.info("Report-only mode: loading latest scan data")
        results = load_previous_scan(data_dir) or []
    else:
        results = run_scan(args, config, logger)

        # Save timestamped and latest snapshots
        scan_date = args.date or date.today().isoformat()
        save_scan_results(results, data_dir, scan_date)
        save_latest_snapshot(results, data_dir)
        logger.info(f"Saved {len(results)} supplier records to {data_dir}/")

    # Generate reports
    if args.output_format in ("html", "both"):
        html_path = generate_html_report(results, data_dir, config)
        logger.info(f"HTML report: {html_path}")

    if args.output_format in ("markdown", "both"):
        md_path = generate_markdown_report(results, data_dir, config)
        logger.info(f"Markdown report: {md_path}")

    # Send notifications for high/critical findings
    high_risk = [r for r in results if any(
        f.get("severity") in ("High", "Critical") for f in r.get("flags", [])
    )]
    if high_risk:
        logger.warning(f"{len(high_risk)} suppliers have High/Critical findings")
        send_notifications(high_risk, results, config, logger)

    # Summary
    logger.info("─" * 60)
    logger.info(f"Scan complete: {len(results)} suppliers processed")
    avg_score = sum(r.get("risk_score", 0) for r in results if r.get("risk_score", -1) >= 0)
    if results:
        avg_score /= len(results)
    logger.info(f"Average risk score: {avg_score:.1f}/100")
    critical = [r for r in results if r.get("risk_score", 0) >= 75]
    logger.info(f"High-risk suppliers (score ≥75): {len(critical)}")
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
