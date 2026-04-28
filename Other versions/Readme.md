# Supplier Attack Surface Monitor

A powerful Python-based tool for **continuous monitoring of supplier external attack surface**, infrastructure changes, and cyber risk indicators — including ransomware and dark web leak detection.

Designed to run daily via CRON, this script helps organizations proactively manage supply chain cyber risk by tracking changes in suppliers' exposed infrastructure using **Shodan**, **LeakIX**, and **Ransomware.live**.

---

## Features

- Daily automated scanning of multiple suppliers from a CSV file
- **Shodan integration** (full support for paid API) – ports, banners, technologies, vulnerabilities, hostnames
- **LeakIX integration** – exposed services, misconfigurations, and leaks
- **Ransomware & Dark Web Leak Detection** using Ransomware.live API
- Intelligent **change detection** with severity-based flagging (Critical, High, Medium, Low)
- Historical tracking using SQLite database
- Automatic daily **Markdown reports** with executive summary and prioritized alerts
- Robust logging, error handling, and rate-limit awareness
- Modular and extensible design

---

## Technology Detection

Automatically identifies technologies including:
- Web servers: Apache, Nginx, IIS, Tomcat
- Security appliances: Cisco, Palo Alto, Fortinet, Juniper, Checkpoint
- Operating systems, databases, and management interfaces

---

## Prerequisites

- Python 3.10+
- **Paid Shodan API key** (required)
- Optional free API keys:
  - LeakIX
  - Ransomware.live (recommended – register at https://my.ransomware.live)

---

## Installation

1. Clone or download the project into a directory.

2. Install the required packages:
   ```bash
   pip install -r requirements.txt


## Project Structure

supplier-monitor/
├── supplier_monitor.py          # Main script
├── requirements.txt
├── .env                         # API keys (git ignore this!)
├── config.yaml
├── suppliers.csv
├── data/                        # SQLite database + scan data
├── reports/                     # Daily Markdown reports
└── monitor.log                  # Log file


## Cron Job Setup
0 6 * * * /usr/bin/python3 /full/path/to/supplier_monitor.py >> /full/path/to/monitor.log 2>&1