"""
modules/collectors.py
=====================
Data collection functions for each external intelligence source.

Each collector is designed to:
- Be independently callable and testable
- Degrade gracefully on errors
- Respect rate limits via the retry decorator
- Return a consistently structured dict (empty dict on failure)
"""

import logging
import socket
import time
from datetime import datetime, timezone
from functools import wraps
from typing import Optional

import dns.resolver
import requests
import whois

logger = logging.getLogger("supplier_monitor.collectors")

# ─── Retry Decorator ──────────────────────────────────────────────────────────

def retry_with_backoff(max_retries: int = 3, base_delay: float = 1.0, exceptions=(Exception,)):
    """
    Decorator: retry a function with exponential backoff on failure.

    Args:
        max_retries: Maximum number of retry attempts
        base_delay: Initial delay in seconds (doubles each retry)
        exceptions: Tuple of exception types to catch and retry
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            delay = base_delay
            last_exception = None
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    if attempt < max_retries:
                        logger.warning(
                            f"{func.__name__}: attempt {attempt+1} failed ({e}), "
                            f"retrying in {delay:.1f}s"
                        )
                        time.sleep(delay)
                        delay = min(delay * 2, 60)  # Cap at 60s
                    else:
                        logger.error(f"{func.__name__}: all {max_retries+1} attempts failed")
            raise last_exception
        return wrapper
    return decorator


# ─── DNS Resolution ───────────────────────────────────────────────────────────

def resolve_domain_to_ip(domain: str) -> list[str]:
    """
    Resolve a domain to its A record IP addresses.

    Args:
        domain: Domain name (e.g., 'example.com')

    Returns:
        List of IP address strings
    """
    try:
        result = socket.getaddrinfo(domain, None)
        ips = list(dict.fromkeys(r[4][0] for r in result if r[0].name == "AF_INET"))
        return ips
    except socket.gaierror:
        # Fallback to dnspython
        try:
            answers = dns.resolver.resolve(domain, "A")
            return [str(r) for r in answers]
        except Exception as e:
            logger.warning(f"DNS resolution failed for {domain}: {e}")
            return []


# ─── Shodan ───────────────────────────────────────────────────────────────────

RISKY_PORTS = {
    21: "FTP", 23: "Telnet", 25: "SMTP", 445: "SMB", 1433: "MSSQL",
    1521: "Oracle", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    9200: "Elasticsearch", 27017: "MongoDB", 11211: "Memcached",
    2375: "Docker", 2376: "Docker-TLS", 4848: "GlassFish",
    8888: "Jupyter", 9090: "Prometheus", 9000: "Portainer",
}

TECH_FINGERPRINTS = {
    "Apache": ["Apache", "httpd"],
    "Nginx": ["nginx"],
    "IIS": ["IIS", "Microsoft-IIS"],
    "Tomcat": ["Tomcat", "Apache-Coyote"],
    "Cisco": ["Cisco", "IOS"],
    "Palo Alto": ["PAN-OS", "Palo Alto"],
    "Fortinet": ["FortiGate", "Fortinet", "FortiOS"],
    "Juniper": ["Juniper", "JunOS", "JUNOS"],
    "Checkpoint": ["Check Point", "FireWall-1"],
    "OpenSSH": ["OpenSSH"],
    "Windows": ["Windows", "Microsoft"],
    "Linux": ["Linux", "Ubuntu", "Debian", "CentOS", "Red Hat"],
    "Elasticsearch": ["Elastic", "elasticsearch"],
    "Redis": ["Redis"],
    "MongoDB": ["MongoDB"],
    "MySQL": ["MySQL"],
    "PostgreSQL": ["PostgreSQL"],
    "RDP": ["Remote Desktop Protocol", "MSTSC"],
    "VPN": ["OpenVPN", "WireGuard", "Cisco AnyConnect", "FortiVPN"],
    "Grafana": ["Grafana"],
    "Kubernetes": ["kubernetes", "k8s"],
    "Prometheus": ["Prometheus"],
}


def _extract_tech_stack(banners: list[str]) -> list[str]:
    """Parse banners to identify known technologies."""
    found = []
    combined = " ".join(banners).lower()
    for tech, keywords in TECH_FINGERPRINTS.items():
        if any(kw.lower() in combined for kw in keywords):
            found.append(tech)
    return list(dict.fromkeys(found))


@retry_with_backoff(max_retries=3, base_delay=2.0)
def collect_shodan_data(ip: str, domain: str, api_key: str) -> dict:
    """
    Collect host intelligence from Shodan.

    Performs host lookup and extracts: ports, banners, technologies,
    vulnerabilities, organization, ASN, geolocation.

    Args:
        ip: Primary IP address to look up
        domain: Domain name (for context)
        api_key: Shodan API key

    Returns:
        Dict with structured Shodan data
    """
    try:
        import shodan  # Import here so non-Shodan users don't need the library
    except ImportError:
        logger.error("shodan library not installed: pip install shodan")
        return {"error": "shodan library not installed"}

    api = shodan.Shodan(api_key)

    try:
        host = api.host(ip)
    except shodan.APIError as e:
        if "No information available" in str(e):
            logger.info(f"Shodan: no data for {ip}")
            return {"ip": ip, "ports": [], "info": "No Shodan data available"}
        raise

    ports = [item["port"] for item in host.get("data", [])]
    banners = []
    services = []
    vulns_raw = host.get("vulns", {})

    for item in host.get("data", []):
        banner = item.get("data", "").strip()
        if banner:
            banners.append(banner[:500])  # Truncate long banners

        service = {
            "port": item.get("port"),
            "transport": item.get("transport", "tcp"),
            "product": item.get("product", ""),
            "version": item.get("version", ""),
            "cpe": item.get("cpe", []),
            "banner_snippet": banner[:200] if banner else "",
            "timestamp": item.get("timestamp", ""),
        }
        # Extract HTTP headers if present
        http = item.get("http", {})
        if http:
            service["http"] = {
                "server": http.get("server", ""),
                "title": http.get("title", ""),
                "status": http.get("status"),
                "headers": dict(list(http.get("headers", {}).items())[:10]),
            }
        services.append(service)

    # Extract vulnerabilities
    vulns = []
    for cve_id, vuln_info in vulns_raw.items():
        vulns.append({
            "cve": cve_id,
            "cvss": vuln_info.get("cvss", 0),
            "summary": vuln_info.get("summary", "")[:300],
        })
    # Sort by CVSS score descending
    vulns.sort(key=lambda v: v.get("cvss", 0), reverse=True)

    risky = [{"port": p, "service": RISKY_PORTS[p]} for p in ports if p in RISKY_PORTS]

    result = {
        "ip": ip,
        "hostnames": host.get("hostnames", []),
        "domains": host.get("domains", []),
        "ports": ports,
        "services": services,
        "risky_services": risky,
        "tech_stack": _extract_tech_stack(banners),
        "vulns": vulns,
        "vuln_count": len(vulns),
        "critical_vulns": [v for v in vulns if v.get("cvss", 0) >= 9.0],
        "org": host.get("org", ""),
        "isp": host.get("isp", ""),
        "asn": host.get("asn", ""),
        "country": host.get("country_name", ""),
        "city": host.get("city", ""),
        "last_update": host.get("last_update", ""),
        "tags": host.get("tags", []),
    }

    logger.debug(
        f"Shodan [{ip}]: {len(ports)} ports, {len(vulns)} vulns, "
        f"tech: {result['tech_stack']}"
    )
    return result


# ─── LeakIX ───────────────────────────────────────────────────────────────────

LEAKIX_BASE = "https://leakix.net"


@retry_with_backoff(max_retries=2, base_delay=3.0)
def collect_leakix_data(domain: str, ip: Optional[str], api_key: str) -> dict:
    """
    Query LeakIX for exposed services and leaks/misconfigurations.

    LeakIX categorises findings as 'services' (informational) and
    'leaks' (actionable misconfigurations/exposures).

    Args:
        domain: Domain to query
        ip: Optional IP address
        api_key: LeakIX API key

    Returns:
        Dict with services, leaks, and plugin detections
    """
    headers = {
        "api-key": api_key,
        "Accept": "application/json",
    }

    all_services = []
    all_leaks = []
    plugins_seen = set()

    # Query by domain
    for query_type, query_value in [("domain", domain), ("host", ip)]:
        if not query_value:
            continue
        try:
            # Events endpoint (services)
            resp = requests.get(
                f"{LEAKIX_BASE}/host/{query_value}",
                headers=headers,
                timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json()
                for event in data.get("Events", []) or []:
                    plugin = event.get("plugin", "")
                    severity = event.get("severity", "info")
                    service_entry = {
                        "host": event.get("host", ""),
                        "port": event.get("port", 0),
                        "protocol": event.get("protocol", ""),
                        "plugin": plugin,
                        "severity": severity,
                        "summary": event.get("summary", "")[:300],
                        "time": event.get("time", ""),
                    }

                    if severity in ("warning", "critical", "high"):
                        all_leaks.append(service_entry)
                    else:
                        all_services.append(service_entry)

                    if plugin:
                        plugins_seen.add(plugin)
            elif resp.status_code == 404:
                logger.info(f"LeakIX: no data for {query_value}")
            elif resp.status_code == 429:
                logger.warning("LeakIX: rate limited")
                time.sleep(10)
            else:
                logger.warning(f"LeakIX: HTTP {resp.status_code} for {query_value}")

        except requests.RequestException as e:
            logger.warning(f"LeakIX request failed for {query_value}: {e}")

        time.sleep(1)  # Be polite

    return {
        "services": all_services[:50],
        "leaks": all_leaks[:50],
        "plugins": list(plugins_seen),
        "leak_count": len(all_leaks),
        "service_count": len(all_services),
    }


# ─── VirusTotal ───────────────────────────────────────────────────────────────

VT_BASE = "https://www.virustotal.com/api/v3"


@retry_with_backoff(max_retries=2, base_delay=15.0)
def _vt_get(endpoint: str, api_key: str) -> dict:
    """Make an authenticated VirusTotal API request."""
    headers = {"x-apikey": api_key}
    resp = requests.get(f"{VT_BASE}/{endpoint}", headers=headers, timeout=20)

    if resp.status_code == 429:
        logger.warning("VirusTotal: rate limited — waiting 60s")
        time.sleep(60)
        resp = requests.get(f"{VT_BASE}/{endpoint}", headers=headers, timeout=20)

    resp.raise_for_status()
    return resp.json()


def collect_virustotal_data(domain: str, ip: Optional[str], api_key: str) -> dict:
    """
    Check VirusTotal for domain/IP reputation and malicious detections.

    Args:
        domain: Domain to check
        ip: Optional IP address
        api_key: VirusTotal API key

    Returns:
        Dict with reputation stats, categories, and recent detections
    """
    result = {
        "domain": domain,
        "malicious_count": 0,
        "suspicious_count": 0,
        "harmless_count": 0,
        "categories": [],
        "last_analysis_date": "",
        "reputation": 0,
        "ip_data": {},
        "recent_urls": [],
    }

    # Domain lookup
    try:
        domain_data = _vt_get(f"domains/{domain}", api_key)
        attrs = domain_data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        result.update({
            "malicious_count": stats.get("malicious", 0),
            "suspicious_count": stats.get("suspicious", 0),
            "harmless_count": stats.get("harmless", 0),
            "categories": list(attrs.get("categories", {}).values()),
            "last_analysis_date": attrs.get("last_analysis_date", ""),
            "reputation": attrs.get("reputation", 0),
            "registrar": attrs.get("registrar", ""),
            "creation_date": attrs.get("creation_date", ""),
        })
    except Exception as e:
        logger.warning(f"VirusTotal domain lookup failed ({domain}): {e}")

    time.sleep(15)  # VT free tier: ~4 req/min

    # IP lookup
    if ip:
        try:
            ip_data = _vt_get(f"ip_addresses/{ip}", api_key)
            ip_attrs = ip_data.get("data", {}).get("attributes", {})
            ip_stats = ip_attrs.get("last_analysis_stats", {})
            result["ip_data"] = {
                "ip": ip,
                "malicious": ip_stats.get("malicious", 0),
                "asn": ip_attrs.get("asn", ""),
                "country": ip_attrs.get("country", ""),
                "network": ip_attrs.get("network", ""),
                "reputation": ip_attrs.get("reputation", 0),
            }
        except Exception as e:
            logger.warning(f"VirusTotal IP lookup failed ({ip}): {e}")

        time.sleep(15)

    return result


# ─── AbuseIPDB ────────────────────────────────────────────────────────────────

@retry_with_backoff(max_retries=2, base_delay=5.0)
def collect_abuseipdb_data(ip: str, api_key: str) -> dict:
    """
    Check AbuseIPDB for abuse reports and confidence score.

    Args:
        ip: IP address to check
        api_key: AbuseIPDB API key

    Returns:
        Dict with abuse confidence score, report count, and categories
    """
    resp = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": api_key, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": False},
        timeout=15,
    )

    if resp.status_code == 429:
        logger.warning("AbuseIPDB: rate limited")
        return {"ip": ip, "error": "rate_limited"}

    resp.raise_for_status()
    data = resp.json().get("data", {})

    return {
        "ip": ip,
        "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
        "total_reports": data.get("totalReports", 0),
        "num_distinct_users": data.get("numDistinctUsers", 0),
        "last_reported_at": data.get("lastReportedAt", ""),
        "isp": data.get("isp", ""),
        "country": data.get("countryCode", ""),
        "usage_type": data.get("usageType", ""),
        "is_tor": data.get("isTor", False),
    }


# ─── WHOIS ────────────────────────────────────────────────────────────────────

def collect_whois_data(domain: str) -> dict:
    """
    Collect WHOIS registration data for the domain.

    Tracks expiration dates (risk if expiring soon), registrar,
    and creation date for age-based risk assessment.

    Args:
        domain: Domain name

    Returns:
        Dict with registration details
    """
    try:
        w = whois.whois(domain)

        def safe_date(d):
            """Normalize date fields which can be list or datetime."""
            if isinstance(d, list):
                d = d[0]
            if hasattr(d, "isoformat"):
                return d.isoformat()
            return str(d) if d else ""

        expiry = safe_date(w.expiration_date)

        # Days until expiration
        days_until_expiry = None
        exp_date = w.expiration_date
        if isinstance(exp_date, list):
            exp_date = exp_date[0]
        if exp_date and hasattr(exp_date, "date"):
            days_until_expiry = (exp_date.date() - datetime.now().date()).days

        return {
            "registrar": w.registrar or "",
            "creation_date": safe_date(w.creation_date),
            "expiration_date": expiry,
            "days_until_expiry": days_until_expiry,
            "name_servers": list(w.name_servers or []),
            "status": w.status if isinstance(w.status, list) else [w.status or ""],
            "registrant_country": getattr(w, "country", "") or "",
        }
    except Exception as e:
        logger.warning(f"WHOIS failed for {domain}: {e}")
        return {"error": str(e)}


# ─── Certificate Transparency (crt.sh) ───────────────────────────────────────

@retry_with_backoff(max_retries=2, base_delay=5.0)
def collect_crtsh_data(domain: str) -> dict:
    """
    Query crt.sh for SSL certificates issued for the domain.

    Monitors for new subdomains discovered via CT logs,
    suspicious issuers, and recently issued certificates.

    Args:
        domain: Domain name (will search *.domain and domain)

    Returns:
        Dict with certificates and discovered subdomains
    """
    resp = requests.get(
        "https://crt.sh/",
        params={"q": f"%.{domain}", "output": "json"},
        timeout=30,
        headers={"Accept": "application/json"},
    )
    resp.raise_for_status()
    data = resp.json()

    certs = []
    subdomains = set()

    for entry in data[:200]:  # Limit to recent 200
        name = entry.get("name_value", "").lower()
        # Handle wildcard and multi-name certs
        names = [n.strip() for n in name.split("\n")]
        for n in names:
            n_clean = n.lstrip("*.")
            if domain in n_clean:
                subdomains.add(n_clean)

        certs.append({
            "id": entry.get("id"),
            "issuer": entry.get("issuer_name", ""),
            "common_name": entry.get("common_name", ""),
            "name_value": name[:200],
            "not_before": entry.get("not_before", ""),
            "not_after": entry.get("not_after", ""),
            "entry_timestamp": entry.get("entry_timestamp", ""),
        })

    # Sort by most recent
    certs.sort(key=lambda c: c.get("entry_timestamp", ""), reverse=True)

    return {
        "certificates": certs[:50],
        "total_certs_found": len(data),
        "discovered_subdomains": sorted(subdomains),
        "subdomain_count": len(subdomains),
    }


# ─── DNS Records ──────────────────────────────────────────────────────────────

def collect_dns_data(domain: str) -> dict:
    """
    Collect DNS records (A, AAAA, MX, TXT, NS, CNAME, SOA).

    Tracks MX records (email infrastructure), TXT for SPF/DMARC/DKIM,
    and NS for nameserver changes.

    Args:
        domain: Domain name

    Returns:
        Dict with records grouped by type
    """
    record_types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]
    records = {}
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 10

    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype)
            records[rtype] = [str(r) for r in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
            records[rtype] = []
        except Exception as e:
            logger.debug(f"DNS {rtype} lookup failed for {domain}: {e}")
            records[rtype] = []

    # Parse SPF/DMARC from TXT
    spf_record = next((r for r in records.get("TXT", []) if "v=spf1" in r.lower()), "")
    dmarc_records = []
    try:
        dmarc_answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
        dmarc_records = [str(r) for r in dmarc_answers]
    except Exception:
        pass

    return {
        "records": records,
        "spf_configured": bool(spf_record),
        "spf_record": spf_record,
        "dmarc_configured": bool(dmarc_records),
        "dmarc_records": dmarc_records,
        "a_records": records.get("A", []),
        "mx_records": records.get("MX", []),
        "ns_records": records.get("NS", []),
    }


# ─── Ransomware & Breach Monitoring ──────────────────────────────────────────

RANSOMWATCH_FEED = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json"
URLHAUS_API = "https://urlhaus-api.abuse.ch/v1"


def collect_ransomware_mentions(
    supplier_name: str,
    domain: str,
    extra_keywords: list[str],
    config: dict,
) -> dict:
    """
    Check public ransomware tracking feeds for supplier mentions.

    Sources:
    - ransomwatch (GitHub): tracks ransomware group leak site posts
    - URLhaus: checks domain against known malicious URL database

    Args:
        supplier_name: Company name to search for
        domain: Domain to search for
        extra_keywords: Additional keywords from config
        config: Full config dict

    Returns:
        Dict with mentions, threat groups, and indicators
    """
    result = {
        "mention_count": 0,
        "mentions": [],
        "threat_groups": [],
        "urlhaus_hits": [],
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }

    # Build search keywords (company name variations + domain)
    name_clean = supplier_name.lower().strip()
    domain_clean = domain.lower().strip()
    search_terms = set([
        name_clean,
        name_clean.replace(" ", ""),
        name_clean.replace(" ", "-"),
        domain_clean,
        domain_clean.split(".")[0],  # e.g., "example" from "example.com"
    ] + [k.lower() for k in (extra_keywords or [])])

    # ── ransomwatch feed ─────────────────────────────────────────────────────
    try:
        resp = requests.get(RANSOMWATCH_FEED, timeout=30)
        if resp.status_code == 200:
            posts = resp.json()
            for post in posts:
                post_text = (
                    post.get("post_title", "") + " " +
                    post.get("description", "")
                ).lower()

                for term in search_terms:
                    if term and len(term) >= 4 and term in post_text:
                        mention = {
                            "source": "ransomwatch",
                            "group": post.get("group_name", "unknown"),
                            "title": post.get("post_title", "")[:200],
                            "date": post.get("discovered", ""),
                            "matched_term": term,
                            "url": post.get("post_url", ""),
                        }
                        result["mentions"].append(mention)
                        result["threat_groups"].append(post.get("group_name", "unknown"))
                        break  # One mention per post
        else:
            logger.warning(f"ransomwatch feed: HTTP {resp.status_code}")
    except Exception as e:
        logger.warning(f"ransomwatch feed failed: {e}")

    # ── URLhaus domain check ─────────────────────────────────────────────────
    try:
        resp = requests.post(
            f"{URLHAUS_API}/host/",
            data={"host": domain_clean},
            timeout=15,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("query_status") == "is_host":
                urls = data.get("urls", []) or []
                result["urlhaus_hits"] = [
                    {
                        "url": u.get("url", "")[:200],
                        "threat": u.get("threat", ""),
                        "date_added": u.get("date_added", ""),
                        "tags": u.get("tags", []),
                    }
                    for u in urls[:10]
                ]
    except Exception as e:
        logger.warning(f"URLhaus check failed for {domain}: {e}")

    result["mention_count"] = len(result["mentions"])
    result["threat_groups"] = list(dict.fromkeys(result["threat_groups"]))
    return result
