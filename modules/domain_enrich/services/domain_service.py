import requests
import os
import socket
from dotenv import load_dotenv
from datetime import datetime
from database.db import SessionLocal
from database.models import ScanHistory

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")


def normalize_domain(domain: str) -> str:
    """Supprime http://, https://, www. et le slash final"""
    domain = domain.strip().lower()
    for prefix in ["https://", "http://"]:
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    if domain.startswith("www."):
        domain = domain[4:]
    domain = domain.split("/")[0]  # supprime tout ce qui suit un slash
    return domain


def resolve_ip(domain: str) -> str:
    """Résout l'adresse IP d'un domaine"""
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except socket.gaierror:
        return "N/A"


def calculate_risk(malicious, suspicious, reputation):
    reputation_penalty = abs(reputation) if reputation < 0 else 0
    score = (malicious * 5) + (suspicious * 3) + reputation_penalty

    if score == 0:
        level = "Clean"
    elif score <= 20:
        level = "Low"
    elif score <= 50:
        level = "Medium"
    else:
        level = "High"

    return level, score


def calculate_global_risk(vt_malicious, vt_suspicious, shodan_ports, shodan_vulns):
    vt_component = (vt_malicious * 4) + (vt_suspicious * 2)
    shodan_component = (shodan_ports * 1) + (shodan_vulns * 10)
    global_score = vt_component + shodan_component

    if global_score == 0:
        level = "Clean"
    elif global_score <= 50:
        level = "Low"
    elif global_score <= 150:
        level = "Medium"
    else:
        level = "High"

    if vt_malicious > 0 and shodan_vulns > 0:
        confidence = "Strong"
    elif vt_malicious > 0 or shodan_vulns > 0:
        confidence = "Moderate"
    else:
        confidence = "Weak"

    return global_score, level, confidence


def shodan_domain_enrichment(domain: str):
    url = f"https://api.shodan.io/dns/domain/{domain}"
    params = {"key": SHODAN_API_KEY}
    response = requests.get(url, params=params)

    if response.status_code != 200:
        return {
            "shodan_error": "Not found or API error",
            "shodan_subdomains": [],
            "shodan_subdomains_count": 0,
            "shodan_tags": [],
            "shodan_ports": [],
            "shodan_ports_count": 0,
            "shodan_vulns_count": 0
        }

    data = response.json()
    subdomains = data.get("subdomains", [])
    tags = data.get("tags", [])
    all_ports = []
    all_vulns = 0

    for record in data.get("data", []):
        ports = record.get("ports", [])
        all_ports.extend(ports)
        vulns = record.get("vulns", {})
        all_vulns += len(vulns)

    unique_ports = list(set(all_ports))

    return {
        "shodan_subdomains": subdomains,
        "shodan_subdomains_count": len(subdomains),
        "shodan_tags": tags,
        "shodan_ports": unique_ports,
        "shodan_ports_count": len(unique_ports),
        "shodan_vulns_count": all_vulns
    }


def get_domain_report(domain: str):
    # 1. Normalisation du domaine (gère www., http://, etc.)
    domain = normalize_domain(domain)

    # 2. Résolution IP
    ip_address = resolve_ip(domain)

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        return {"error": "Domain not found or API error"}

    data = response.json()["data"]["attributes"]

    stats = data.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    undetected = stats.get("undetected", 0)

    risk_level, risk_score = calculate_risk(
        malicious,
        suspicious,
        data.get("reputation", 0)
    )

    shodan_data = shodan_domain_enrichment(domain)

    global_score, global_level, confidence = calculate_global_risk(
        malicious,
        suspicious,
        shodan_data.get("shodan_ports_count", 0),
        shodan_data.get("shodan_vulns_count", 0)
    )

    last_analysis_timestamp = data.get("last_analysis_date")
    last_analysis_date = (
        datetime.utcfromtimestamp(last_analysis_timestamp).strftime("%Y-%m-%d")
        if last_analysis_timestamp else "N/A"
    )

    creation_timestamp = data.get("creation_date")
    creation_date = (
        datetime.utcfromtimestamp(creation_timestamp).strftime("%Y-%m-%d")
        if creation_timestamp else "N/A"
    )

    registrar = data.get("registrar", "N/A")
    categories = data.get("categories", {})

    db = SessionLocal()
    new_scan = ScanHistory(
        indicator=domain,
        risk_level=risk_level,
        risk_score=risk_score,
        confidence=confidence,
        source="VirusTotal+Shodan"
    )
    db.add(new_scan)
    db.commit()
    db.close()

    return {
        "domain": domain,
        "ip_address": ip_address,          # NOUVEAU
        "registrar": registrar,
        "creation_date": creation_date,
        # --- SOURCE : VIRUSTOTAL ---
        "virustotal": {
            "reputation_score": data.get("reputation", 0),
            "categories": categories,
            "detection": {
                "malicious": malicious,
                "suspicious": suspicious,
                "undetected": undetected
            },
            "last_analysis_date": last_analysis_date,
            "risk_score": risk_score,
            "risk_level": risk_level
        },
        # --- SOURCE : SHODAN ---
        "shodan": {
            "subdomains": shodan_data.get("shodan_subdomains", []),
            "subdomains_count": shodan_data.get("shodan_subdomains_count", 0),
            "tags": shodan_data.get("shodan_tags", []),
            "open_ports": shodan_data.get("shodan_ports", []),
            "open_ports_count": shodan_data.get("shodan_ports_count", 0),
            "cves_count": shodan_data.get("shodan_vulns_count", 0)
        },
        # --- RISK GLOBAL ---
        "global_risk_score": global_score,
        "global_risk_level": global_level,
        "confidence": confidence
    }