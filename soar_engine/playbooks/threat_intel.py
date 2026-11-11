import requests
import logging
from typing import Optional
from models import ThreatIntel
from config import config

logger = logging.getLogger("soar.playbook.threat_intel")

# Known mock threat intelligence database for simulation & test IOCs
KNOWN_THREAT_IOCS = {
    "198.51.100.44": {"country": "Netherlands", "code": "NL", "isp": "Bulletproof Hosting AS49981", "score": 92, "tags": ["SQL-Injection", "OWASP-Top10", "Scanner"]},
    "203.0.113.88": {"country": "China", "code": "CN", "isp": "ChinaNet Backbone AS4134", "score": 89, "tags": ["SSH-Bruteforce", "Credential-Stuffing"]},
    "195.123.245.12": {"country": "Russia", "code": "RU", "isp": "Stark Industries Solutions AS44477", "score": 98, "tags": ["CobaltStrike-C2", "APT29", "Botnet"]},
    "185.220.101.5": {"country": "Germany", "code": "DE", "isp": "Tor Exit Relay AS205100", "score": 84, "tags": ["Tor-Exit-Node", "Port-Scanner", "Masscan"]},
    "91.240.118.172": {"country": "Romania", "code": "RO", "isp": "M247 Europe SRL AS9009", "score": 95, "tags": ["Data-Exfiltration", "RSA-Key-Leak"]},
    "45.154.255.89": {"country": "Bulgaria", "code": "BG", "isp": "Neterra Ltd AS34224", "score": 87, "tags": ["DNS-Tunneling", "Covert-Channel"]},
    "172.16.55.101": {"country": "Internal / Endpoint", "code": "INT", "isp": "Corporate Workstation VLAN-55", "score": 78, "tags": ["Canary-Token-Tripped", "Insider-Trap"]},
    "172.28.0.100": {"country": "United States", "code": "US", "isp": "TOR Exit Node", "score": 95, "tags": ["Scanner", "Brute-Force"]},
    "172.28.0.105": {"country": "Brazil", "code": "BR", "isp": "Botnet Proxy Pool", "score": 85, "tags": ["HTTP-Bruteforce", "Credential-Stuffing"]},
    "172.28.0.110": {"country": "Singapore", "code": "SG", "isp": "Cloud VPS Dropzone", "score": 92, "tags": ["Exfiltration", "Policy-Violation"]},
    "172.28.0.200": {"country": "Russia", "code": "RU", "isp": "Bulletproof Host", "score": 88, "tags": ["C2-Server", "Botnet"]},
    "192.168.1.150": {"country": "China", "code": "CN", "isp": "Known APT Subnet", "score": 90, "tags": ["Exploit-Scanner", "SQL-Injection"]},
    "192.168.1.99": {"country": "Internal / Trap", "code": "INT", "isp": "Honeypot Lure Segment", "score": 82, "tags": ["Canary-Tripped", "Deception"]},
    "198.51.100.55": {"country": "France", "code": "FR", "isp": "OVH Proxy Node AS16276", "score": 72, "tags": ["XSS-Exploit", "Web-Scanner"]},
    "198.51.100.42": {"country": "United Kingdom", "code": "GB", "isp": "Cloud Recon VPS", "score": 68, "tags": ["Port-Sweep", "Recon"]},
    "192.0.2.140": {"country": "Ukraine", "code": "UA", "isp": "Malicious Proxy Relay", "score": 91, "tags": ["SQL-Injection", "Web-Exploit"]},
    "192.0.2.99": {"country": "Latvia", "code": "LV", "isp": "Offshore Tunnel Host", "score": 79, "tags": ["DNS-Exfiltration"]},
    "203.0.113.111": {"country": "Hong Kong", "code": "HK", "isp": "Staging Drop Server", "score": 94, "tags": ["Private-Key-Exfil"]},
    "10.0.0.99": {"country": "Germany", "code": "DE", "isp": "Cloud Proxy", "score": 75, "tags": ["DNS-Tunneling"]}
}

def enrich_ip(ip: str) -> ThreatIntel:
    """Enrich IP with Threat Intelligence (AbuseIPDB, VirusTotal, or Heuristics)."""
    # 1. Check live AbuseIPDB if API Key is configured
    if config.ABUSEIPDB_API_KEY:
        try:
            headers = {
                'Key': config.ABUSEIPDB_API_KEY,
                'Accept': 'application/json'
            }
            params = {'ipAddress': ip, 'maxAgeInDays': '90'}
            resp = requests.get('https://api.abuseipdb.com/api/v2/check', headers=headers, params=params, timeout=3)
            if resp.status_code == 200:
                data = resp.json().get('data', {})
                score = data.get('abuseConfidenceScore', 0)
                return ThreatIntel(
                    ip=ip,
                    reputation_score=score,
                    is_malicious=score > 50,
                    country=data.get('countryName', 'Unknown'),
                    country_code=data.get('countryCode', 'XX'),
                    isp=data.get('isp', 'Unknown'),
                    abuse_confidence_score=score,
                    tags=["AbuseIPDB-Verified"] if score > 50 else ["Clean"],
                    last_reported=data.get('lastReportedAt')
                )
        except Exception as e:
            logger.warning(f"AbuseIPDB lookup failed for {ip}: {e}")

    # 2. Check local threat cache / mock threat DB for simulation
    if ip in KNOWN_THREAT_IOCS:
        mock = KNOWN_THREAT_IOCS[ip]
        return ThreatIntel(
            ip=ip,
            reputation_score=mock["score"],
            is_malicious=True,
            country=mock["country"],
            country_code=mock.get("code", mock["country"][:2].upper()),
            isp=mock["isp"],
            abuse_confidence_score=mock["score"],
            tags=mock["tags"]
        )

    # 3. Default classification for local / lab traffic
    is_private = ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.") or ip.startswith("127.")
    return ThreatIntel(
        ip=ip,
        reputation_score=10 if is_private else 40,
        is_malicious=False,
        country="Local/Lab Network" if is_private else "External Entity",
        country_code="LOC" if is_private else "EXT",
        isp="Private LAN" if is_private else "Public WAN",
        abuse_confidence_score=0,
        tags=["Internal-Host"] if is_private else ["External-Host"]
    )
