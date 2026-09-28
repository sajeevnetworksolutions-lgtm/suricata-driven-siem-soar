import requests
import logging
from typing import Optional
from models import ThreatIntel
from config import config

logger = logging.getLogger("soar.playbook.threat_intel")

# Known mock database for internal & common test IOCs
KNOWN_THREAT_IOCS = {
    "172.28.0.100": {"country": "US", "isp": "TOR Exit Node", "score": 95, "tags": ["Scanner", "Brute-Force"]},
    "172.28.0.200": {"country": "RU", "isp": "Bulletproof Host", "score": 88, "tags": ["C2 Server", "Botnet"]},
    "192.168.1.150": {"country": "CN", "isp": "Known APT Subnet", "score": 90, "tags": ["Exploit Scanner"]},
    "10.0.0.99": {"country": "DE", "isp": "Cloud Proxy", "score": 75, "tags": ["DNS Tunneling"]}
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
            country_code=mock["country"],
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
