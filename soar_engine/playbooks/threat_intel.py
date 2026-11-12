import ipaddress
import logging
import requests
from typing import Any, Dict, Tuple

from models import ThreatIntel
from config import config

logger = logging.getLogger("soar.playbook.threat_intel")

# High-risk ASN & hosting risk heuristic scores S_asn in [0, 100]
HIGH_RISK_ASN_SCORES = {
    "AS49981": 87,  # Bulletproof hosting
    "AS44477": 96,  # Stark Industries / C2 bulletproofing
    "AS205100": 89, # Tor exit relay
    "AS9009": 93,   # M247 hosting
    "AS4134": 84,   # ChinaNet backbone
    "AS34224": 85,  # Neterra Ltd
    "AS16276": 63,  # OVH
}

# Explicitly labelled local IOC cache for private/RFC5737 lab IPs (non-global testbed)
KNOWN_THREAT_IOCS: Dict[str, Dict[str, Any]] = {
    "198.51.100.44": {"country": "Netherlands", "code": "NL", "isp": "Bulletproof Hosting", "asn": "AS49981", "abuse_score": 94, "asn_score": 87, "tags": ["SQL-Injection", "OWASP-Top10", "Scanner"]},
    "203.0.113.88": {"country": "China", "code": "CN", "isp": "ChinaNet Backbone", "asn": "AS4134", "abuse_score": 91, "asn_score": 84, "tags": ["SSH-Bruteforce", "Credential-Stuffing"]},
    "195.123.245.12": {"country": "Russia", "code": "RU", "isp": "Stark Industries Solutions", "asn": "AS44477", "abuse_score": 99, "asn_score": 96, "tags": ["CobaltStrike-C2", "APT29", "Botnet"]},
    "185.220.101.5": {"country": "Germany", "code": "DE", "isp": "Tor Exit Relay", "asn": "AS205100", "abuse_score": 82, "asn_score": 89, "tags": ["Tor-Exit-Node", "Port-Scanner", "Masscan"]},
    "91.240.118.172": {"country": "Romania", "code": "RO", "isp": "M247 Europe SRL", "asn": "AS9009", "abuse_score": 96, "asn_score": 93, "tags": ["Data-Exfiltration", "RSA-Key-Leak"]},
    "45.154.255.89": {"country": "Bulgaria", "code": "BG", "isp": "Neterra Ltd", "asn": "AS34224", "abuse_score": 88, "asn_score": 85, "tags": ["DNS-Tunneling", "Covert-Channel"]},
    "172.16.55.101": {"country": "Internal / Endpoint", "code": "INT", "isp": "Corporate Workstation VLAN-55", "asn": "AS64512", "abuse_score": 85, "asn_score": 62, "tags": ["Canary-Token-Tripped", "Insider-Trap"]},
    "172.28.0.100": {"country": "United States", "code": "US", "isp": "TOR Exit Node", "asn": "AS64520", "abuse_score": 97, "asn_score": 90, "tags": ["Scanner", "Brute-Force"]},
    "172.28.0.105": {"country": "Brazil", "code": "BR", "isp": "Botnet Proxy Pool (CASE-AUTH)", "asn": "AS64521", "abuse_score": 88, "asn_score": 78, "tags": ["HTTP-Bruteforce", "Credential-Stuffing"]},
    "172.28.0.110": {"country": "Singapore", "code": "SG", "isp": "Cloud VPS Dropzone", "asn": "AS64522", "abuse_score": 95, "asn_score": 85, "tags": ["Exfiltration", "Policy-Violation"]},
    "172.28.0.200": {"country": "Russia", "code": "RU", "isp": "Bulletproof Host (CASE-C2)", "asn": "AS64523", "abuse_score": 90, "asn_score": 83, "tags": ["C2-Server", "Botnet"]},
    "192.168.1.150": {"country": "China", "code": "CN", "isp": "Known APT Subnet", "asn": "AS64530", "abuse_score": 95, "asn_score": 78, "tags": ["Exploit-Scanner", "SQL-Injection"]},
    "192.168.1.99": {"country": "Internal / Trap", "code": "INT", "isp": "Honeypot Lure Segment", "asn": "AS64531", "abuse_score": 88, "asn_score": 68, "tags": ["Canary-Tripped", "Deception"]},
    "198.51.100.55": {"country": "France", "code": "FR", "isp": "OVH Proxy Node", "asn": "AS16276", "abuse_score": 76, "asn_score": 63, "tags": ["XSS-Exploit", "Web-Scanner"]},
    "198.51.100.42": {"country": "United Kingdom", "code": "GB", "isp": "Cloud Recon VPS", "asn": "AS64532", "abuse_score": 70, "asn_score": 63, "tags": ["Port-Sweep", "Recon"]},
    "192.0.2.140": {"country": "Ukraine", "code": "UA", "isp": "Malicious Proxy Relay", "asn": "AS64533", "abuse_score": 93, "asn_score": 86, "tags": ["SQL-Injection", "Web-Exploit"]},
    "192.0.2.99": {"country": "Latvia", "code": "LV", "isp": "Offshore Tunnel Host", "asn": "AS64534", "abuse_score": 81, "asn_score": 74, "tags": ["DNS-Exfiltration"]},
    "203.0.113.111": {"country": "Hong Kong", "code": "HK", "isp": "Staging Drop Server", "asn": "AS64535", "abuse_score": 96, "asn_score": 89, "tags": ["Private-Key-Exfil"]},
    "10.0.0.99": {"country": "Germany", "code": "DE", "isp": "Cloud Proxy", "asn": "AS64536", "abuse_score": 80, "asn_score": 63, "tags": ["DNS-Tunneling"]},
}


def compute_reputation_score(
    abuse_score: float,
    asn_score: float,
    w1: float = config.TI_WEIGHT_ABUSEIPDB,
    w2: float = config.TI_WEIGHT_ASN,
) -> int:
    """
    Paper Reputation Formula:
      R(x) = w1 * AbuseIPDB(x) + w2 * ASN(x), clamped to [0, 100].
      Default documented weights: w1 = 0.7, w2 = 0.3.
    """
    raw = (w1 * float(abuse_score)) + (w2 * float(asn_score))
    return max(0, min(100, int(round(raw))))


def _derive_asn_risk(data: Dict[str, Any]) -> Tuple[str, int]:
    """Compute ASN risk component S_asn in [0, 100] from AbuseIPDB response metadata."""
    isp = str(data.get("isp") or "Unknown")
    usage = str(data.get("usageType") or "").lower()
    is_tor = bool(data.get("isTor", False))

    for asn, risk in HIGH_RISK_ASN_SCORES.items():
        if asn in isp:
            return asn, risk

    if is_tor:
        return "TOR-RELAY", 90
    if any(k in usage for k in ("data center", "web hosting", "transit")):
        return "HOSTING-ASN", 70
    if "reserved" in usage:
        return "RESERVED", 30
    return "PUBLIC-ASN", 45


def _is_non_public_lab_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return not addr.is_global
    except ValueError:
        return True


def enrich_ip(ip: str) -> ThreatIntel:
    """
    Enrich IP using documented weighted scoring R(x) = w1*AbuseIPDB + w2*ASN:
      - Public routable IPs with ABUSEIPDB_API_KEY -> live AbuseIPDB lookup (`intel_source='abuseipdb'`)
      - Known lab / documentation RFC5737 / RFC1918 IOC IPs -> labelled `intel_source='local_ioc_cache'`
      - Other uncategorized IPs -> labelled `intel_source='heuristic_fallback'`
    """
    w1 = config.TI_WEIGHT_ABUSEIPDB
    w2 = config.TI_WEIGHT_ASN
    weights = {"w1": w1, "w2": w2}

    # 1. Live AbuseIPDB lookup for real globally-routable public IPs
    if config.ABUSEIPDB_API_KEY and not _is_non_public_lab_ip(ip):
        try:
            headers = {"Key": config.ABUSEIPDB_API_KEY, "Accept": "application/json"}
            params = {"ipAddress": ip, "maxAgeInDays": "90"}
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers=headers,
                params=params,
                timeout=3,
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                abuse_score = int(data.get("abuseConfidenceScore", 0))
                asn, asn_score = _derive_asn_risk(data)
                r_x = compute_reputation_score(abuse_score, asn_score, w1, w2)
                return ThreatIntel(
                    ip=ip,
                    reputation_score=r_x,
                    is_malicious=r_x >= 50,
                    country=data.get("countryName", "Unknown"),
                    country_code=data.get("countryCode", "XX"),
                    isp=data.get("isp", "Unknown"),
                    asn=asn,
                    abuse_confidence_score=abuse_score,
                    asn_risk_score=asn_score,
                    formula_weights=weights,
                    intel_source="abuseipdb",
                    tags=["AbuseIPDB-Verified"] if r_x >= 50 else ["Clean"],
                    last_reported=data.get("lastReportedAt"),
                )
        except Exception as e:
            logger.warning(f"AbuseIPDB lookup failed for {ip}: {e}")

    # 2. Labelled Local IOC Cache for private lab / RFC5737 simulation IPs
    if ip in KNOWN_THREAT_IOCS:
        mock = KNOWN_THREAT_IOCS[ip]
        abuse_score = int(mock["abuse_score"])
        asn_score = int(mock["asn_score"])
        r_x = compute_reputation_score(abuse_score, asn_score, w1, w2)
        return ThreatIntel(
            ip=ip,
            reputation_score=r_x,
            is_malicious=r_x >= 50,
            country=mock["country"],
            country_code=mock.get("code", mock["country"][:2].upper()),
            isp=f"{mock['isp']} {mock['asn']}",
            asn=mock["asn"],
            abuse_confidence_score=abuse_score,
            asn_risk_score=asn_score,
            formula_weights=weights,
            intel_source="local_ioc_cache",
            tags=list(mock["tags"]),
        )

    # 3. Fallback classification for uncached lab / external traffic
    is_private = _is_non_public_lab_ip(ip)
    abuse_score = 0
    asn_score = 10 if is_private else 40
    r_x = compute_reputation_score(abuse_score, asn_score, w1, w2)
    return ThreatIntel(
        ip=ip,
        reputation_score=r_x,
        is_malicious=False,
        country="Local/Lab Network" if is_private else "External Entity",
        country_code="LOC" if is_private else "EXT",
        isp="Private LAN" if is_private else "Public WAN",
        asn="AS64512" if is_private else "PUBLIC-WAN",
        abuse_confidence_score=abuse_score,
        asn_risk_score=asn_score,
        formula_weights=weights,
        intel_source="heuristic_fallback",
        tags=["Internal-Host"] if is_private else ["External-Host"],
    )
