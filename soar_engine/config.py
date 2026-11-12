import os
from typing import List

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)

_default_data_dir = "/app/data" if os.path.exists("/.dockerenv") else os.path.join(BASE_DIR, "data")
_default_eve_path = "/var/log/suricata/eve.json" if os.path.exists("/.dockerenv") else os.path.join(PROJECT_ROOT, "logs", "eve.json")


def _parse_bool(env_name: str, default: bool) -> bool:
    val = os.getenv(env_name)
    if val is None:
        return default
    return val.strip().lower() in ("true", "1", "yes", "on")


def _parse_csv(env_name: str, default: str) -> List[str]:
    raw = os.getenv(env_name, default)
    return [item.strip() for item in raw.split(",") if item.strip()]


class SOARConfig:
    EVE_LOG_PATH = os.getenv("EVE_LOG_PATH", _default_eve_path)
    ELASTICSEARCH_URL = os.getenv("ELASTICSEARCH_URL", "http://elasticsearch:9200")
    SOAR_INPUT_MODE = os.getenv("SOAR_INPUT_MODE", "eve").strip().lower()  # 'eve' or 'elasticsearch'

    # Automated Incident Response (SOAR) Policies (Paper Eq. 8-10, Sec. 4.4)
    AUTO_BAN_ENABLED = _parse_bool("AUTO_BAN_ENABLED", True)
    BAN_THRESHOLD_SEVERITY = int(os.getenv("BAN_THRESHOLD_SEVERITY", "1"))  # S_threshold = 1
    BAN_TTL_SECONDS = int(os.getenv("BAN_TTL_SECONDS", "300"))  # tau_TTL = 300 s
    POLL_INTERVAL_MS = int(os.getenv("POLL_INTERVAL_MS", "200"))  # 200 ms async tailing
    MAX_ACTIVE_BANS = int(os.getenv("MAX_ACTIVE_BANS", "1000"))
    DRY_RUN = _parse_bool("DRY_RUN", False)

    # Infrastructure whitelist (never banned: gateway, target, loopback, DNS)
    INTERNAL_WHITELIST = _parse_csv(
        "INTERNAL_WHITELIST",
        "172.28.0.1,172.28.0.10,127.0.0.0/8,::1/128",
    )

    # Threat Intelligence scoring weights: R(x) = w1 * AbuseIPDB + w2 * ASN
    TI_WEIGHT_ABUSEIPDB = float(os.getenv("TI_WEIGHT_ABUSEIPDB", "0.7"))
    TI_WEIGHT_ASN = float(os.getenv("TI_WEIGHT_ASN", "0.3"))

    # Ablation switches for empirical Table IV evaluation
    ENABLE_TTL = _parse_bool("ENABLE_TTL", True)
    ENABLE_THREAT_INTEL = _parse_bool("ENABLE_THREAT_INTEL", True)
    ENABLE_ECS = _parse_bool("ENABLE_ECS", True)
    ENABLE_FORENSICS = _parse_bool("ENABLE_FORENSICS", True)
    ASYNC_MODE = _parse_bool("ASYNC_MODE", True)

    # Webhook Notifications (Optional)
    SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")
    DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "")

    # Threat Intelligence API Keys (Optional)
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

    # Persistence Paths
    DATA_DIR = os.getenv("DATA_DIR", _default_data_dir)
    INCIDENTS_FILE = os.path.join(DATA_DIR, "incidents.json")
    BANS_FILE = os.path.join(DATA_DIR, "bans.json")
    AUDIT_FILE = os.path.join(DATA_DIR, "audit.json")
    BAN_DB = os.getenv("BAN_DB", os.path.join(DATA_DIR, "bans.db"))
    BAN_AUDIT_LOG = os.getenv("BAN_AUDIT_LOG", os.path.join(DATA_DIR, "audit.jsonl"))
    DOSSIER_DIR = os.getenv("DOSSIER_DIR", os.path.join(DATA_DIR, "forensics"))
    ENABLE_CHATTR = _parse_bool("ENABLE_CHATTR", True)


config = SOARConfig()
