import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)

_default_data_dir = "/app/data" if os.path.exists("/.dockerenv") else os.path.join(BASE_DIR, "data")
_default_eve_path = "/var/log/suricata/eve.json" if os.path.exists("/.dockerenv") else os.path.join(PROJECT_ROOT, "logs", "eve.json")


class SOARConfig:
    EVE_LOG_PATH = os.getenv("EVE_LOG_PATH", _default_eve_path)
    ELASTICSEARCH_URL = os.getenv("ELASTICSEARCH_URL", "http://elasticsearch:9200")

    # Automated Incident Response (SOAR) Policies
    AUTO_BAN_ENABLED = os.getenv("AUTO_BAN_ENABLED", "true").lower() in ("true", "1", "yes")
    BAN_THRESHOLD_SEVERITY = int(os.getenv("BAN_THRESHOLD_SEVERITY", "1"))  # 1 = Critical, 2 = High
    BAN_TTL_SECONDS = int(os.getenv("BAN_TTL_SECONDS", "300"))  # 5 minutes default ban duration

    # Webhook Notifications (Optional)
    SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")
    DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "")

    # Threat Intelligence API Keys (Optional)
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

    # Persistence
    DATA_DIR = os.getenv("DATA_DIR", _default_data_dir)
    INCIDENTS_FILE = os.path.join(DATA_DIR, "incidents.json")
    BANS_FILE = os.path.join(DATA_DIR, "bans.json")
    AUDIT_FILE = os.path.join(DATA_DIR, "audit.json")


config = SOARConfig()
