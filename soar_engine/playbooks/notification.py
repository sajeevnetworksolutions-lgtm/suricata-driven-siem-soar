import json
import logging
import requests
from typing import Optional
from models import IncidentAlert
from config import config

logger = logging.getLogger("soar.playbook.notification")

def send_incident_notification(alert: IncidentAlert, action_taken: str) -> bool:
    """Dispatches formatted Incident Alert Cards to Slack, Discord, or SIEM webhook."""
    success = True
    
    # 1. Discord Webhook
    if config.DISCORD_WEBHOOK_URL:
        try:
            color = 15158332 if alert.severity == 1 else 15105570 if alert.severity == 2 else 3447003
            payload = {
                "username": "Suricata SIEM SOAR Bot",
                "embeds": [{
                    "title": f"🚨 SOAR Incident Triggered: {alert.signature}",
                    "color": color,
                    "fields": [
                        {"name": "Attacker IP", "value": f"`{alert.src_ip}:{alert.src_port}`", "inline": True},
                        {"name": "Target IP", "value": f"`{alert.dest_ip}:{alert.dest_port}`", "inline": True},
                        {"name": "Severity", "value": f"Level {alert.severity}", "inline": True},
                        {"name": "Category", "value": alert.category, "inline": True},
                        {"name": "MITRE Tactic", "value": alert.mitre_tactic or "N/A", "inline": True},
                        {"name": "Automated Action", "value": f"**{action_taken}**", "inline": False}
                    ],
                    "timestamp": alert.timestamp
                }]
            }
            res = requests.post(config.DISCORD_WEBHOOK_URL, json=payload, timeout=4)
            if res.status_code >= 400:
                logger.error(f"Discord webhook failed with code {res.status_code}")
                success = False
        except Exception as e:
            logger.error(f"Discord webhook error: {e}")
            success = False

    # 2. Slack Webhook
    if config.SLACK_WEBHOOK_URL:
        try:
            payload = {
                "text": f"🚨 *SOAR Automated Alert*\n*Signature:* {alert.signature}\n*Attacker:* `{alert.src_ip}` -> *Target:* `{alert.dest_ip}`\n*Severity:* Level {alert.severity}\n*Action:* {action_taken}"
            }
            res = requests.post(config.SLACK_WEBHOOK_URL, json=payload, timeout=4)
            if res.status_code >= 400:
                logger.error(f"Slack webhook failed with code {res.status_code}")
                success = False
        except Exception as e:
            logger.error(f"Slack webhook error: {e}")
            success = False

    return success
