import os
import subprocess
import logging
from datetime import datetime, timedelta
from typing import Dict, Optional, List
from models import BanRecord, PlaybookExecutionLog
from config import config

logger = logging.getLogger("soar.playbook.ip_block")

class IPBlockPlaybook:
    def __init__(self):
        self.active_bans: Dict[str, BanRecord] = {}

    def is_banned(self, ip: str) -> bool:
        if ip in self.active_bans:
            record = self.active_bans[ip]
            if record.status == "ACTIVE":
                # Check TTL
                now = datetime.utcnow()
                exp = datetime.fromisoformat(record.expires_at)
                if now > exp:
                    self.unban_ip(ip, reason="TTL_EXPIRED")
                    return False
                return True
        return False

    def ban_ip(self, ip: str, reason: str, signature: str, severity: int, ttl_seconds: Optional[int] = None) -> BanRecord:
        if ttl_seconds is None:
            ttl_seconds = config.BAN_TTL_SECONDS

        now = datetime.utcnow()
        expires = now + timedelta(seconds=ttl_seconds)

        # Attempt OS-level iptables rule if running in privileged container
        try:
            cmd = f"iptables -C INPUT -s {ip} -j DROP 2>/dev/null || iptables -I INPUT 1 -s {ip} -j DROP"
            subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            logger.info(f"[SOAR FIREWALL] Added iptables DROP rule for IP: {ip}")
        except Exception as e:
            logger.debug(f"[SOAR FIREWALL] iptables command skipped/failed: {e}")

        record = BanRecord(
            ip=ip,
            banned_at=now.isoformat(),
            expires_at=expires.isoformat(),
            reason=reason,
            associated_signature=signature,
            severity=severity,
            status="ACTIVE"
        )
        self.active_bans[ip] = record
        logger.warning(f"🚨 [SOAR-ACTION] Automated IP Quarantine executed on {ip} for {ttl_seconds}s! Reason: {signature}")
        return record

    def unban_ip(self, ip: str, reason: str = "MANUAL_PARDON") -> Optional[BanRecord]:
        if ip in self.active_bans:
            record = self.active_bans[ip]
            record.status = "EXPIRED" if reason == "TTL_EXPIRED" else "MANUALLY_REMOVED"
            
            # Remove from iptables
            try:
                cmd = f"iptables -D INPUT -s {ip} -j DROP"
                subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                logger.info(f"[SOAR FIREWALL] Removed iptables DROP rule for IP: {ip}")
            except Exception as e:
                logger.debug(f"[SOAR FIREWALL] iptables removal skipped: {e}")
                
            logger.info(f"✅ [SOAR-ACTION] IP Quarantine lifted for {ip}. Reason: {reason}")
            return record
        return None

    def get_all_active_bans(self) -> List[BanRecord]:
        # Clean expired first
        now = datetime.utcnow()
        active = []
        for ip, record in list(self.active_bans.items()):
            if record.status == "ACTIVE":
                exp = datetime.fromisoformat(record.expires_at)
                if now > exp:
                    record.status = "EXPIRED"
                else:
                    active.append(record)
        return active

ip_blocker = IPBlockPlaybook()
