import os
import json
import shutil
import ipaddress
import subprocess
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, List
from models import BanRecord
from config import config

logger = logging.getLogger("soar.playbook.ip_block")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def to_utc_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse_utc_iso(ts: str) -> datetime:
    if not ts:
        return utc_now()
    cleaned = ts.strip()
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"
    dt = datetime.fromisoformat(cleaned)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


class IPBlockPlaybook:
    def __init__(self):
        self.active_bans: Dict[str, BanRecord] = {}
        self._load_state()

    def _load_state(self):
        try:
            if os.path.exists(config.BANS_FILE):
                with open(config.BANS_FILE, "r", encoding="utf-8") as f:
                    raw = json.load(f)
                now = utc_now()
                for ip, rec_dict in raw.items():
                    rec = BanRecord(**rec_dict)
                    if rec.status == "ACTIVE" and parse_utc_iso(rec.expires_at) > now:
                        self.active_bans[ip] = rec
        except Exception as e:
            logger.debug(f"Could not load persisted bans: {e}")

    def _save_state(self):
        try:
            os.makedirs(config.DATA_DIR, exist_ok=True)
            serialized = {ip: rec.model_dump() if hasattr(rec, "model_dump") else rec.dict()
                          for ip, rec in self.active_bans.items() if rec.status == "ACTIVE"}
            with open(config.BANS_FILE, "w", encoding="utf-8") as f:
                json.dump(serialized, f, indent=2)
        except Exception as e:
            logger.debug(f"Could not persist bans state: {e}")

    def _apply_os_firewall(self, ip: str, action: str):
        """Safely enforces or removes iptables DROP rules when running in Linux/container environments."""
        if os.name != "posix" or not shutil.which("iptables"):
            return
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            logger.warning(f"[SOAR FIREWALL] Invalid IP format skipped for OS firewall: {ip}")
            return

        try:
            if action == "DROP":
                check = subprocess.run(["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if check.returncode != 0:
                    subprocess.run(["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    logger.info(f"[SOAR FIREWALL] Added iptables DROP rule for IP: {ip}")
            elif action == "UNBAN":
                subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                logger.info(f"[SOAR FIREWALL] Removed iptables DROP rule for IP: {ip}")
        except Exception as e:
            logger.debug(f"[SOAR FIREWALL] iptables {action} skipped: {e}")

    def is_banned(self, ip: str) -> bool:
        if ip in self.active_bans:
            record = self.active_bans[ip]
            if record.status == "ACTIVE":
                if utc_now() > parse_utc_iso(record.expires_at):
                    self.unban_ip(ip, reason="TTL_EXPIRED")
                    return False
                return True
        return False

    def ban_ip(self, ip: str, reason: str, signature: str, severity: int, ttl_seconds: Optional[int] = None) -> BanRecord:
        if ttl_seconds is None:
            ttl_seconds = config.BAN_TTL_SECONDS

        now = utc_now()
        expires = now + timedelta(seconds=ttl_seconds)

        self._apply_os_firewall(ip, "DROP")

        record = BanRecord(
            ip=ip,
            banned_at=to_utc_iso(now),
            expires_at=to_utc_iso(expires),
            reason=reason,
            associated_signature=signature,
            severity=severity,
            status="ACTIVE"
        )
        self.active_bans[ip] = record
        self._save_state()
        logger.warning(f"[SOAR-ACTION] Automated IP Quarantine executed on {ip} for {ttl_seconds}s! Reason: {signature}")
        return record

    def unban_ip(self, ip: str, reason: str = "MANUAL_PARDON") -> Optional[BanRecord]:
        if ip in self.active_bans:
            record = self.active_bans[ip]
            record.status = "EXPIRED" if reason == "TTL_EXPIRED" else "MANUALLY_REMOVED"
            self._apply_os_firewall(ip, "UNBAN")
            self._save_state()
            logger.info(f"[SOAR-ACTION] IP Quarantine lifted for {ip}. Reason: {reason}")
            return record
        return None

    def expire_stale_bans(self) -> List[BanRecord]:
        """Expires all active bans whose TTL has elapsed and returns the newly expired records."""
        now = utc_now()
        expired = []
        for ip, record in list(self.active_bans.items()):
            if record.status == "ACTIVE" and now > parse_utc_iso(record.expires_at):
                unbanned = self.unban_ip(ip, reason="TTL_EXPIRED")
                if unbanned:
                    expired.append(unbanned)
        return expired

    def get_all_active_bans(self) -> List[BanRecord]:
        self.expire_stale_bans()
        return [rec for rec in self.active_bans.values() if rec.status == "ACTIVE"]


ip_blocker = IPBlockPlaybook()
