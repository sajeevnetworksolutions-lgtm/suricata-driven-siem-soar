import os
import re
import json
import time
import shutil
import sqlite3
import logging
import ipaddress
import subprocess
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Protocol, Sequence, Set

from models import BanRecord, BanStatus
from config import config

logger = logging.getLogger("soar.ban_manager")


class WhitelistedIPError(ValueError):
    """Raised when attempting to ban a protected infrastructure IP."""


class InvalidIPError(ValueError):
    """Raised when an IP address fails strict validation."""


class BanCapacityError(RuntimeError):
    """Raised when MAX_ACTIVE_BANS capacity is reached."""


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def to_utc_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse_utc_iso(ts: str) -> datetime:
    if not ts or ts == "PERMANENT":
        return datetime.max.replace(tzinfo=timezone.utc)
    cleaned = ts.strip()
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"
    dt = datetime.fromisoformat(cleaned)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def validate_ip(ip: str) -> str:
    """Strictly parse IPv4/IPv6 string and return normalized canonical representation."""
    if not isinstance(ip, str) or not ip.strip():
        raise InvalidIPError(f"Empty or invalid IP: {ip!r}")
    candidate = ip.strip()
    # Reject zone identifiers or embedded whitespace/metacharacters
    if any(ch.isspace() or ch in ";|&$`><\\" for ch in candidate):
        raise InvalidIPError(f"Unsafe characters in IP: {ip!r}")
    try:
        parsed = ipaddress.ip_address(candidate)
    except ValueError as exc:
        raise InvalidIPError(f"Invalid IP address: {ip!r}") from exc
    return str(parsed)


class FirewallBackend(Protocol):
    def block(self, ip: str) -> bool: ...
    def unblock(self, ip: str) -> bool: ...
    def is_blocked(self, ip: str) -> bool: ...
    def list_blocked_ips(self) -> Set[str]: ...


class MockKernelBackend:
    """In-memory simulated kernel netfilter table for DRY_RUN, Windows, or rootless tests."""

    def __init__(self):
        self.input_chain: List[str] = []
        self.forward_chain: List[str] = []

    def block(self, ip: str) -> bool:
        ip = validate_ip(ip)
        if ip not in self.input_chain:
            self.input_chain.insert(0, ip)
        if ip not in self.forward_chain:
            self.forward_chain.insert(0, ip)
        return True

    def unblock(self, ip: str) -> bool:
        ip = validate_ip(ip)
        removed = False
        while ip in self.input_chain:
            self.input_chain.remove(ip)
            removed = True
        while ip in self.forward_chain:
            self.forward_chain.remove(ip)
            removed = True
        return removed

    def is_blocked(self, ip: str) -> bool:
        ip = validate_ip(ip)
        return ip in self.input_chain

    def list_blocked_ips(self) -> Set[str]:
        return set(self.input_chain) | set(self.forward_chain)


class IptablesBackend:
    """Real Linux netfilter enforcement implementing Eq. 9 & Eq. 10 without shell invocation."""

    _RULE_RE = re.compile(
        r"^-A\s+(?:INPUT|FORWARD)\s+-s\s+([0-9a-fA-F:\.]+)(?:/(?:32|128))?(?:\s+.*)?\s+-j\s+DROP$"
    )
    _COMMENT_ARGS = ("-m", "comment", "--comment", "siem-soar")

    @staticmethod
    def _binary_for_ip(ip: str) -> str:
        addr = ipaddress.ip_address(ip)
        return "ip6tables" if addr.version == 6 else "iptables"

    def _run(self, cmd: Sequence[str]) -> subprocess.CompletedProcess:
        return subprocess.run(list(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=False)

    def block(self, ip: str) -> bool:
        ip = validate_ip(ip)
        binary = self._binary_for_ip(ip)
        if not shutil.which(binary):
            return False
        success = True
        for chain in ("INPUT", "FORWARD"):
            if self._is_chain_blocked(binary, chain, ip):
                continue
            ins = self._run([binary, "-I", chain, "1", "-s", ip, *self._COMMENT_ARGS, "-j", "DROP"])
            if ins.returncode != 0:
                ins = self._run([binary, "-I", chain, "1", "-s", ip, "-j", "DROP"])
            if ins.returncode != 0:
                logger.warning(f"[FIREWALL] {binary} -I {chain} failed for {ip}: {ins.stderr.strip()}")
                if chain == "INPUT":
                    success = False
        return success

    def unblock(self, ip: str) -> bool:
        ip = validate_ip(ip)
        binary = self._binary_for_ip(ip)
        if not shutil.which(binary):
            return False
        removed = False
        for chain in ("INPUT", "FORWARD"):
            for spec in (("-s", ip, *self._COMMENT_ARGS, "-j", "DROP"), ("-s", ip, "-j", "DROP")):
                for _ in range(16):  # bounded cleanup of any duplicate rules
                    res = self._run([binary, "-D", chain, *spec])
                    if res.returncode == 0:
                        removed = True
                    else:
                        break
        return removed

    def _is_chain_blocked(self, binary: str, chain: str, ip: str) -> bool:
        if self._run([binary, "-C", chain, "-s", ip, *self._COMMENT_ARGS, "-j", "DROP"]).returncode == 0:
            return True
        return self._run([binary, "-C", chain, "-s", ip, "-j", "DROP"]).returncode == 0

    def is_blocked(self, ip: str) -> bool:
        ip = validate_ip(ip)
        binary = self._binary_for_ip(ip)
        if not shutil.which(binary):
            return False
        return self._is_chain_blocked(binary, "INPUT", ip)

    def list_blocked_ips(self) -> Set[str]:
        found: Set[str] = set()
        for binary in ("iptables", "ip6tables"):
            if not shutil.which(binary):
                continue
            for chain in ("INPUT", "FORWARD"):
                res = self._run([binary, "-S", chain])
                if res.returncode != 0:
                    continue
                for line in res.stdout.splitlines():
                    match = self._RULE_RE.match(line.strip())
                    if match:
                        try:
                            found.add(validate_ip(match.group(1)))
                        except InvalidIPError:
                            pass
        return found


def build_default_backend() -> FirewallBackend:
    if not config.DRY_RUN and os.name == "posix" and shutil.which("iptables"):
        # Probe read-only permission to confirm CAP_NET_ADMIN is active
        probe = subprocess.run(["iptables", "-S", "INPUT"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=False)
        if probe.returncode == 0:
            return IptablesBackend()
    return MockKernelBackend()


def discover_dns_nameservers(resolv_path: str = "/etc/resolv.conf") -> List[str]:
    servers: List[str] = []
    if os.path.exists(resolv_path):
        try:
            with open(resolv_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    stripped = line.strip()
                    if stripped.startswith("nameserver "):
                        parts = stripped.split()
                        if len(parts) >= 2:
                            servers.append(parts[1])
        except Exception:
            pass
    return servers


class Whitelist:
    def __init__(self, entries: Sequence[str], include_system_dns: bool = True):
        self.networks: List[ipaddress._BaseNetwork] = []
        raw_entries = list(entries)
        if include_system_dns:
            raw_entries.extend(discover_dns_nameservers())
            raw_entries.append("127.0.0.11")  # Docker embedded DNS resolver
        for item in raw_entries:
            item = item.strip()
            if not item:
                continue
            try:
                self.networks.append(ipaddress.ip_network(item, strict=False))
            except ValueError:
                logger.warning(f"Ignoring invalid whitelist entry: {item}")

    def contains(self, ip: str) -> bool:
        addr = ipaddress.ip_address(validate_ip(ip))
        return any(addr in net for net in self.networks)


class BanManager:
    """
    Production & testbed quarantine state machine implementing Paper Eq. 8-10:
      States: ACTIVE -> EXPIRED | PARDONED
      Persistence: SQLite DB (`bans.db`) + append-only JSONL audit ledger (`audit.jsonl`)
      Enforcement: Real netfilter (`iptables` / `ip6tables` INPUT & FORWARD) or MockKernelBackend
    """

    def __init__(
        self,
        db_path: Optional[str] = None,
        audit_log_path: Optional[str] = None,
        whitelist_entries: Optional[Sequence[str]] = None,
        max_active_bans: Optional[int] = None,
        backend: Optional[FirewallBackend] = None,
        reconcile: bool = True,
        include_system_dns: bool = True,
    ):
        self.db_path = db_path or config.BAN_DB
        self.audit_log_path = audit_log_path or config.BAN_AUDIT_LOG
        self.max_active_bans = max_active_bans if max_active_bans is not None else config.MAX_ACTIVE_BANS
        self.whitelist = Whitelist(
            whitelist_entries if whitelist_entries is not None else config.INTERNAL_WHITELIST,
            include_system_dns=include_system_dns,
        )
        self.backend = backend if backend is not None else build_default_backend()
        self.active_bans: Dict[str, BanRecord] = {}

        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        os.makedirs(os.path.dirname(os.path.abspath(self.audit_log_path)), exist_ok=True)
        self._init_db()
        if reconcile:
            self.reconcile_on_startup()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS bans (
                    ip TEXT PRIMARY KEY,
                    banned_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    pardoned_at TEXT,
                    reason TEXT NOT NULL,
                    associated_signature TEXT NOT NULL,
                    severity INTEGER NOT NULL,
                    ttl_seconds INTEGER NOT NULL,
                    permanent INTEGER NOT NULL DEFAULT 0,
                    status TEXT NOT NULL CHECK(status IN ('ACTIVE','EXPIRED','PARDONED'))
                )
                """
            )
            conn.commit()

    def _append_audit(self, event: str, ip: str, **fields):
        record = {
            "ts": time.time(),
            "timestamp": to_utc_iso(utc_now()),
            "event": event,
            "ip": ip,
            **fields,
        }
        try:
            with open(self.audit_log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
        except Exception as e:
            logger.debug(f"Could not write ban audit entry: {e}")

    def _save_record(self, rec: BanRecord):
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO bans (
                    ip, banned_at, expires_at, pardoned_at, reason,
                    associated_signature, severity, ttl_seconds, permanent, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    banned_at = excluded.banned_at,
                    expires_at = excluded.expires_at,
                    pardoned_at = excluded.pardoned_at,
                    reason = excluded.reason,
                    associated_signature = excluded.associated_signature,
                    severity = excluded.severity,
                    ttl_seconds = excluded.ttl_seconds,
                    permanent = excluded.permanent,
                    status = excluded.status
                """,
                (
                    rec.ip,
                    rec.banned_at,
                    rec.expires_at,
                    rec.pardoned_at,
                    rec.reason,
                    rec.associated_signature,
                    rec.severity,
                    rec.ttl_seconds,
                    1 if rec.permanent else 0,
                    rec.status.value,
                ),
            )
            conn.commit()
        self._sync_legacy_bans_json()

    def _sync_legacy_bans_json(self):
        try:
            os.makedirs(os.path.dirname(os.path.abspath(config.BANS_FILE)), exist_ok=True)
            serialized = {
                ip: rec.model_dump() if hasattr(rec, "model_dump") else rec.dict()
                for ip, rec in self.active_bans.items()
                if rec.status == BanStatus.ACTIVE
            }
            with open(config.BANS_FILE, "w", encoding="utf-8") as f:
                json.dump(serialized, f, indent=2)
        except Exception:
            pass

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> BanRecord:
        return BanRecord(
            ip=row["ip"],
            banned_at=row["banned_at"],
            expires_at=row["expires_at"],
            pardoned_at=row["pardoned_at"],
            reason=row["reason"],
            associated_signature=row["associated_signature"],
            severity=row["severity"],
            ttl_seconds=row["ttl_seconds"],
            permanent=bool(row["permanent"]),
            status=BanStatus(row["status"]),
        )

    def reconcile_on_startup(self):
        """Re-arm active DB bans and delete orphaned firewall rules on restart."""
        now = utc_now()
        self.active_bans.clear()
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM bans WHERE status = 'ACTIVE'").fetchall()

        for row in rows:
            rec = self._row_to_record(row)
            if not rec.permanent and now >= parse_utc_iso(rec.expires_at):
                rec.status = BanStatus.EXPIRED
                self.backend.unblock(rec.ip)
                self._save_record(rec)
                self._append_audit("BAN_EXPIRED_ON_STARTUP", rec.ip, expires_at=rec.expires_at)
            else:
                if self.whitelist.contains(rec.ip):
                    rec.status = BanStatus.PARDONED
                    self.backend.unblock(rec.ip)
                    self._save_record(rec)
                    self._append_audit("WHITELIST_PURGE", rec.ip)
                    continue
                self.backend.block(rec.ip)
                self.active_bans[rec.ip] = rec
                self._append_audit("STARTUP_REARM", rec.ip, expires_at=rec.expires_at)

        # Delete any orphaned DROP rules left in the kernel that are not ACTIVE in DB
        kernel_ips = self.backend.list_blocked_ips()
        for ip in kernel_ips:
            if ip not in self.active_bans:
                self.backend.unblock(ip)
                self._append_audit("ORPHAN_PRUNED", ip)

        self._sync_legacy_bans_json()

    def is_whitelisted(self, ip: str) -> bool:
        try:
            return self.whitelist.contains(validate_ip(ip))
        except InvalidIPError:
            return False

    def ban_ip(
        self,
        ip: str,
        reason: str,
        signature: str,
        severity: int,
        ttl_seconds: Optional[int] = None,
        enable_ttl: Optional[bool] = None,
    ) -> BanRecord:
        normalized_ip = validate_ip(ip)

        if self.whitelist.contains(normalized_ip):
            self._append_audit("WHITELIST_SKIP", normalized_ip, reason=reason, signature=signature)
            raise WhitelistedIPError(f"Refusing to ban whitelisted infrastructure IP: {normalized_ip}")

        self.expire_stale_bans()

        if normalized_ip not in self.active_bans and len(self.active_bans) >= self.max_active_bans:
            self._append_audit("CAPACITY_REACHED", normalized_ip, max_active_bans=self.max_active_bans)
            raise BanCapacityError(f"Active ban limit reached ({self.max_active_bans})")

        ttl_enabled = config.ENABLE_TTL if enable_ttl is None else enable_ttl
        effective_ttl = config.BAN_TTL_SECONDS if ttl_seconds is None else int(ttl_seconds)

        now = utc_now()
        if not ttl_enabled or effective_ttl <= 0:
            permanent = True
            expires_str = "PERMANENT"
            effective_ttl = 0
        else:
            permanent = False
            expires_str = to_utc_iso(now + timedelta(seconds=effective_ttl))

        self.backend.block(normalized_ip)

        record = BanRecord(
            ip=normalized_ip,
            banned_at=to_utc_iso(now),
            expires_at=expires_str,
            pardoned_at=None,
            reason=reason,
            associated_signature=signature,
            severity=severity,
            ttl_seconds=effective_ttl,
            permanent=permanent,
            status=BanStatus.ACTIVE,
        )
        self.active_bans[normalized_ip] = record
        self._save_record(record)
        self._append_audit(
            "ban",
            normalized_ip,
            state="ACTIVE",
            ttl_seconds=effective_ttl,
            expires_at=expires_str,
            permanent=permanent,
            signature=signature,
            severity=severity,
        )
        logger.warning(
            f"[SOAR-ACTION] Quarantine enforced on {normalized_ip} "
            f"({'PERMANENT' if permanent else f'{effective_ttl}s TTL'}). Signature: {signature}"
        )
        return record

    def pardon_ip(self, ip: str, reason: str = "MANUAL_PARDON") -> Optional[BanRecord]:
        normalized_ip = validate_ip(ip)
        record = self.active_bans.pop(normalized_ip, None)
        if record is None:
            return None
        record.status = BanStatus.PARDONED
        record.pardoned_at = to_utc_iso(utc_now())
        self.backend.unblock(normalized_ip)
        self._save_record(record)
        self._append_audit(
            "pardoned",
            normalized_ip,
            state="PARDONED",
            reason=reason,
            pardoned_at=record.pardoned_at,
        )
        logger.info(f"[SOAR-ACTION] Quarantine PARDONED for {normalized_ip}. Reason: {reason}")
        return record

    def unban_ip(self, ip: str, reason: str = "MANUAL_PARDON") -> Optional[BanRecord]:
        """Backwards-compatible alias distinguishing TTL_EXPIRED from PARDONED."""
        normalized_ip = validate_ip(ip)
        record = self.active_bans.pop(normalized_ip, None)
        if record is None:
            return None
        is_ttl = reason == "TTL_EXPIRED"
        record.status = BanStatus.EXPIRED if is_ttl else BanStatus.PARDONED
        if not is_ttl:
            record.pardoned_at = to_utc_iso(utc_now())
        self.backend.unblock(normalized_ip)
        self._save_record(record)
        self._append_audit(
            "expired" if is_ttl else "pardoned",
            normalized_ip,
            state=record.status.value,
            reason=reason,
        )
        logger.info(f"[SOAR-ACTION] IP Quarantine lifted ({record.status.value}) for {normalized_ip}. Reason: {reason}")
        return record

    def expire_stale_bans(self, now: Optional[datetime] = None) -> List[BanRecord]:
        current = now or utc_now()
        expired: List[BanRecord] = []
        for ip, record in list(self.active_bans.items()):
            if record.permanent:
                continue
            if current >= parse_utc_iso(record.expires_at):
                rec = self.unban_ip(ip, reason="TTL_EXPIRED")
                if rec:
                    expired.append(rec)
        return expired

    def is_banned(self, ip: str) -> bool:
        try:
            normalized_ip = validate_ip(ip)
        except InvalidIPError:
            return False
        self.expire_stale_bans()
        return normalized_ip in self.active_bans

    def get_all_active_bans(self) -> List[BanRecord]:
        self.expire_stale_bans()
        return [rec for rec in self.active_bans.values() if rec.status == BanStatus.ACTIVE]

    def get_ban_record(self, ip: str) -> Optional[BanRecord]:
        normalized_ip = validate_ip(ip)
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM bans WHERE ip = ?", (normalized_ip,)).fetchone()
        return self._row_to_record(row) if row else None

    def clear_all(self):
        for ip in list(self.active_bans.keys()):
            self.backend.unblock(ip)
        self.active_bans.clear()
        with self._connect() as conn:
            conn.execute("DELETE FROM bans")
            conn.commit()
        self._sync_legacy_bans_json()
