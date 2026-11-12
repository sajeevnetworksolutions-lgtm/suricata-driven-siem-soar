import os
import sys
from datetime import timedelta

import pytest

SOAR_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "soar_engine"))
if SOAR_DIR not in sys.path:
    sys.path.insert(0, SOAR_DIR)

from ban_manager import (
    BanManager,
    MockKernelBackend,
    WhitelistedIPError,
    InvalidIPError,
    BanCapacityError,
    utc_now,
    to_utc_iso,
)
from models import BanStatus


def make_manager(tmp_path, max_bans=10, backend=None, reconcile=True):
    db_path = str(tmp_path / "bans.db")
    audit_path = str(tmp_path / "audit.jsonl")
    kb = backend or MockKernelBackend()
    mgr = BanManager(
        db_path=db_path,
        audit_log_path=audit_path,
        whitelist_entries=["172.28.0.1", "172.28.0.10", "127.0.0.0/8", "::1/128", "172.28.0.2"],
        max_active_bans=max_bans,
        backend=kb,
        reconcile=reconcile,
        include_system_dns=False,
    )
    return mgr, kb


def test_ban_block_and_ttl_auto_unban_at_300s(tmp_path):
    mgr, kb = make_manager(tmp_path)
    rec = mgr.ban_ip(
        "172.28.0.105",
        reason="HTTP 401 Brute Force",
        signature="SID 1000012",
        severity=1,
        ttl_seconds=300,
        enable_ttl=True,
    )
    assert rec.status == BanStatus.ACTIVE
    assert mgr.is_banned("172.28.0.105")
    assert kb.is_blocked("172.28.0.105")
    assert "172.28.0.105" in kb.input_chain
    assert "172.28.0.105" in kb.forward_chain

    # Before 300s elapsed -> still blocked
    assert mgr.expire_stale_bans(now=utc_now() + timedelta(seconds=299)) == []
    assert kb.is_blocked("172.28.0.105")

    # At 300s+ elapsed -> auto-unbanned with EXPIRED state
    expired = mgr.expire_stale_bans(now=utc_now() + timedelta(seconds=301))
    assert len(expired) == 1
    assert expired[0].ip == "172.28.0.105"
    assert expired[0].status == BanStatus.EXPIRED
    assert not kb.is_blocked("172.28.0.105")
    assert not mgr.is_banned("172.28.0.105")


def test_pardon_state_machine(tmp_path):
    mgr, kb = make_manager(tmp_path)
    mgr.ban_ip("172.28.0.200", "C2", "SID 1000030", 1, ttl_seconds=300, enable_ttl=True)
    pardoned = mgr.pardon_ip("172.28.0.200", reason="Manual analyst pardon")
    assert pardoned is not None
    assert pardoned.status == BanStatus.PARDONED
    assert pardoned.pardoned_at is not None
    assert not kb.is_blocked("172.28.0.200")

    persisted = mgr.get_ban_record("172.28.0.200")
    assert persisted is not None
    assert persisted.status == BanStatus.PARDONED


def test_whitelist_blocks_infrastructure_bans(tmp_path):
    mgr, kb = make_manager(tmp_path)
    for safe_ip in ("172.28.0.1", "172.28.0.10", "127.0.0.1", "127.0.0.11", "::1", "172.28.0.2"):
        with pytest.raises(WhitelistedIPError):
            mgr.ban_ip(safe_ip, "Test", "SID 1", 1, ttl_seconds=300, enable_ttl=True)
        assert not kb.is_blocked(safe_ip)


def test_strict_ip_validation_rejects_injection_and_supports_ipv6(tmp_path):
    mgr, kb = make_manager(tmp_path)
    for bad_ip in ("1.2.3.4; rm -rf /", "1.2.3.4 && id", "not-an-ip", ""):
        with pytest.raises(InvalidIPError):
            mgr.ban_ip(bad_ip, "Injection test", "SID", 1, ttl_seconds=300, enable_ttl=True)

    rec = mgr.ban_ip("2001:0db8:0000:0000:0000:0000:0000:0042", "IPv6 test", "SID", 1, ttl_seconds=300, enable_ttl=True)
    assert rec.ip == "2001:db8::42"  # canonicalized
    assert kb.is_blocked("2001:db8::42")


def test_startup_reconciliation_rearms_active_and_prunes_orphans(tmp_path):
    kb = MockKernelBackend()
    mgr1, _ = make_manager(tmp_path, backend=kb)
    mgr1.ban_ip("198.51.100.44", "Live ban", "SID 1000020", 1, ttl_seconds=300, enable_ttl=True)

    # Simulate restart: kernel lost live rule and gained an orphaned rule
    kb.input_chain.clear()
    kb.forward_chain.clear()
    kb.block("192.0.2.254")  # orphan not in SQLite

    mgr2, _ = make_manager(tmp_path, backend=kb, reconcile=True)
    assert mgr2.is_banned("198.51.100.44")
    assert kb.is_blocked("198.51.100.44")  # re-armed
    assert not kb.is_blocked("192.0.2.254")  # orphan deleted


def test_max_active_bans_capacity(tmp_path):
    mgr, _ = make_manager(tmp_path, max_bans=2)
    mgr.ban_ip("198.51.100.1", "A", "S", 1, ttl_seconds=300, enable_ttl=True)
    mgr.ban_ip("198.51.100.2", "B", "S", 1, ttl_seconds=300, enable_ttl=True)
    with pytest.raises(BanCapacityError):
        mgr.ban_ip("198.51.100.3", "C", "S", 1, ttl_seconds=300, enable_ttl=True)


def test_no_ttl_ablation_permanent_ban(tmp_path):
    mgr, kb = make_manager(tmp_path)
    rec = mgr.ban_ip("198.51.100.9", "Permanent", "SID 1000020", 1, ttl_seconds=300, enable_ttl=False)
    assert rec.permanent is True
    assert rec.expires_at == "PERMANENT"
    assert mgr.expire_stale_bans(now=utc_now() + timedelta(days=30)) == []
    assert kb.is_blocked("198.51.100.9")
