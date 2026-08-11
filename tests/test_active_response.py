"""Tests for core/active_response.py — whitelist, block duration escalation,
and iptables fail-safe behavior (mocked, since this dev machine isn't Linux
and can't actually run iptables)."""
import core.active_response as ar


# ─── whitelist ──────────────────────────────────────────────────────────────

def test_no_whitelist_configured_blocks_nothing_from_it(monkeypatch):
    monkeypatch.delenv('WHITELIST_IPS', raising=False)
    assert ar.is_whitelisted('1.2.3.4') is False


def test_whitelisted_ip_is_recognized(monkeypatch):
    monkeypatch.setenv('WHITELIST_IPS', '1.2.3.4, 5.6.7.8')
    assert ar.is_whitelisted('1.2.3.4') is True
    assert ar.is_whitelisted('5.6.7.8') is True
    assert ar.is_whitelisted('9.9.9.9') is False


# ─── compute_duration ───────────────────────────────────────────────────────

def test_first_offense_is_base_duration():
    assert ar.compute_duration(0) == ar.BASE_BLOCK_SECONDS


def test_duration_doubles_per_prior_offense():
    assert ar.compute_duration(1) == ar.BASE_BLOCK_SECONDS * 2
    assert ar.compute_duration(2) == ar.BASE_BLOCK_SECONDS * 4


def test_duration_never_exceeds_24_hours():
    assert ar.compute_duration(10) == ar.MAX_BLOCK_SECONDS


# ─── block_ip / unblock_ip (subprocess mocked) ─────────────────────────────

class FakeResult:
    def __init__(self, returncode=0, stderr=''):
        self.returncode = returncode
        self.stderr = stderr


def test_block_ip_success(monkeypatch):
    monkeypatch.setattr(ar.subprocess, 'run', lambda *a, **k: FakeResult(returncode=0))
    ok, message = ar.block_ip('1.2.3.4')
    assert ok is True
    assert '1.2.3.4' in message


def test_block_ip_nonzero_exit_fails_safely(monkeypatch):
    monkeypatch.setattr(ar.subprocess, 'run', lambda *a, **k: FakeResult(returncode=1, stderr='permission denied'))
    ok, message = ar.block_ip('1.2.3.4')
    assert ok is False
    assert 'permission denied' in message


def test_block_ip_missing_iptables_fails_safely(monkeypatch):
    def raise_not_found(*a, **k):
        raise FileNotFoundError()
    monkeypatch.setattr(ar.subprocess, 'run', raise_not_found)
    ok, message = ar.block_ip('1.2.3.4')
    assert ok is False
    assert 'not available' in message


def test_block_ip_permission_error_fails_safely(monkeypatch):
    def raise_permission(*a, **k):
        raise PermissionError()
    monkeypatch.setattr(ar.subprocess, 'run', raise_permission)
    ok, message = ar.block_ip('1.2.3.4')
    assert ok is False
    assert 'permission' in message.lower()


def test_block_ip_never_raises_on_unexpected_error(monkeypatch):
    def raise_weird(*a, **k):
        raise RuntimeError("something else broke")
    monkeypatch.setattr(ar.subprocess, 'run', raise_weird)
    ok, message = ar.block_ip('1.2.3.4')
    assert ok is False
    assert 'something else broke' in message


def test_unblock_ip_success(monkeypatch):
    monkeypatch.setattr(ar.subprocess, 'run', lambda *a, **k: FakeResult(returncode=0))
    ok, message = ar.unblock_ip('1.2.3.4')
    assert ok is True
    assert '1.2.3.4' in message


def test_unblock_ip_never_raises_on_unexpected_error(monkeypatch):
    def raise_weird(*a, **k):
        raise RuntimeError("boom")
    monkeypatch.setattr(ar.subprocess, 'run', raise_weird)
    ok, message = ar.unblock_ip('1.2.3.4')
    assert ok is False
    assert 'boom' in message
