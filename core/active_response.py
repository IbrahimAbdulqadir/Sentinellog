"""
SentinelLog — Active Response

Automated blocking, scoped deliberately narrow: only fires on brute_force
alerts (the highest-confidence, lowest false-positive detection SentinelLog
has), always time-boxed rather than permanent, and never touches anything on
the whitelist. This mirrors exactly the safety discipline real Wazuh
operators recommend before ever turning on automated response — a wrong
automated block is often worse than the attack it was trying to stop.

Requires the process to have permission to run iptables (root, or a sudoers
rule scoped to exactly the iptables commands below). If it doesn't, blocking
fails safely — it logs the failure and the alert still fires normally, this
can never crash a monitoring session.
"""
import os
import subprocess
from datetime import datetime, timedelta

BASE_BLOCK_SECONDS = 30 * 60       # 30 minutes for a first offense
MAX_BLOCK_SECONDS = 24 * 60 * 60   # never longer than 24 hours, even for repeat offenders


def get_whitelist():
    """IPs that can never be blocked, no matter what — always include your own
    admin/office IPs here. Configure via WHITELIST_IPS in .env, comma-separated."""
    raw = os.environ.get('WHITELIST_IPS', '')
    return {ip.strip() for ip in raw.split(',') if ip.strip()}


def is_whitelisted(ip):
    return ip in get_whitelist()


def compute_duration(prior_block_count):
    """Escalating duration for repeat offenders, capped at 24h — the same
    pattern real Wazuh deployments use, not a permanent ban on the first strike."""
    seconds = BASE_BLOCK_SECONDS * (2 ** prior_block_count)
    return min(seconds, MAX_BLOCK_SECONDS)


def block_ip(ip) -> tuple[bool, str]:
    """Returns (success, message). Never raises — a failure here must never
    take down the monitoring session that triggered it."""
    try:
        result = subprocess.run(
            ['iptables', '-I', 'INPUT', '-s', ip, '-j', 'DROP'],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            return True, f"Blocked {ip} via iptables"
        return False, f"iptables failed: {result.stderr.strip()}"
    except FileNotFoundError:
        return False, "iptables not available on this system (likely not Linux, or not installed)"
    except PermissionError:
        return False, "No permission to run iptables — needs to run as root, or a sudoers rule for this command"
    except Exception as e:
        return False, f"Unexpected error blocking {ip}: {e}"


def unblock_ip(ip) -> tuple[bool, str]:
    try:
        result = subprocess.run(
            ['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            return True, f"Unblocked {ip}"
        return False, f"iptables failed: {result.stderr.strip()}"
    except Exception as e:
        return False, f"Unexpected error unblocking {ip}: {e}"
