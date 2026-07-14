"""
SentinelLog — Week 3: Telegram Alerting
"""
import requests
import threading
from dataclasses import asdict

SEVERITY_EMOJI = {'critical':'🚨','high':'⚠️','medium':'🔔','low':'ℹ️'}
RULE_EMOJI = {
    'brute_force':'🔐','404_flood':'🌐',
    'directory_traversal':'📁','privilege_escalation':'👑','suspicious_time':'🕐'
}

class TelegramAlerter:
    def __init__(self, bot_token: str, chat_id: str):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.base_url = f"https://api.telegram.org/bot{bot_token}"
        self.enabled = bool(bot_token and chat_id)

    def send(self, alert) -> bool:
        if not self.enabled:
            return False
        a = asdict(alert) if not isinstance(alert, dict) else alert
        severity = a.get('severity', 'medium')
        rule = a.get('rule', 'unknown')
        evidence = a.get('evidence', [])
        evidence_text = '\n'.join(f'  `{line[:80]}`' for line in evidence[-3:])
        message = (
            f"{SEVERITY_EMOJI.get(severity,'🔔')} *SentinelLog Alert*\n\n"
            f"{RULE_EMOJI.get(rule,'🛡️')} *{a.get('title','Threat Detected')}*\n\n"
            f"📋 {a.get('description','')}\n\n"
            f"🔴 Severity: `{severity.upper()}`\n"
            f"📌 Rule: `{rule.replace('_',' ')}`\n"
        )
        if a.get('source_ip'):
            message += f"🌍 Source IP: `{a['source_ip']}`\n"
        if a.get('username'):
            message += f"👤 User: `{a['username']}`\n"
        message += f"📊 Events: `{a.get('event_count',1)}`\n"
        message += f"🕐 Time: `{a.get('timestamp','')[:19]}`\n"
        if evidence_text:
            message += f"\n📄 *Evidence:*\n{evidence_text}"
        def _send():
            try:
                requests.post(f"{self.base_url}/sendMessage",
                    json={'chat_id':self.chat_id,'text':message,'parse_mode':'Markdown'},
                    timeout=10)
            except Exception:
                pass
        threading.Thread(target=_send, daemon=True).start()
        return True

    def send_startup(self, target_name: str):
        if not self.enabled:
            return
        msg = (
            f"🛡️ *SentinelLog Started*\n\n"
            f"✅ Now monitoring: `{target_name}`\n"
            f"📱 Alerts will be sent here in real time"
        )
        def _send():
            try:
                requests.post(f"{self.base_url}/sendMessage",
                    json={'chat_id':self.chat_id,'text':msg,'parse_mode':'Markdown'},
                    timeout=10)
            except Exception:
                pass
        threading.Thread(target=_send, daemon=True).start()
