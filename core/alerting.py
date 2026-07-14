"""
SentinelLog — Week 4
Multi-channel alerting: Telegram + Email (Gmail or any SMTP)
"""

import smtplib
import urllib.request
import urllib.parse
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dataclasses import asdict


SEVERITY_EMOJI = {
    'critical': '🚨',
    'high':     '⚠️',
    'medium':   '🔔',
    'low':      'ℹ️',
}

RULE_EMOJI = {
    'brute_force':          '🔐',
    'suspicious_time':      '🕐',
    '404_flood':            '🌐',
    'directory_traversal':  '📁',
    'privilege_escalation': '⛔',
}


class TelegramAlerter:
    def __init__(self, bot_token: str, chat_id: str):
        self.bot_token = bot_token
        self.chat_id = str(chat_id)
        self.base_url = f"https://api.telegram.org/bot{bot_token}"

    def send(self, alert) -> bool:
        sev_emoji = SEVERITY_EMOJI.get(alert.severity, '🔔')
        rule_emoji = RULE_EMOJI.get(alert.rule, '🛡️')
        lines = [
            f"{sev_emoji} *SentinelLog Alert*",
            f"",
            f"{rule_emoji} *{alert.title}*",
            f"",
            f"{alert.description}",
            f"",
        ]
        if alert.source_ip:
            lines.append(f"🌍 *IP:* `{alert.source_ip}`")
        if alert.username:
            lines.append(f"👤 *User:* `{alert.username}`")
        lines += [
            f"📊 *Events:* {alert.event_count}",
            f"⏰ *Time:* {alert.last_seen[:19]}",
            f"🔑 *Severity:* {alert.severity.upper()}",
        ]
        if alert.evidence:
            lines += ["", "📄 *Evidence:*", "```"]
            for line in alert.evidence[-3:]:
                lines.append(line[:120])
            lines.append("```")
        message = '\n'.join(lines)
        try:
            payload = urllib.parse.urlencode({
                'chat_id': self.chat_id,
                'text': message,
                'parse_mode': 'Markdown'
            }).encode()
            req = urllib.request.Request(
                f"{self.base_url}/sendMessage",
                data=payload, method='POST'
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status == 200
        except Exception as e:
            print(f"[Telegram] Failed: {e}")
            return False

    def test(self) -> bool:
        try:
            payload = urllib.parse.urlencode({
                'chat_id': self.chat_id,
                'text': '✅ *SentinelLog connected*\nTelegram alerting is active.',
                'parse_mode': 'Markdown'
            }).encode()
            req = urllib.request.Request(
                f"{self.base_url}/sendMessage",
                data=payload, method='POST'
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status == 200
        except Exception as e:
            print(f"[Telegram] Test failed: {e}")
            return False


class EmailAlerter:
    def __init__(self, smtp_host: str, smtp_port: int,
                 username: str, password: str,
                 from_addr: str, to_addr: str,
                 use_tls: bool = True):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.from_addr = from_addr
        self.to_addr = to_addr
        self.use_tls = use_tls

    @classmethod
    def gmail(cls, username: str, password: str, to_addr: str):
        """Convenience constructor for Gmail."""
        return cls(
            smtp_host='smtp.gmail.com',
            smtp_port=587,
            username=username,
            password=password,
            from_addr=username,
            to_addr=to_addr,
            use_tls=True
        )

    def send(self, alert) -> bool:
        sev_emoji = SEVERITY_EMOJI.get(alert.severity, '🔔')
        subject = f"{sev_emoji} SentinelLog Alert — {alert.title}"

        evidence_html = ""
        if alert.evidence:
            rows = ''.join(f"<tr><td style='font-family:monospace;font-size:12px;padding:4px 8px;border-bottom:1px solid #eee'>{line[:120]}</td></tr>" for line in alert.evidence[-5:])
            evidence_html = f"""
            <h3 style='color:#374151;font-size:14px;margin:20px 0 8px'>Evidence</h3>
            <table style='width:100%;background:#f9fafb;border-radius:6px;overflow:hidden;border:1px solid #e5e7eb'>
              {rows}
            </table>"""

        sev_color = {'critical':'#dc2626','high':'#d97706','medium':'#2563eb','low':'#6b7280'}.get(alert.severity,'#6b7280')

        html = f"""
        <div style='font-family:Inter,sans-serif;max-width:600px;margin:0 auto;background:#fff;border:1px solid #e5e7eb;border-radius:10px;overflow:hidden'>
          <div style='background:{sev_color};padding:20px 24px'>
            <div style='font-size:11px;color:rgba(255,255,255,0.8);letter-spacing:.1em;text-transform:uppercase;margin-bottom:4px'>SentinelLog Alert</div>
            <div style='font-size:20px;font-weight:600;color:#fff'>{alert.title}</div>
          </div>
          <div style='padding:24px'>
            <p style='color:#374151;font-size:14px;line-height:1.6;margin:0 0 20px'>{alert.description}</p>
            <table style='width:100%;border-collapse:collapse'>
              <tr>
                <td style='padding:8px 0;border-bottom:1px solid #f3f4f6;font-size:13px;color:#9ca3af;width:120px'>Severity</td>
                <td style='padding:8px 0;border-bottom:1px solid #f3f4f6;font-size:13px;color:#111827;font-weight:500'>{alert.severity.upper()}</td>
              </tr>
              <tr>
                <td style='padding:8px 0;border-bottom:1px solid #f3f4f6;font-size:13px;color:#9ca3af'>Rule</td>
                <td style='padding:8px 0;border-bottom:1px solid #f3f4f6;font-size:13px;color:#111827'>{alert.rule.replace('_',' ')}</td>
              </tr>
              {"<tr><td style='padding:8px 0;border-bottom:1px solid #f3f4f6;font-size:13px;color:#9ca3af'>Source IP</td><td style='padding:8px 0;border-bottom:1px solid #f3f4f6;font-size:13px;font-family:monospace;color:#111827'>" + alert.source_ip + "</td></tr>" if alert.source_ip else ""}
              {"<tr><td style='padding:8px 0;border-bottom:1px solid #f3f4f6;font-size:13px;color:#9ca3af'>User</td><td style='padding:8px 0;border-bottom:1px solid #f3f4f6;font-size:13px;font-family:monospace;color:#111827'>" + alert.username + "</td></tr>" if alert.username else ""}
              <tr>
                <td style='padding:8px 0;border-bottom:1px solid #f3f4f6;font-size:13px;color:#9ca3af'>Events</td>
                <td style='padding:8px 0;border-bottom:1px solid #f3f4f6;font-size:13px;color:#111827'>{alert.event_count}</td>
              </tr>
              <tr>
                <td style='padding:8px 0;font-size:13px;color:#9ca3af'>Time</td>
                <td style='padding:8px 0;font-size:13px;color:#111827'>{alert.last_seen[:19]}</td>
              </tr>
            </table>
            {evidence_html}
          </div>
          <div style='background:#f9fafb;padding:14px 24px;font-size:12px;color:#9ca3af'>
            Generated by SentinelLog · Open-source SIEM for small businesses
          </div>
        </div>"""

        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = self.from_addr
        msg['To'] = self.to_addr
        msg.attach(MIMEText(alert.description, 'plain'))
        msg.attach(MIMEText(html, 'html'))

        try:
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=10) as server:
                if self.use_tls:
                    server.starttls()
                server.login(self.username, self.password)
                server.sendmail(self.from_addr, self.to_addr, msg.as_string())
            return True
        except Exception as e:
            print(f"[Email] Failed: {e}")
            return False

    def test(self) -> bool:
        try:
            msg = MIMEText('SentinelLog email alerting is connected and working.', 'plain')
            msg['Subject'] = '✅ SentinelLog — Email connected'
            msg['From'] = self.from_addr
            msg['To'] = self.to_addr
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=10) as server:
                if self.use_tls:
                    server.starttls()
                server.login(self.username, self.password)
                server.sendmail(self.from_addr, self.to_addr, msg.as_string())
            return True
        except Exception as e:
            print(f"[Email] Test failed: {e}")
            return False


class AlertDispatcher:
    """
    Manages multiple alert channels for a session.
    Call dispatch(alert) to send to all configured channels.
    """

    def __init__(self):
        self.channels = []

    def add_telegram(self, token: str, chat_id: str):
        if token and chat_id:
            self.channels.append(TelegramAlerter(token, chat_id))

    def add_email(self, smtp_host: str, smtp_port: int,
                  username: str, password: str,
                  from_addr: str, to_addr: str,
                  use_tls: bool = True):
        if username and password and to_addr:
            self.channels.append(EmailAlerter(
                smtp_host, smtp_port, username,
                password, from_addr, to_addr, use_tls
            ))

    def add_gmail(self, username: str, password: str, to_addr: str):
        if username and password and to_addr:
            self.channels.append(EmailAlerter.gmail(username, password, to_addr))

    def dispatch(self, alert) -> dict:
        results = {}
        for ch in self.channels:
            name = ch.__class__.__name__
            results[name] = ch.send(alert)
        return results
