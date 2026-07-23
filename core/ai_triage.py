"""
SentinelLog — AI Triage

Turns a raw rule match into a plain-language verdict, the way a Tier-1 SOC
analyst would explain it to someone who isn't a security engineer. This is
the actual differentiator: instead of a business owner reading
"brute_force: 6 events from 185.220.101.45", they read a couple of honest
sentences about what happened and what to actually do about it.

Requires OPENAI_API_KEY in .env. If it's missing, or the call fails or
times out, investigate() returns None and the caller falls back to the
existing raw alert — this must never be able to break monitoring itself.
"""
import os

SYSTEM_PROMPT = """You are a calm, plain-spoken Tier-1 security analyst writing a message that will be read by a small business owner on WhatsApp or Telegram, not a security engineer. They may not know what an IP address is.

Given the details of a triggered security alert, write a short verdict in 3-5 sentences:
1. What actually happened, in plain language, no jargon.
2. How worried they should genuinely be — be honest, don't inflate small things into emergencies, and don't undersell real ones.
3. One clear, concrete next action they should take right now.

Do not use technical terms like "brute force," "threshold," or "regex" without immediately explaining what it means in plain words. Do not pad with disclaimers. Write like a person, not a report."""


def investigate(alert, baseline_context: str = None) -> str | None:
    api_key = os.environ.get('OPENAI_API_KEY')
    if not api_key:
        return None

    try:
        from openai import OpenAI
    except ImportError:
        print("[AI Triage] 'openai' package not installed — run: pip install openai")
        return None

    evidence_text = "\n".join(alert.evidence[-5:]) if alert.evidence else "(no raw log lines captured)"

    user_prompt = f"""Alert type: {alert.rule}
Severity: {alert.severity}
Title: {alert.title}
Technical description: {alert.description}
Source IP: {alert.source_ip or 'n/a'}
Username involved: {alert.username or 'n/a'}
Number of events: {alert.event_count}
First seen: {alert.first_seen}
Last seen: {alert.last_seen}

Raw log evidence:
{evidence_text}"""

    if baseline_context:
        user_prompt += f"\n\nWhat's actually normal for this account, based on real history:\n{baseline_context}\n\nUse this to say specifically how today's event compares to their real pattern, not just describe today's event on its own."

    try:
        client = OpenAI(api_key=api_key, timeout=15.0)
        response = client.chat.completions.create(
            model="gpt-4o-mini",  # fast + cheap, fits an SMB price point — swap to gpt-4o for deeper reasoning if needed
            max_tokens=300,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        print(f"[AI Triage] Failed, falling back to raw alert: {e}")
        return None
