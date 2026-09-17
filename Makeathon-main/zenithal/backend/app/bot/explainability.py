import os
import httpx
import logging
import json
from dotenv import load_dotenv

load_dotenv("C:\\Makeathon-main\\.env")

logger = logging.getLogger("zenithal.bot.explainability")

GROQ_API_KEY = os.getenv("GROQ_API_KEY")

async def get_active_model(client: httpx.AsyncClient) -> str:
    """Fetch an active model from Groq dynamically."""
    try:
        response = await client.get(
            "https://api.groq.com/openai/v1/models",
            headers={"Authorization": f"Bearer {GROQ_API_KEY}"},
            timeout=10.0
        )
        if response.status_code == 200:
            data = response.json()
            models = [m["id"] for m in data.get("data", [])]
            for m in models:
                if "llama3" in m.lower():
                    return m
            if models:
                return models[0]
    except Exception as e:
        logger.warning(f"Failed to fetch Groq models: {e}")
    return "llama3-8b-8192"

def _build_fallback(fused_score: float) -> dict:
    return {
        "verdict_summary": f"This link received a risk score of {fused_score:.1f}/100.",
        "key_reasons": [
            "We were unable to generate a detailed AI explanation.",
            "The score is based on domain age, SSL status, and structure.",
            "Please exercise caution."
        ],
        "confidence_note": "Based on fallback automated analysis."
    }

async def explain_risk(fused_score: float, whois: dict, ssl: dict, ip_intel: dict, community: dict, sender: dict) -> dict:
    """Generate structured JSON explaining the risk."""
    if not GROQ_API_KEY:
        logger.warning("GROQ_API_KEY not found. Using fallback explanation.")
        return _build_fallback(fused_score)

    system_prompt = (
        "You are a helpful cybersecurity assistant for a Telegram bot. "
        "Your job is to explain why a URL received its specific risk score (0-100, where 100 is most dangerous). "
        "You will receive concrete forensic detail including WHOIS (domain creation, registrar, registrant), "
        "SSL (certificate issuer, validity), IP Intel (hosting provider, geo), Community reports, and the Telegram sender's info. "
        "IMPORTANT RULES:\n"
        "1. Never fabricate fields that are missing or null. If something is missing, just state it's unavailable.\n"
        "2. If WHOIS privacy_enabled is true, state that the registrant is privacy-protected.\n"
        "3. Explicitly differentiate between the 'Registrant' (who owns the domain) and the 'Telegram Sender' (the user who asked you to check the link).\n\n"
        "You MUST output ONLY valid JSON in the following exact format without Markdown wrappers:\n"
        "{\n"
        '  "verdict_summary": "1-2 sentence plain-English verdict",\n'
        '  "key_reasons": ["short bullet", "short bullet", "short bullet"],\n'
        '  "confidence_note": "1 sentence on how solid the evidence is"\n'
        "}"
    )
    
    # Format the inputs safely
    whois_str = (
        f"Creation Date: {whois.get('creation_date', 'Unknown')} (Age: {whois.get('domain_age_days', 'Unknown')} days)\n"
        f"Registrar: {whois.get('registrar', 'Unknown')}\n"
        f"Privacy Enabled: {whois.get('privacy_enabled', False)}\n"
        f"Registrant Org: {whois.get('registrant_org', 'Unknown')}\n"
        f"Registrant Name: {whois.get('registrant_name', 'Unknown')}\n"
    )
    ssl_str = (
        f"Exists: {ssl.get('ssl_exists', False)}\n"
        f"Issuer: {ssl.get('issuer', 'Unknown')}\n"
        f"Valid from {ssl.get('issued_on', 'Unknown')} to {ssl.get('expires_on', 'Unknown')}\n"
        f"Self-signed: {ssl.get('self_signed', False)}\n"
    )
    ip_str = (
        f"IP: {ip_intel.get('ip', 'Unknown')}\n"
        f"ASN Org: {ip_intel.get('org', 'Unknown')}\n"
        f"Location: {ip_intel.get('city', 'Unknown')}, {ip_intel.get('country', 'Unknown')}\n"
    )
    comm_str = (
        f"Reports: {community.get('report_count', 0)}\n"
        f"Safe Votes: {community.get('safe_votes', 0)} | Malicious Votes: {community.get('malicious_votes', 0)}\n"
    )
    sender_str = (
        f"Username: @{sender.get('username', 'Unknown')} (ID: {sender.get('id', 'Unknown')})\n"
        f"Time: {sender.get('date', 'Unknown')}\n"
    )

    user_prompt = (
        f"Fused Risk Score: {fused_score:.1f}/100\n\n"
        f"--- WHOIS Data ---\n{whois_str}\n"
        f"--- SSL Data ---\n{ssl_str}\n"
        f"--- IP Data ---\n{ip_str}\n"
        f"--- Community Data ---\n{comm_str}\n"
        f"--- Telegram Sender ---\n{sender_str}\n\n"
        "Produce the JSON."
    )

    try:
        async with httpx.AsyncClient() as client:
            model = await get_active_model(client)
            
            response = await client.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {GROQ_API_KEY}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt}
                    ],
                    "temperature": 0.3,
                    "response_format": {"type": "json_object"},
                    "max_tokens": 300
                },
                timeout=15.0
            )
            
            if response.status_code == 200:
                data = response.json()
                content = data["choices"][0]["message"]["content"].strip()
                return json.loads(content)
            else:
                logger.error(f"Groq API error: {response.status_code} - {response.text}")
                return _build_fallback(fused_score)
                
    except Exception as e:
        logger.error(f"Failed to generate explanation from Groq: {e}")
        return _build_fallback(fused_score)
