import os
import re
import logging
from datetime import timezone
from dotenv import load_dotenv

from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

from app import db
from app.engines.url_engine import engine as url_engine
from app.bot.explainability import explain_risk

load_dotenv("C:\\Makeathon-main\\.env")

TELEGRAM_HTTP_API = os.getenv("TELEGRAM_HTTP_API")

logger = logging.getLogger("zenithal.bot")

URL_REGEX = re.compile(r'(https?://[^\s]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?)')

def escape_md2(text: str) -> str:
    """Escape characters for Telegram MarkdownV2."""
    if not text:
        return "Not available"
    # The list of characters to escape in MarkdownV2
    escape_chars = r'_*[]()~`>#+-=|{}.!'
    return re.sub(f'([{re.escape(escape_chars)}])', r'\\\1', str(text))

def get_fallback_str(val, fallback="Not available"):
    return val if val else fallback

def extract_url(text: str) -> str | None:
    match = URL_REGEX.search(text)
    if match:
        url = match.group(1)
        if not url.startswith("http"):
            url = "http://" + url
        return url
    return None

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "👋 Welcome to the Zenithal Threat Bot\\!\n"
        "Send me any URL or a message containing a link, and I will analyze it for phishing or malicious threats\\.",
        parse_mode="MarkdownV2"
    )

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "Just send a message with a link\\. For example:\n"
        "Check this out: http://example\\.com",
        parse_mode="MarkdownV2"
    )

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text or ""
    url = extract_url(text)
    
    if not url:
        await update.message.reply_text("I couldn't find a URL in your message\\. Please send a valid link\\!", parse_mode="MarkdownV2")
        return
        
    await update.message.reply_chat_action("typing")
    
    try:
        # 1. Fetch community data
        community_entry = await db.get_community_url(url)
        community_data = {}
        community_score_for_engine = None
        if community_entry:
            community_data = community_entry.to_dict()
            if community_data["report_count"] > 0:
                community_score_for_engine = community_data["risk_score"]

        # 2. Run engine analysis
        ai_result = url_engine.analyze(
            url, 
            with_ip_intel=True, 
            community_score=community_score_for_engine,
            return_breakdown=True
        )
        
        fused_score = round(ai_result.get("score", 50.0), 1)
        whois_data = ai_result.get("whois_intelligence") or {}
        ssl_data = ai_result.get("ssl_intelligence") or {}
        ip_data = ai_result.get("ip_intel") or {}
        
        # 3. Determine status
        report_count = community_data.get("report_count", 0)
        safe_votes = community_data.get("safe_votes", 0)
        malicious_votes = community_data.get("malicious_votes", 0)
        community_risk = community_data.get("risk_score", 50.0)

        if community_risk >= 70 and malicious_votes >= 3 and report_count >= 3 and fused_score >= 60:
            status = "verified\\_phishing"
        elif community_risk < 30 and safe_votes >= 2:
            status = "safe"
        else:
            status = "unverified"
            
        # 4. Telegram Sender info
        sender_user = update.message.from_user
        sender_info = {
            "username": sender_user.username if sender_user else None,
            "id": sender_user.id if sender_user else None,
            "first_name": sender_user.first_name if sender_user else None,
            "date": update.message.date.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if update.message.date else "Unknown"
        }
        
        # 5. Generate LLM Explainability JSON
        expl_json = await explain_risk(fused_score, whois_data, ssl_data, ip_data, community_data, sender_info)
        
        # Format Verdict Header
        if fused_score >= 70:
            emoji = "🔴"
            header_title = "Risky Link Detected"
        elif fused_score < 30:
            emoji = "🟢"
            header_title = "Safe Link"
        else:
            emoji = "🟡"
            header_title = "Unverified Link"
            
        # Format Domain Intel fields with explicit "Not available" fallback
        c_date = get_fallback_str(whois_data.get("creation_date"))
        c_age = str(whois_data.get("domain_age_days")) + " days" if whois_data.get("domain_age_days") is not None else "Not available"
        registrar = get_fallback_str(whois_data.get("registrar"))
        
        if whois_data.get("privacy_enabled"):
            registrant = "privacy-protected"
        else:
            reg_org = whois_data.get("registrant_org")
            reg_name = whois_data.get("registrant_name")
            if reg_org and reg_name:
                registrant = f"{reg_org} ({reg_name})"
            elif reg_org:
                registrant = reg_org
            elif reg_name:
                registrant = reg_name
            else:
                registrant = "Not available"
                
        ssl_exists = ssl_data.get("ssl_exists", False)
        if ssl_exists:
            if ssl_data.get("self_signed"):
                ssl_text = "self-signed"
            else:
                iss = get_fallback_str(ssl_data.get("issuer"))
                d_from = get_fallback_str(ssl_data.get("issued_on"))
                d_to = get_fallback_str(ssl_data.get("expires_on"))
                ssl_text = f"{iss} — valid {d_from} to {d_to}"
        else:
            ssl_text = "none"
            
        hosting_ip = get_fallback_str(ip_data.get("ip"))
        hosting_asn = get_fallback_str(ip_data.get("org"))
        hosting_geo = f"{ip_data.get('city', 'Unknown')}, {ip_data.get('country', 'Unknown')}"
        if hosting_geo == "Unknown, Unknown":
            hosting_geo = "Not available"

        sender_tag = f"@{sender_info['username']}" if sender_info.get("username") else sender_info.get("first_name", "Unknown User")
        
        # Format JSON response
        verdict_summary = expl_json.get("verdict_summary", "No verdict generated.")
        key_reasons = expl_json.get("key_reasons", [])
        reasons_text = "\n".join([f"• {escape_md2(r)}" for r in key_reasons])
        
        reply_text = (
            f"{emoji} *{escape_md2(header_title)}*\n"
            f"{escape_md2(url)}\n\n"
            f"*Verdict:* {escape_md2(verdict_summary)}\n\n"
            f"*Why:*\n"
            f"{reasons_text}\n\n"
            f"*Domain Intel:*\n"
            f"• Created: {escape_md2(c_date)} \\({escape_md2(c_age)}\\)\n"
            f"• Registrar: {escape_md2(registrar)}\n"
            f"• Registrant: {escape_md2(registrant)}\n"
            f"• SSL: {escape_md2(ssl_text)}\n"
            f"• Hosting: {escape_md2(hosting_ip)} \\· {escape_md2(hosting_asn)} \\· {escape_md2(hosting_geo)}\n\n"
            f"*Community:* {report_count} reports \\· {safe_votes}/{malicious_votes} votes \\· status: {status}\n\n"
            f"_Checked by {escape_md2(sender_tag)} at {escape_md2(sender_info['date'])}_"
        )
        
        await update.message.reply_text(reply_text, parse_mode="MarkdownV2", disable_web_page_preview=True)
        
    except Exception as e:
        logger.exception("Error processing URL in Telegram bot")
        await update.message.reply_text("Sorry, an error occurred while analyzing the URL\\.", parse_mode="MarkdownV2")

telegram_app = None

def get_telegram_app():
    global telegram_app
    if telegram_app is None and TELEGRAM_HTTP_API:
        telegram_app = Application.builder().token(TELEGRAM_HTTP_API).build()
        telegram_app.add_handler(CommandHandler("start", start_command))
        telegram_app.add_handler(CommandHandler("help", help_command))
        telegram_app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    return telegram_app
