import asyncio
import os
import sys

# Force UTF-8 stdout
sys.stdout.reconfigure(encoding='utf-8')

# Add backend to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from datetime import datetime, timezone
from app.bot.telegram_bot import handle_message

class MockMessage:
    def __init__(self, text):
        self.text = text
        self.date = datetime.now(timezone.utc)
        self.from_user = type("User", (), {"username": "test_user", "id": 12345, "first_name": "Test"})()
        self.replies = []
        
    async def reply_text(self, text, parse_mode=None, disable_web_page_preview=False):
        self.replies.append({"text": text, "parse_mode": parse_mode})

    async def reply_chat_action(self, action):
        pass

class MockUpdate:
    def __init__(self, text):
        self.message = MockMessage(text)

async def main():
    urls = [
        "https://google.com",
        "http://fake-login-paypal.xyz/verify",
        "http://does-not-exist-9999.xyz"
    ]
    
    for url in urls:
        print(f"\n{'='*50}")
        print(f"Testing URL: {url}")
        print(f"{'='*50}")
        update = MockUpdate(url)
        await handle_message(update, None)
        
        for reply in update.message.replies:
            print("--- RENDERED TELEGRAM MESSAGE ---")
            print(f"Parse Mode: {reply['parse_mode']}")
            print(reply['text'])

if __name__ == "__main__":
    asyncio.run(main())
