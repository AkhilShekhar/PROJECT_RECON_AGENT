"""Shared HTTP headers for all outbound requests."""
import os
from dotenv import load_dotenv

load_dotenv()

HTTP_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "X-Bug-Bounty": os.getenv("BUGBOUNTY_HANDLE", "security-researcher"),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}
