"""Recon agent CLI that uses Groq to orchestrate recon tools.

This module provides a simple REPL to run an LLM-based agent which can
call local reconnaissance tools. It is intended for authorized
penetration testing only.
"""

import json
import os
from dotenv import load_dotenv
from groq import Groq

from tools.dns_lookup import dns_lookup
from tools.http_fingerprint import http_fingerprint
from tools.subdomain_check import subdomain_check
from tools.crt_search import crt_search
from tools.wayback_urls import wayback_urls
from tools.shodan_lookup import shodan_lookup
from tools.asn_lookup import asn_lookup
from tools.probe_alive import probe_alive
from tools.db import init_db, save_finding, get_targets, query_findings

load_dotenv()

client = Groq(api_key=os.getenv("GROQ_API_KEY"))
MODEL = "llama-3.3-70b-versatile"

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "dns_lookup",
            "description": "Look up DNS records (A, AAAA, MX, NS, TXT) for a domain.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "The domain to query, e.g. hackthebox.com"}
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "http_fingerprint",
            "description": "Fingerprint a web server by reading its HTTP response headers.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "The domain or URL to fingerprint"}
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "subdomain_check",
            "description": "Discover subdomains of a domain using a wordlist.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "The base domain to enumerate, e.g. hackthebox.com"}
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "crt_search",
            "description": "Search certificate transparency logs on crt.sh to find subdomains and exposed hosts.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "The base domain to search, e.g. hackthebox.com"}
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "wayback_urls",
            "description": "Fetch historical URLs from the Wayback Machine to find subdomains and old endpoints.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "The base domain to query, e.g. hackthebox.com"}
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "shodan_lookup",
            "description": "Search Shodan using shodan API for origin IP, hosts, open ports, and services associated with a domain or IP.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "The domain or IP to search on Shodan"}
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "asn_lookup",
            "description": "Given an IP address, find its ASN number and all netblocks owned by that organization.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ip": {"type": "string", "description": "The IP address to look up"}
                },
                "required": ["ip"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "probe_alive",
            "description": "Check which subdomains are alive by probing HTTP/HTTPS. Takes a comma-separated list of subdomains.",
            "parameters": {
                "type": "object",
                "properties": {
                    "subdomains": {"type": "string", "description": "Comma-separated list of subdomains to probe, e.g. www.example.com,api.example.com"}
                },
                "required": ["subdomains"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "query_findings",
            "description": "Query the local database for past recon findings on a domain. Use this before running tools to check if we already have results.",
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "The domain to look up in the database, e.g. cloudways.com"},
                    "tool_name": {"type": "string", "description": "Optional: filter by a specific tool name, e.g. crt_search. Leave empty to get all findings."},
                },
                "required": ["domain"],
            },
        },
    },
]

TOOL_MAP = {
    "dns_lookup": dns_lookup,
    "http_fingerprint": http_fingerprint,
    "subdomain_check": subdomain_check,
    "crt_search": crt_search,
    "wayback_urls": wayback_urls,
    "shodan_lookup": shodan_lookup,
    "asn_lookup": asn_lookup,
    "probe_alive": probe_alive,
    "query_findings": query_findings,
}

SYSTEM_PROMPT = """You are a recon assistant for authorized penetration testing.

Workflow rules:
1. Always call query_findings first to check if we already have data for a target before running tools.
2. For subdomain enumeration, always use the base domain (e.g. cloudways.com not api.cloudways.com).
3. Run tools in logical order: DNS → HTTP fingerprint → subdomain enum → probe alive → Shodan → ASN.
4. If a tool fails (success: false), note the error and continue with the remaining tools.
5. After all tools complete, summarize findings concisely: IPs, alive subdomains, open ports, and anything unusual.

Only run tools against targets the user has confirmed are authorized."""

HISTORY_FILE = "conversation_history.json"
MAX_HISTORY = 20  # max messages to keep (excluding system prompt)


def _message_to_dict(msg) -> dict:
    """Convert a Groq ChatCompletionMessage object to a plain dict for JSON serialization."""
    if isinstance(msg, dict):
        return msg
    d = {"role": msg.role, "content": msg.content}
    if msg.tool_calls:
        d["tool_calls"] = [
            {
                "id": tc.id,
                "type": "function",
                "function": {
                    "name": tc.function.name,
                    "arguments": tc.function.arguments,
                },
            }
            for tc in msg.tool_calls
        ]
    return d


def load_conversation() -> list:
    """Load conversation history from disk, or start fresh."""
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, encoding="utf-8") as f:
            return json.load(f)
    return [{"role": "system", "content": SYSTEM_PROMPT}]


def save_conversation() -> None:
    """Persist current conversation history to disk."""
    with open(HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump([_message_to_dict(m) for m in conversation], f, indent=2)


conversation = load_conversation()


def _trim_conversation() -> None:
    """Drop oldest messages when history exceeds MAX_HISTORY, keeping system prompt."""
    if len(conversation) > MAX_HISTORY + 1:
        del conversation[1 : len(conversation) - MAX_HISTORY]


def _compress_conversation() -> None:
    """After a turn, strip raw tool call/result messages — keep only text turns.

    The assistant summary already contains the synthesised findings, so the
    raw JSON tool results are dead weight that bloat future API calls.
    """
    compressed = [
        msg for msg in conversation
        if not (
            (isinstance(msg, dict) and msg.get("role") == "tool")
            or (isinstance(msg, dict) and msg.get("role") == "assistant" and msg.get("tool_calls"))
            or (not isinstance(msg, dict) and getattr(msg, "tool_calls", None))
        )
    ]
    conversation.clear()
    conversation.extend(compressed)


def run_agent(user_input: str):
    conversation.append({"role": "user", "content": user_input})
    _trim_conversation()

    while True:
        response = client.chat.completions.create(
            model=MODEL,
            messages=conversation,
            tools=TOOLS,
            tool_choice="auto",
        )

        message = response.choices[0].message

        if not message.tool_calls:
            print(f"\nAgent: {message.content}\n")
            conversation.append({"role": "assistant", "content": message.content})
            _compress_conversation()
            save_conversation()
            break

        conversation.append(message)

        for tool_call in message.tool_calls:
            name = tool_call.function.name
            args = json.loads(tool_call.function.arguments)

            print(f"  [calling {name}({args})]")

            func = TOOL_MAP[name]
            result = func(**args)

            domain = args.get("target") or args.get("ip") or args.get("subdomains", "").split(",")[0].strip()
            if domain:
                save_finding(domain, name, result)

            conversation.append({
                "role": "tool",
                "tool_call_id": tool_call.id,
                "content": json.dumps(result),
            })


if __name__ == "__main__":
    init_db()
    print("Recon Agent — type a target or task. Ctrl+C to exit.")
    known = get_targets()
    if known:
        print(f"Known targets in DB: {', '.join(known)}")
    print()
    while True:
        try:
            user_input = input("You: ").strip()
            if user_input:
                run_agent(user_input)
        except KeyboardInterrupt:
            print("\nExiting.")
            break
