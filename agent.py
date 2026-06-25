import json
import os
from dotenv import load_dotenv
from groq import Groq

from tools.dns_lookup import dns_lookup
from tools.http_fingerprint import http_fingerprint
from tools.subdomain_check import subdomain_check

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
]

TOOL_MAP = {
    "dns_lookup": dns_lookup,
    "http_fingerprint": http_fingerprint,
    "subdomain_check": subdomain_check,
}

SYSTEM_PROMPT = """You are a recon assistant for authorized penetration testing.
When given a target, use the available tools to gather information.
Only run tools against targets the user has confirmed are authorized.
Summarize findings clearly and highlight anything that looks interesting."""


def run_agent(user_input: str):
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_input},
    ]

    while True:
        response = client.chat.completions.create(
            model=MODEL,
            messages=messages,
            tools=TOOLS,
            tool_choice="auto",
        )

        message = response.choices[0].message

        # No tool calls — Claude is done, print final answer
        if not message.tool_calls:
            print(f"\nAgent: {message.content}\n")
            break

        # Execute every tool the model requested
        messages.append(message)

        for tool_call in message.tool_calls:
            name = tool_call.function.name
            args = json.loads(tool_call.function.arguments)

            print(f"  [calling {name}({args})]")

            func = TOOL_MAP[name]
            result = func(**args)

            messages.append({
                "role": "tool",
                "tool_call_id": tool_call.id,
                "content": json.dumps(result),
            })


if __name__ == "__main__":
    print("Recon Agent — type a target or task. Ctrl+C to exit.\n")
    while True:
        try:
            user_input = input("You: ").strip()
            if user_input:
                run_agent(user_input)
        except KeyboardInterrupt:
            print("\nExiting.")
            break
