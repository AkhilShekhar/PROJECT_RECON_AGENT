# Project Recon Agent

An AI-powered reconnaissance agent for authorized penetration testing. Built with plain Python tools and a Groq-backed LLM agent loop — no LangChain.

## What it does

Give it a target domain and it runs:
- **DNS lookup** — A, AAAA, MX, NS, TXT records
- **HTTP fingerprinting** — server headers, tech stack detection
- **Subdomain enumeration** — concurrent wordlist-based discovery

## Setup

```bash
pip install dnspython requests groq python-dotenv
```

Create a `.env` file:
```
GROQ_API_KEY=your_key_here
```

Get a free Groq API key at [console.groq.com](https://console.groq.com).

## Usage

```bash
python agent.py
```

```
You: run a full recon on scanme.nmap.org
  [calling dns_lookup({'target': 'scanme.nmap.org'})]
  [calling http_fingerprint({'target': 'scanme.nmap.org'})]
  [calling subdomain_check({'target': 'scanme.nmap.org'})]

Agent: The target is running Apache on Ubuntu...
```

## Project structure

```
tools/
  dns_lookup.py       # DNS record enumeration via dnspython
  http_fingerprint.py # HTTP header analysis via requests
  subdomain_check.py  # Concurrent subdomain discovery
agent.py              # Groq LLM agent loop with tool use
test_tools.py         # Manual tool testing script
```

## Authorization

Only run against targets you are authorized to test:
- Your own infrastructure
- Lab platforms (HackTheBox, TryHackMe)
- Explicitly scoped engagements

## Part of a 6-project series

1. **Recon agent** ← current
2. Vulnerability triager
3. Multi-step exploit planner (LangGraph)
4. RAG payload generator
5. Autonomous CTF solver
6. Multi-agent red team
