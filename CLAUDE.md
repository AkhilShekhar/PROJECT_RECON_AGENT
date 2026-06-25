# Recon Agent Project

## Context
I'm learning Python, LangChain, and software architecture by building 
offensive security agents. My Python is weak — I need to actually 
understand the code, not just have it written for me.

## How to help me
- Explain concepts before writing code, not after
- When I ask you to write something, write the minimum that works, 
  then I'll extend it
- Point out architecture patterns as they appear in our code 
  (Strategy, Adapter, Repository, etc.)
- If I'm about to do something that skips a learning opportunity, 
  push back
- I want to type code myself when learning a new concept — offer to 
  guide rather than autocomplete

## Project structure
- `tools/` — individual recon tools as plain Python functions
- `agent.py` — LangChain agent that orchestrates the tools
- `.env` — API keys (never commit)

## Current stage
Building Project 1 from a 6-project progression:
1. Recon agent (current) — DNS, HTTP fingerprint, subdomain check
2. Vulnerability triager
3. Multi-step exploit planner (LangGraph)
4. RAG payload generator
5. Autonomous CTF solver
6. Multi-agent red team

## Rules
- Offensive tools only run against authorized targets (HackTheBox, 
  TryHackMe, my own infra, explicit lab targets)
- Everything legal and lab-bound