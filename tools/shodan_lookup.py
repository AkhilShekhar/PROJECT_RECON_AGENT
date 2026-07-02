"""Shodan host and service lookup with Cloudflare origin IP discovery."""
import os
import shodan
from dotenv import load_dotenv

load_dotenv()

CLOUDFLARE_ASN = "AS13335"


def _parse_matches(matches: list) -> dict:
    """Deduplicate Shodan matches by IP, merging ports."""
    ip_map = {}
    for match in matches:
        ip = match.get("ip_str")
        if not ip:
            continue
        if ip not in ip_map:
            ip_map[ip] = {
                "ip": ip,
                "ports": [match.get("port")],
                "org": match.get("org"),
                "isp": match.get("isp"),
                "country": match.get("location", {}).get("country_name"),
                "asn": match.get("asn", ""),
            }
        else:
            ip_map[ip]["ports"].append(match.get("port"))
    return ip_map


def shodan_lookup(target: str) -> dict:
    """Search Shodan for a domain. Runs two queries:
    1. hostname search  — finds edge/CDN nodes
    2. SSL cert search excluding Cloudflare — finds potential origin IPs
    """
    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        return {"success": False, "error": "SHODAN_API_KEY not set in .env"}

    api = shodan.Shodan(api_key)

    # Query 1: standard hostname lookup
    try:
        hostname_results = api.search(f"hostname:{target}")
        hostname_hosts = _parse_matches(hostname_results.get("matches", []))
    except shodan.APIError as e:
        hostname_hosts = {}
        hostname_error = str(e)
    else:
        hostname_error = None

    # Query 2: SSL cert search, excluding Cloudflare ASN to find origin IP
    try:
        ssl_results = api.search(f'ssl:"{target}" -asn:{CLOUDFLARE_ASN}')
        ssl_hosts = _parse_matches(ssl_results.get("matches", []))
    except shodan.APIError:
        # Free Shodan accounts can't always run ssl: queries — degrade gracefully
        ssl_hosts = {}

    # Flag which IPs are likely Cloudflare
    all_hosts = {**hostname_hosts}
    for ip, host in ssl_hosts.items():
        if ip not in all_hosts:
            all_hosts[ip] = host

    for ip, host in all_hosts.items():
        host["is_cloudflare"] = host.get("asn") == CLOUDFLARE_ASN or "cloudflare" in (host.get("org") or "").lower()

    origin_candidates = [h for h in all_hosts.values() if not h["is_cloudflare"]]

    return {
        "success": True,
        "data": {
            "target": target,
            "all_hosts": list(all_hosts.values()),
            "origin_candidates": origin_candidates,
            "note": hostname_error or (
                "Origin candidates are IPs that present the domain SSL cert but are NOT on Cloudflare's ASN."
            ),
        },
    }
