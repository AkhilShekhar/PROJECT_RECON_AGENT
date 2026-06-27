"""Shodan host and service lookup."""
import os
import shodan
from dotenv import load_dotenv

load_dotenv()


def shodan_lookup(target: str) -> dict:
    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        return {"success": False, "error": "SHODAN_API_KEY not set in .env"}

    api = shodan.Shodan(api_key)

    try:
        results = api.search(f"hostname:{target}")
    except shodan.APIError as e:
        return {"success": False, "error": str(e)}

    hosts = []
    for match in results.get("matches", []):
        hosts.append({
            "ip": match.get("ip_str"),
            "ports": [match.get("port")],
            "org": match.get("org"),
            "isp": match.get("isp"),
            "country": match.get("location", {}).get("country_name"),
            "banner": match.get("data", "")[:200],
        })

    # Deduplicate by IP, merging ports
    ip_map = {}
    for host in hosts:
        ip = host["ip"]
        if ip not in ip_map:
            ip_map[ip] = host
        else:
            ip_map[ip]["ports"].extend(host["ports"])

    return {
        "success": True,
        "data": {
            "target": target,
            "total_results": results.get("total", 0),
            "hosts": list(ip_map.values()),
        },
    }
