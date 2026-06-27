"""ASN and netblock discovery via ipinfo.io and bgpview.io."""
import requests


def asn_lookup(ip: str) -> dict:
    """Look up ASN and netblocks for a given IP address.
    
    Args:
        ip: IP address to lookup.
        
    Returns:
        Dictionary with success status, ASN details, and netblock information.
    """
    # Step 1: resolve the IP to an ASN
    try:
        ip_info = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10).json()
    except (requests.RequestException, ValueError) as e:
        return {"success": False, "error": f"ipinfo.io failed: {e}"}

    asn_raw = ip_info.get("org", "")  # format: "AS13335 Cloudflare, Inc."
    if not asn_raw or not asn_raw.startswith("AS"):
        return {"success": False, "error": "Could not determine ASN for this IP"}

    asn_number = asn_raw.split(" ")[0]          # "AS13335"
    org_name = " ".join(asn_raw.split(" ")[1:]) # "Cloudflare, Inc."

    # Step 2: get all netblocks owned by this ASN
    try:
        bgp_response = requests.get(
            f"https://api.bgpview.io/asn/{asn_number.replace('AS', '')}/prefixes",
            timeout=15,
        )
        bgp_data = bgp_response.json()
    except (requests.RequestException, ValueError) as e:
        return {"success": False, "error": f"bgpview.io failed: {e}"}

    ipv4_prefixes = [
        {
            "prefix": p.get("prefix"),
            "name": p.get("name"),
            "description": p.get("description"),
        }
        for p in bgp_data.get("data", {}).get("ipv4_prefixes", [])
    ]

    return {
        "success": True,
        "data": {
            "ip": ip,
            "asn": asn_number,
            "org": org_name,
            "country": ip_info.get("country"),
            "total_ipv4_ranges": len(ipv4_prefixes),
            "netblocks": ipv4_prefixes,
        },
    }
