"""Historical URL and subdomain discovery via the Wayback Machine CDX API."""
import requests


def wayback_urls(target: str) -> dict:
    url = "http://web.archive.org/cdx/search/cdx"
    params = {
        "url": f"*.{target}/*",
        "output": "json",
        "fl": "original",
        "collapse": "urlkey",
        "limit": 200,
    }

    try:
        response = requests.get(url, params=params, timeout=20)
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.Timeout:
        return {"success": False, "error": "Wayback Machine request timed out"}
    except Exception as e:
        return {"success": False, "error": str(e)}

    # First row is the header ["original"], skip it
    raw_urls = [row[0] for row in data[1:]] if len(data) > 1 else []

    # Extract unique subdomains from the URLs
    subdomains = set()
    for raw_url in raw_urls:
        try:
            # Strip scheme, grab the hostname part
            host = raw_url.split("//")[-1].split("/")[0].split(":")[0].lower()
            if target in host:
                subdomains.add(host)
        except Exception:
            continue

    return {
        "success": True,
        "data": {
            "target": target,
            "total_urls": len(raw_urls),
            "subdomains": sorted(subdomains),
            "sample_urls": raw_urls[:10],
        },
    }
