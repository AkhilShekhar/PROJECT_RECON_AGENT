"""Certificate transparency log search via crt.sh."""
import time
import requests


def crt_search(target: str, retries: int = 2) -> dict:
    """Search certificate transparency logs for subdomains of a target domain.
    
    Args:
        target: The target domain to search for.
        
    Returns:
        A dictionary with 'success' status and either 'data' with subdomains or 'error' message.
    """
    url = f"https://crt.sh/?q=%.{target}&output=json"

    last_error = ""
    for attempt in range(retries):
        try:
            response = requests.get(url, timeout=15)
            response.raise_for_status()
            entries = response.json()
            break
        except requests.exceptions.Timeout:
            last_error = "crt.sh request timed out"
        except requests.exceptions.RequestException as e:
            last_error = str(e)
        if attempt < retries - 1:
            time.sleep(3)
    else:
        return {"success": False, "error": last_error}

    subdomains = set()
    for entry in entries:
        # name_value can contain multiple names separated by newlines
        names = entry.get("name_value", "").split("\n")
        for name in names:
            name = name.strip().lower()
            if name and not name.startswith("*"):
                subdomains.add(name)

    return {
        "success": True,
        "data": {
            "target": target,
            "total_certs": len(entries),
            "subdomains": sorted(subdomains),
        },
    }
