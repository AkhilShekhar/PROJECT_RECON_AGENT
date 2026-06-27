"""Concurrent HTTP/HTTPS liveness probe for a list of subdomains."""
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from tools.config import HTTP_HEADERS


def _probe(subdomain: str) -> dict | None:
    for scheme in ("https", "http"):
        url = f"{scheme}://{subdomain}"
        try:
            response = requests.get(
                url,
                headers=HTTP_HEADERS,
                timeout=8,
                allow_redirects=True,
            )
            return {
                "subdomain": subdomain,
                "url": response.url,
                "status": response.status_code,
                "server": response.headers.get("Server", ""),
                "title": _extract_title(response.text),
            }
        except requests.exceptions.SSLError:
            continue
        except Exception:
            continue
    return None


def _extract_title(html: str) -> str:
    try:
        start = html.lower().index("<title>") + 7
        end = html.lower().index("</title>")
        return html[start:end].strip()[:100]
    except ValueError:
        return ""


def probe_alive(subdomains: str, workers: int = 20) -> dict:
    targets = [s.strip() for s in subdomains.split(",") if s.strip()]
    alive = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(_probe, t): t for t in targets}
        for future in as_completed(futures):
            result = future.result()
            if result:
                alive.append(result)

    alive.sort(key=lambda x: x["subdomain"])

    return {
        "success": True,
        "data": {
            "total_probed": len(targets),
            "alive": len(alive),
            "hosts": alive,
        },
    }
