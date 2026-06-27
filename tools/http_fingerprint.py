"""HTTP response header fingerprinting."""
import requests
from tools.config import HTTP_HEADERS

FINGERPRINT_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-Generator",
    "X-Drupal-Cache",
    "X-Frame-Options",
]

COOKIE_SIGNATURES = {
    "PHPSESSID": "PHP",
    "ASP.NET_SessionId": "ASP.NET",
    "JSESSIONID": "Java (Tomcat/Spring)",
    "rack.session": "Ruby (Rack)",
    "connect.sid": "Node.js (Express)",
}


def http_fingerprint(target: str) -> dict:
    """Fetch HTTP headers from target and identify server technology."""
    if not target.startswith("https"):
        target = "https://" + target

    try:
        response = requests.get(target, headers=HTTP_HEADERS, timeout=10, allow_redirects=True)
    except requests.exceptions.ConnectionError:
        return {"success": False, "error": "Could not connect to target"}
    except requests.exceptions.Timeout:
        return {"success": False, "error": "Request timed out"}
    except requests.exceptions.RequestException as e:
        return {"success": False, "error": str(e)}

    headers = dict(response.headers)

    fingerprints = {
        header: headers[header]
        for header in FINGERPRINT_HEADERS
        if header in headers
    }

    detected_stack = []
    for cookie_name, technology in COOKIE_SIGNATURES.items():
        if cookie_name in response.cookies:
            detected_stack.append(technology)

    return {
        "success": True,
        "data": {
            "url": response.url,
            "status_code": response.status_code,
            "headers": fingerprints,
            "detected_stack": detected_stack,
        },
    }
