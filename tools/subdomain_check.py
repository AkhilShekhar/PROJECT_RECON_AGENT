import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed

WORDLIST = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
    "portal", "vpn", "remote", "blog", "shop", "app", "cdn", "static",
    "beta", "dashboard", "login", "support", "help", "docs", "git",
    "jenkins", "ci", "monitor", "prometheus", "grafana", "kibana",
]


def _check_subdomain(subdomain: str, domain: str) -> dict | None:
    fqdn = f"{subdomain}.{domain}"
    try:
        answers = dns.resolver.resolve(fqdn, "A")
        return {"subdomain": fqdn, "ips": [str(r) for r in answers]}
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return None
    except Exception:
        return None


def subdomain_check(target: str, workers: int = 20) -> dict:
    found = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(_check_subdomain, sub, target): sub
            for sub in WORDLIST
        }
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)

    return {"success": True, "data": {"target": target, "found": found}}
