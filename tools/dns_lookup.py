import dns.resolver


def dns_lookup(target: str) -> dict:
    results = {}
    record_types = ["A", "AAAA", "MX", "NS", "TXT"]

    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(target, record_type)
            results[record_type] = [str(r) for r in answers]
        except dns.resolver.NoAnswer:
            results[record_type] = []
        except dns.resolver.NXDOMAIN:
            return {"success": False, "error": "Domain does not exist"}
        except Exception as e:
            results[record_type] = [f"Error: {e}"]

    return {"success": True, "data": results}
