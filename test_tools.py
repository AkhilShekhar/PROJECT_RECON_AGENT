from tools.dns_lookup import dns_lookup
from tools.http_fingerprint import http_fingerprint
from tools.subdomain_check import subdomain_check

TARGET = "api.cloudways.com"

print(f"\n{'='*50}")
print(f"TARGET: {TARGET}")
print(f"{'='*50}")

print("\n[1] DNS LOOKUP")
result = dns_lookup(TARGET)
if result["success"]:
    for record_type, values in result["data"].items():
        if values:
            print(f"  {record_type}: {values}")
else:
    print(f"  ERROR: {result['error']}")

print("\n[2] HTTP FINGERPRINT")
result = http_fingerprint(TARGET)
if result["success"]:
    data = result["data"]
    print(f"  Status : {data['status_code']}")
    print(f"  URL    : {data['url']}")
    for header, value in data["headers"].items():
        print(f"  {header}: {value}")
    if data["detected_stack"]:
        print(f"  Stack  : {data['detected_stack']}")
else:
    print(f"  ERROR: {result['error']}")

print("\n[3] SUBDOMAIN CHECK")
result = subdomain_check(TARGET)
if result["success"]:
    found = result["data"]["found"]
    if found:
        for item in found:
            print(f"  {item['subdomain']} -> {item['ips']}")
    else:
        print("  No subdomains found")
else:
    print(f"  ERROR: {result['error']}")
