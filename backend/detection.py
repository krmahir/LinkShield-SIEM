
from ipaddress import ip_address, ip_network


# Test-only watchlist.
# Replace with verified indicators when ready.
WATCHLIST = [
    ip_network("203.0.113.10/32"),
]


def detect_remote_ip(remote_ip: str | None):
    findings = []

    if not remote_ip:
        return findings

    try:
        address = ip_address(remote_ip)

    except ValueError:
        return findings

    for network in WATCHLIST:
        if address in network:
            findings.append({
                "rule_id": "LS-001",
                "title": "Connection involving watchlisted IP",
                "severity": "medium",
                "description": (
                    f"Connection observed involving {address}. "
                    "Review the destination and associated process."
                ),
            })

            break

    return findings
