"""Passive DNS-response correlation for LinkShield.

A DNS association is a clue, not proof that a particular flow used a hostname.
We intentionally return no association if several names share one IP.
"""

from ipaddress import ip_address
from time import monotonic

from scapy.layers.dns import DNS, DNSRR


class DNSCorrelator:
    def __init__(self):
        # remote IP -> {DNS answer name: monotonic expiry}
        self._records: dict[str, dict[str, float]] = {}
        self._last_cleanup = monotonic()

    def observe(self, packet) -> None:
        if DNS not in packet:
            return

        dns = packet[DNS]
        if int(dns.qr) != 1 or int(dns.rcode) != 0:
            return

        now = monotonic()
        for answer in (dns.an or []):
            if not isinstance(answer, DNSRR) or int(answer.type) not in (1, 28):
                continue

            try:
                ip = str(ip_address(answer.rdata))
                name = answer.rrname.decode("ascii", errors="ignore").rstrip(".").lower()
                ttl = min(int(answer.ttl), 3600)
            except (ValueError, TypeError, AttributeError):
                continue

            if name and ttl > 0:
                self._records.setdefault(ip, {})[name] = now + ttl

        # Bound memory growth during long-running capture.
        if now - self._last_cleanup >= 60:
            self._cleanup(now)
            self._last_cleanup = now

    def lookup(self, remote_ip: str | None) -> str | None:
        if not remote_ip:
            return None

        names = self._records.get(remote_ip)
        if not names:
            return None

        now = monotonic()
        active = [name for name, expiry in names.items() if expiry > now]
        if not active:
            self._records.pop(remote_ip, None)
            return None

        # A shared IP can serve several domains: don't present a guess.
        if len(active) != 1:
            return None

        return active[0]

    def _cleanup(self, now: float) -> None:
        for ip, names in list(self._records.items()):
            for name, expiry in list(names.items()):
                if expiry <= now:
                    del names[name]
            if not names:
                del self._records[ip]
