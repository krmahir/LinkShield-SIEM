
import socket
import threading
import time
from datetime import datetime, timezone

import psutil
import requests

from scapy.all import (
    AsyncSniffer,
    conf,
    IP,
    IPv6,
    TCP,
    UDP,
    ICMP,
    ARP,
    DNS,
    DNSQR,
)
from process_attribution import ProcessResolver
from dns_correlator import DNSCorrelator


API_URL = "http://127.0.0.1:8001/flows"

WINDOWS_INTERFACE = "Wi-Fi"
SCAPY_INTERFACE_INDEX = 18

FLUSH_INTERVAL = 5
MAX_BATCH_SIZE = 200

INTERFACE = conf.ifaces.dev_from_index(
    SCAPY_INTERFACE_INDEX
)

lock = threading.Lock()
pending_flows = {}
process_resolver = ProcessResolver()
dns_correlator = DNSCorrelator()


def get_local_ips():
    addresses = set()

    for address in psutil.net_if_addrs().get(
        WINDOWS_INTERFACE, []
    ):
        if address.family in (
            socket.AF_INET,
            socket.AF_INET6,
        ):
            addresses.add(
                address.address.split("%")[0]
            )

    return addresses


LOCAL_IPS = get_local_ips()


def merge_flow(target, incoming):
    target["packet_count"] += incoming["packet_count"]
    target["byte_count"] += incoming["byte_count"]

    target["observed_at"] = max(
        target["observed_at"],
        incoming["observed_at"],
    )

    # Keep a known process owner if a failed batch is retried.
    if target.get("process_id") is None and incoming.get("process_id") is not None:
        target["process_name"] = incoming.get("process_name")
        target["process_id"] = incoming["process_id"]

    if not target.get("observed_dns_name") and incoming.get("observed_dns_name"):
        target["observed_dns_name"] = incoming["observed_dns_name"]


def process_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

    elif IPv6 in packet:
        src_ip = packet[IPv6].src
        dst_ip = packet[IPv6].dst

    elif ARP in packet:
        src_ip = packet[ARP].psrc
        dst_ip = packet[ARP].pdst

    else:
        return

    src_port = None
    dst_port = None
    dns_query = None

    if TCP in packet:
        protocol = "TCP"
        src_port = int(packet[TCP].sport)
        dst_port = int(packet[TCP].dport)

    elif UDP in packet:
        protocol = "UDP"
        src_port = int(packet[UDP].sport)
        dst_port = int(packet[UDP].dport)

    elif ICMP in packet:
        protocol = "ICMP"

    elif ARP in packet:
        protocol = "ARP"

    else:
        protocol = "OTHER"

    if src_ip in LOCAL_IPS:
        direction = "outbound"

    elif dst_ip in LOCAL_IPS:
        direction = "inbound"

    else:
        direction = "other"

    owner = None

    if direction == "outbound":
        owner = process_resolver.lookup(
            protocol,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
        )

    elif direction == "inbound":
        owner = process_resolver.lookup(
            protocol,
            dst_ip,
            dst_port,
            src_ip,
            src_port,
        )

    # Attribution is optional for both inbound and outbound packets.
    process_name, process_id = owner if owner else (None, None)

    # Learn IP-to-name associations from visible DNS responses.
    dns_correlator.observe(packet)

    if DNS in packet and DNSQR in packet:
        if packet[DNS].qr == 0:
            dns_query = (
                packet[DNSQR]
                .qname.decode(errors="replace")
                .rstrip(".")
            )[:253]

    remote_ip = (
        src_ip if direction == "inbound"
        else dst_ip if direction == "outbound"
        else None
    )
    observed_dns_name = dns_correlator.lookup(remote_ip)

    key = (
        direction,
        protocol,
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        dns_query,
    )

    observed_at = datetime.now(
        timezone.utc
    ).isoformat()

    with lock:
        if key in pending_flows:
            pending_flows[key]["packet_count"] += 1
            pending_flows[key]["byte_count"] += len(packet)
            pending_flows[key]["observed_at"] = observed_at

            # A later packet may be attributable when the first was not.
            if owner and pending_flows[key].get("process_id") is None:
                pending_flows[key]["process_name"] = process_name
                pending_flows[key]["process_id"] = process_id

            if observed_dns_name and not pending_flows[key].get("observed_dns_name"):
                pending_flows[key]["observed_dns_name"] = observed_dns_name

        else:
            pending_flows[key] = {
                "direction": direction,
                "protocol": protocol,
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "packet_count": 1,
                "byte_count": len(packet),
                "dns_query": dns_query,
                "observed_at": observed_at,
                "process_name": process_name,
                "process_id": process_id,
                "observed_dns_name": observed_dns_name,
            }


def flush_flows():
    global pending_flows

    with lock:
        snapshot = pending_flows
        pending_flows = {}

    if not snapshot:
        return

    items = list(snapshot.items())

    for start in range(0, len(items), MAX_BATCH_SIZE):
        batch = items[start:start + MAX_BATCH_SIZE]

        payload = {
            "hostname": socket.gethostname(),
            "flows": [flow for _, flow in batch],
        }

        try:
            response = requests.post(
                API_URL,
                json=payload,
                timeout=10,
            )

            response.raise_for_status()

            print(
                f"[SENT] {len(batch)} flow summaries"
            )

        except requests.RequestException as error:
            print(f"[ERROR] Delivery failed: {error}")

            # Restore unsent flows for the next attempt.
            with lock:
                for key, flow in items[start:]:
                    if key in pending_flows:
                        merge_flow(pending_flows[key], flow)
                    else:
                        pending_flows[key] = flow

            break


def main():
    if not LOCAL_IPS:
        raise RuntimeError(
            "No local IP addresses found for Wi-Fi"
        )

    print("LinkShield Network Flow Collector")
    print(f"Interface: {INTERFACE}")
    print(f"Local IPs: {LOCAL_IPS}")

    process_resolver.start()
    sniffer = None

    try:
        sniffer = AsyncSniffer(
            iface=INTERFACE,
            prn=process_packet,
            store=False,
            promisc=False,
        )
        sniffer.start()
        print("[STARTED] Capturing network packets")
        while True:
            time.sleep(FLUSH_INTERVAL)
            flush_flows()

    except KeyboardInterrupt:
        print("\n[STOPPING] Flow collector")

    finally:
        try:
            if sniffer is not None and sniffer.running:
                sniffer.stop()
            flush_flows()
        finally:
            process_resolver.stop()
            print("[STOPPED] Flow collector")


if __name__ == "__main__":
    main()
