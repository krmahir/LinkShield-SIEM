
import socket
from datetime import datetime

import psutil

from scapy.all import (
    conf,
    sniff,
    IP,
    IPv6,
    TCP,
    UDP,
    ICMP,
    ARP,
    DNS,
    DNSQR,
)


WINDOWS_INTERFACE = "Wi-Fi"
SCAPY_INTERFACE_INDEX = 18

INTERFACE = conf.ifaces.dev_from_index(
    SCAPY_INTERFACE_INDEX
)


def get_local_ips():
    addresses = set()

    interfaces = psutil.net_if_addrs()

    for address in interfaces.get(WINDOWS_INTERFACE, []):
        if address.family in (
            socket.AF_INET,
            socket.AF_INET6,
        ):
            ip = address.address.split("%")[0]
            addresses.add(ip)

    return addresses


LOCAL_IPS = get_local_ips()


def process_packet(packet):
    timestamp = datetime.now().strftime("%H:%M:%S")

    source_port = "-"
    destination_port = "-"
    domain = ""

    if IP in packet:
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

    elif IPv6 in packet:
        source_ip = packet[IPv6].src
        destination_ip = packet[IPv6].dst

    elif ARP in packet:
        source_ip = packet[ARP].psrc
        destination_ip = packet[ARP].pdst

    else:
        print(
            f"[{timestamp}] OTHER "
            f"| {packet.summary()}"
        )
        return

    if TCP in packet:
        protocol = "TCP"
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

    elif UDP in packet:
        protocol = "UDP"
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    elif ICMP in packet:
        protocol = "ICMP"

    elif ARP in packet:
        protocol = "ARP"

    else:
        protocol = "OTHER"

    if source_ip in LOCAL_IPS:
        direction = "OUTBOUND"

    elif destination_ip in LOCAL_IPS:
        direction = "INBOUND"

    else:
        direction = "OTHER"

    if DNS in packet and DNSQR in packet:
        if packet[DNS].qr == 0:
            domain = (
                packet[DNSQR]
                .qname.decode(errors="replace")
                .rstrip(".")
            )

    packet_size = len(packet)

    print(
        f"[{timestamp}] {direction:<8} "
        f"| {protocol:<5} "
        f"| {source_ip}:{source_port} "
        f"-> {destination_ip}:{destination_port} "
        f"| {packet_size} bytes"
        f"{' | DNS: ' + domain if domain else ''}"
    )


def main():
    print("=" * 70)
    print("LinkShield Live Packet Monitor")
    print("=" * 70)

    print(f"Interface: {INTERFACE}")
    print(f"Local addresses: {LOCAL_IPS}")
    print("Monitoring inbound and outbound packets...")
    print("Press Ctrl+C to stop.\n")

    sniff(
        iface=INTERFACE,
        prn=process_packet,
        store=False,
        promisc=False,
    )


if __name__ == "__main__":
    try:
        main()

    except KeyboardInterrupt:
        print("\nPacket monitoring stopped.")
